from __future__ import annotations
from pathlib import Path
import json
import datetime
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

from .settings import settings
from .crypto import ed25519_verify, jcs_dumps, B64D
from .receipts import make_receipt
from .models import ExchangePayload
from .pipeline import run_sft
from .provenance import verify_request
from .middleware.size_limit import SizeLimitMiddleware

app = FastAPI(title="Signet Micro-MVP")
app.add_middleware(SizeLimitMiddleware)


def _ensure_dirs():
    Path(settings.storage_dir).mkdir(parents=True, exist_ok=True)
    Path("./keys").mkdir(parents=True, exist_ok=True)


def _load_keys():
    _ensure_dirs()
    sk_path = Path(settings.signing_key_path)
    pk_path = Path(settings.signing_pubkey_path)
    if not sk_path.exists() or not pk_path.exists():
        # generate if allowed for development only (gated by SIGNET_ALLOW_DEV_KEYGEN)
        allow_dev = getattr(settings, "allow_dev_keygen", False)
        if not allow_dev:
            raise FileNotFoundError(
                "signing keypair not found; set SIGNET_ALLOW_DEV_KEYGEN=true to auto-generate for development"
            )
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        pk = sk.verify_key
        sk_path.write_bytes(sk.encode())
        pk_path.write_bytes(pk.encode())
    return sk_path.read_bytes(), pk_path.read_bytes()


@app.post("/vex/exchange")
async def vex_exchange(request: Request):
    # enforce content type and size limits
    import os as _os
    max_bytes = int(_os.getenv("SIGNET_INGRESS_MAX_BODY_BYTES", getattr(settings, "ingress_max_body_bytes", 1048576)))
    ct = request.headers.get("content-type", "")
    if not ct.lower().startswith("application/json"):
        raise HTTPException(status_code=415, detail="unsupported content type")
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                raise HTTPException(status_code=413, detail="request too large")
        except ValueError:
            # ignore malformed content-length and fall back to post-read check
            pass

    body = request.scope.get("_cached_body")
    if body is None:
        body = await request.body()
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail="request too large")
    # cache body for provenance verifier (already set by middleware; keep for safety)
    request.scope["_cached_body"] = body

    # Verify provenance (HTTP Message Signatures + Content-Digest)
    try:
        prov = verify_request(request)
    except Exception:
        raise HTTPException(status_code=401, detail="provenance verification failed")

    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    # Validate schema
    try:
        payload_model = ExchangePayload(**raw)
    except Exception:
        raise HTTPException(status_code=400, detail="payload schema invalid")
    payload = payload_model.model_dump()

    # Run SFT (sanitize/normalize/policy) exactly once; map denial to 403
    try:
        sft_payload = run_sft(payload)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    # Load signing keys and compute prev link if any
    sk_bytes, pk_bytes = _load_keys()

    receipts_dir = (
        Path(settings.storage_dir) / "receipts" / datetime.date.today().isoformat()
    )
    receipts_dir.mkdir(parents=True, exist_ok=True)

    # Find the most recent receipt to link from (hash-link). Lexicographic
    # ordering of UUID filenames is not chronological, so we parse timestamps.
    prev_hash_b64 = None
    candidates = []
    for p in receipts_dir.glob("*.json"):
        try:
            obj = json.loads(p.read_text())
            ts = obj.get("ts")
            # Parse ISO timestamp; ignore if invalid
            if isinstance(ts, str):
                from datetime import datetime as _dt
                try:
                    parsed = _dt.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue
                candidates.append((parsed, obj.get("payload_hash_b64")))
        except Exception:
            continue
    if candidates:
        candidates.sort(key=lambda x: x[0])
        prev_hash_b64 = candidates[-1][1]

    http_meta = {
        "method": request.method,
        "path": request.url.path,
        "content_digest": request.headers.get("content-digest"),
        "signer_key_id": prov.get("key_id"),
    }

    receipt = make_receipt(sft_payload, prev_hash_b64, sk_bytes, pk_bytes, http_meta)

    # Persist receipt
    rid = receipt.receipt_id
    out_path = receipts_dir / f"{rid}.json"
    out_path.write_text(json.dumps(receipt.model_dump(), indent=2))

    return JSONResponse(receipt.model_dump())


@app.get("/healthz")
async def healthz():
    return {"ok": True, "ts": datetime.datetime.utcnow().isoformat()}


@app.post("/vex/verify")
async def vex_verify(receipt: dict):
    try:
        sig_b64 = receipt.get("signature_b64")
        if not sig_b64:
            raise ValueError("missing signature_b64")
        body = {k: receipt[k] for k in receipt.keys() if k != "signature_b64"}
        canon = jcs_dumps(body)
        ok = ed25519_verify(B64D(receipt["signer_pubkey_b64"]), canon, B64D(sig_b64))
        return {"signature_valid": bool(ok)}
    except Exception:
        raise HTTPException(status_code=400, detail="invalid receipt")
