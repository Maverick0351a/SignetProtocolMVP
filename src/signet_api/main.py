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

app = FastAPI(title="Signet Micro-MVP")


def _ensure_dirs():
    Path(settings.storage_dir).mkdir(parents=True, exist_ok=True)
    Path("./keys").mkdir(parents=True, exist_ok=True)


def _load_keys():
    _ensure_dirs()
    sk_path = Path(settings.signing_key_path)
    pk_path = Path(settings.signing_pubkey_path)
    if not sk_path.exists() or not pk_path.exists():
        # generate if missing (dev only)
        from nacl.signing import SigningKey

        sk = SigningKey.generate()
        pk = sk.verify_key
        sk_path.write_bytes(sk.encode())
        pk_path.write_bytes(pk.encode())
    return sk_path.read_bytes(), pk_path.read_bytes()


@app.post("/vex/exchange")
async def vex_exchange(request: Request):
    body = await request.body()
    # cache body for provenance verifier
    request.scope["_cached_body"] = body

    # Verify provenance (HTTP Message Signatures + Content-Digest)
    try:
        prov = verify_request(request)
    except Exception as e:
        raise HTTPException(
            status_code=401, detail=f"provenance verification failed: {e}"
        )

    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    # Validate schema
    try:
        payload_model = ExchangePayload(**raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"payload schema invalid: {e}")
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

    # Find the last receipt to link from (hash-link)
    prev_hash_b64 = None
    existing = sorted(receipts_dir.glob("*.json"))
    if existing:
        last = json.loads(existing[-1].read_text())
        prev_hash_b64 = last.get("payload_hash_b64")

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
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
