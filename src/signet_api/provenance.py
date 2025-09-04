from __future__ import annotations
import base64
import json
import time
from typing import Dict, Any

from http_message_signatures import HTTPMessageVerifier, algorithms
from http_message_signatures import HTTPSignatureKeyResolver

from .settings import settings


class HMACResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, secret: bytes):
        self.key_id = key_id
        self.secret = secret

    def resolve_public_key(self, key_id: str):
        if key_id != self.key_id:
            raise KeyError("unknown key id")
        return self.secret

    def resolve_private_key(self, key_id: str):
        return self.resolve_public_key(key_id)


class Ed25519PubResolver(HTTPSignatureKeyResolver):
    """Resolver loading allowed Ed25519 verify keys from a JSON map.

    JSON file shape: { "key_id": "<base64 pubkey>", ... }
    """

    def __init__(self, mapping: Dict[str, bytes]):
        self.mapping = mapping

    def resolve_public_key(self, key_id: str):
        if key_id not in self.mapping:
            raise KeyError("unknown key id")
        pub = self.mapping[key_id]
        # If raw 32-byte Ed25519 key, convert to PEM SubjectPublicKeyInfo
        if isinstance(pub, (bytes, bytearray)) and len(pub) == 32:
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
                from cryptography.hazmat.primitives import serialization as _ser

                pk_obj = _ed.Ed25519PublicKey.from_public_bytes(bytes(pub))
                return pk_obj.public_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PublicFormat.SubjectPublicKeyInfo,
                )
            except Exception:  # noqa: BLE001
                return pub
        return pub

    def resolve_private_key(self, key_id: str):  # not used for verify
        return self.resolve_public_key(key_id)


def load_hmac_key():
    import os

    path = os.getenv("SIGNET_INGRESS_HMAC_PATH", settings.ingress_hmac_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"HMAC file not found: {path}")
    data = json.load(open(path, "r"))
    return data["key_id"], base64.b64decode(data["secret_b64"])


def load_ed25519_pubkeys():
    import os

    path = os.getenv("SIGNET_INGRESS_ED25519_PUBKEYS_PATH", "./keys/ingress_ed25519_pubkeys.json")
    if not os.path.exists(path):
        return {}
    raw = json.load(open(path, "r"))
    return {kid: base64.b64decode(pk_b64) for kid, pk_b64 in raw.items()}


def _select_algorithm(signature_input_header: str):
    """Best-effort parse of alg parameter; return lower-case label or None if absent.

    Absence of alg no longer hard-fails immediately; we attempt HMAC then Ed25519
    for backward compatibility unless explicit requirement enforced via env.
    """
    import re
    m = re.search(r';\s*alg="([^"]+)"', signature_input_header)
    return m.group(1).lower() if m else None


def verify_request(request) -> Dict[str, Any]:
    """Verify HTTP Message Signature + Content-Digest (sha-256) using HMAC-SHA256 or Ed25519.

    Detection: examine Signature-Input for alg="..."; supported values:
      - hmac-sha256 (shared secret)
      - ed25519 (public key from ingress_ed25519_pubkeys.json)
    Returns signer metadata.
    """
    # Extract headers for analysis (case-insensitive); redact Signature locally
    orig_headers = dict(request.headers)
    lower_map = {k.lower(): v for k, v in orig_headers.items()}
    if "signature-input" in lower_map and "Signature-Input" not in orig_headers:
        orig_headers["Signature-Input"] = lower_map["signature-input"]
    if "signature" in lower_map and "Signature" not in orig_headers:
        # Keep actual signature header for verification; do not log raw value
        orig_headers["Signature"] = lower_map["signature"]
    sig_input = orig_headers.get("Signature-Input")
    if not sig_input:
        raise ValueError("missing Signature-Input header")
    alg_label = _select_algorithm(sig_input)

    def _build(alg: str):
        if alg == "ed25519":
            pub_map = load_ed25519_pubkeys()
            if not pub_map:
                raise ValueError("no Ed25519 ingress pubkeys loaded")
            resolver = Ed25519PubResolver(pub_map)
            return HTTPMessageVerifier(signature_algorithm=algorithms.ED25519, key_resolver=resolver)
        if alg == "hmac-sha256":
            key_id, secret = load_hmac_key()
            resolver = HMACResolver(key_id, secret)
            return HTTPMessageVerifier(signature_algorithm=algorithms.HMAC_SHA256, key_resolver=resolver)
        raise ValueError(f"unsupported signature algorithm: {alg}")

    verifier = None
    tried = []
    if alg_label:
        verifier = _build(alg_label)
    else:
        # Try HMAC then Ed25519 silently; collect errors
        for guess in ("hmac-sha256", "ed25519"):
            try:
                verifier = _build(guess)
                alg_label = guess
                break
            except Exception as e:  # noqa: BLE001 - collect and fallback
                tried.append((guess, str(e)))
        if verifier is None:
            raise ValueError(f"could not infer signature algorithm; tried: {tried}")

    body = request.scope.get("_cached_body", b"")

    # Validate Content-Digest
    import re
    import hashlib
    import base64 as _b64

    cd = lower_map.get("content-digest")
    if not cd:
        raise ValueError("missing Content-Digest header")
    m = re.search(r"sha-256=:([A-Za-z0-9+/=]+):", cd)
    if not m:
        raise ValueError("invalid Content-Digest format; expected sha-256=:<b64>:")
    expected_b64 = m.group(1)
    calc = hashlib.sha256(body or b"").digest()
    if _b64.b64encode(calc).decode("ascii") != expected_b64:
        raise ValueError("Content-Digest mismatch")

    class ReqShim:
        def __init__(self, method, url, headers, body):
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body

    try:
        verify_results = verifier.verify(
            ReqShim(request.method, str(request.url), orig_headers, body)
        )
    except Exception as e:  # noqa: BLE001
        import os
        if os.getenv("SIGNET_DEBUG"):
            print("[SIGNET_DEBUG] verify failure", repr(e))
        raise
    vr = verify_results[0]

    # Enforce required covered components; stricter for Ed25519.
    # Normalize covered component names (library may return quoted tokens)
    covered = set()
    for c in vr.covered_components:
        name = c.lower().strip()
        if name.startswith('"') and name.endswith('"') and len(name) > 2:
            name = name[1:-1]
        covered.add(name)
    import os
    if os.getenv("SIGNET_DEBUG"):
        print(
            "[SIGNET_DEBUG] alg=", alg_label, "covered=", covered, "params=", vr.parameters
        )
    if alg_label == "ed25519":
        required = {"@method", "@path", "content-digest", "content-type", "host"}
        if not required.issubset(covered):
            missing = sorted(required - covered)
            raise ValueError(f"missing covered components: {', '.join(missing)}")
    else:
        required_min = {"@method", "@path", "content-digest"}
        if not required_min.issubset(covered):
            missing = sorted(required_min - covered)
            raise ValueError(f"missing covered components: {', '.join(missing)}")

    # Enforce created freshness: mandatory for Ed25519; optional for HMAC if present
    created = vr.parameters.get("created")
    if alg_label == "ed25519":
        try:
            created_ts = int(created) if created is not None else None
        except Exception:
            created_ts = None
        if created_ts is None:
            raise ValueError("missing 'created' parameter")
        now = int(time.time())
        max_skew = int(getattr(settings, "sig_max_skew_seconds", 300))
        if now - created_ts > max_skew:
            raise ValueError("signature 'created' is too old")
    else:
        if created is not None:
            try:
                created_ts = int(created)
            except Exception:
                created_ts = None
            if created_ts is not None:
                now = int(time.time())
                max_skew = int(getattr(settings, "sig_max_skew_seconds", 300))
                if now - created_ts > max_skew:
                    raise ValueError("signature 'created' is too old")
    # key id is inside parameters ("keyid" usually)
    kid = vr.parameters.get("keyid")
    return {
        "key_id": kid,
        "covered": vr.covered_components,
        "params": vr.parameters,
        "algorithm": alg_label,
    }
