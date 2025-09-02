from __future__ import annotations
import base64
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
            # For demo MVP, single key_id; extend to lookup by id
            raise KeyError("unknown key id")
        return self.secret

    def resolve_private_key(self, key_id: str):
        return self.resolve_public_key(key_id)


def load_hmac_key():
    import json
    import os

    # Re-resolve path each call so tests that set env after import are honored.
    path = os.getenv("SIGNET_INGRESS_HMAC_PATH", settings.ingress_hmac_path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"HMAC file not found: {path}")
    data = json.load(open(path, "r"))
    return data["key_id"], base64.b64decode(data["secret_b64"])


def verify_request(request) -> Dict[str, Any]:
    """Verify HTTP Message Signature + Content-Digest (sha-256) with shared HMAC key.

    Returns a dict with signer key_id and covered components if valid, raises on failure.
    """
    key_id, secret = load_hmac_key()
    resolver = HMACResolver(key_id=key_id, secret=secret)
    verifier = HTTPMessageVerifier(
        signature_algorithm=algorithms.HMAC_SHA256, key_resolver=resolver
    )

    # http_message_signatures expects a requests.PreparedRequest-like object.
    # Build a minimal shim from FastAPI request.
    url = str(request.url)
    method = request.method
    # FastAPI gives case-insensitive headers object; convert to a plain dict with original case
    orig_headers = dict(request.headers)
    lower_map = {k.lower(): v for k, v in orig_headers.items()}
    # Provide canonical keys if only lowercase present
    if "signature-input" in lower_map and "Signature-Input" not in orig_headers:
        orig_headers["Signature-Input"] = lower_map["signature-input"]
    if "signature" in lower_map and "Signature" not in orig_headers:
        orig_headers["Signature"] = lower_map["signature"]
    headers = lower_map
    body = request.scope.get("_cached_body", b"")

    # Enforce presence of Content-Digest and verify it matches the body (sha-256)
    import re
    import hashlib
    import base64 as _b64

    cd = headers.get("content-digest")
    if not cd:
        raise ValueError("missing Content-Digest header")
    m = re.search(r"sha-256=:(.*):", cd)
    if not m:
        raise ValueError("invalid Content-Digest format; expected sha-256=:<b64>:")
    expected_b64 = m.group(1)
    calc = hashlib.sha256(body or b"").digest()
    if _b64.b64encode(calc).decode("ascii") != expected_b64:
        raise ValueError("Content-Digest mismatch")

    # Verify signature; also return what was covered
    class ReqShim:
        def __init__(self, method, url, headers, body):
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body

    # http_message_signatures library expects canonical header names; supply case-insensitive mapping
    verify_results = verifier.verify(ReqShim(method, url, orig_headers, body))
    vr = verify_results[0]
    return {
        "key_id": key_id,
        "covered": vr.covered_components,
        "params": vr.parameters,
    }
