from __future__ import annotations
import base64
import json
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
        return self.mapping[key_id]

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

    path = "./keys/ingress_ed25519_pubkeys.json"
    if not os.path.exists(path):
        return {}
    raw = json.load(open(path, "r"))
    return {kid: base64.b64decode(pk_b64) for kid, pk_b64 in raw.items()}


def _select_algorithm(signature_input_header: str) -> str:
    """Parse Signature-Input to discover alg parameter if present.

    If alg is absent, default to hmac-sha256 (legacy behavior).
    """
    # Very small parser: look for ;alg="..." pattern
    import re

    m = re.search(r";\\s*alg=\"([^\"]+)\"", signature_input_header)
    if not m:
        return "hmac-sha256"
    return m.group(1).lower()


def verify_request(request) -> Dict[str, Any]:
    """Verify HTTP Message Signature + Content-Digest (sha-256) using HMAC-SHA256 or Ed25519.

    Detection: examine Signature-Input for alg="..."; supported values:
      - hmac-sha256 (shared secret)
      - ed25519 (public key from ingress_ed25519_pubkeys.json)
    Returns signer metadata.
    """
    # Extract headers for analysis
    orig_headers = dict(request.headers)
    lower_map = {k.lower(): v for k, v in orig_headers.items()}
    if "signature-input" in lower_map and "Signature-Input" not in orig_headers:
        orig_headers["Signature-Input"] = lower_map["signature-input"]
    if "signature" in lower_map and "Signature" not in orig_headers:
        orig_headers["Signature"] = lower_map["signature"]
    sig_input = orig_headers.get("Signature-Input")
    if not sig_input:
        raise ValueError("missing Signature-Input header")
    alg_label = _select_algorithm(sig_input)

    # Choose verifier
    if alg_label == "ed25519":
        pub_map = load_ed25519_pubkeys()
        if not pub_map:
            raise ValueError("no Ed25519 ingress pubkeys loaded")
        resolver = Ed25519PubResolver(pub_map)
        sig_alg = algorithms.ED25519
    elif alg_label == "hmac-sha256":
        key_id, secret = load_hmac_key()
        resolver = HMACResolver(key_id, secret)
        sig_alg = algorithms.HMAC_SHA256
    else:
        raise ValueError(f"unsupported signature algorithm: {alg_label}")

    verifier = HTTPMessageVerifier(signature_algorithm=sig_alg, key_resolver=resolver)

    body = request.scope.get("_cached_body", b"")

    # Validate Content-Digest
    import re
    import hashlib
    import base64 as _b64

    cd = lower_map.get("content-digest")
    if not cd:
        raise ValueError("missing Content-Digest header")
    m = re.search(r"sha-256=:(.*):", cd)
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

    verify_results = verifier.verify(
        ReqShim(request.method, str(request.url), orig_headers, body)
    )
    vr = verify_results[0]
    # key id is inside parameters ("keyid" usually)
    kid = vr.parameters.get("keyid")
    return {
        "key_id": kid,
        "covered": vr.covered_components,
        "params": vr.parameters,
        "algorithm": alg_label,
    }
