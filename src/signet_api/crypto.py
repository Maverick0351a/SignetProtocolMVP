from __future__ import annotations
import base64
import hashlib
from typing import Tuple

import nacl.signing
import nacl.encoding
import rfc8785


def B64(b: bytes) -> str:
    """Base64-encode bytes to ASCII string."""
    return base64.b64encode(b).decode("ascii")


def B64D(s: str) -> bytes:
    """Decode base64 ASCII string to bytes with strict validation."""
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as e:
        raise ValueError("invalid base64") from e


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def jcs_dumps(obj) -> bytes:
    """Deterministic canonical JSON bytes per RFC8785."""
    return rfc8785.dumps(obj)


def ed25519_generate() -> Tuple[bytes, bytes]:
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    return (sk.encode(), pk.encode())


def ed25519_sign(sk_bytes: bytes, data: bytes) -> bytes:
    sk = nacl.signing.SigningKey(sk_bytes)
    sig = sk.sign(data).signature
    return sig


def ed25519_verify(pk_bytes: bytes, data: bytes, signature: bytes) -> bool:
    vk = nacl.signing.VerifyKey(pk_bytes)
    try:
        vk.verify(data, signature)
        return True
    except Exception:
        return False
