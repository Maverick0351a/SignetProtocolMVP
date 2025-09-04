from __future__ import annotations
from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class NaClToPEMResolver:
    def __init__(self, sk: SigningKey):
        # Prefer using seed (32 bytes)
        try:
            seed = sk._seed  # type: ignore[attr-defined]
        except Exception:
            seed = bytes(sk)[:32]
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        self._pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def resolve_public_key(self, key_id: str):
        # Not used by http_message_signatures for signing
        return None

    def resolve_private_key(self, key_id: str):
        return self._pem
