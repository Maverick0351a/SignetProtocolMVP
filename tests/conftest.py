import os
import sys
from pathlib import Path

from nacl.signing import SigningKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Ensure the 'src' directory is on sys.path for imports in tests
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Reduce noise and ensure default dev keygen is allowed in tests
os.environ.setdefault("SIGNET_ALLOW_DEV_KEYGEN", "true")

class NaClToPEMResolver:
    """Convert a NaCl SigningKey to a PEM PKCS#8 Ed25519 private key.

    Exposes both resolve_private_key and __call__ for compatibility with
    http_message_signatures interfaces that may expect either.
    """
    def __init__(self, sk: SigningKey):
        # Prefer stable 32-byte seed if present, else derive from key bytes
        seed = getattr(sk, "_seed", None) or bytes(sk)[:32]
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        self._pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def resolve_private_key(self, key_id: str):  # type: ignore[override]
        return self._pem

    def resolve_public_key(self, key_id: str):  # type: ignore[override]
        return None

    def __call__(self, key_id: str):  # pragma: no cover
        return self._pem
