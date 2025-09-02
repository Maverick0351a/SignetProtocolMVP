from __future__ import annotations
import uuid
import datetime
from typing import Optional

from .crypto import jcs_dumps, sha256, ed25519_sign, B64
from .models import SR1Receipt
from .settings import settings


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def canonical_payload_hash(payload: dict) -> bytes:
    c = jcs_dumps(payload)
    return sha256(c)


def make_receipt(
    payload: dict,
    prev_receipt_hash_b64: Optional[str],
    signer_sk_bytes: bytes,
    signer_pk_bytes: bytes,
    http_meta: dict,
) -> SR1Receipt:
    payload_hash = canonical_payload_hash(payload)
    body = {
        "receipt_id": str(uuid.uuid4()),
        "chain_id": settings.chain_id,
        "ts": _now_iso(),
        "payload_hash_b64": B64(payload_hash),
        "prev_receipt_hash_b64": prev_receipt_hash_b64,
        "signer_pubkey_b64": B64(signer_pk_bytes),
        "http": http_meta,
    }
    canon = jcs_dumps(body)
    sig = ed25519_sign(signer_sk_bytes, canon)
    return SR1Receipt(**{**body, "signature_b64": B64(sig)})
