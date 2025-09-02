import base64
from typing import Dict, Any
from signet_api.crypto import ed25519_verify, jcs_dumps, B64D


def verify_receipt(receipt_json: Dict[str, Any]) -> bool:
    """Return True if the SR-1 style receipt's signature is valid.

    Expects the receipt to include signer_pubkey_b64 and signature_b64 fields.
    Canonicalizes the body (all fields except signature_b64) using RFC 8785 JSON
    and verifies the Ed25519 signature.
    """
    try:
        sig_b64 = receipt_json["signature_b64"]
        pub_b64 = receipt_json["signer_pubkey_b64"]
    except KeyError:
        return False
    body = {k: v for k, v in receipt_json.items() if k != "signature_b64"}
    canon = jcs_dumps(body)
    try:
        return ed25519_verify(B64D(pub_b64), canon, B64D(sig_b64))
    except Exception:
        return False


def verify_sth(sth_json: Dict[str, Any]) -> bool:
    """Verify STH signature (Merkle root attestation)."""
    try:
        sig_b64 = sth_json["signature_b64"]
        pub_b64 = sth_json["signer_pubkey_b64"]
    except KeyError:
        return False
    body = {k: v for k, v in sth_json.items() if k != "signature_b64"}
    import rfc8785
    canon = rfc8785.dumps(body)
    try:
        return ed25519_verify(B64D(pub_b64), canon, B64D(sig_b64))
    except Exception:
        return False


def verify_inclusion(receipt_json: Dict[str, Any], sth_json: Dict[str, Any]) -> bool:
    """Placeholder: Merkle inclusion proof verification (not yet implemented).

    Returns False until proof mechanism is wired up.
    """
    return False
