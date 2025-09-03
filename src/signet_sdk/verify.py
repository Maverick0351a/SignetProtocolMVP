from typing import Dict, Any, List, Tuple, Optional
import base64
import json
from pathlib import Path
import hashlib
import rfc8785
from nacl.signing import VerifyKey

#############################
# Minimal crypto primitives #
#############################


def jcs_dumps(obj: Any) -> str:  # RFC 8785 canonical JSON
    return rfc8785.dumps(obj)


def B64D(b64s: str) -> bytes:
    return base64.b64decode(b64s)


def ed25519_verify(pub: bytes, msg: str, sig: bytes) -> bool:
    try:
        vk = VerifyKey(pub)
        vk.verify(msg.encode() if isinstance(msg, str) else msg, sig)
        return True
    except Exception:
        return False


#############################
# Merkle verification (SDK) #
#############################


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _verify_inclusion(
    leaf: bytes, index: int, proof: List[Tuple[bytes, str]], root: bytes
) -> bool:
    h = leaf
    idx = index
    for sibling, side in proof:
        if side == "L":
            h = _h(sibling + h)
        else:
            h = _h(h + sibling)
        idx //= 2
    return h == root


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


def verify_inclusion(
    receipt_json: Dict[str, Any],
    sth_json: Dict[str, Any],
    proofs_path: Optional[str] = None,
) -> bool:
    """Verify that the given receipt is included in the Merkle tree attested by the STH.

    Strategy mirrors CLI build_merkle/verify-inclusion:
      1. Recompute leaf hash as sha256 of canonical JSON (including signature field).
      2. Load proofs.json (same directory as receipt unless proofs_path provided).
      3. Find matching proof entry; reconstruct sibling list.
      4. Verify path to root and compare with STH merkle_root_b64.
    """
    try:
        # Step 1: leaf hash
        leaf_bytes = hashlib.sha256(
            json.dumps(receipt_json, separators=(",", ":"), sort_keys=True).encode()
        ).digest()
        # Step 2: locate proofs.json
        if proofs_path:
            p_path = Path(proofs_path)
        else:
            raise_file = receipt_json.get("__file_path__")  # non-standard hint
            if raise_file:
                p_path = Path(raise_file).parent / "proofs.json"
            else:
                # Can't infer location; require caller to pass proofs_path
                return False
        if not p_path.exists():
            return False
        proofs_data = json.loads(p_path.read_text())
        # Heuristic: each entry has receipt filename; we may not have filename.
        # Accept either exact match via stored hint or hash of payload if none.
        receipt_name = Path(receipt_json.get("__file_path__", "")).name
        entry = None
        if receipt_name:
            entry = next(
                (e for e in proofs_data if e.get("receipt") == receipt_name), None
            )
        if entry is None:
            return False
        proof_list: List[Tuple[bytes, str]] = [
            (base64.b64decode(item["sibling_b64"]), item["side"])
            for item in entry.get("proof", [])
        ]
        root = base64.b64decode(sth_json["merkle_root_b64"])
        return _verify_inclusion(leaf_bytes, entry["index"], proof_list, root)
    except Exception:
        return False
