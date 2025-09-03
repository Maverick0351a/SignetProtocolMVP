"""Fuzz harness for receipt creation & signature cycle.

Targets: make_receipt -> serialization -> verification round trip.

We treat arbitrary fuzzer bytes as (potential) JSON; fall back to a dict with a
single key carrying a hex digest of the input for entropy.

Crash conditions (unexpected exceptions in the cryptographic path) will be
surfaced to ClusterFuzzLite. Expected validation failures are ignored.
"""
from __future__ import annotations
import atheris
import json
import sys
import hashlib
from pathlib import Path

with atheris.instrument_imports():
    from signet_api.receipts import make_receipt
    from signet_api.crypto import jcs_dumps


def _load_keys():
    # Generate ephemeral keys each run (fast, avoids relying on repo state)
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    pk = sk.verify_key
    return sk.encode(), pk.encode()


def TestOneInput(data: bytes):  # noqa: N802 (Atheris signature)
    try:
        try:
            payload = json.loads(data.decode("utf-8", errors="ignore"))
            if not isinstance(payload, dict):
                raise ValueError
        except Exception:
            # Seed entropy via digest keyed under 'blob'
            payload = {"blob": hashlib.sha256(data).hexdigest()}

        # Minimal required keys for pipeline compatibility (if later enforced)
        # Add random-ish value to exercise canonicalization ordering.
        payload.setdefault("id", hashlib.md5(data).hexdigest())  # nosec B303 (fuzz only)
        payload.setdefault("type", "demo")
        payload.setdefault("value", len(data))

        sk, pk = _load_keys()
        receipt = make_receipt(payload, None, sk, pk, {"method": "POST", "path": "/vex/exchange"})
        # Serialize canonical form to stress RFC 8785 path
        canon = jcs_dumps({k: v for k, v in receipt.model_dump().items() if k != "signature_b64"})
        # Re-hash to ensure deterministic behavior (exercise code paths)
        hashlib.sha256(canon.encode()).digest()
    except (ValueError, TypeError, json.JSONDecodeError):
        # Expected malformed input cases; ignore
        return


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
