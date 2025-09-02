#!/usr/bin/env python3
"""Emit HTTP Message Signature headers for a prepared request body.

Generates:
  - Content-Digest
  - Signature-Input
  - Signature

Usage (HMAC):
  python scripts/emit_sig_headers.py \\
    --algo hmac --hmac-json ./keys/ingress_hmac.json \\
    --method POST --url http://127.0.0.1:8000/vex/exchange --body-file ./body.json

Usage (Ed25519):
  python -m signet_cli gen-asym-caller --out ./keys/caller_ed25519.json
  python scripts/emit_sig_headers.py \\
    --algo ed25519 --caller-json ./keys/caller_ed25519.json \\
    --method POST --url http://127.0.0.1:8000/vex/exchange --body-file ./body.json

Copy the three printed headers into Postman.
"""

from __future__ import annotations
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import requests
from http_message_signatures import (
    HTTPMessageSigner,
    algorithms,
    HTTPSignatureKeyResolver,
)


class HMACResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, secret: bytes):
        self._key_id = key_id
        self._secret = secret

    def resolve_public_key(self, key_id: str):  # type: ignore[override]
        if key_id != self._key_id:
            raise KeyError("unknown key id")
        return self._secret

    def resolve_private_key(self, key_id: str):  # type: ignore[override]
        if key_id != self._key_id:
            raise KeyError("unknown key id")
        return self._secret


class Ed25519Resolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, sk: bytes):
        self._key_id = key_id
        self._sk = sk

    def resolve_public_key(self, key_id: str):  # type: ignore[override]
        # Not needed for signing only path.
        raise NotImplementedError

    def resolve_private_key(self, key_id: str):  # type: ignore[override]
        if key_id != self._key_id:
            raise KeyError("unknown key id")
        from nacl.signing import SigningKey

        return SigningKey(self._sk)


def _load_body(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        print(f"[ERR] body file not found: {path}", file=sys.stderr)
        sys.exit(2)
    return p.read_bytes()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--algo", choices=["hmac", "ed25519"], default="hmac")
    ap.add_argument("--hmac-json", help="Path to ./keys/ingress_hmac.json (HMAC mode)")
    ap.add_argument(
        "--caller-json", help="Path to ./keys/caller_ed25519.json (Ed25519 mode)"
    )
    ap.add_argument("--method", default="POST")
    ap.add_argument("--url", required=True)
    ap.add_argument("--body-file", required=True)
    args = ap.parse_args()

    body = _load_body(args.body_file)
    # Build a prepared request so library can sign canonical components
    req = requests.Request(
        args.method.upper(),
        args.url,
        data=body,
        headers={"content-type": "application/json"},
    )
    pre = req.prepare()

    # Content-Digest per RFC 9530 (sha-256)
    digest = hashlib.sha256(body).digest()
    pre.headers["Content-Digest"] = (
        f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"
    )

    if args.algo == "hmac":
        if not args.hmac_json:
            print("--hmac-json required for hmac mode", file=sys.stderr)
            return 2
        data = json.load(open(args.hmac_json, "r"))
        key_id = data["key_id"]
        secret = base64.b64decode(data["secret_b64"])
        resolver = HMACResolver(key_id, secret)
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.HMAC_SHA256, key_resolver=resolver
        )
        signer.sign(
            pre,
            key_id=key_id,
            covered_component_ids=("@method", "@path", "content-digest"),
        )
    else:
        if not args.caller_json:
            print("--caller-json required for ed25519 mode", file=sys.stderr)
            return 2
        data = json.load(open(args.caller_json, "r"))
        key_id = data["key_id"]
        sk = base64.b64decode(data["sk_b64"])
        resolver = Ed25519Resolver(key_id, sk)
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519, key_resolver=resolver
        )
        signer.sign(
            pre,
            key_id=key_id,
            covered_component_ids=("@method", "@path", "content-digest"),
        )

    # Emit headers for copy/paste into Postman
    print("Content-Digest:", pre.headers["Content-Digest"])  # noqa: T201
    print("Signature-Input:", pre.headers.get("Signature-Input"))  # noqa: T201
    print("Signature:", pre.headers.get("Signature"))  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
