# Signet Protocol — Verified Exchanges & Cryptographic Receipts

[![CI](https://github.com/Maverick0351a/SignetProtocolMVP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Maverick0351a/SignetProtocolMVP/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Maverick0351a/SignetProtocolMVP?include_prereleases&sort=semver)](https://github.com/Maverick0351a/SignetProtocolMVP/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20|%203.12-blue)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-Ruff-1f2e3d)](https://docs.astral.sh/ruff/)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Maverick0351a/SignetProtocolMVP/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Maverick0351a/SignetProtocolMVP)
[![Coverage](https://codecov.io/gh/Maverick0351a/SignetProtocolMVP/branch/main/graph/badge.svg)](https://codecov.io/gh/Maverick0351a/SignetProtocolMVP)
[![Container](https://img.shields.io/badge/container-ghcr.io-2496ED?logo=docker&logoColor=white)](https://github.com/users/Maverick0351a/packages)
[![Google Partner](https://img.shields.io/badge/Google%20Partner-Verified-4285F4?logo=google)](https://partners.google.com/)

**Signet** is a verifiable exchange layer for AI↔AI and service↔service traffic.  
Every incoming request is **provenanced** (HTTP Message Signatures, RFC 9421), every payload is **canonically hashed** (RFC 8785), every receipt is **Ed25519‑signed**, and each day’s activity is **Merkle‑anchored** into a Signed Tree Head (STH). The result is a **tamper‑evident audit trail** that turns runtime behavior into cryptographic evidence.

---

## Why Signet

- **Provable ingress** — Verify `Signature-Input`, `Signature`, and `Content-Digest` against the actual request body.
- **Cryptographic receipts** — SR‑1 receipts: canonical JSON → SHA‑256 → Ed25519 signature; **hash‑linked** across exchanges.
- **Transparency at rest** — Daily **Merkle root + STH** to attest scope and integrity of the receipt set.
- **Policy guard** — Deterministic allow/deny with signed outcomes.
- **Operational tooling** — CLI for keygen, signed calls (HMAC or Ed25519), verification, STH build, and Compliance Pack export.

> **Outcome:** verifiable evidence you can hand to auditors, attach to Annex‑style dossiers, and use to unlock approvals.

---

## Architecture (at a glance)



Caller ──(HTTP Message Signatures + Content‑Digest)──▶ Signet Ingress
└─ HMAC‑SHA256 or Ed25519

Ingress ▶ SFT Pipeline: sanitize → normalize → policy (deterministic)
▶ SR‑1: canonicalize (RFC 8785) → sha256 → Ed25519 sign
▶ Hash‑link with previous receipt

Storage ▶ receipts/YYYY‑MM‑DD/*.json → Merkle tree → STH (Ed25519 signed)

Tooling ▶ CLI: verify‑receipt | build‑merkle | build‑compliance‑pack | make‑demo‑exchange


---

## Quickstart

> **Requirements:** Python 3.11+ (Windows, macOS, Linux). Optional: Docker.

### Install only the verification SDK

```bash
pip install signet-sdk
```

Import:

```python
from signet_sdk import verify_receipt, verify_sth, verify_inclusion
```

### macOS/Linux
```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install

export PYTHONPATH=./src
cp .env.example .env
python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json

uvicorn signet_api.main:app --reload --port 8000
# New terminal:
export PYTHONPATH=./src
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange

Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install

$env:PYTHONPATH = "./src"
Copy-Item .env.example .env -ErrorAction SilentlyContinue
python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json

python -m uvicorn signet_api.main:app --port 8000
# New terminal:
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "./src"
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange


Receipts: ./storage/receipts/<YYYY-MM-DD>/*.json
Verify: python -m signet_cli verify-receipt <path>
STH: python -m signet_cli build-merkle --dir ./storage/receipts

Ingress Signatures (HMAC + Ed25519)

HMAC‑SHA256 for private/internal callers (shared secret JSON at ./keys/ingress_hmac.json)

Ed25519 for third‑party callers (public key verification map at ./keys/ingress_ed25519_pubkeys.json)

Client CLI (HMAC default)

# HMAC
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange

# Ed25519 (generate caller key, then sign)
python -m signet_cli gen-asym-caller --out ./keys/caller_ed25519.json
python -m signet_cli make-demo-exchange --algo ed25519 --caller-key ./keys/caller_ed25519.json \
	--url http://127.0.0.1:8000/vex/exchange


Headers verified: Content-Digest (sha‑256) + RFC 9421 Signature-Input / Signature with @method, @path, and content-digest covered.

SR‑1 Cryptographic Receipt (spec)

receipt_id (uuid4), chain_id, ts (RFC 3339 UTC)

payload_hash_b64 (sha‑256 of RFC 8785 canonical JSON of the sanitized payload)

prev_receipt_hash_b64 (hash‑link), signer_pubkey_b64 (Ed25519 32‑byte)

signature_b64 (Ed25519 over canonicalized receipt sans signature)

http metadata (method, path, content_digest, signer_key_id)

Verify a receipt

python -m signet_cli verify-receipt ./storage/receipts/$(date +%F)/<receipt>.json

Transparency Root (Merkle + STH)

Build a daily Merkle tree over receipts and sign the STH:

python -m signet_cli build-merkle --dir ./storage/receipts
cat ./storage/receipts/$(date +%F)/sth.json

Compliance Pack (export & verify)

Produce a zip with: receipts, sth.json, README, and verification scripts.

python -m signet_cli build-compliance-pack --out ./dist/compliance_pack.zip --days 1


Unpack and run verify.sh (bash) or verify.ps1 (PowerShell) to sample‑verify receipts and STH signature, printing PASS/FAIL.

API

POST /vex/exchange — Provenanced ingress; returns SR‑1 receipt JSON

POST /vex/verify — Submit a receipt JSON; returns {"signature_valid": true|false}

GET /healthz — Liveness probe

Swagger UI: /docs (when server is running)

SDK (verification helpers)

A lightweight signet_sdk package exposes:

verify_receipt(receipt_json: dict) -> bool

verify_sth(sth_json: dict) -> bool

verify_inclusion(receipt_json, sth_json) -> bool (inclusion proof wiring extended next)

Inclusion Proof (after build_merkle creates proofs.json)

```bash
# build merkle (writes sth.json + proofs.json)
python -m signet_cli build-merkle --dir ./storage/receipts

# verify inclusion for a given receipt
python -m signet_cli verify-inclusion --receipt ./storage/receipts/$(date +%F)/<receipt>.json \
	--sth ./storage/receipts/$(date +%F)/sth.json
```

Build and install locally:

python -m build
pip install --force-reinstall dist/*.whl
python -c "from signet_sdk import verify_receipt; print('sdk import ok')"

Docker

# health
curl http://127.0.0.1:8000/healthz


The runtime image runs as non‑root, copies only required files, and sets PYTHONPATH=/app/src.

Security

Provenanced ingress: RFC 9421 HTTP Message Signatures + Content-Digest verification.

Canonicalization: RFC 8785; no non‑canonical serialization before hashing/signing.

No payload decryption; no private keys exposed in logs.

Responsible disclosure: open a Security Advisory in GitHub or email the maintainers (see repository “About”).

Roadmap

Inclusion proofs API and CLI (verify_inclusion)

Receipts Transparency Log (append‑only CT‑style) with inclusion endpoints

Asymmetric keys for all external ingress by default

SBOM (CycloneDX) + signed release artifacts

Multi‑tenant quotas & reserved capacity

LangChain and JS adapter examples

Fuzzing harnesses (ClusterFuzzLite) for receipt & Merkle logic

Contributing

ruff check + ruff format must pass

pytest -q must pass

Update docs for any behavior change

Run all:

python -m ruff check src tests && python -m ruff format --check src tests && python -m pytest -q

### Fuzzing (ClusterFuzzLite)

We provide Atheris-based fuzz harnesses under `fuzz/` and two GitHub Actions workflows:

- `fuzzing-pr.yml` (quick 2‑minute fuzz on every PR touching Python code or harnesses)
- `fuzzing-cron.yml` (15‑minute nightly fuzz run)

Local run (example):

```bash
pip install -r requirements-fuzz.txt
python -m pip install -r requirements.txt
PYTHONPATH=./src python fuzz/fuzz_merkle.py  # (runs until interrupted)
```

Workflows currently pin action references via placeholders (`PINNED_SHA_*`). Replace with real commit SHAs for full supply‑chain integrity and an improved OpenSSF Scorecard Fuzzing score.

License

Licensed under the Apache License, Version 2.0.
See LICENSE
 for details.

Google and the Google logo are trademarks of Google LLC. The “Google Partner” badge indicates partner status and does not imply endorsement of this repository’s artifacts.


---

## 🧪 Copilot prompts to add “proof” (copy/paste)

These are **guardrailed prompts** you can paste into Copilot Chat. They focus on **cryptographic proof**, test coverage, and release hygiene. Keep your Guardrails doc in effect.

### 1) Inclusion proofs end‑to‑end
