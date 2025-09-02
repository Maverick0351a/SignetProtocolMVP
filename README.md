# Signet Protocol — Micro‑MVP

This is a *micro‑MVP* scaffold for **Signet Protocol: the trust fabric for AI↔AI**.

It includes:
- FastAPI service that issues **SR‑1 signed receipts** for verified exchanges (VEx).
- Minimal **Proof‑Carrying HTTP** (RFC 9421 HTTP Message Signatures) ingress using HMAC or Ed25519 for provenance.
- Deterministic **JSON Canonicalization (RFC 8785)** via `rfc8785`.
- **Ed25519** signing/verification for receipts.
- A simple **Merkle tree** builder with inclusion proofs and a **Signed Tree Head** (STH).
- A **Typer CLI** for keygen, verification, and demo requests.
- Tests, Dockerfile, devcontainer, pre-commit, and a **Copilot Prompt Pack** to help you finish/extend quickly.

> Scope is intentionally small and pragmatic so you can ship fast and iterate.
> Use this as the seed for the fuller Signet pipeline and SDKs.

## Quickstart

```sh
# 1) Create and activate a virtual environment (Python 3.11+ recommended)
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) Install deps
export PYTHONPATH=./src  # ensure local packages are importable
pip install --upgrade pip
pip install -r requirements.txt

# 3) Generate a demo signing keypair + an ingress HMAC secret
python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json

# 4) Copy env
cp .env.example .env

# 5) Start the API (dev)
uvicorn signet_api.main:app --reload --port 8000

# 6) Send a demo exchange (signed with HTTP Message Signatures HMAC)
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange
```

### Asymmetric ingress quickstart (Ed25519)

```sh
# 1) Generate server-side caller verify pubkey mapping (append new pubkey)
python -m signet_cli gen-asym-caller --out ./keys/caller_ed25519.json
jq '. as $all | .[input_filename|split("/")[-1]|sub(".*";"caller-1")] = (input | .pk_b64)' ./keys/ingress_ed25519_pubkeys.json ./keys/caller_ed25519.json 2>/dev/null || \
	python - <<'PY'
import json,base64,os
src='keys/caller_ed25519.json'; dst='keys/ingress_ed25519_pubkeys.json'
c=json.load(open(src)); m={}
if os.path.exists(dst): m=json.load(open(dst))
m[c['key_id']]=c['pk_b64']
json.dump(m,open(dst,'w'),indent=2)
print('Updated',dst)
PY

# 2) Send an Ed25519-signed exchange
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange --algo ed25519 --caller-key ./keys/caller_ed25519.json
```

If the `Signature-Input` header includes `alg="ed25519"`, the server will look up the `keyid` in `./keys/ingress_ed25519_pubkeys.json`.

Receipts are written to `./storage/receipts/<date>/...` and returned in the API response.
Use `python -m signet_cli verify-receipt <path>` and `build-merkle` to verify locally.

## What’s in here

- `src/signet_api`: FastAPI app, models, pipeline, provenance verification, crypto, merkle.
- `src/signet_cli`: Typer CLI commands.
- `tests`: a few basic tests to validate the flow.
- `copilot/`: **Prompt pack** with guardrails and copy‑paste commands to let GitHub Copilot do heavy lifting.
- `scripts/`: helpers for dev and a work log utility.
- `Dockerfile` and `.devcontainer/` for reproducible local dev.
- `requirements.txt` pinned to current stable versions.

## License

This scaffold is provided as‑is under the MIT license for the parts authored here. See third‑party licenses for dependencies.
