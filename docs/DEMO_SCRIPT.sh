#!/usr/bin/env bash
set -euo pipefail

# Demo: start API, make HMAC & Ed25519 exchanges, verify receipt, build STH & Compliance Pack
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install || true

export PYTHONPATH=./src
cp -n .env.example .env 2>/dev/null || true

python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json
python -m signet_cli gen-asym-caller --out ./keys/caller_ed25519.json

uvicorn signet_api.main:app --port 8000 &
API_PID=$!
sleep 2

# HMAC exchange
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange --algo hmac
# Ed25519 exchange
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange --algo ed25519 --caller-key ./keys/caller_ed25519.json

TODAY=$(date +%F)
LATEST=$(ls -1t storage/receipts/$TODAY/*.json | head -n1)
echo "Latest receipt: $LATEST"
python -m signet_cli verify-receipt "$LATEST"

python -m signet_cli build-merkle --dir ./storage/receipts || true
python -m signet_cli build-compliance-pack --out ./dist/compliance_pack.zip --days 1 || true

kill $API_PID 2>/dev/null || true
echo "Demo complete."
