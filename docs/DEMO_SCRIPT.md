# Signet Protocol Demo Script (<=30 lines)

```powershell
# 1) Setup env
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH=(Resolve-Path .\src).Path

# 2) Generate signing + ingress keys
python -m signet_cli gen-keys --out-dir .\keys
python -m signet_cli gen-hmac --out .\keys\ingress_hmac.json
python -m signet_cli gen-asym-caller --out .\keys\caller_ed25519.json

# 3) (Terminal A) Start API
uvicorn signet_api.main:app --port 8000
# --- run remaining in Terminal B ---

# 4) HMAC demo exchange
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange --algo hmac

# 5) Ed25519 demo exchange
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange --algo ed25519 --caller-key .\keys\caller_ed25519.json

# 6) Show latest receipt path
Get-ChildItem .\storage\receipts\(Get-Date -Format 'yyyy-MM-dd') | Select-Object -First 1

# 7) Verify that receipt
python -m signet_cli verify-receipt (Get-ChildItem .\storage\receipts\(Get-Date -Format 'yyyy-MM-dd') | Select -First 1).FullName

# 8) Build STH + Compliance Pack
python -m signet_cli build-merkle
python -m signet_cli build-compliance-pack --out .\dist\compliance_pack.zip
```
