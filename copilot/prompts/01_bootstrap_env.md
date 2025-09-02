# Bootstrap Environment (Copy into Copilot Chat)

You are my build/run assistant. Respond with **commands only**, no explanations.
Target: macOS/Linux shell. If a step fails, print the failing command and a brief fix as a comment.

Commands:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install
cp .env.example .env
python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json
uvicorn signet_api.main:app --reload --port 8000
```
