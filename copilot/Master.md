# Master Copilot Prompt (One Copy-Paste)

You are my build/ship agent for the **Signet Micro‑MVP**. Follow the *Guardrails* in `copilot/prompts/00_guardrails.md`.

**Phase 1 — Bootstrap (commands only):**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install
export PYTHONPATH=./src
cp .env.example .env
python -m signet_cli gen-keys --out-dir ./keys
python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json
uvicorn signet_api.main:app --reload --port 8000
```

**Phase 2 — Demo Call (new terminal):**
```bash
export PYTHONPATH=./src
python -m signet_cli make-demo-exchange --url http://127.0.0.1:8000/vex/exchange
```

**Phase 3 — Tests + Lint:**
```bash
export PYTHONPATH=./src
ruff check src tests
ruff format src tests
pytest -q
```

**Phase 4 — GitHub (replace <URL>):**
```bash
git init
git add -A
git commit -m "feat(signet): ship micro‑MVP with SR‑1 receipts, RFC8785, HTTP Sig ingress"
git branch -M main
git remote add origin <URL>
git push -u origin main
```

**Phase 5 — Work Log:**
```bash
python scripts/log_workdone.py "Bootstrapped project; demo exchange successful"
git add WORKDONE.md
git commit -m "chore: log workdone"
git push
```
