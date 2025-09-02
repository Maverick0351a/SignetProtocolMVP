# Fill Any Gaps in API + Pipeline

Follow guardrails. Add missing types, docstrings, and tests. Then open a PR in this repo.
When editing files, summarize the diff briefly.

Focus items:
- Validate `ExchangePayload` schema and enforce `message: dict` with string keys.
- Extend `policy()` to deny if `message.text` contains `blocked:` prefix; return 403.
- Add `/vex/verify` endpoint to accept a receipt JSON and return `{"signature_valid": true|false}`.

After coding, run:
```bash
ruff check src tests
ruff format src tests
pytest -q
```

If tests fail, show failing test output and propose fixes.
