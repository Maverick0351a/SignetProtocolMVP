# Debug Session

When I paste errors, respond with a numbered **fix plan** then the minimal patch (file path + unified diff).
Run:
```bash
ruff check src tests
pytest -q
```
Stop after the first red test, fix, re-run until green.
