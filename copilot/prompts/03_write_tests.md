# Write Additional Tests

Add tests:
- `test_receipt_signature_stable`: same payload -> same canonical hash; signature verifies.
- `test_provenance_missing_digest`: POST without `Content-Digest` returns 401.

Then run:
```bash
pytest -q
```
If failures, show the trace and suggest minimal fixes.
