# API

## POST /vex/exchange

- Body: arbitrary JSON (MVP expects `{ "message": { "text": "..." } }`)
- Required headers:
  - `Content-Digest: sha-256=:<base64-sha256-of-body>:`
  - `Signature-Input` and `Signature` per RFC 9421 (HMAC demo key).

Returns: SR‑1 receipt JSON.

## GET /healthz
Returns `{ "ok": true }`.
