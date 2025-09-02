# SR‑1 Signed Receipt (Micro‑MVP)

Fields:
- `receipt_id` (uuid4)
- `chain_id`
- `ts` (RFC 3339 UTC)
- `payload_hash_b64` (sha‑256 of RFC8785 canonical JSON)
- `prev_receipt_hash_b64` (optional)
- `signer_pubkey_b64` (Ed25519 raw 32 bytes, base64)
- `signature_b64` (Ed25519 signature, base64)
- `http` (method, path, content_digest, signer_key_id)

Canonicalization: RFC 8785 via `rfc8785.dumps()`.
Signature: Ed25519 over the canonicalized JSON of the receipt without the `signature_b64` field.
