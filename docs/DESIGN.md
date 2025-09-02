# Design Notes (Micro‑MVP)

- Provenance: RFC 9421 HTTP Message Signatures using HMAC‑SHA256.
- Canonicalization: RFC 8785 (Trail of Bits `rfc8785`).
- Receipts: minimal SR‑1 schema, signed with Ed25519.
- Storage: flat files (`storage/receipts/YYYY-MM-DD/`).

Upgrade path:
- Support Ed25519 (asymmetric) for HTTP Message Signatures (requires compatible lib support).
- Receipts Transparency Log (Merkle STH + append‑only file).
- Billing + quotas.
