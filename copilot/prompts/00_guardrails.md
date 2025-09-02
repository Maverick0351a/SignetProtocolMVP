# Copilot Guardrails (Read This First)

You are helping implement and harden the **Signet Protocol Micro‑MVP**.

**Non‑negotiables:**
1) Prefer minimal, tested code. Avoid unnecessary abstraction.
2) Do *not* change public signatures without updating tests and docs.
3) Keep all crypto at the edges; use audited libraries (`rfc8785`, `PyNaCl`, `http-message-signatures`).
4) When you propose code, include short rationale and test snippets.
5) When executing a shell step, output only the exact commands (no prose).

**Security constraints:**
- Never log secrets. Redact with `***`.
- Verify **Content-Digest** and HTTP Message Signatures on ingress.
- Use **RFC 8785** canonicalization for receipts. Never re‑serialize via non‑canonical JSON before hashing/signing.
- Keep deterministic hashes stable—changing schema or ordering must be a conscious, versioned decision.

**Definition of Done (DoD) for any task:**
- Code compiles and unit tests pass: `pytest -q`.
- `ruff check` and `ruff format` clean.
- Updates to `README.md` or `docs/*.md` if behavior changed.
- Adds or updates an example when a new feature is added.
