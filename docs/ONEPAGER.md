# Signet Protocol — One‑Pager

## 1. The Problem
Modern AI systems exchange large volumes of machine‑generated facts, judgments, and recommendations. Downstream teams (security, audit, compliance, regulators, customers) ask:
- Who produced this artifact and under what policy?
- Has it been tampered with in flight?
- Can we *prove* a specific model / agent actually saw and signed off on it?
- Can we establish a tamper‑evident timeline for critical AI ↔ AI / AI ↔ API exchanges?

Today these answers are scattered across logs, opaque vendor attestations, or are simply unverifiable. Trust gaps slow deals, expand audit scope, and increase risk.

## 2. The Solution
Signet Protocol is a lightweight, cryptographically‑verifiable receipt layer for AI exchanges. Every verified exchange produces an SR‑1 Receipt:
- Canonical JSON transcript hash (RFC 8785)  
- Ed25519 signature by the accountable signing key  
- Chain / policy metadata  
- Merkle inclusion (daily) via Signed Tree Head (STH) for set consistency

Ingress provenance (HMAC or Ed25519 HTTP Message Signatures) ensures only authenticated, integrity‑checked requests produce receipts.

## 3. Deliverables (MVP Scope)
| Deliverable | Description | Proof Artifact |
|-------------|-------------|----------------|
| SR‑1 Receipts | Per‑exchange signed JSON receipts | `receipt-*.json` (signature + pubkey) |
| Signed Tree Head | Daily Merkle root over receipts | `sth.json` (root + signature) |
| Compliance Pack | Zip bundle for auditors | `compliance_pack.zip` |
| Verification SDK | Python helper to verify receipts/STH | `signet_sdk` |
| Ingress Provenance | Dual algorithm (HMAC / Ed25519) request signing | HTTP Sig headers |
| Policy Gate | Deterministic block/allow filter | 403 response + test |

## 4. How We Prove It
| Claim | Mechanism | How to Verify |
|-------|-----------|---------------|
| Receipt not forged | Ed25519 signature over canonical receipt body | `signet_sdk.verify_receipt()` |
| Body not altered | Canonical JSON + signature check | Re‑serialize & verify |
| Exchange existed that day | Merkle inclusion (roadmap) + STH signature | Compare receipt hash vs STH proof |
| No receipts silently removed | STH chain + (optional future) root timestamping | Recompute Merkle tree |
| Request integrity at ingress | HTTP Message Signatures + `Content-Digest` | Rebuild signature base, verify secret/pubkey |

## 5. Two‑Week Implementation Timeline (Example)
| Day Range | Milestone | Output |
|-----------|-----------|--------|
| 1‑2 | Environment + Key Management | Keys generated, signing service up |
| 3‑4 | Provenance Gate (HMAC) | Authenticated exchanges produce receipts |
| 5‑6 | Ed25519 Ingress + Policy Rules | Dual algo, policy test green |
| 7‑8 | Merkle & STH + CLI Tools | `build-merkle`, STH signed |
| 9‑10 | Compliance Pack & SDK | Zip + `verify_receipt`, `verify_sth` |
| 11‑12 | Integration in Client Workflow | Client emits signed exchanges |
| 13 | Audit Run / Dry Compliance Review | Pack shared with stakeholders |
| 14 | Harden & Handover | Docs, runbooks, backlog next steps |

## 6. Pricing (Pilot Illustration)
| Package | Scope | Monthly (USD) | Notes |
|---------|-------|--------------|-------|
| Pilot (MVP) | 1 environment, ≤5M receipts/month | $4,000 | Shared support channel |
| Growth | 3 env (dev/stage/prod), ≤25M receipts | $9,500 | 99.9% SLA, advisory reviews |
| Enterprise | Custom scale & retention | Custom | SSO, DPA, on‑prem option |

(Add‑ons: Inclusion proof API, Hardware‑backed keys, SIEM export connectors.)

## 7. Why Now
- Regulatory pressure on AI transparency & model accountability is rising.
- Simple, composable, cryptographic evidence reduces audit friction & sales cycles.
- Lightweight integration (HTTP signatures + JSON) keeps engineering cost low.

## 8. Next Step
Run a 14‑day pilot: integrate signing at one AI ↔ API junction, emit receipts, ship a compliance pack to internal audit. Expand after a tangible win.

---
© 2025 Signet Protocol (MVP). Draft for customer discussions. Not a binding offer.
