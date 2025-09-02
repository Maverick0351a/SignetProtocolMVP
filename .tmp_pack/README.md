# Signet Compliance Pack

Included days: 2025-09-02

## Contents
- receipts/<date>/*.json SR-1 receipts (each has payload hash + signature)
- receipts/<date>/sth.json Signed Tree Head (Merkle root + signature) if present
- verify.sh / verify.ps1 helper scripts

## SR-1 Receipt Verification
A receipt's signature covers canonical RFC 8785 JSON of the receipt body (minus signature field).
Use:

```bash
python -m signet_cli verify-receipt receipts/2025-09-02/<receipt_id>.json
```

## Merkle STH Verification (conceptual)
The STH signs the Merkle root of the day's receipts. Inclusion proofs not included in this pack, but root attests set membership.

## Sample Verification Script
See verify.sh or verify.ps1 to run a random sample and report PASS/FAIL.

## Ed25519 Keys
The verifying public key is embedded in each receipt (`signer_pubkey_b64`).
