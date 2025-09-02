## Signet Client Examples

This document shows how to call the `/vex/exchange` endpoint using both HMAC and Ed25519 HTTP Message Signatures.

### Prerequisites

1. Server running locally on port 8000.
2. HMAC key JSON: `./keys/ingress_hmac.json` (created via `python -m signet_cli gen-hmac`).
3. Ed25519 caller key JSON: `./keys/caller_ed25519.json` (created via `python -m signet_cli gen-asym-caller`).
4. For Ed25519, ensure the caller public key is present in `./keys/ingress_ed25519_pubkeys.json`.

---
### Bash: HMAC Example

```bash
PAY='{"message":{"text":"hello hmac"}}'
DIGEST=$(printf "%s" "$PAY" | openssl dgst -binary -sha256 | base64)
SIG_INPUT='sig1=("@method" "@path" "content-digest");created='$(date +%s)';alg="hmac-sha256";keyid="demo-hmac-key"'
CONTENT_DIGEST="sha-256=:${DIGEST}:"
# Compute signature (demo uses Python snippet with shared secret)
SECRET=$(jq -r .secret_b64 ./keys/ingress_hmac.json | base64 -d | xxd -p -c 256)
TO_SIGN="@method: POST\n@path: /vex/exchange\ncontent-digest: ${CONTENT_DIGEST}"
# Placeholder: actual HTTP Message Signatures canonicalization differs; use CLI for production.
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Content-Digest: ${CONTENT_DIGEST}" \
  -H "Signature-Input: ${SIG_INPUT}" \
  -H "Signature: sig1=:PLACEHOLDER_BASE64_SIG:" \
  http://localhost:8000/vex/exchange -d "$PAY"
```

> For a fully correct signature, prefer `python -m signet_cli make-demo-exchange`.

---
### Bash: Ed25519 Example

```bash
PAY='{"message":{"text":"hello ed25519"}}'
DIGEST=$(printf "%s" "$PAY" | openssl dgst -binary -sha256 | base64)
CONTENT_DIGEST="sha-256=:${DIGEST}:"
KEY_JSON=./keys/caller_ed25519.json
KEY_ID=$(jq -r .key_id $KEY_JSON)
SK_B64=$(jq -r .sk_b64 $KEY_JSON)
SIG_INPUT='sig1=("@method" "@path" "content-digest");created='$(date +%s)';alg="ed25519";keyid="'${KEY_ID}'"'
# Placeholder: Creating a real HTTP Message Signature requires canonicalization.
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Content-Digest: ${CONTENT_DIGEST}" \
  -H "Signature-Input: ${SIG_INPUT}" \
  -H "Signature: sig1=:PLACEHOLDER_BASE64_SIG:" \
  http://localhost:8000/vex/exchange -d "$PAY"
```

---
### PowerShell: HMAC Example

```powershell
$Payload = '{"message":{"text":"hello hmac"}}'
$DigestBytes = [System.Text.Encoding]::UTF8.GetBytes($Payload) | ForEach-Object { $_ } | \
    %{} # placeholder for pipeline clarity
$DigestB64 = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Payload)))
$ContentDigest = "sha-256=:$DigestB64:"
$Created = [int][double]::Parse((Get-Date -UFormat %s))
$SigInput = "sig1=(\"@method\" \"@path\" \"content-digest\");created=$Created;alg=\"hmac-sha256\";keyid=\"demo-hmac-key\""
Invoke-RestMethod -Method Post -Uri http://localhost:8000/vex/exchange -Body $Payload -ContentType 'application/json' -Headers @{
  'Content-Digest' = $ContentDigest
  'Signature-Input' = $SigInput
  'Signature' = 'sig1=:PLACEHOLDER_BASE64_SIG:'
} | ConvertTo-Json -Depth 5
```

---
### PowerShell: Ed25519 Example

```powershell
$Payload = '{"message":{"text":"hello ed25519"}}'
$DigestB64 = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Payload)))
$ContentDigest = "sha-256=:$DigestB64:"
$Key = Get-Content ./keys/caller_ed25519.json | ConvertFrom-Json
$Created = [int][double]::Parse((Get-Date -UFormat %s))
$SigInput = "sig1=(\"@method\" \"@path\" \"content-digest\");created=$Created;alg=\"ed25519\";keyid=\"$($Key.key_id)\""
Invoke-RestMethod -Method Post -Uri http://localhost:8000/vex/exchange -Body $Payload -ContentType 'application/json' -Headers @{
  'Content-Digest' = $ContentDigest
  'Signature-Input' = $SigInput
  'Signature' = 'sig1=:PLACEHOLDER_BASE64_SIG:'
} | ConvertTo-Json -Depth 5
```

---
### Recommended: Use Provided CLI

```bash
python -m signet_cli make-demo-exchange --url http://localhost:8000/vex/exchange --algo hmac
python -m signet_cli make-demo-exchange --url http://localhost:8000/vex/exchange --algo ed25519 --caller-key ./keys/caller_ed25519.json
```

The CLI performs canonicalization, computes Content-Digest, and produces valid HTTP Message Signatures.
