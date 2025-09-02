from __future__ import annotations
import os
import json
import base64
import pathlib
import datetime
import hashlib
import typer
from rich import print
import requests

from signet_api.crypto import ed25519_generate, B64
from signet_api.settings import settings

from http_message_signatures import HTTPMessageSigner, algorithms
from http_message_signatures import HTTPSignatureKeyResolver

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def gen_keys(out_dir: str = typer.Option("./keys", help="Directory to write keypair")):
    os.makedirs(out_dir, exist_ok=True)
    sk, pk = ed25519_generate()
    (pathlib.Path(out_dir) / "ed25519_private.key").write_bytes(sk)
    (pathlib.Path(out_dir) / "ed25519_public.key").write_bytes(pk)
    print(f"[green]Wrote keys to {out_dir}[/green]")


@app.command()
def gen_hmac(
    out: str = typer.Option("./keys/ingress_hmac.json"),
    key_id: str = typer.Option("demo-hmac-key"),
    secret_b64: str = typer.Option(
        None, help="Optional: provide your own base64 secret"
    ),
):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if secret_b64 is None:
        secret = os.urandom(32)
        secret_b64 = B64(secret)
    data = {"key_id": key_id, "secret_b64": secret_b64}
    json.dump(data, open(out, "w"), indent=2)
    print(f"[green]Wrote HMAC key to {out}[/green]")


class StaticResolver(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, secret: bytes):
        self.key_id = key_id
        self.secret = secret

    def resolve_public_key(self, key_id: str):
        return self.secret

    def resolve_private_key(self, key_id: str):
        return self.secret


@app.command()
def make_demo_exchange(
    url: str = typer.Option(..., help="POST URL for /vex/exchange"),
    key_path: str = typer.Option(
        "./keys/ingress_hmac.json", help="HMAC key json (when --algo hmac)"
    ),
    message: str = typer.Option("hello from signet", help="Message value"),
    algo: str = typer.Option("hmac", help="Signature algorithm: hmac|ed25519"),
    caller_key: str = typer.Option(
        "./keys/caller_ed25519.json",
        help="Caller Ed25519 key json (when --algo ed25519)",
    ),
):
    algo = algo.lower()
    if algo == "hmac":
        data = json.load(open(key_path))
        key_id = data["key_id"]
        secret = base64.b64decode(data["secret_b64"])
        resolver = StaticResolver(key_id, secret)
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.HMAC_SHA256, key_resolver=resolver
        )
        sig_args = {"key_id": key_id}
    elif algo == "ed25519":
        k = json.load(open(caller_key))
        key_id = k["key_id"]
        sk_b64 = k["sk_b64"]
        sk = base64.b64decode(sk_b64)
        from nacl.signing import SigningKey

        class Ed25519Resolver(HTTPSignatureKeyResolver):
            def resolve_public_key(self, key_id_inner: str):
                raise NotImplementedError

            def resolve_private_key(self, key_id_inner: str):
                if key_id_inner != key_id:
                    raise KeyError("unknown key id")
                return SigningKey(sk)

        resolver = Ed25519Resolver()
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519, key_resolver=resolver
        )
        sig_args = {"key_id": key_id}
    else:
        raise typer.BadParameter("Unsupported algo; choose hmac or ed25519")

    payload = {"message": {"text": message}}
    req = requests.Request("POST", url, json=payload)
    prepared = req.prepare()

    # Add Content-Digest header per RFC 9530 (was draft); minimal implementation
    digest = hashlib.sha256(prepared.body).digest()
    prepared.headers["Content-Digest"] = (
        f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"
    )

    signer.sign(
        prepared,
        covered_component_ids=("@method", "@path", "content-digest"),
        **sig_args,
    )
    s = requests.Session()
    resp = s.send(prepared)
    print(f"[cyan]Status[/cyan]: {resp.status_code}")
    try:
        print(resp.json())
    except Exception:
        print(resp.text)


@app.command()
def verify_receipt(path: str):
    obj = json.load(open(path))
    body = {k: obj[k] for k in obj.keys() if k != "signature_b64"}
    from signet_api.crypto import ed25519_verify, jcs_dumps, B64D

    canon = jcs_dumps(body)
    ok = ed25519_verify(
        B64D(obj["signer_pubkey_b64"]), canon, B64D(obj["signature_b64"])
    )
    print({"signature_valid": ok})


@app.command()
def build_merkle(
    dir: str = typer.Option("./storage/receipts", help="Base receipts directory"),
):
    """Build a Merkle tree over today's receipts and emit a Signed Tree Head (STH)."""
    from signet_api.merkle import MerkleTree
    from signet_api.crypto import ed25519_sign

    day_dir = pathlib.Path(dir) / datetime.date.today().isoformat()
    if not day_dir.exists():
        print(f"[red]No receipts for today in {day_dir}[/red]")
        raise typer.Exit(code=1)

    receipts = []
    for p in sorted(day_dir.glob("*.json")):
        obj = json.loads(p.read_text())
        # Leaf is sha256 of canonical JSON of receipt *including* signature (stable transcript)
        leaf = hashlib.sha256(
            json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        ).digest()
        receipts.append((p.name, leaf))

    if not receipts:
        print("[yellow]No receipts found[/yellow]")
        raise typer.Exit(code=0)

    tree = MerkleTree.from_leaves([leaf for _, leaf in receipts])
    root = tree.root
    # Sign the STH with the same Ed25519 key used for receipts
    sk = pathlib.Path(settings.signing_key_path).read_bytes()
    pk = pathlib.Path(settings.signing_pubkey_path).read_bytes()
    sth = {
        "tree_size": len(receipts),
        "merkle_root_b64": base64.b64encode(root).decode(),
        "ts": datetime.datetime.utcnow()
        .replace(tzinfo=datetime.timezone.utc)
        .isoformat(),
        "signer_pubkey_b64": base64.b64encode(pk).decode(),
    }
    import rfc8785

    sig = ed25519_sign(sk, rfc8785.dumps(sth))
    sth["signature_b64"] = base64.b64encode(sig).decode()

    out = day_dir / "sth.json"
    out.write_text(json.dumps(sth, indent=2))
    print(f"[green]Wrote STH to {out}[/green]")


@app.command()
def gen_asym_caller(
    out: str = typer.Option("./keys/caller_ed25519.json", help="Output JSON path"),
    key_id: str = typer.Option("caller-1", help="Key ID to embed"),
):
    """Generate an Ed25519 keypair for an ingress caller (asymmetric mode)."""
    sk, pk = ed25519_generate()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(
        {"key_id": key_id, "sk_b64": B64(sk), "pk_b64": B64(pk)},
        open(out, "w"),
        indent=2,
    )
    print(
        f"[green]Wrote caller Ed25519 keypair to {out}[/green]\n"
        "Hint: add its public key to ./keys/ingress_ed25519_pubkeys.json for server verify."
    )


@app.command()
def build_compliance_pack(
    out: str = typer.Option("./dist/compliance_pack.zip", help="Output zip path"),
    days: int = typer.Option(1, help="Number of days (including today) to include"),
    receipts_dir: str = typer.Option(
        "./storage/receipts", help="Base directory containing dated receipt folders"
    ),
):
    """Build a Compliance Pack zip containing receipts, sth.json, and verification scripts."""
    from zipfile import ZipFile, ZIP_DEFLATED

    out_path = pathlib.Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect days
    today = datetime.date.today()
    day_dirs = [today - datetime.timedelta(days=i) for i in range(days)]
    collected = []
    for d in day_dirs:
        day_path = pathlib.Path(receipts_dir) / d.isoformat()
        if not day_path.exists():
            continue
        for f in sorted(day_path.glob("*.json")):
            # include all receipts + sth.json if present
            collected.append((d.isoformat(), f))

    if not collected:
        print("[red]No receipts found for requested window[/red]")
        raise typer.Exit(code=1)

    # Ensure STH exists for today (or newest day) by calling build_merkle logic if missing
    latest_day_dir = pathlib.Path(receipts_dir) / today.isoformat()
    sth_path = latest_day_dir / "sth.json"
    if latest_day_dir.exists() and not sth_path.exists():
        # Directly invoke build_merkle to create missing STH
        build_merkle(dir=receipts_dir)

    # Re-scan to capture sth.json after potential build
    pack_files = []
    for d, f in collected:
        rel = f"receipts/{d}/{f.name}"
        pack_files.append((rel, f))

    # README content
    readme = f"""# Signet Compliance Pack\n\nIncluded days: {", ".join(sorted(set(d for d, _ in collected)))}\n\n## Contents\n- receipts/<date>/*.json SR-1 receipts (each has payload hash + signature)\n- receipts/<date>/sth.json Signed Tree Head (Merkle root + signature) if present\n- verify.sh / verify.ps1 helper scripts\n\n## SR-1 Receipt Verification\nA receipt's signature covers canonical RFC 8785 JSON of the receipt body (minus signature field).\nUse:\n\n```bash\npython -m signet_cli verify-receipt receipts/{today.isoformat()}/<receipt_id>.json\n```\n\n## Merkle STH Verification (conceptual)\nThe STH signs the Merkle root of the day's receipts. Inclusion proofs not included in this pack, but root attests set membership.\n\n## Sample Verification Script\nSee verify.sh or verify.ps1 to run a random sample and report PASS/FAIL.\n\n## Ed25519 Keys\nThe verifying public key is embedded in each receipt (`signer_pubkey_b64`).\n"""

    # Verification scripts (simple sampling)
    sample_script_bash = """#!/usr/bin/env bash
set -euo pipefail
echo "Verifying sample receipts..."
fails=0
total=0
mapfile -t RECEIPTS < <(find receipts -maxdepth 2 -type f -name '*.json' ! -name 'sth.json')
shuf -n 5 < <(printf '%s\n' "${RECEIPTS[@]}") | while read -r r; do
  if python -m signet_cli verify-receipt "$r" | grep -q 'True'; then
    echo "[OK] $r"
  else
    echo "[FAIL] $r"; fails=$((fails+1))
  fi
  total=$((total+1))
done
if [ -f receipts/$(date +%Y-%m-%d)/sth.json ]; then
  echo "STH present: receipts/$(date +%Y-%m-%d)/sth.json"
fi
echo "Failures: $fails / $total"; [ "$fails" -eq 0 ] && echo PASS || (echo FAIL; exit 1)
"""

    sample_script_ps = """Param()
$ErrorActionPreference = 'Stop'
Write-Host 'Verifying sample receipts...'
$receipts = Get-ChildItem -Recurse -Filter *.json receipts | Where-Object { $_.Name -ne 'sth.json' }
$sample = $receipts | Get-Random -Count ([Math]::Min(5, $receipts.Count))
$fails = 0
foreach ($r in $sample) {
  $out = python -m signet_cli verify-receipt $r.FullName | Out-String
  if ($out -match 'True') { Write-Host "[OK] $($r.Name)" } else { Write-Host "[FAIL] $($r.Name)"; $fails++ }
}
$sth = Join-Path 'receipts' (Get-Date -Format 'yyyy-MM-dd') 'sth.json'
if (Test-Path $sth) { Write-Host "STH present: $sth" }
Write-Host "Failures: $fails"; if ($fails -eq 0) { Write-Host PASS } else { Write-Host FAIL; exit 1 }
"""

    with ZipFile(out_path, "w", compression=ZIP_DEFLATED) as z:
        # write receipts
        for rel, f in pack_files:
            z.write(f, rel)
        z.writestr("README.md", readme)
        z.writestr("verify.sh", sample_script_bash)
        z.writestr("verify.ps1", sample_script_ps)

    print(
        f"[green]Wrote compliance pack to {out_path} (files: {len(pack_files)})[/green]"
    )


if __name__ == "__main__":
    app()
