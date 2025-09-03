#!/usr/bin/env python3
"""Auto-pin GitHub Actions in workflow files to immutable commit SHAs.

Scans .github/workflows/*.yml / *.yaml for `uses:` directives that reference
GitHub actions via tags, branches, or other non-40char refs and resolves them
(to full commit SHAs) using the GitHub CLI (`gh api`).

For every rewritten line it appends a trailing comment:
  # pinned from <original-ref>

Creates a one-time backup of each modified workflow as <file>.bak.

Usage:
  Dry run (see how many would change):
    python scripts/pin_actions.py --dry-run

  Apply changes:
    python scripts/pin_actions.py

Prerequisites:
  - GitHub CLI installed and authenticated: `gh auth login`
  - Token must have at least repo read access.

Safe to re-run; already pinned 40-char SHAs are skipped.
"""
import json, os, re, subprocess, sys, glob, shutil
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
USES_RE = re.compile(r"^(\s*uses:\s*)(?!\./|docker://)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)@([^\s#]+)(.*)$")

def gh_api(path: str):
    """Call GitHub REST API via `gh api` and return parsed JSON."""
    out = subprocess.check_output(["gh", "api", path], text=True)
    return json.loads(out)

def resolve_ref_to_commit_sha(repo: str, ref: str) -> str:
    """Resolve repo@ref to a commit SHA.

    Tries tag, then branch, then generic commit lookup.
    Raises RuntimeError if it cannot resolve.
    """
    # Try tag
    try:
        data = gh_api(f"/repos/{repo}/git/ref/tags/{ref}")
        obj = data.get("object", {})
        if obj.get("type") == "tag":  # annotated tag
            t = gh_api(f"/repos/{repo}/git/tags/{obj['sha']}")
            return t["object"]["sha"]
        if obj.get("type") == "commit":  # lightweight tag
            return obj["sha"]
    except subprocess.CalledProcessError:
        pass
    # Try branch
    try:
        data = gh_api(f"/repos/{repo}/git/ref/heads/{ref}")
        obj = data.get("object", {})
        if obj.get("type") == "commit":
            return obj["sha"]
    except subprocess.CalledProcessError:
        pass
    # Try commit-ish
    try:
        data = gh_api(f"/repos/{repo}/commits/{ref}")
        return data["sha"]
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Cannot resolve {repo}@{ref} to a commit SHA")

def process_file(p: Path, dry_run=False) -> int:
    changed = 0
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = []
    for line in lines:
        m = USES_RE.match(line)
        if not m:
            new_lines.append(line); continue
        prefix, repo, ref, suffix = m.groups()
        # Skip local actions, docker images already excluded by regex negative lookahead.
        # Already pinned to a 40-char hex? Skip.
        if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            new_lines.append(line); continue
        try:
            sha = resolve_ref_to_commit_sha(repo, ref)
        except Exception as e:
            print(f"[!] {p.name}: skipped {repo}@{ref} ({e})", file=sys.stderr)
            new_lines.append(line); continue
        new_line = f"{prefix}{repo}@{sha}{suffix}"
        if "# pinned from " not in new_line:
            new_line = new_line.rstrip("\n") + f"  # pinned from {ref}\n"
        if new_line != line:
            changed += 1
        new_lines.append(new_line)
    if changed and not dry_run:
        backup = p.with_suffix(p.suffix + ".bak")
        if not backup.exists():
            shutil.copyfile(p, backup)
        p.write_text("".join(new_lines), encoding="utf-8")
    return changed

def main():
    dry = "--dry-run" in sys.argv
    files = sorted(glob.glob(str(WORKFLOWS / "*.yml"))) + sorted(glob.glob(str(WORKFLOWS / "*.yaml")))
    if not files:
        print("No workflow files found."); return
    total = 0
    for f in files:
        total += process_file(Path(f), dry_run=dry)
    print(("(dry-run) " if dry else "") + f"updated references: {total}")

if __name__ == "__main__":
    main()
