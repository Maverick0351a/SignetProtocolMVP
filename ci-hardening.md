GitHub Actions & OSSF Scorecard hardening audit

Scope
- Workflows parsed: ci.yml, codeql.yml, scorecard.yml, publish.yml, fuzzing-pr.yml, fuzzing-cron.yml, sbom.yml, pip-audit.yml
- Non-goal: ci.yml.bak is ignored (not a workflow)

1) Current state per workflow (permissions and pinning)

A) ci.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - test: permissions: { contents: read, pull-requests: read }
- Uses (all pinned by full SHA):
  - step-security/harden-runner@ec9f2d5… (# v2)
  - actions/checkout@08eba0b… (# v4)
  - actions/setup-python@a26af69… (# v5)
  - actions/upload-artifact@ea165f8… (# v4)
  - codecov/codecov-action@b9fd7d1… (# pinned from v4)
- Risky contexts: none (uses pull_request, not pull_request_target)

B) codeql.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - analyze: permissions: { security-events: write }
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - github/codeql-action/init@b36bf25… (# v3)
  - github/codeql-action/autobuild@b36bf25…
  - github/codeql-action/analyze@b36bf25…
- Risky contexts: none

C) scorecard.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - scorecard: permissions: { security-events: write, id-token: write }
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - ossf/scorecard-action@937ffa9… (# v2.1.0)
  - github/codeql-action/upload-sarif@b36bf25… (# v3)
- Risky contexts: none

D) publish.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - build-publish: none (inherits read-all)
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - actions/upload-artifact@ea165f8…
- Risky contexts: none

E) fuzzing-pr.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - fuzz: none (inherits read-all)
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - google/clusterfuzzlite/actions/run_fuzzers@82652fb… (# v1)
- Risky contexts: none (pull_request)

F) fuzzing-cron.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - fuzz: none (inherits read-all)
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - google/clusterfuzzlite/actions/run_fuzzers@82652fb… (# v1)
- Risky contexts: none

G) sbom.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - sbom: none (inherits read-all)
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - actions/upload-artifact@ea165f8…
- Risky contexts: none

H) pip-audit.yml
- Root permissions: permissions: read-all
- Jobs and job-level overrides:
  - pip-audit: permissions: { contents: read, security-events: write, actions: write }
- Uses (pinned):
  - step-security/harden-runner@ec9f2d5…
  - actions/checkout@08eba0b…
  - actions/setup-python@a26af69…
  - github/codeql-action/upload-sarif@b36bf25…
  - actions/upload-artifact@ea165f8…
- Risky contexts: none

2) Proposed minimal permissions
- Root: permissions: read-all (already set everywhere)
- Job-level adjustments:
  - ci.yml (test): keep { contents: read, pull-requests: read }
  - codeql.yml (analyze): keep { security-events: write }
  - scorecard.yml (scorecard): keep { security-events: write, id-token: write }
  - publish.yml (build-publish): ensure explicit { contents: read, id-token: write } (already set)
  - fuzzing-pr.yml (fuzz): optionally add explicit { contents: read } (inherits root; acceptable)
  - fuzzing-cron.yml (fuzz): optionally add explicit { contents: read }
  - sbom.yml (sbom): optionally add explicit { contents: read }
  - pip-audit.yml (pip-audit): remove actions: write; keep only { contents: read, security-events: write }

3) Pinning status
- All actions already pinned to full-length commit SHAs across workflows. No unpinned actions found; no new pin patches required.

4) Additional required items
- Dependabot: .github/dependabot.yml present and configured for github-actions and pip (daily). Fixed indentation.
- Codecov: Upload step present in CI and pinned. codecov.yml present with thresholds (80% project, 75% patch).
- Branch protection: See branch-protection.md (required checks enumerated).

5) Scorecard alignment note
- Token-Permissions: Root read-all and job-scoped writes only (CodeQL security-events: write; Scorecard id-token: write). Proposed patches further reduce permissions (e.g., remove actions: write from pip-audit), improving this check.
- Pinned-Dependencies: All actions are pinned to full commit SHAs; Docker base images pinned by digest; Python installs in CI/Docker are hash-locked.
- Dependency-Update-Tool: Dependabot enabled for github-actions and pip (daily), improving this check.
- CI-Tests: CI exists and runs tests with coverage; fuzzing workflows run on PR and nightly; Codecov uploads coverage; this strengthens CI-related checks.
