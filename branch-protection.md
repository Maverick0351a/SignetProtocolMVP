Branch protection (required checks and policy)

Scope
- Branches: main, release/*
- Tags: v*.*.* (restrict creation to maintainers or use GitHub Releases)

Required status checks (set in repository settings)
- CI: workflow "CI" (require the job: test (ubuntu-latest))
- Code scanning: CodeQL (workflow "CodeQL")
- OpenSSF Scorecard: workflow "OpenSSF Scorecard"
- Codecov: codecov/project (>=80% target) & codecov/patch (>=75% patch coverage)
- SBOM (CycloneDX): workflow "SBOM (CycloneDX)" (optional initially; recommend requiring once stable)
- Vulnerability Scan (pip-audit): optional but recommended to require once noise is under control

Review rules
- Require pull request reviews: at least 1 (2 recommended)
- Require review from Code Owners
- Dismiss stale pull request approvals when new commits are pushed
- Require conversation resolution before merging

History and provenance
- Require signed commits (enforce for administrators)
- Require linear history (disallow merge commits)
- Disallow force pushes and branch deletions on protected branches

Workflow permissions (Actions settings)
- Default: Read repository contents
- Job-level writes only where strictly required: security-events: write (CodeQL/Scorecard SARIF), id-token: write (Scorecard OIDC), actions: write (artifact upload if needed)

Rationale
- Ensures tests and SAST pass before merge, enforces provenance via signed commits, and limits token scope per job to minimize blast radius.
