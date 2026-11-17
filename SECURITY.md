# Security policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting: the repository's **Security**
tab, **Report a vulnerability** (on since the repository went public, ADR-0016). Give a description, reproduction
steps and the affected version or commit. We aim to acknowledge reports within 72 hours.

## Scope

- In scope: the SentinelCI CLI, platform, workflows, policies and deployment manifests.
- Out of scope: `demo-shop/`, which is **intentionally vulnerable** and exists only as a benchmark target.
  It must never be deployed or exposed beyond localhost.

## Our own supply chain

- GitHub Actions are pinned by full commit SHA and audited with zizmor on every change.
- Python dependencies are locked with hashes (`uv.lock`) and updated by Dependabot with a cooldown period.
- Workflow jobs run with least-privilege tokens; jobs that execute repository code never receive secrets.
- No real credentials are stored in the repository; signing keys are never committed.
