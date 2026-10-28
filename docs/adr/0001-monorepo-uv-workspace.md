# ADR-0001: Single monorepo with a uv workspace

- Status: accepted
- Date: 2026-10-28

## Context

Two people build tightly coupled components (CLI, platform, AI, policies, deployment) that share contracts.
The repository must stay private until the end of the project, and GitHub Actions minutes are limited.

## Decision

Use one repository containing every component, including the intentionally vulnerable `demo-shop/` target.
Python packages are members of a single uv workspace (`cli`, `platform/api`, `platform/worker`, `ai`) with one
lockfile (`uv.lock`) that pins every dependency with hashes.

## Consequences

- One PR can change a contract and both sides of it atomically; contract tests run on every change.
- A single lockfile makes dependency review and Dependabot updates simple.
- `demo-shop/` must be excluded from lint, typing and SentinelCI's self-scan, and scanned by its own workflow.
- Reusable workflows are consumed locally (`uses: ./.github/workflows/...`) instead of across repositories.
