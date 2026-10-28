# ADR-0002: GitHub Actions as the primary CI/CD system

- Status: accepted
- Date: 2026-10-28

## Context

We need hosted runners, OIDC identities for signing, and tight pull-request integration, at no cost.

## Decision

Use GitHub Actions with reusable workflows. All pipeline logic lives in the `sentinel` CLI, so workflows stay
thin and the same stages run locally (`make pipeline-local`) and could run on Jenkins (stretch goal).

## Consequences

- Every action is pinned by full commit SHA, workflows are audited with zizmor, tokens are least-privilege.
- No self-hosted runners: they would execute untrusted pull-request code on our machines.
- Private-repository minutes are capped (see ADR-0006 for the budget measures).
