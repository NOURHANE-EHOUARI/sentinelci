# ADR-0004: Deterministic decides, AI advises

- Status: accepted
- Date: 2026-10-28

## Context

LLMs are useful for explaining findings, grouping alerts and drafting patches, but their outputs are not
reproducible and can be manipulated by untrusted input (for example prompt injection in code comments).

## Decision

The decision path (`sentinelci.normalize`, `enrich`, `risk`, `policy`) never depends on AI. This is enforced by an
import-linter contract in CI. AI runs in the platform after the decision is stored, writes only advisory data,
and every output is validated against a schema. AI patches re-enter through the remediation loop and are accepted
only after deterministic verification.

## Consequences

- A fooled model can produce a wrong explanation but can never change a verdict; injection canaries measure both.
- The gate works offline and without a GPU.
- The AI package can evolve (models, prompts) without touching the security decision logic.
