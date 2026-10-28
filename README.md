# SentinelCI

**Intelligent DevSecOps and software supply-chain security platform.**

Every change is scanned by a hardened pipeline, every release is decided by testable policy-as-code, every
artifact carries signed evidence of why it is safe, and Kubernetes refuses to run anything without that
evidence. AI explains findings and proposes fixes — it never decides.

> Status: work in progress (Sprint 0). Private repository until v1.0.0.

## Why

In March 2026 the Trivy scanner and its GitHub Action were compromised and turned into a credential stealer,
and the same campaign reached the LiteLLM package on PyPI. SentinelCI is designed around the lessons of that
incident chain: pinned and verified tooling, least-privilege pipelines, signed artifacts, deploy-time
enforcement, and security decisions that are deterministic, reproducible and auditable.

## Core ideas

| Principle | In practice |
|---|---|
| Deterministic decides, AI advises | The release gate (risk model + OPA policies) runs without AI; an architecture contract forbids the decision path from importing the AI package |
| Fail closed | Scanner errors, timeouts or integrity mismatches block the release |
| Everything is evidence | Each decision records the digests of all its inputs and can be replayed bit-for-bit |
| Practice what we preach | SHA-pinned actions, least-privilege jobs, workflow security audits on this very repository |
| Contracts before code | Versioned JSON Schemas with fixtures let both tracks build in parallel |

## Architecture at a glance

```
PR / push ──► GitHub Actions (scan · build · gate · sign/attest) ──► OCI registry (image + signature + attestations)
                     │                                                        │
                     │ evidence bundle                                        ▼
                     ▼                                         kind cluster: Argo CD ──► Kyverno admission ──► workloads
          SentinelCI control plane (FastAPI · PostgreSQL+pgvector · SeaweedFS · workers)
          ├─ AI analyst (Ollama, advisory only) · correlator · remediation bot
          └─ dashboard (React) · Prometheus + Grafana
```

## Repository layout

```
cli/                 sentinelci core library + `sentinel` CLI (the deterministic decision path)
platform/api         control-plane API (FastAPI)
platform/worker      background jobs (sync, enrichment refresh, AI, remediation)
ai/                  sentinel_ai: explanations, triage, correlation, patch proposals (advisory)
schemas/             contracts: finding, decision, patch proposal, verification result (+ fixtures)
policies/            OPA/Rego release-gate policies and risk model
deploy/              compose, kind, Helm, Kyverno, Argo CD, Grafana
eval/                evaluation harness and benchmark reports
demo-shop/           INTENTIONALLY VULNERABLE demo target used for the benchmark — never deploy it
docs/                specification, ADRs
```

## Getting started

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.12+, Docker (later sprints), make.

```bash
make setup   # install the locked workspace and git hooks
make check   # lint, strict typing, architecture contract, tests, workflow audit
make up      # local platform in Docker (see deploy/compose/README.md)
```

## Documentation

- [Specification](docs/spec/SPEC.md) — architecture, pipeline, risk model, contracts, task division, roadmap
- [Architecture decision records](docs/adr/)
- [Security policy](SECURITY.md)
- [Instructions for coding agents](CLAUDE.md)

## Team

Built by [@NOURHANE-EHOUARI](https://github.com/NOURHANE-EHOUARI) and [@Hiba-elouazi](https://github.com/Hiba-elouazi)
as a final-year portfolio project.
