# SentinelCI

**A verifiable security-control system for software delivery.**

SentinelCI scans every change with pinned, integrity-checked scanners. A policy-as-code gate that anyone can
replay decides whether the change or release may ship. The artifact is signed together with the evidence behind
that decision, and Kubernetes refuses to run anything without it. AI explains findings, groups them by root
cause and proposes fixes. It never decides: an architecture contract keeps it out of the decision path.

> Status: v1.0.0 in preparation. The repository is private until then (ADR-0006), so signing and the runs that
> need Docker or a local model happen on the maintainers' laptop (ADR-0011, ADR-0014).

## Why

In March 2026 the Trivy scanner and its GitHub Action were compromised and turned into a credential stealer,
and the same campaign reached the LiteLLM package on PyPI. A security pipeline is itself part of the supply
chain. SentinelCI is built around that lesson: every tool is pinned and verified before it runs, every job
holds the least privilege it needs, a pull request is judged with its base branch's pipeline (never its own),
and every decision is deterministic, recorded and reproducible.

## What happens to a change

```
pull request / release
  │
  ├─ 1. Scan ─── Gitleaks (secrets) · Opengrep (SAST) · Trivy (IaC) · Syft + Grype (SBOM, SCA, images)
  │              · zizmor (CI workflows). Binaries pinned by sha256 in tools.lock.toml, run offline,
  │              never configured or silenced by the scanned repository. A failed or missing scanner is a
  │              BLOCK (SC-010), never an empty pass.
  ├─ 2. Normalize ─ one Finding v1 per issue, with a stable fingerprint, so "new in this PR" is exact
  ├─ 3. Score ─── CVSS × exploitability (EPSS, CISA KEV) × reachability × exposure → priority P0–P4
  ├─ 4. Decide ── OPA/Rego rules → PASS / WARN / BLOCK with rule ids; a Decision v1 record holds the digest of
  │              every input and replays bit for bit (`sentinel replay`)
  ├─ 5. Sign ──── image + CycloneDX/SPDX SBOMs + SLSA provenance + the decision, as Cosign attestations
  └─ 6. Admit ─── Argo CD deploys by digest; Kyverno admits only an image signed with the release key and
                 carrying its attestations, as `sentinel verify` would
```

Around that deterministic core:

- **AI analyst, advisory only** (local models through Ollama, pinned by digest). It explains a finding with
  references taken only from the finding's own CWE, CVE and GHSA ids, gives triage hints, and groups findings
  by root cause. The decision path cannot import it (`lint-imports`), and its outputs are schema-validated.
  Prompt-injection canaries planted in the demo target measure whether a model obeys instructions hidden in
  the text it reads; whatever it answers, the verdict was already made.
- **Verified remediation.** A bot proposes deterministic fixes for Kubernetes manifests and Dockerfiles and
  opens one pull request per proposal. A separate read-only job rebuilds each patched commit, scans it, runs the
  gate and re-runs the fixer to check that the patch is its own output. Only then is it VERIFIED. LLM code fixes
  are tested against the service's own tests in a sandboxed container. The bot never merges.
- **Platform.** A FastAPI control plane on PostgreSQL keeps runs, findings, decisions, releases, correlations
  and remediation attempts, byte for byte. A React dashboard and Prometheus + Grafana show findings over time,
  gate outcomes, MTTR per priority and alert reduction.

## The release gate

| Rule | Effect | When |
|---|---|---|
| SC-001 | BLOCK | A secret, new in the PR or anywhere in a release image |
| SC-002 | BLOCK | A P0 finding without a valid waiver |
| SC-003 | BLOCK | A KEV-listed vulnerability with a fix, in an internet-facing service |
| SC-004 | BLOCK | A release image without its signature, SBOM or provenance |
| SC-005 | BLOCK | An invalid waiver (no owner, justification or expiry, or more than 90 days) |
| SC-006 | WARN | P1 findings (BLOCK above a threshold in the strict profile) |
| SC-009 | BLOCK | A high-severity CI workflow issue introduced by the PR |
| SC-010 | BLOCK | A scanner failure, time-out or integrity mismatch, or a required scanner missing |
| SC-011 | BLOCK | A misconfiguration that exposes the service by itself, introduced by the PR |

Exceptions are waivers: reviewed, owned, justified, expiring, and merged through a pull request. A scanner's
own ignore files and inline comments are never read.

## How it is verified

- **About 5,200 tests** (`make check`): unit, contract and end-to-end. They include runs of the real pinned
  scanners and OPA, the remediation workflow's scripts executed against a local origin, and the API on a real
  PostgreSQL.
- **Contracts first.** A JSON Schema for every contract between the two tracks (findings, decisions, tool
  status, waivers, VEX, patch proposals, verification results, correlations, ...), with valid and invalid
  fixtures. Each Python model is pinned to its schema.
- **Mutation testing** on the security-critical code. Each review lists the mutants it killed.
- **Practice what we preach.** Every GitHub Action is pinned by full commit SHA, every job has least
  privilege, and zizmor audits this repository's workflows. `make self-gate` runs SentinelCI's own release
  gate on its own tree.
- **A labelled benchmark** (`demo-shop/`, intentionally vulnerable, never deployed outside its container). Its
  seeds cover secrets, SAST, SCA, containers, IaC, CI workflows and prompt-injection canaries, plus clean
  controls. `make eval` measures recall per category and false positives, and `make eval-correlation` measures
  the root-cause grouping (ARI, alert reduction). On 14 November 2026, with the pinned scanners and that day's
  Grype database, all 28 seeds were detected and no clean control gave a false positive.

## Try it

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.12, make; Docker for the platform and the demos.

```bash
make setup          # the locked workspace and git hooks
make tools          # the pinned scanners, checked against tools.lock.toml
make check          # lint, strict typing, the architecture contract, tests, workflow audit
make up             # the platform in Docker (deploy/compose/README.md)
make eval           # the detection report on demo-shop
```

The release demo (the laptop, during the private phase) goes through these steps:
1. `make release-block`: the gate blocks an image with a known-vulnerable dependency, and nothing is signed.
2. `make release`: the release image is built, judged, signed and verified.
3. `make kind-up` and `make demo-release`: Argo CD deploys the release into a local kind cluster.
4. `make demo-attack`: five attacks (a tampered layer, the same image through GitOps or kubectl, an image from
   another registry, the blocked image) are each refused by the check that should refuse them.

## Repository layout

```
cli/                 sentinelci: the `sentinel` CLI and the deterministic decision path
platform/api         control-plane API (FastAPI, PostgreSQL)
platform/web         dashboard (React)
ai/                  sentinel_ai: explanations, triage, correlation, patch proposals (advisory)
schemas/             contracts (JSON Schema 2020-12) with valid and invalid fixtures
policies/            OPA/Rego gate rules and the risk model
deploy/              compose, kind, Kyverno, Argo CD, Grafana, the laptop release and remediation scripts
eval/                detection and correlation evaluations
demo-shop/           INTENTIONALLY VULNERABLE demo target, with its ground truth
docs/                specification, architecture decision records, threat model
```

## Documentation

- [Specification](docs/spec/SPEC.md): architecture, pipeline, risk model, contracts, evaluation
- [Threat model](docs/threat-model.md): assets, attackers, trust boundaries, and each control with its test
- [Architecture decision records](docs/adr/): among them OPA for policy (0003), AI advises and policy decides
  (0004), the base branch's pipeline judges a PR (0008), local models (0009), release attestations (0010), the
  laptop release (0011), the remediation bot (0013) and LLM fixes verified on the laptop (0014)
- [Security policy](SECURITY.md) · [Instructions for coding agents](CLAUDE.md)

## Team

Built by [@NOURHANE-EHOUARI](https://github.com/NOURHANE-EHOUARI) (pipeline, supply chain, runtime) and
[@Hiba-elouazi](https://github.com/Hiba-elouazi) (risk intelligence, policy, AI platform) as a final-year
portfolio project.
