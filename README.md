# SentinelCI

**A verifiable security-control system for software delivery.**

SentinelCI scans every change with pinned, integrity-checked scanners. A policy-as-code gate that anyone can
replay decides whether the change or release may ship. The artifact is signed together with the evidence behind
that decision, and the demo cluster refuses to run an unsigned or unproven image in the application's
namespace. AI explains findings, groups them by root cause and proposes fixes. It never decides: an architecture contract keeps it out of the decision path.

> Status: v1.0.0 in preparation. The repository is private until then (ADR-0006), so signing and the runs that
> need Docker or a local model happen on the maintainers' laptop (ADR-0011, ADR-0014). Signing uses a Cosign key
> pair kept on that laptop, with nothing uploaded to the public Rekor log, until the repository is public.

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
  │              never configured or silenced by the scanned repository. A failed or missing required
  │              scanner is a BLOCK (SC-010), never an empty pass.
  ├─ 2. Normalize ─ one Finding v1 per issue, with a stable fingerprint, so "new in this PR" is exact
  ├─ 3. Score ─── severity × exploitability (EPSS, CISA KEV) × exposure × reachability → priority P0–P4,
  │              benchmarked against a CVSS-only ranking
  ├─ 4. Decide ── OPA/Rego rules → PASS / WARN / BLOCK with rule ids; a Decision v1 record holds the digest of
  │              every input and replays bit for bit (`sentinel replay`)
  ├─ 5. Sign ──── image + the decision, the CycloneDX SBOM, the vulnerability scan and SLSA provenance, as
  │              four Cosign attestations (the SPDX SBOM is kept with the evidence)
  └─ 6. Admit ─── Argo CD deploys by digest; in demo-shop's namespace, Kyverno admits a release image only if
                 it is signed with the release key and carries its attestations (as `sentinel verify` would),
                 and the API server refuses images from any other registry
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
| SC-004 | BLOCK | A release image without its signature, SBOM or provenance (enforced by `sentinel verify` and at admission, ADR-0010, not by the pull request gate) |
| SC-005 | BLOCK | An invalid waiver (no owner, justification or expiry, or more than 90 days) |
| SC-006 | WARN | P1 findings (BLOCK above a threshold in the strict profile) |
| SC-009 | BLOCK | A high-severity CI workflow issue introduced by the PR |
| SC-010 | BLOCK | A scanner failure, time-out or integrity mismatch, or a required scanner missing |
| SC-011 | BLOCK | A misconfiguration that exposes the service by itself, introduced by the PR |

Exceptions are waivers: reviewed, owned, justified, expiring, and merged through a pull request. A scanner's
own ignore files and inline comments are never read.

## How it is verified

- **More than 6,000 tests** (`make check`): unit, contract and end-to-end. They include runs of the real pinned
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
  controls. Each report below is a make target that anyone can run again.

## Results

Measured in November 2026 on demo-shop, with the pinned scanners and that day's Grype database. Each number
comes from the report its make target writes under `out/eval/`, and the misses are reported as plainly as the
hits.

| What | Target (SPEC §3) | Result | Report |
|---|---|---|---|
| Detection | ≥ 90% of seeds | All 28 seeds that `make eval` measures detected, no false positive on the clean controls (the container seed is checked in the built BLOCK image by an opt-in test) | `make eval` |
| Alert reduction | ≥ 40% | **Missed:** 25.8% on the whole run, with the stages that have no parameter. With stage 2b, the held-out half reaches an ARI of 0.827 against hand labels (42 findings in 18 groups), its threshold calibrated on the other half | `make eval-correlation` |
| Prompt-injection robustness | 0 verdict changes | 0 of 10 outputs of `gemma4:12b-it-qat` followed a planted instruction, 0 seeded weaknesses called false positives. With a control model that obeys every instruction, the gate's decision stayed the same, byte for byte | `make eval-canaries` |
| Explanations | (a rubric, §17) | Two people rated 23 explanations on four criteria and agree substantially (Cohen's kappa 0.71). A judge using the same model agrees with neither of them beyond chance (0.00), so people, not that judge, rate explanations | `make eval-rubric` |
| Replay determinism | 100% identical | 10 of 10 recorded decisions replayed byte for byte | `make eval-replay` |
| PR feedback time | p95 ≤ 10 min | One pass of the gate's steps: p95 12.8 s over 20 runs. A pull request scans its head and its base, so about 26 s | `make eval-timing` |
| Verified fix rate | ≥ 60% | Not measured yet | `make eval-fixrate` |

## Try it

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.12, make; Docker for the platform and the demos; kubectl,
git and the pinned kind and Cosign (`uv run sentinel tools install kind cosign`) for the demo cluster.

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
3. `make kind-up`, `make kind-policy` and `make demo-release`: Kyverno gets the release key's policy, and Argo CD
   deploys the release into a local kind cluster.
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
