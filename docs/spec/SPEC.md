# SentinelCI — Project Specification

**Version 1.1 — 28 October 2026.** Section numbers are stable; tasks and prompts reference them
(for example "implement task A2 as described in §13.1").

> **How to read this document.** In 30 minutes: §1, §4, §13 (contracts), your track in §15, then the Sprint 0
> checklist in §20. Everything else is reference material.

## Changelog

| Version | Change |
|---|---|
| 1.1.19 | A5 admission policy (§7): `sentinel admission-policy` renders the Kyverno 1.19 `ImageValidatingPolicy` (`policies.kyverno.io/v1`) from the parameters of `sentinel verify`, and requires the same things: the image's `cosign sign` statement (as an attestation, since `verifyImageSignatures` accepts any key-signed statement) and the four attestations, bound as `sentinel verify` binds them. Kyverno CLI pinned in `tools.lock.toml`; every bad case the tests cover is refused by both verifiers (`kyverno apply` against a real registry). The decision must be a non-BLOCK Decision v1 verdict (versions rendered from the contract); images match as a prefix of the lower-cased reference; `pods/ephemeralcontainers` is covered; the key file must hold exactly one public key. Admission is weaker than `sentinel verify` on the full schemas and on ambiguity (named in the README). |
| 1.1.18 | A4 registry mode (§7, ADR-0010 decision 4): `sentinel attest --push` also signs the image and attaches the four attestations to it in its registry (Cosign 3 bundles, by digest); `sentinel verify` without `--evidence` reads them back and requires the image's own `cosign sign` statement, since Cosign 3 accepts any key-signed statement about the digest as a signature. A digest has one release per registry: `attest --push` refuses a different one before signing, and a re-run signs the same statements (the provenance names the run, not its attempt). `--registry-http` is for a loopback or single-label local registry only. crane is pinned in `tools.lock.toml` (local test registry, copies by digest). |
| 1.1.12 | A4 release attestations (§7, ADR-0010): `sentinel attest` signs the release decision, CycloneDX SBOM, vulnerability scan (`schemas/vuln-result.v1.json`) and SLSA v1 provenance of an image digest with the pinned Cosign and a key pair (no transparency log), only for a non-BLOCK release decision about that image that recorded these findings and this SBOM; `sentinel verify` checks the four Sigstore bundles offline and prints a trust report (exit 0 trusted, 1 not, 3 could not run). |
| 1.1.6 | A9 first seeds (§17): 5 fake secrets, 6 IaC, 3 CI-workflow seeds and 4 clean controls in `demo-shop/`, with a draft ground-truth format (`demo-shop/ground-truth/`, final schema owned by B9) checked against the pinned Gitleaks, Trivy and zizmor. SentinelCI's Trivy configuration trusts only the kind registry for KSV0125. |
| 1.1.5 | A3 pipeline (§5): reusable `sentinel-scan.yml` (scan · gate · report) and `demo-shop.yml`. Pull requests are judged by the base branch's pipeline: CLI, lock, scanner configuration, policies and waivers come from the base commit, and the change is only data (ADR-0008). `sentinel report pr-comment` renders the deterministic, injection-safe comment and fails closed. |
| 1.1.4 | Enrichment (B2, §6.1): `schemas/enrichment-snapshot.v1.json` (`schema_version` "1.0", `sources.kev.cves`: the CVEs the KEV lookup covered) and `schemas/sentinel-config.v1.json` (`sentinel.yaml`, canonical component paths); `sentinel enrich`. "Not listed in KEV" only for covered CVEs; `sentinel.yaml` read with a restricted YAML loader. |
| 1.1.3 | Scanner hardening (§5): verify-before-exec, minimal child environment, scanner configuration owned by SentinelCI; repository-controlled suppressions are neutralized or refused (Gitleaks: `.gitleaks.toml`, `gitleaks:allow`, `.gitleaksignore`, and `.gitattributes` `-diff`/`binary` in git mode); merge commits scanned with `--diff-merges=remerge` plus a `first-parent` pass for octopus merges (evil merges), archives opened in dir mode. |
| 1.1.2 | Tool lock is `tools.lock.toml` (read with the standard library: no extra dependency). A1 split: A1a = lock + `sentinel tools install/verify` (done), A1b = scanner adapters + Opengrep pinning via signature verification. |
| 1.1.1a | Package fingerprints use the purl base (no version, qualifiers or subpath — same as the gate's waiver matching), agreed in the review of PR #1. "Green CI" may be a local `make check` report while Actions minutes are exhausted. |
| 1.1.1 | No GitHub Pro: `main` protected by convention + local guard until the repository goes public. |
| 1.1 | **Single private repository**: the demo target lives in `demo-shop/` instead of a second repo. **Private-phase adaptations** (§4.3, ADR-0006): Cosign key-pair signing without public transparency log, provenance as a Cosign attestation, no code-scanning upload, local registry for Kubernetes demos, Actions-minutes budget. Dependabot (with cooldown) replaces Renovate. |
| 1.0 | Initial specification (PDF shared with the team). |

---

## 1. Executive summary

SentinelCI is a **verifiable security-control system for software delivery**. It runs a hardened DevSecOps
pipeline on every change, turns raw scanner output into risk-ranked findings, decides with policy-as-code whether
a change or release may proceed, signs the artifact together with the evidence behind that decision, and makes
Kubernetes refuse anything that lacks this evidence. On top of this deterministic core, an AI layer explains
findings, groups related alerts into root causes and proposes patches, and a remediation loop only accepts a
patch when tests and re-scans prove it works.

### 1.1 Headline capabilities

| # | Capability | What it means concretely |
|---|---|---|
| 1 | Hardened security pipeline | Secrets, SAST, SCA, container, IaC and CI-workflow scanning in isolated, least-privilege jobs; scanners pinned, integrity-checked, fail-closed |
| 2 | Supply-chain integrity | CycloneDX + SPDX SBOMs, Cosign signatures, in-toto attestations, SLSA provenance |
| 3 | Risk-based release gate | CVSS × exploitability (EPSS, KEV) × reachability × exposure → P0–P4; OPA/Rego → PASS / WARN / BLOCK with rule IDs; signed and replayable |
| 4 | Deploy-time enforcement | Kyverno rejects images without a valid signature, SBOM, or with a BLOCK decision; GitOps via Argo CD |
| 5 | AI security analyst | Grounded explanations, root-cause clustering, triage hints, patch proposals; schema-validated, advisory only |
| 6 | Verified remediation loop | Bot fix PRs (deterministic fixers first, LLM for code) accepted only after build, tests and re-scan pass |
| 7 | Observability | Dashboard + Grafana: vulnerabilities over time, gate outcomes, MTTR, attestation coverage |
| 8 | Measured results | Labelled benchmark: ranking vs CVSS baseline, alert reduction, fix rate, injection robustness, replay |

### 1.2 Design principles (non-negotiable)

- **P1 — Deterministic decides, AI advises.** The gate runs before and without AI; enforced by an import contract
  and tested with prompt-injection canaries.
- **P2 — Fail closed.** Scanner crash, timeout or integrity failure blocks the release.
- **P3 — Everything is evidence.** Each decision records the digests of all inputs and can be replayed bit-for-bit.
- **P4 — Practice what we preach.** This repository is protected by SentinelCI itself (dogfooding).
- **P5 — Contracts before code.** Tracks integrate through versioned JSON Schemas and an OpenAPI spec with fixtures.

## 2. Why this project, why now

In March 2026 attackers reused credentials from an earlier, non-atomically rotated breach to publish a malicious
Trivy release (v0.69.4), force-push 76 of 77 tags of `aquasecurity/trivy-action` to a credential stealer and
replace the tags of `setup-trivy` (CVE-2026-33634). The same campaign reached LiteLLM: malicious versions 1.82.7
and 1.82.8 were uploaded directly to PyPI on 24 March 2026; public analyses link the stolen publishing credentials
to LiteLLM's own CI, which ran Trivy. Supply-chain failures are category A03 of the OWASP Top 10:2025.

| What went wrong | SentinelCI response |
|---|---|
| Actions referenced by mutable tags | Full-SHA pins + version comment, zizmor audit, Dependabot updates |
| Scanner binaries trusted blindly | `tools.lock.toml` with SHA-256/digests; `sentinel tools verify` first; mismatch = SC-010 BLOCK |
| Scan jobs could read publishing secrets | Scan jobs: `contents: read`, no secrets; signing job never runs repo code |
| Publishing outside the reviewed path | Only artifacts signed by our release workflow are admitted by Kyverno |
| Developer machines / AI agents as entry points | `CLAUDE.md` rules, no real secrets locally, dependencies only via lockfile + review |

## 3. Goals, scope, success criteria

**Goals.** G1 block unsafe changes with actionable explanations · G2 make every release verifiable · G3 prioritize
by real risk and prove it · G4 use AI without weakening decisions · G5 close the loop to verified fix PRs ·
G6 zero cloud cost (laptops + GitHub).

**Non-goals.** New scanners · replacing human review (bot never merges, AI never waives) · SaaS, cloud deployment,
runtime threat detection.

| Metric | Target | Measured by |
|---|---|---|
| Seeded-vulnerability detection | ≥ 90% of seeds found by ≥ 1 scanner | Eval harness (§17) |
| Gate correctness | 100% of must-block scenarios blocked; 0 blocks on clean controls | Scenario suite |
| Prioritization | NDCG@10 above CVSS-only baseline | Eval harness |
| Alert reduction | ≥ 40% (findings → root-cause groups) | Eval harness |
| Verified fix rate | ≥ 60% of attempted fixable seeds | Remediation runs |
| Prompt-injection robustness | 0 verdict changes (hard requirement) | Canary suite |
| Replay determinism | 100% identical | Nightly replay job |
| Deploy enforcement | 100% of bad images denied | Kyverno tests on kind |
| PR feedback time | p95 ≤ 10 min | Pipeline metrics |

Report real numbers, including misses.

## 4. System architecture

Four planes: **CI plane** (GitHub Actions running the `sentinel` CLI: scan, decide, sign), **artifact plane**
(OCI registry: images + signatures + attestations), **runtime plane** (kind + Argo CD + Kyverno: only verified
images run), **control plane** (FastAPI platform: history, AI and remediation workers, dashboards).

### 4.1 Decisions in the pipeline, intelligence in the platform

The gate must work without the platform (hosted runners cannot reach a laptop). The deterministic core
(normalize → enrich → score → evaluate → attest) is a library + CLI running in CI. The platform **pulls** each
run's evidence bundle through the GitHub API (GitHub App or fine-grained token) and can **replay** any decision.
Local CLI runs can **push** to the same ingestion API. No self-hosted runners (anti-pattern for untrusted PRs).

### 4.2 Operating modes

| | Private mode (now) | GitHub mode (after going public) | Local mode |
|---|---|---|---|
| Pipeline | GitHub Actions | GitHub Actions | `make pipeline-local` |
| Signing | Cosign key pair, no Rekor upload | Cosign keyless (GitHub OIDC) | Developer key pair |
| Provenance | SLSA predicate via `cosign attest` | GitHub artifact attestations (reusable workflow → Build L3 target) | `cosign attest` |
| Registry | GHCR private (CI) + kind local registry (demos) | GHCR public | kind local registry |
| Results | PR comment, artifacts, dashboard | + GitHub code scanning (SARIF) | Terminal + dashboard |

### 4.3 Private-phase constraints (ADR-0006)

- Keyless certificates embed the repository identity and are logged in the public Rekor log → key pairs until public.
- GitHub artifact attestations require a public repository on non-Enterprise plans → Cosign attestations meanwhile.
- The signing key is a repository secret referenced **only** by the attest job; rotate it when going public.
- We stay on GitHub Free: server-side branch protection is not available for this private repository, so `main`
  is protected **by convention** (every change through a PR, reviewed by the other member, merged only with
  a green CI, or a local `make check` report on the PR head while Actions cannot run) plus a local pre-commit guard that refuses commits on `main`. Technical protection is enabled when
  the repository goes public.
- Actions minutes are capped (Free: 2,000/month for private repositories): path filters, caching of
  vulnerability DBs, nightly full scans.
- Going public = switch to GitHub mode (a configuration change, by design).

### 4.4 Component catalogue

| Component | Responsibility | Technology | Owner |
|---|---|---|---|
| `sentinel` CLI / core | scan, normalize, enrich, score, evaluate, sign/attest, verify, replay | Python 3.12, Typer, Pydantic v2 | A + B |
| Reusable workflows | `sentinel-scan.yml`, `sentinel-release.yml` | GitHub Actions | A |
| Policy bundle | Rego rules, risk model, tests | OPA (Rego v1) | B |
| Platform API | ingestion, sync, query, OpenAPI | FastAPI, SQLAlchemy 2, Alembic | B |
| Workers | sync, enrichment refresh, AI, remediation | Celery + Redis | B / A |
| AI analyst | explanations, triage hints, patch proposals | Ollama, own provider interface | B |
| Correlator | dedup, embeddings, clustering, labels | pgvector, scikit-learn/HDBSCAN | A |
| Remediation orchestrator | fixers, branches/PRs, verification | GitHub App / token, httpx2 | A |
| Evidence store | content-addressed bundles | SeaweedFS (S3 API, ADR-0007) | B |
| Database | runs, findings, decisions, waivers, groups, remediations | PostgreSQL + pgvector | B |
| Web dashboard | product UI | React, TypeScript, Vite | B core, pages split |
| Observability | metrics, dashboards as code | Prometheus, Grafana | A |
| Runtime | cluster, GitOps, admission | kind, Helm, Argo CD, Kyverno | A |
| Demo target | intentionally vulnerable app + ground truth | `demo-shop/` | A + B |

## 5. The DevSecOps pipeline

| # | Stage | Tools | Output | Gate |
|---|---|---|---|---|
| 0 | Tool integrity | `sentinel tools verify` (tools.lock.toml) | manifest | mismatch → SC-010 |
| 1 | Secrets | Gitleaks (Betterleaks-compatible config) | SARIF | SC-001 |
| 2 | SAST | Opengrep + Semgrep-format rules | SARIF/JSON | risk + policy |
| 3 | SCA | Syft source SBOM → Grype; OSV | JSON | risk + policy |
| 4 | IaC + CI config | Checkov; zizmor | SARIF | policy |
| 5 | Tests | pytest / npm test | JUnit | must pass |
| 6 | Build | docker buildx, by digest | image@sha256 | — |
| 7 | Image analysis | Syft (CycloneDX + SPDX), Grype, Trivy | SBOM, JSON | risk + policy |
| 8 | Normalize + enrich | `sentinel normalize` / `enrich` | findings.v1.ndjson + snapshot | — |
| 9 | Decision | `sentinel evaluate` (risk + OPA) | decision.v1.json | job fails on BLOCK |
| 10 | Sign + attest | Cosign (sign, attest SBOM / vuln / decision / provenance) | registry | only if ≠ BLOCK |
| 11 | Report | PR comment, evidence artifact | comment, artifact | — |
| 12 | Deploy | GitOps digest bump → Argo CD → Kyverno | pods | admission deny |

**Scanner hardening (A1).** Every scanner run (1) re-verifies the binary against `tools.lock.toml` right
before execution, (2) gets a minimal environment (no CI tokens, keys or proxy variables), (3) uses a configuration
owned by SentinelCI, never one from the scanned repository, and (4) treats crashes, timeouts and missing reports as
SC-010. Suppression mechanisms that live in the scanned repository are written by the change author, so they are
neutralized (`--config`, `--ignore-gitleaks-allow`) or refused when the tool offers no way to disable them
(Gitleaks always loads `<source>/.gitleaksignore`). In git mode, `git log -p` honours the repository's
`.gitattributes`, where a `-diff` or `binary` attribute would hide a file's patch, so patches are forced to text
(`--text`, no textconv or external diff) and caller `--log-opts` are restricted to revisions, pathspecs and a few
harmless options. Merge commits are scanned with `--diff-merges=remerge`, so a secret slipped into a merge
(an "evil merge") is found while an honest merge of the base branch blames nobody (octopus merges excepted:
remerge does not diff them, so they get a second `first-parent` pass, which also reports what the other parents
already had; the PR baseline drops what the base branch has). Each Gitleaks pass gets the full scanner time
limit, so git mode can take twice as long. Dir mode opens archives (`.zip`, nested up to 3 levels). Legitimate
exceptions go through waivers (§6.4).

**Job isolation.** `scan` (runs repo code; `contents: read`; no secrets) · `build` (runs Dockerfile;
`packages: write` on main only; PR builds never push) · `gate` (no repo code; calls EPSS/KEV/OSV) · `attest`
(no repo code; signing key / OIDC only here) · `report` (`pull-requests: write`). In PR mode every job checks out
the pipeline (CLI, `tools.lock.toml`, policies, waivers) at the **base** commit and the change only as data to
scan; tools live in `$RUNNER_TEMP` (ADR-0008).

**PR mode (diff-aware):** only findings new to the PR (fingerprints not in the base-branch baseline) can block. A known
secret also counts as new in a file where the base did not have it (every place counts: `location` plus
`other_locations`, Finding 1.1).
**Release mode:** full evaluation, then signing. In this single repo, `demo-shop/` is scanned by its own workflow
calling `./.github/workflows/sentinel-scan.yml`; the self-scan of SentinelCI excludes `demo-shop/`.

Example deterministic PR comment:

```
SentinelCI  verdict: BLOCK   policy bundle 1.3.0 · risk model 1.0.0 · decision 0193f2c4-…
  SC-001  Hard-coded secret                    demo-shop/services/shop-api/app/config.py:12   P0
  SC-003  Known-exploited CVE, fix available   example-lib 1.2.0 -> 1.2.4                     P0
Findings: 2 P0 · 3 P1 · 7 P2 · 21 P3 (33 total, 12 new)   Replay: sentinel replay 0193f2c4-…
AI advisory: in the dashboard (advisory only — does not affect the verdict)
```

## 6. Risk engine and release gate

### 6.1 Enrichment sources

| Signal | Source | Used for |
|---|---|---|
| CVSS | OSV.dev advisories (NVD fallback) | S |
| EPSS score + percentile | FIRST EPSS API `api.first.org/data/v1/epss` (daily) | E |
| Known exploited | CISA KEV JSON feed | E = 1.0, SC-003 |
| Fixed versions, aliases | OSV.dev | fix_available, remediation target |
| Reachability | static import analysis (Python AST, JS imports) | R |
| Service context | `sentinel.yaml` (exposure, environment, data class) | X, policy profile |

Each run stores a content-addressed **enrichment snapshot**; replay never uses live feeds.

Implementation (B2): fetching (network) and applying (offline) are separate. The fetchers write a snapshot
(`schemas/enrichment-snapshot.v1.json`), keyed by vulnerability id and dated by the feeds; a feed that could not be
reached is absent, so its values stay unknown. `sentinel enrich --snapshot --config sentinel.yaml` applies it to
package findings (CVSS and EPSS: the highest among the finding's ids and their aliases; KEV; fix availability) and
gives every finding the exposure of its `sentinel.yaml` component (longest matching path). Unknown stays absent:
the risk engine counts it as the worst case. `sentinel.yaml` (`schemas/sentinel-config.v1.json`) is read from the
base branch, like the policies and waivers, so a change cannot lower its own exposure.

Fetchers (B2, `sentinel snapshot`): OSV by id (one extra round for the aliases it reveals), EPSS in batches of
100 CVEs, and the KEV catalogue filtered to those CVEs; HTTPS to those three hosts only. The CVSS 3.0/3.1 base
score is computed from the OSV vector (highest vector wins). Each feed is all or nothing: a failure leaves the
feed out with a warning, never a partial feed; KEV is read before EPSS, and EPSS is left out when KEV could not
be read (EPSS alone would lower the risk of a listed vulnerability); the KEV catalogue is trusted whole or not at
all; redirects are never followed. `--record` / `--offline` capture and replay the feed answers (raw bytes and
their sha256, gzip-compressed) as offline fixtures; in CI they come from the base commit or a trusted store, like the
policies. `eval/feeds/` holds committed fixtures: 7 real vulnerable packages (Maven, PyPI, npm; KEV-listed and not;
alias chains), their recordings and the snapshot they give, checked offline by the tests. The NVD fallback for CVSS is not implemented yet: an id without a 3.x vector in OSV keeps an
unknown CVSS, which the risk engine counts as the worst case.

"Known no" is written only for what was checked: `kev: {listed: false}` only when the KEV lookup covered every
CVE id of the finding (`sources.kev.cves`), and `fix_available: false` only when OSV knew the vulnerability and
fixes none of the package (package URLs compared in canonical form). A KEV outage therefore leaves KEV unknown,
never "not listed", and the risk engine counts unknown as the worst case. `sentinel.yaml` is a reviewed trust
boundary: it is read with a YAML loader that refuses duplicate keys, anchors and aliases, and tags beyond plain
scalars, lists and mappings, and is limited to 64 KiB; component paths are canonical and unique. Residual risk:
where a change puts its files decides their path-scoped exposure (a file under an `offline` component is scored
as offline), so changes to `sentinel.yaml` and new top-level directories deserve a reviewer's eye.

Reachability (B2, `sentinel enrich --source`): static import analysis of the scanned tree for PyPI and npm SCA
findings, never executing it. `imported` when first-party code imports the package, or when a lockfile shows that
an imported package depends on it at runtime; nothing otherwise (the worst case, R = 1.0). `not_imported` is not
claimed: libraries load packages themselves (FastAPI templates load jinja2, PyJWT's RS256 loads cryptography)
through optional dependencies a lockfile does not record, so it needs per-library evidence first. CONTAINER
findings, `MAL-` advisories and npm packages with install scripts get no answer. In PR mode the base and the head
are both analysed and `imported` must hold in both, so a change cannot lower its own score by adding an import.
`reachable` would need call-graph analysis, a stretch goal (§16). Residual risk: a deliberately written import that
nothing uses gives `imported` (R 0.9 instead of 1.0); a missed import only leaves the worst case.

### 6.2 Risk model

`risk = 100 × S × E × X × R` clamped to [0, 100]. For CVEs: `E = 1.0` if KEV-listed else
`E = 0.4 + 0.6 × epss_percentile`. Weights live in `policies/risk-model.yaml`:

```yaml
version: 1.0.0
severity_weight: {CRITICAL: 1.0, HIGH: 0.75, MEDIUM: 0.45, LOW: 0.2, INFO: 0.05}
exploitability:
  kev: 1.0
  epss_floor: 0.4
  non_cve: {SECRET: 1.0, SAST_TAINT: 0.8, SAST_PATTERN: 0.5, IAC: 0.5, PIPELINE: 0.7}
exposure: {internet-facing: 1.0, internal: 0.7, offline: 0.5}
reachability: {reachable: 1.0, imported: 0.9, unknown: 0.8, not_imported: 0.4}
priority_bands: {P0: 70, P1: 50, P2: 30, P3: 10}   # below 10 -> P4
```

| Same CRITICAL CVE (EPSS pct 0.95, not KEV) in… | X | R | Score | Priority |
|---|---|---|---|---|
| Internet-facing API importing the package | 1.0 | 0.9 | 87 | P0 |
| Internal service importing it | 0.7 | 0.9 | 61 | P1 |
| Offline batch job never importing it | 0.5 | 0.4 | 19 | P3 |

Implementation (`sentinel score`, B3): the score is rounded to 0.1 and banded from the rounded value; `factors`
records S, E, X and R. Missing enrichment never lowers a score (E < 1 only when KEV was read and the CVE is not
listed, so a KEV outage next to a working EPSS feed cannot lower E; no exposure: X = 1.0; no
reachability analysis: R = 1.0, while `unknown` is for an analysis that ran and could not decide), so every score
stays at most `100 × severity_weight`, the bound the gate uses for unscored findings, and a finding with no
enrichment scores exactly that bound. Every priority band floor lies in (0, 100]. R applies to SCA and CONTAINER only; SAST counts as `SAST_TAINT` until findings carry the
analysis kind; a category without a `non_cve` weight counts as E = 1.0.

### 6.3 Rule catalogue

| Rule | Verdict | Condition |
|---|---|---|
| SC-001 | BLOCK | Secret detected (new in PR, or anywhere in a release image), not waived |
| SC-002 | BLOCK | Any P0 finding without valid waiver |
| SC-003 | BLOCK | KEV-listed vulnerability with a fix, internet-facing service (an unknown exposure counts as internet-facing) |
| SC-004 | BLOCK | Release image missing signature, SBOM or provenance |
| SC-005 | BLOCK | Invalid waiver (no owner / justification / expiry, or expiry > 90 days) |
| SC-006 | WARN | P1 findings (BLOCK above threshold in strict profile) |
| SC-007 | WARN | Base image not pinned by digest, or container runs as root |
| SC-008 | WARN | Copyleft licence in a distributed component |
| SC-009 | BLOCK | High-severity CI workflow issue introduced by the PR |
| SC-010 | BLOCK | Scanner failure, timeout or tool-integrity mismatch; a required scanner (`policies/required_tools.rego`) missing from the tool status, or no tool status where one is required (`pr`, `release`); malformed gate input |
| SC-011 | BLOCK | Misconfiguration that exposes the service by itself, introduced by the PR (privileged pod, host namespaces, root mounts or kernel modules; a public bucket, database or dataset; SSH, RDP or database ports open to the internet): a short list of Trivy rule ids in `policies/exposing.rego`, matched on Trivy findings only, whatever the finding's score |

Priority-based rules (SC-002, SC-006) read `risk.priority` (B3), only when `risk.model_version` is the bundle's
risk model (`inputs.risk_model_version`); an unscored finding, or one scored with another model, counts at its
worst case, `100 × severity_weight` banded, so CRITICAL and HIGH are P0 until scored. Each finding is reported under its most
specific rule (SC-001, SC-003, SC-009 or SC-011 before SC-002/SC-006). SC-011 exists because the exposure factor
X discounts a misconfiguration by its service's exposure, while a privileged pod or a public bucket creates the
exposure itself; every other misconfiguration keeps its risk-model priority (IaC weight 0.5). Waivers and diff-aware PR mode apply to every finding
rule. Not yet implemented: SC-004 (A4 attestations), SC-007, SC-008, the strict profile and VEX.

Policy rules use `input.evaluated_at`, never `time.now_ns()`. Reference implementation of the verdict logic
(verified with OPA 1.21):

```rego
package sentinel.gate

import rego.v1

now := time.parse_rfc3339_ns(input.evaluated_at)

waived(f) if {
	some w in input.waivers
	w.finding_id == f.id
	time.parse_rfc3339_ns(w.expires_at) > now
}

block contains v if {
	some f in input.findings
	f.category == "SECRET"
	not waived(f)
	v := {"rule": "SC-001", "finding": f.id, "msg": "Hard-coded secret"}
}

verdict := "BLOCK" if count(block) > 0
else := "WARN" if count(warn) > 0
else := "PASS"
```

### 6.4 Waivers and VEX

Waivers in `.sentinel/waivers.yaml` (finding id or vuln + purl, owner, justification, expiry ≤ 90 days), added by
PR and approved by CODEOWNERS; expired waivers stop applying. OpenVEX statements for "not affected". The AI may
draft a waiver PR; only a human approval makes it effective.

### 6.5 Decision record and replay

Schema: `schemas/decision.v1.json`. Fields: `decision_id`, `evaluated_at`, `subject` (repo, ref, commit, image
digest, context), `verdict`, `violations` (rule, effect, finding ids, message), `waivers_applied`, `inputs`
(digests of findings, SBOM, enrichment snapshot, policy bundle, waivers file (since 1.1), base-branch findings
baseline and tool status (since 1.2, when given); risk model version;
tool versions),
`engine_version`. The schema enforces verdict consistency (BLOCK ⇒ at least one BLOCK violation; PASS ⇒ none).
Attached to the image as an in-toto attestation, predicate type
`https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1`. `sentinel replay` re-evaluates from
digests and must be identical; checked nightly.

**Evidence store (replay input).** Content-addressed: `sha256/<hex>` holds every input exactly as digested
(findings, waivers, baseline, tool status, enrichment snapshot, SBOM, each policy file) and each policy bundle
manifest (`<sha256>  <path>` per file, sorted; its digest is `policy_bundle_digest`); `decisions/<id>.json` holds
decisions. Written by `sentinel evaluate --store`; every read is checked against its digest. `sentinel replay
<id | file>` takes all inputs from the store, policy included, and compares the whole record (exit 0 identical,
1 differs, 3 missing or tampered evidence). Recorded scanner versions are passed back as evidence; the OPA and
engine versions are the running ones, so an upgrade shows up as a difference. Proposed: the evidence bundle
(A4) and the platform evidence store (SeaweedFS, ADR-0007) carry the same `sha256/<hex>` layout, so replay works
on either.

**Nightly replay** (`.github/workflows/replay-nightly.yml`): replays the last successful night's corpus with
today's engine (`sentinel replay --all`), then records a fresh corpus (`eval/replay/corpus.py`: fixed gate cases
covering PASS, SC-001, SC-005 and SC-010), replays it in a fresh process and uploads it. `--all` skips decisions
recorded with another engine or OPA version (after checking that the record's `decision_id` matches its own
subject, time, inputs and engine version, so an edited version cannot turn a difference into a skip) and fails
on any difference, on missing evidence, on an empty
store and when nothing was compared (every decision skipped; the previous-night step accepts that with
`--allow-all-skipped`, so an engine bump night says so in its summary). Consequence: a change to what the engine decides for the same inputs must come with an engine version bump.

## 7. Supply-chain integrity and deploy-time enforcement

- **SBOM:** Syft → CycloneDX JSON (primary) + SPDX JSON, for source and image.
- **Signing:** Cosign v3 (Sigstore bundle format). Private mode: key pair, no transparency-log upload. GitHub mode:
  keyless, identity = release workflow path + ref. Always sign digests, never tags.
- **Attestations:** SLSA provenance, CycloneDX SBOM, vulnerability scan, release decision (ADR-0010: one
  in-toto statement each about the image digest, signed by the attest job only for a decision that is not BLOCK;
  `sentinel attest` checks that the decision is about this image and recorded these findings and this SBOM, and
  the vulnerability result, `schemas/vuln-result.v1.json`, names the decision, the findings and the SBOM's
  CycloneDX `serialNumber`, so the four are bound together).
- **`sentinel verify <image@digest>`:** checks signature, provenance, SBOM, decision; prints a trust report; must
  fail on unsigned, wrong key/identity, modified image, missing or BLOCK decision (automated tests). Each
  attestation must be signed by `--key` and about this digest; the decision must be a release decision about
  this image from `--repo`; the provenance must come from `--builder-id` and the decision's commit; the
  vulnerability result and the SBOM must be the decision's. Exit 0 trusted, 1 not trusted, 3 could not run.
  Offline from the evidence directory's Sigstore bundles (`--evidence`), or from the registry (the image's
  `cosign sign` statement and the four attestations `sentinel attest --push` attached, A4d).
- **Kyverno ImageValidatingPolicy** (`policies.kyverno.io/v1`, Kyverno 1.19, rendered by
  `sentinel admission-policy`): match our images (a prefix of the lower-cased reference), attestor = our
  public key (private mode; a keyless identity comes with keyless `sentinel verify` in GitHub mode), require
  the image signature and the four attestations bound as `sentinel verify` binds them (a non-BLOCK Decision v1
  verdict about this digest, from our repository; provenance from the release workflow and the decision's
  commit; the vulnerability result and SBOM of that decision), `mutateDigest: true`. CEL reads one statement
  per type, so admission is weaker than `sentinel verify` on the full Decision v1 and vuln-result schemas and
  on ambiguity (a second statement of a type). Negative tests with `kyverno apply` against a real registry,
  then on kind in CI.

## 8. AI layer

AI runs after the decision is stored, writes only advisory tables, and every output is schema-validated and traced.

| Capability | Input | Output | Owner | Evaluated by |
|---|---|---|---|---|
| Explain | finding + code window + CWE + advisory | Explanation {summary, impact, exploit_scenario, fix_guidance, references, confidence} | B | rubric + LLM-judge agreement |
| Triage hint | finding + context + past waivers | TriageHint {likely_false_positive, rationale, confidence} | B | precision on labelled FPs |
| Correlate | all findings of a run | RootCauseGroup {title, root_cause, finding_ids, single_fix} | A | ARI, alert reduction |
| Patch | finding + file + explanation (+ CI logs) | PatchProposal (`schemas/patch-proposal.v1.json`) | B | verified fix rate |

- **Provider interface** `sentinel_ai.providers.LLMProvider` (`complete(system, user, schema)`, `embed(texts)`).
  Default: local models via Ollama, `gemma4:12b-it-qat` for generation and `qwen3-embedding:0.6b` for
  embeddings, pinned by digest (ADR-0009, measured in `eval/model-selection/`). No multi-provider gateway dependency.
- **Grounding:** offline CWE catalogue, OSV advisory text, code window; references must come from the context.
- **Guardrails:** import contract; untrusted text in delimited data blocks; schema validation with one repair
  retry, else "unavailable"; secret redaction before any prompt; model/prompt/input hash logged; injection
  canaries prove verdict invariance.
- **Correlation (A7):** stage 1 fingerprint dedup → stage 2 embeddings (pgvector) + clustering → stage 3 LLM
  labels and single fix; each stage measured separately.

## 9. Verified remediation loop

States: PROPOSED → PATCH_READY → PR_OPEN → VERIFYING → VERIFIED | REJECTED (retry ≤ 2 with CI feedback) | FAILED.

| Strategy | Applies to | How |
|---|---|---|
| Dependency bump | SCA with fixed version | minimal fixed version, regenerate lockfile |
| Dockerfile fixer | container hygiene | non-root USER, base pinned by digest, no `curl \| sh` |
| Kubernetes fixer | manifest findings | runAsNonRoot, readOnlyRootFilesystem, drop ALL, limits |
| LLM code fixer (B6) | SAST | diff restricted to flagged files; retried with CI logs |

**Verification gate (all must hold; encoded in `schemas/verification-result.v1.json`):** build OK · tests pass ·
target fingerprint gone · no new ≥ MEDIUM finding · verdict ≠ BLOCK. Bot uses `pull_request` (never
`pull_request_target`), verification jobs get no secrets, the bot never merges.

## 10. Dashboard and observability

Pages: Overview, Findings, Finding detail, Policies & waivers (B) · Releases & evidence, Supply chain,
Remediation (A).

| Metric | Definition |
|---|---|
| MTTR (per priority) | mean(fixed_at − first_seen_at) |
| Gate block rate | BLOCK ÷ all decisions, per context |
| Policy compliance | % running images with signature + SBOM + provenance + non-BLOCK decision |
| Remediation success | VERIFIED ÷ attempted, per strategy |
| Alert reduction | 1 − groups ÷ raw findings |

Prometheus names: `sentinel_gate_decisions_total{verdict,context}`, `sentinel_findings_open{priority,category}`,
`sentinel_pipeline_stage_duration_seconds{stage}`, `sentinel_remediation_attempts_total{strategy,outcome}`,
`sentinel_ai_request_duration_seconds{task,model}`, `sentinel_attestation_verifications_total{result}`.

## 11. Technology stack

| Layer | Choice |
|---|---|
| CI/CD | GitHub Actions (reusable workflows); Jenkins as stretch |
| Core | Python 3.12, uv workspace (locked with hashes), Typer, Pydantic v2 |
| Secrets / SAST | Gitleaks (Betterleaks-compatible) / Opengrep + Semgrep-format rules |
| SCA / container | Syft → Grype; Trivy (pinned, verified) as second engine; OSV |
| IaC / CI config | Checkov / zizmor |
| Signing / provenance | Cosign v3 (key pair now, keyless later); GitHub attestations after going public |
| VEX / policy / admission | OpenVEX / OPA (Rego v1) / Kyverno ImageValidatingPolicy |
| Backend / data | FastAPI, SQLAlchemy 2, Alembic, Celery, Redis / PostgreSQL + pgvector, SeaweedFS (S3) |
| AI | Ollama (local), own provider interface |
| Frontend | React, TypeScript, Vite, TanStack Query, Tailwind, Recharts |
| Observability / runtime | Prometheus, Grafana / Docker, Compose, kind, Helm, Argo CD |
| Quality | pytest, Hypothesis, ruff, mypy (strict), import-linter, pre-commit, Dependabot (cooldown), zizmor |

Pin exact versions (`tools.lock.toml`, `uv.lock`, chart versions); never use `latest`.

## 12. Repository layout

```
.github/workflows/   ci.yml (this repo) · sentinel-scan.yml · sentinel-release.yml · demo-shop.yml · replay-nightly.yml
cli/src/sentinelci/  scanners(A) normalize(A) enrich(B) risk(B) policy(B) supplychain(A) report(A)
platform/api         (B)      platform/worker (B; remediation jobs A)      platform/web (B core; pages split)
ai/src/sentinel_ai/  providers, prompts, explain, triage, patch, guardrails (B) · correlate (A)
policies/            (B) *.rego, *_test.rego, risk-model.yaml
schemas/             (shared) contracts + fixtures
deploy/              (A) compose, kind, helm, kyverno, argocd, grafana
eval/                (B) harness, datasets, reports
demo-shop/           (A+B) INTENTIONALLY VULNERABLE: services/, infra/, gitops/, examples/bad-workflows/, ground-truth/
docs/                spec/, adr/
tools.lock.toml      (A) pinned scanner versions + checksums
```

## 13. Contracts between the two tracks

Contracts live in `schemas/`, are validated in CI (`tests/contracts`), and are versioned (breaking change → v2).

### 13.1 Finding v1 — `schemas/finding.v1.json`

Required: `schema_version`, `id`, `tool`, `rule_id`, `category` (SECRET | SAST | SCA | CONTAINER | IAC | PIPELINE |
LICENSE), `title`, `severity` (CRITICAL | HIGH | MEDIUM | LOW | INFO), `run`. Conditional: SECRET ⇒ `location` +
`evidence.secret_hash` (raw secrets are never stored); SAST/IAC/PIPELINE ⇒ `location`; SCA/LICENSE ⇒ `package`;
CONTAINER ⇒ `package` + `image`. Optional blocks `enrichment` (B2) and `risk` (B3). Paths must be relative and
cannot contain `..`. No pattern-checked field (ids, digests, paths, purls) may contain a line break, in any validator.

**Several locations (1.1, additive).** One finding (one `id`) can be seen in several places, e.g. the same secret
in two files. `location` is the first one by (path, start line); `other_locations` lists every other one, sorted
the same way, without duplicates and never truncated. It is only allowed in a `schema_version` 1.1 finding and
only next to `location`. A finding seen in one place may stay 1.0. Consumers that compare locations (diff-aware PR
mode in the gate, SPEC section 6.5) read `location` plus `other_locations`.

**Fingerprint rules:**
- SCA / CONTAINER: `sha256(category | vuln id | purl base)` where *purl base* = the purl without version,
  qualifiers or subpath (same definition as `purl_base` in `policies/gate.rego`). After a bump the finding disappears; base-image point releases, other
  architectures and Grype/Trivy qualifier differences keep the same fingerprint. Waivers use the same purl base.
- SAST: `sha256(rule id | path | hash of normalized snippet)` — survives line shifts.
- SECRET: `sha256(rule id | sha256(secret value))`.
- IAC / PIPELINE: `sha256(rule id | path | resource or job id)`.

### 13.2 Other contracts

| Contract | Producer → consumer | Content |
|---|---|---|
| `decision.v1.json` | B4 → A4, A5, B1 | §6.5 |
| `tool-status.v1.json` | A3 → B4 | per tool: version, hashes, status (`ok` … `not_run`), detail; any non-`ok` status → SC-010; required in `pr`/`release`, and must list every required scanner |
| `patch-proposal.v1.json` | B6 / A6 fixers → A6 | finding ids, strategy, diff, files, rationale, model (required for `llm:code`) |
| `verification-result.v1.json` | A6 → B1, B8 | gate outcome; VERIFIED only if every condition holds |
| evidence bundle layout | A4 → B1 | `manifest.json` (sha256 of each file, signed) + decision, findings, snapshot, SBOMs, raw outputs; `attestations/<kind>.sigstore.json` (ADR-0010) |
| `vuln-result.v1.json` | A4 attest → `sentinel verify`, Kyverno (A5), B1 | `scanner.result` of the vulnerability attestation: decision id, findings digest, SBOM digest and `serialNumber`, totals by severity and category, tool versions |
| `openapi.yaml` | B1 → A3, A6, A8, B7 | Platform API |
| `sentinel.yaml` (`sentinel-config.v1.json`) | target → B2, B4 | service, exposure, environment, data_classification, owners, policy_profile; optional `components` (path, exposure, data class) |
| `enrichment-snapshot.v1.json` | B2 fetchers → B2 apply, evidence store | per vulnerability id: aliases, CVSS, fixed versions per purl base, EPSS, KEV; dated sources |

### 13.3 Platform API v1 (first cut)

`POST /api/v1/runs` · `POST /api/v1/runs/{id}/findings` (NDJSON) · `POST /api/v1/runs/{id}/artifacts` ·
`POST /api/v1/sync/github` · `GET /api/v1/findings[/{id}]` · `POST /api/v1/findings/{id}/explain` ·
`GET /api/v1/groups` (A) · `POST|GET /api/v1/remediations` (A) · `GET /api/v1/releases[/{digest}/evidence]` (A) ·
`GET /metrics` · `GET /healthz`.

## 14. Engineering workflow

- Trunk-based, branches `<task-id>/<name>` (e.g. `a2/normalizer-grype`), Conventional Commits, squash merge.
- `main` is protected by convention during the private phase (§4.3): PR + approval by the other member + green
  `ci` before merge; no direct push, no force push. Enforced by branch protection once public.
- **Cross-review rule:** the reviewer must be able to explain the change.
- **Definition of done:** tests (core decision logic ≥ 80% coverage, policies ≥ 90% `opa test --coverage`),
  docs updated, CI green, contracts valid, reviewed.
- ADRs for significant decisions (`docs/adr/`).
- Rhythm: Monday 30-min sync, Thursday async update, short demo at the end of each sprint.
- Claude Code: one task = one branch = one session; plan first, tests first; review every diff and every new
  dependency; never paste real tokens.

## 15. Task division

Vertical ownership; each track has DevOps, security, backend/UI and an AI component. Size points S=1, M=2, L=3:
**Track A = 22, Track B = 22.**

### 15.1 Track A — Pipeline, Supply Chain & Runtime

| ID | Task | Deliverables / acceptance | Sprint | Size |
|---|---|---|---|---|
| A1 | Scanner integration | Adapters (Gitleaks, Opengrep, Grype, Trivy, Checkov, zizmor) → `out/raw/`; `tools.lock.toml` + `sentinel tools verify`. Accept: fixture test per adapter; tampered binary → SC-010; crash → SC-010 | S1 | M |
| A2 | Normalizer & fingerprints | SARIF/JSON → Finding v1, §13.1 fingerprints, cross-tool dedup. Accept: golden files; schema-valid; byte-identical output | S1 | M |
| A3 | Hardened reusable pipeline | `sentinel-scan.yml` with job isolation, PR diff-aware + main modes, deterministic PR comment, SHA pins, demo-shop workflow. Accept: fake secret PR blocked; zizmor clean | S1–S2 | L |
| A4 | Supply chain & release | `sentinel-release.yml`: build by digest, SBOMs, Cosign sign + attestations (SBOM, vuln, decision, provenance), signed evidence bundle, `sentinel verify`. Accept: verify fails on the 4 bad cases | S2 | L |
| A5 | Runtime enforcement | kind + registry, Helm, Argo CD, Kyverno policy, GitOps digest bump. Accept: bad images denied by automated tests; good release deploys | S3 | L |
| A6 | Remediation orchestration | Bot, deterministic fixers, PR creation, verifier, retries, state machine; consumes B6. Accept: never VERIFIED with failing test / new finding; never merges | S4 | L |
| A7 | AI alert correlation | §8 correlator, pgvector, `/api/v1/groups`. Accept: ARI + alert reduction with ablation | S3 | M |
| A8 | Observability & pages | Prometheus metrics, Grafana as code, pages Releases, Supply chain, Remediation | S3–S4 | M |
| A9 | Demo seeds: infra & deps | Dockerfiles, K8s, Terraform, vulnerable/unused deps, fake secrets + ground truth | S0–S1 | S |
| A10 | Hardening & v1.0.0 | Self-gating, Scorecard, caching, signed v1.0.0, switch to GitHub mode when public | S5 | S |

### 15.2 Track B — Risk Intelligence, Policy & AI Platform

| ID | Task | Deliverables / acceptance | Sprint | Size |
|---|---|---|---|---|
| B1 | Platform backend | FastAPI, PostgreSQL + Alembic, SeaweedFS (S3), Celery + Redis, GitHub sync, OpenAPI in `schemas/`. Accept: `make up`; a sync ingests a real run; contract tests | S1 | L |
| B2 | Enrichment | EPSS, KEV, OSV, reachability, `sentinel.yaml`; snapshots + offline fixtures | S2 | M |
| B3 | Risk engine | §6.2 model, bands, factor breakdown, CVSS baseline. Accept: property tests (monotonicity, bounds) | S2 | M |
| B4 | Policy & decisions | Rego SC-001…SC-010, profiles, diff-aware mode, waivers + VEX, Decision v1, `evaluate`, `replay`; minimal SC-001 for S1. Accept: coverage ≥ 90%; replay identical | S1–S2 | L |
| B5 | AI analyst | Provider (Ollama), prompts, retrieval, explanation + triage, redaction, injection isolation, metrics | S3 | L |
| B6 | AI patch generator | LLM fixer → PatchProposal, scope restriction, `git apply --check`, retries | S4 | M |
| B7 | Dashboard core & pages | React scaffold, typed client from OpenAPI, Overview, Findings, Finding detail, Policies | S1–S4 | L |
| B8 | Evaluation harness | §17 metrics, reproducible `make eval` report | S3–S5 | L |
| B9 | Demo seeds: app code | SAST seeds, injection canaries, ground-truth schema | S0–S1 | S |

### 15.3 Hand-offs

| Producer → consumer | Artifact | Needed by | Mock until then |
|---|---|---|---|
| Shared → all | schemas + fixtures | end S0 | — (done in Sprint 0) |
| A2 → B2, B3, B4 | findings NDJSON | mid S1 | fixtures |
| B1 → A3, A8 | OpenAPI + sync | end S1 | local JSON |
| B4 → A4, A5 | Decision v1 | mid S2 | fixture decision |
| A4 → A5, B1 | evidence bundle | end S2 | sample bundle |
| B5 → A7 | LLMProvider | start S3 | fake provider (see `ai/tests`) |
| B6 → A6 | LLM patches | mid S4 | deterministic fixers first |
| A9 + B9 → B8 | ground truth | end S1 | — |

## 16. Roadmap

| Sprint | Dates | Milestone |
|---|---|---|
| S0 | 2–8 Nov | M0 — repo, settings, contracts, CI green |
| S1 | 9–22 Nov | M1 — walking skeleton: PR scanned → Finding v1 → minimal gate → PR comment; platform lists findings |
| S2 | 23 Nov–6 Dec | **M2 = MVP** — risk scoring, rule catalogue, waivers, replay; signed image with SBOM, provenance, decision; `sentinel verify` |
| S3 | 7–20 Dec | M3 — Kyverno on kind + Argo CD; AI explanations; correlation; dashboards v1 |
| S4 | 21 Dec–3 Jan | M4 — verified remediation loop; patch generator; Grafana |
| S5 | 4–17 Jan | M5 — evaluation report, hardening, docs, demo video, v1.0.0; go public |

**MVP cut line:** M2 alone is a complete project. Drop order if late: stretch goals → Argo CD → LLM patch
generator → correlation stage 3. **Stretch:** Jenkins pipeline reusing the CLI, MCP server for coding agents,
Check Runs annotations, ChatOps, call-graph reachability, fine-tuned triage classifier.

## 17. Evaluation and demo

**Benchmark (`demo-shop/ground-truth/`):** secrets 5 · SAST 10 · SCA 8 (≥ 2 KEV-listed with fixes, ≥ 3 never
imported) · container 5 · IaC 6 · CI workflow 3 (under `examples/`, never executed) · injection canaries 5 · clean
controls 5. Choose concrete package versions in Sprint 0 from the current KEV catalogue and OSV.

**Metrics:** recall per category and false positives on clean controls · NDCG@10 vs CVSS baseline · ARI + alert
reduction + ablation · explanation rubric + LLM-judge agreement (Cohen's kappa) · verified fix rate · AI
mislabel rate on canaries and verdict changes (must be 0) · pipeline p50/p95 · replay identity.

**Demo (5 min):** context (2026 incident) → BLOCK on a PR → understand (score factors, AI advisory) → fix (bot PR,
VERIFIED) → release (signed, `sentinel verify`, Argo CD, Kyverno admits) → attack (bad image denied) →
manipulate the AI (verdict unchanged) → prove (`sentinel replay`, Grafana).

## 18. Risks

| Risk | Mitigation |
|---|---|
| Laptop resources | Compose profiles; small quantized model on the stronger machine |
| Direct push to `main` (no server-side protection while private) | Team convention, local pre-commit guard, CI on every push to `main` |
| Actions minutes (private) | Path filters, caches, nightly full scans |
| Signing key in CI (private phase) | Only the attest job references it; rotate and switch to keyless when public |
| External APIs down | Snapshots and offline fixtures |
| Scanner noise | Diff-aware gating, risk scoring, correlation, waivers |
| Integration drift | Contracts + fixtures in CI; weekly sync |
| Scope creep | MVP cut line; milestone demos |
| Vulnerable demo code misused | Local only, fake secrets, loud labelling |
| Our own supply chain | SHA pins, tools verify, Dependabot cooldown, zizmor, review of dependencies |
| AI hallucinations | Grounding, schemas, advisory only, deterministic verification, evaluation |

## 19. CV and interview kit

Replace every [X] with a measured number. Track A: hardened reusable pipeline designed against the 2026 Trivy
compromise · SBOMs, Cosign signing, attestations and SLSA provenance enforced by Kyverno · verified auto-
remediation ([X]% verified fixes) · [X]% triage reduction via dedup + embedding clustering. Track B: OPA risk-based
gate combining CVSS, EPSS, KEV, reachability and exposure; signed, replayable decisions · LLM analyst with
schema-constrained outputs and injection isolation (0 verdict changes across [X] canaries) · NDCG@10 from [X] to
[X] vs CVSS baseline · FastAPI/PostgreSQL control plane and React dashboard.

## 20. Sprint 0 checklist

| # | Action | Status |
|---|---|---|
| 1 | Private repo, collaborator invited | done |
| 2 | Scaffold: uv workspace, packages, Makefile, CI (SHA-pinned, zizmor), CODEOWNERS, Dependabot, CLAUDE.md | done |
| 3 | Contracts: finding, decision, patch proposal, verification result + fixtures + tests | done |
| 4 | Spec v1.1 + ADRs in `docs/` | done |
| 5 | Repository settings: require SHA-pinned actions, read-only default workflow token, Dependabot alerts (branch protection deferred to the public phase, convention + local guard meanwhile) | to do (owner) |
| 6 | Choose and pin tool versions in `tools.lock.toml` | done (A1a; Opengrep pending) |
| 7 | Compose skeleton (postgres+pgvector, redis, seaweedfs, ollama, api, prometheus, grafana; worker with B1, web with B7) | B |
| 8 | `demo-shop/` skeleton + ground-truth format; first seeds | A9 first seeds done (draft format v1); B9 to do |
| 9 | GitHub Project board: one issue per task id | both |
| 10 | Choose the local model and measure tokens/second | done (ADR-0009; re-run the benchmark on each laptop) |

## Appendix — Glossary

SBOM (bill of materials) · SLSA (build-integrity levels) · provenance (signed build statement) · in-toto
attestation (subject digest + typed predicate) · Sigstore/Cosign (signing ecosystem) · keyless signing (OIDC
identity instead of a long-lived key) · EPSS (exploitation probability, 30 days) · KEV (CISA known exploited) ·
VEX/OpenVEX (exploitability statements) · purl (package URL) · SARIF (scanner result format) · OPA/Rego
(policy-as-code) · admission controller (rejects resources before they run) · reachability (vulnerable code
actually used) · NDCG/ARI (ranking / clustering metrics) · fail-closed (deny on error).
