# SentinelCI threat model

What SentinelCI defends, against whom, and where each defence lives and is tested. It complements SPEC §18
(project risks) and the ADRs, which record why each control was chosen. Status: **main** (merged), **PR #n**
(written and tested, not merged yet), **planned** (not written).

## 1. What is worth attacking

| Asset | Why it matters |
|---|---|
| The release decision (PASS, WARN, BLOCK) | It is what lets an image ship. A forged or wrongly computed PASS ships a vulnerable image |
| The pipeline that judges a change | The CLI, `tools.lock.toml`, the policies, the waivers. Whoever controls it controls the decision |
| The security tools | A tampered scanner can stay silent, or steal what the job can reach (the Trivy incident of March 2026) |
| The release signing key | With it, anything can be made to look released |
| The signed release and its evidence | Image, signature and the four attestations (decision, SBOM, vulnerability scan, provenance) |
| The cluster | What finally runs |
| Findings and decisions stored by the platform | Evidence; findings may describe secrets (never their values) |
| Repository write access | `main` has no server-side protection in the private phase (ADR-0006) |

## 2. Who attacks

- **A1, the outside contributor**: opens a pull request with any content, including workflows, code that
  runs in CI, scanner configuration files and comments meant for an AI.
- **A2, the compromised dependency or tool**: a scanner release, a GitHub Action, a Python package or a
  container base image turned malicious upstream.
- **A3, the malicious or confused AI output**: a model that follows instructions hidden in finding text, or
  invents a fix.
- **A4, the attacker inside the network path**: a proxy, a redirect, a registry that serves something else.
- **A5, the insider with push rights**: one of the two team members, or a session acting for one. In the
  private phase this attacker is accepted as a residual risk (section 5).

## 3. Trust boundaries

```mermaid
flowchart LR
  PR["Pull request (untrusted data)"] --> SCAN
  subgraph CI["GitHub Actions"]
    SCAN["scan: base commit's pipeline, read-only token, no secret"] --> GATE["gate: base policies and waivers, no repository code"]
    GATE --> REPORT["report: PR comment only"]
    PROPOSE["bot propose: read-only"] --> PUBLISH["bot publish: write token, no repository code"]
    PUBLISH --> VERIFY["bot verify: read-only, base pipeline"] --> BREPORT["bot report: comment and status, no repository code"]
  end
  subgraph LAPTOP["Laptop signer (private phase)"]
    REL["make release: clean tree at origin/main"] --> KEY["release key, password-protected"]
  end
  REL --> BUNDLE["release bundle: image + signature + 4 attestations"]
  BUNDLE --> KIND
  subgraph KIND["kind cluster"]
    ARGO["Argo CD, read-only GitOps repo"] --> KYV["Kyverno + admission policy"] --> POD["workloads"]
  end
  CLI["sentinel upload"] --> API["platform API, 127.0.0.1, token hash only"]
  API --> AI["AI layer: advice only, local models"]
```

Data crosses each arrow; code and credentials do not. A job that runs repository code never holds a write
token or a secret, and a job that holds one runs no repository code.

## 4. Threats and controls

### 4.1 Pipeline: a change must not judge itself

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T1 | A pull request runs code with secrets or a write token ("pwn request") (A1) | No `pull_request_target`; the scan job has `contents: read` and no secret; only the report job can write, and only a comment | `.github/workflows/sentinel-scan.yml`, ADR-0008 | `tests/ci/test_workflows.py` (permissions, no `pull_request_target`, no persisted token) | main |
| T2 | A pull request edits the CLI, the lock, the policies, the waivers, the VEX document or `sentinel.yaml` that judge it (A1) | Every job checks out the pipeline at the base commit; the change is checked out only as data, never run. The PR comment lists the pipeline files the change touches | ADR-0008, `sentinel-scan.yml` | `test_the_pipeline_change_warning_covers_every_input_read_from_the_base_commit` | main |
| T3 | A pull request silences a scanner: `.gitleaks.toml`, `.gitleaksignore`, `gitleaks:allow`, `.trivyignore`, `zizmor.yml`, `# zizmor: ignore`, `.gitattributes` (A1) | Each adapter passes SentinelCI's own configuration, an empty ignore location, offline flags; inline allow comments are not honoured | `cli/src/sentinelci/scanners/{gitleaks,trivy,zizmor}.py` | planted `.gitleaksignore`, `.trivyignore` and `.gitattributes` in `test_gitleaks_scan.py`, `test_trivy_scan.py`; zizmor's in `test_zizmor_scan.py` | main |
| T4 | A pull request drops a scanner step from the workflow it carries (A1) | The required scanners come from the base policies (`required_tools.rego`); a missing one is SC-010 | `policies/required_tools.rego`, `gate.rego` | `gate_test.rego` (SC-010 cases) | main (Gitleaks, Trivy, zizmor); Opengrep not required yet |
| T5 | A secret is added, then removed, inside one pull request (A1) | Gitleaks scans every commit of the pull request (`base..head`) as patches | `sentinel-scan.yml` | git-mode tests in `test_gitleaks_scan.py` (text patches forced, octopus merges) | main |
| T6 | Only what the change introduces should block, but a failed baseline must not hide anything (A1) | Diff-aware gating against the base commit's scan; without a baseline every finding counts | `sentinel-scan.yml`, SPEC §5 | the baseline step of `sentinel-scan.yml`; PR #66 adds a test that it runs every scanner the head runs | main; zizmor in PR #66 |
| T7 | A contributor waives their own finding, declares it `not_affected` in VEX, or lowers its service's exposure in `sentinel.yaml` (A1) | Waivers, the VEX document and `sentinel.yaml` are read from the base commit; a waiver needs an owner, a justification and expires within 90 days, or it is SC-005; a `not_affected` statement needs a justification and expires 90 days after it was made; a statement or document dated after `evaluated_at` blocks (SC-010); a statement of any other status disputes it; secrets are never covered | `policies/gate.rego`, `.sentinel/waivers.yaml`, `.sentinel/vex.json`, `sentinel.yaml` | `gate_test.rego` (SC-005 and VEX cases) | main |
| T8 | A CI workflow introduces a dangerous pattern (A1) | zizmor audits the workflows of every change; a new high-severity issue is SC-009 | `sentinel scan pipelines`, `sentinel-scan.yml` | GT-PIPELINE-001 to 003 give SC-009 | scanner: main; in the gate: PR #66 |

### 4.2 Tools and dependencies: trust nothing that was downloaded

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T9 | A scanner release is replaced upstream (A2) | `tools.lock.toml` pins each binary by sha256 (and Opengrep by its signature); the binary is re-hashed right before every run; a mismatch never runs and is SC-010 | `cli/src/sentinelci/scanners/lock.py`, `runner.py` | `test_install_verify.py`, `test_runner.py`, `test_status.py` | main; Opengrep in PR #40 |
| T10 | A scanner crashes, times out or reports nothing, and silence reads as a pass (A2) | Every scanner writes a tool status on failure too; any status other than `ok` is SC-010; each run has a time limit the job outlives | `scanners/status.py`, `gate.rego` | crash, timeout and integrity tests; `test_the_scan_job_outlives_every_scanner_run` | main; zizmor's status in PR #66 |
| T11 | A GitHub Action tag is moved to malicious code (A2) | Every action is pinned by full commit SHA with its version comment | all workflows | `test_every_reference_exists_or_is_pinned_by_commit_sha` | main |
| T12 | A malicious Python package or update (A2) | `uv.lock` with hashes, dependencies added only with `uv add` and justified; Dependabot waits 7 days before proposing an update | `uv.lock`, `.github/dependabot.yml` | `uv sync --locked` in CI | main |
| T13 | A container base image changes under its tag (A2) | Compose images are pinned by tag and digest; the release image's base is pinned by digest (ADR-0011) | `deploy/compose/compose.yaml` | `tests/deploy/test_compose.py` | main; release Dockerfile planned (with B9) |

### 4.3 Release: only what the gate allowed can run

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T14 | The signing key is stolen from CI (A1, A5) | The release key never reaches GitHub; the laptop signer (`make release`) refuses unless the tree is clean at `origin/main`, builds from the commit, and asks the password on the terminal, giving it only to the two processes that use the key; the key must be the pair of the committed public key | ADR-0011, `deploy/release/release.py` | `tests/deploy/test_release.py`, `tests/deploy/test_release_tools.py` | A4c |
| T15 | A BLOCK image gets signed (A5, A2) | `sentinel attest` refuses a BLOCK or non-release decision, or a decision about another digest | `supplychain/attestations.py` | `cli/tests/supplychain/test_attestations.py` | main |
| T16 | An unsigned, tampered or BLOCK image is deployed (A1, A4) | `sentinel verify` checks the signature and the four attestations; Kyverno applies the same checks at admission; a native admission policy only admits release images in the demo namespace | `supplychain/verify.py`, `deploy/kyverno`, ADR-0011 | `test_verify.py`; admission tests with the Kyverno CLI; `make demo-attack` (5 attacks) | verify and the admission policy: main; the cluster: PR #60 to #62 |
| T17 | A registry or bundle serves another image under the right name (A4) | Everything is addressed by digest; the attest step re-reads the digest from the layout itself; Kyverno re-verifies at admission | ADR-0011 | registry-mode tests | main |
| T18 | The GitOps repository is edited to deploy something else (A5, A4) | A local bare repository served read-only inside kind (push refused); a NetworkPolicy lets only Argo CD's repo server reach it; admission still verifies whatever it deploys | `deploy/argocd` | `tests/deploy` and the kind end-to-end test of PR #61 | PR #61 |

### 4.4 Evidence: a decision can be checked later

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T19 | A decision is altered or cannot be reproduced (A5) | Each decision records the sha256 of every input; the evidence store keeps them; `sentinel replay` re-runs it, and a nightly job replays recent decisions | `policy/`, `replay-nightly.yml` | replay tests; nightly replay | main; the nightly job is stopped while Actions is blocked (§5) |
| T20 | Recorded evidence is replaced on the platform (A5) | The database refuses any change to a recorded run or its findings, and keeps the uploaded bytes only if they hash to the recorded digest | migrations 0002 to 0004 | `platform/api/tests` | main |

### 4.5 Platform API

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T21 | Unauthenticated or oversized writes (A1, A4) | Every port binds 127.0.0.1; writes need a bearer token, and the API only holds its sha256; bodies are capped before parsing or authentication | `platform/api`, `deploy/compose` | `test_ingest.py`, `test_compose.py` | main |
| T22 | The upload client leaks its token (A4) | The token comes only from `SENTINEL_API_TOKEN`; no redirect is followed; plain http (loopback only) never goes through a proxy; the token is never printed, even in errors | `report/upload.py` | `cli/tests/report/test_upload.py` (stub servers, proxies, redirects) | main |
| T23 | Metrics reveal what runs contain (A1) | Read-only aggregates, SPEC §10 names only, enumerated label values only (never a repository, commit or id) | `sentinel_api/metrics.py` | `test_metrics.py` | PR #67 |

### 4.6 AI: it advises, it never decides

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T24 | AI output changes a verdict, creates a waiver or merges (A3) | The decision path cannot import the AI package (import contract); AI output is advice stored next to the decision | `pyproject.toml` (`importlinter`), ADR-0004 | `lint-imports` in `make check` | main |
| T25 | Finding text carries a prompt injection (A1, A3) | Findings are sent as JSON lines inside a delimited block, with `<` and `>` escaped; no ids, snippets or evidence are sent; an answer is schema-checked, retried once, and never replaces a deterministic label | `ai/.../correlate/labels.py` | guardrail tests (7 tampered guardrails) | main |
| T26 | A secret reaches a model or comes back in its answer (A3) | Secret findings are never sent; text is redacted; an answer that contains a secret is refused | `ai/.../correlate/labels.py` | redaction tests | main |

### 4.7 Remediation bot

| # | Threat (attacker) | Control | Where | Proof | Status |
|---|---|---|---|---|---|
| T27 | A compromised proposal step pushes arbitrary code (A2) | `propose` is read-only; `publish` holds the write token and runs no repository code; it accepts a bundle only if it holds one commit on the scanned commit, on a `sentinel/fix/` branch, carrying the proposal id and editing in place exactly the listed files, all under the scanned path | ADR-0013, `sentinel-remediate.yml` | `test_bot_workflow.py`: 9 tampered outputs refused | PR #64, #65 |
| T28 | A bot pull request is reported as safe without being judged (A2, A3) | `verify` rebuilds the commit from the proposal with the base pipeline, scans both commits with the required scanners, builds and tests the patch, and runs the verification gate; `report` re-checks the gate's invariant; the bot never merges | ADR-0013, `remediation/check.py` | end-to-end test with the real scanners; 6 untrusted results reported FAILED | PR #65 |

### 4.8 The demo target

| # | Threat | Control | Status |
|---|---|---|---|
| T29 | The intentionally vulnerable demo is run or exposed | Never run outside a container, never exposed beyond localhost; its seeded Dockerfile cannot build; every secret is fake and listed in the ground truth | main |

## 5. Residual risks (accepted, with a reason)

| Risk | Why it is accepted now | What removes it |
|---|---|---|
| `main` has no server-side protection; anyone who can push can change the pipeline | GitHub Free, private repository (ADR-0006); two people and their sessions only | Branch protection when the repository goes public |
| Any workflow run can read a repository secret | No environment branch rules on GitHub Free for a private repository | There is no signing secret on GitHub (ADR-0011) |
| Opengrep is not a required scanner: a pull request that deletes its step is not caught | Its gate wiring is new (PR #40) | Adding it to `policies/required_tools.rego` |
| The laptop signer trusts the laptop | A local key is the only signer the private phase allows | Keyless signing in CI when public (ADR-0006) |
| `verify` in the bot runs the same code as `propose` | A compromised dependency could write a false result, but holds no write token: at worst a wrong comment on a pull request a reviewer still judges | — |
| Local models may be wrong | Their output is advice, schema-checked, and never decides | — |
| The platform API's reads need no token: anything on the host, or in the Compose network, can read runs and findings | Every port binds 127.0.0.1, findings never hold a secret's value (only its hash), and nothing but the dashboard reads them yet | A read token (B1), when the dashboard (B7) and the Grafana datasource need one |
| The nightly replay, like every other workflow, is stopped while GitHub Actions is blocked (the account's spending limit) | Decisions can still be replayed by hand (`sentinel replay --all`), and each pull request carries a local `make check` report | Actions running again |

## 6. Keeping this document true

Each control above names the test that proves it. A change that removes a control must remove its row here
and say why in an ADR. A new threat gets a row before its control is written.
