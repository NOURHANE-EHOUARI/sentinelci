# sentinelci (core library + CLI)

The deterministic core of SentinelCI. It runs inside CI and locally with the same behaviour.

| Module | Responsibility | Track | Tasks |
|---|---|---|---|
| `scanners/` | Scanner adapters and `sentinel tools verify` | A | A1 |
| `normalize/` | SARIF/JSON to Finding v1, fingerprints, dedup | A | A2 |
| `enrich/` | EPSS, KEV, OSV, reachability, service context | B | B2 |
| `risk/` | Risk model and priority bands | B | B3 |
| `policy/` | OPA evaluation, decision records, replay | B | B4 |
| `supplychain/` | SBOM, signing, attestations, verify, evidence bundle | A | A4 |
| `report/` | PR comment, SARIF export | A | A3 |

`risk/`, `policy/`, `enrich/` and `normalize/` must never import `sentinel_ai` (enforced by import-linter).

## `sentinel snapshot` (enrichment fetchers, B2)

```bash
uv run sentinel snapshot --findings out/findings.ndjson --out out/enrichment-snapshot.json
uv run sentinel snapshot --findings out/findings.ndjson --out out/enrichment-snapshot.json --record fixtures/feeds
uv run sentinel snapshot --findings out/findings.ndjson --out out/enrichment-snapshot.json --offline fixtures/feeds
```

- The only command that uses the network: OSV (`GET /v1/vulns/{id}` for the ids of package findings, then once
  more for the aliases they reveal), FIRST EPSS (100 CVEs per request) and the CISA KEV catalogue. HTTPS to those
  three hosts only, no credentials, `--timeout` seconds per request (default 30), 32 MB per response.
- CVSS comes from the OSV vector: the 3.0/3.1 base score is computed (`enrich/cvss.py`), the highest vector wins;
  CVSS 2.0 and 4.0 vectors are not scored, so the score stays unknown. Fixed versions come from ECOSYSTEM and
  SEMVER ranges only (GIT ranges name commits).
- Each feed is all or nothing: a failed request or an answer the API does not document leaves that feed out, with
  a warning on stderr; its values stay unknown (worst case for the risk engine). Exit 0 with the partial snapshot.
- The snapshot is validated against `schemas/enrichment-snapshot.v1.json` and written canonically (sorted keys),
  so the same feed answers give the same bytes and digest. An unreadable findings file, or a snapshot that
  fails its contract, writes nothing and exits 3.
- `--record DIR` saves every response (raw bytes in base64, with their sha256); `--offline DIR` answers from
  those files only, after checking the digest (a request never recorded, or an altered recording, counts as an
  outage). This gives the offline fixtures for demos, evaluation and tests. Recordings are inputs like the
  policies: in CI, use them only from the base commit or a trusted store, since a change that edits them could
  forge EPSS or KEV answers. Committed fixtures for a fixed finding set live in `eval/feeds/` (gzip-compressed;
  `uv run python eval/feeds/refresh.py --check` replays them offline).
- KEV is read before EPSS, and EPSS is left out when KEV could not be read: EPSS alone would lower the risk of a
  KEV-listed vulnerability. When OSV could not be read, KEV and EPSS are left out too: the findings' aliases are
  then unknown, and the CVE KEV lists may be one only OSV links to a finding. The KEV catalogue is trusted whole
  or not at all (every entry, its `count`, at least 1,000 entries).
- Redirects are never followed. Each request has one overall deadline (enforced on every read, so a slow drip
  cannot hold it) and is retried once only on a timeout, a reset or a retryable status (429, 5xx), never on a
  TLS failure or a refused redirect; the whole run stops after 10 minutes. `--timeout` must be in (0, 300].
  An `--out` that cannot be written, or anything unexpected, exits 3 with nothing written.

## `sentinel enrich` (enrichment, B2)

```bash
uv run sentinel enrich --findings out/findings.ndjson --snapshot out/enrichment-snapshot.json \
  --config sentinel.yaml --source . --out out/findings.enriched.ndjson
# PR mode: --source <base checkout> --source <head checkout>
```

- Offline: applies an enrichment snapshot (`schemas/enrichment-snapshot.v1.json`) and the service context
  (`sentinel.yaml`, `schemas/sentinel-config.v1.json`) to findings. Pass the same snapshot to `sentinel evaluate
  --enrichment-snapshot` so the decision records its digest.
- Package findings (SCA, CONTAINER): `cvss` and `epss` (highest among the finding's ids and every alias reachable
  from them in the snapshot; CVE ids compared in upper case), `kev` (only when the KEV feed was read),
  `fix_available` (true from the finding or OSV, false only when OSV knew the vulnerability and fixes none of the
  package). Every finding: `exposure` of its `sentinel.yaml` component (longest matching path), else the top-level
  exposure; a finding without a path (a container image) gets the highest exposure of the service and its
  components.
- Unknown stays absent; the risk engine treats absent as the worst case. Without `--snapshot` or `--config`,
  nothing from that source is added.
- Read `sentinel.yaml` from the base branch in PR mode: a change must not lower its own exposure.
- `--source DIR` (repeatable) adds `reachability: imported` to PyPI and npm SCA findings by static import analysis
  (`enrich/reachability.py`). The tree is only read: nothing in it is run, imported or installed, and symlinks
  are never followed.
  - `imported`: first-party code imports the package (Python AST; JS/TS `import`, `export ... from`, literal
    `require()` and `import()`, comments ignored), or an imported package depends on it at runtime (uv.lock,
    poetry.lock, package-lock.json v2/v3, pip-compile `# via` annotations; optional and peer dependencies are
    not followed).
  - Nothing otherwise, which the risk engine counts as the worst case. `not_imported` and `unknown` are not
    claimed: a library can load a package itself through an optional dependency the lockfile does not record.
  - No answer for CONTAINER findings, `MAL-` advisories or npm packages with install scripts.
  - With several trees `imported` must hold in all of them: in PR mode pass the base and the head, so a change
    cannot lower the score of its own dependencies by adding an import.
  - Files that cannot be read or parsed, are too large, or hold a dotted name of 64 parts or more are skipped
    (fixed limits, no clock: the same tree always gives the same answer).
- `kev: {listed: false}` only for CVEs the snapshot's KEV lookup covered (`sources.kev.cves`); otherwise KEV stays
  unknown. Package URLs are compared in canonical form (PyPI names per PEP 503).
- `sentinel.yaml` is read with a restricted YAML loader: no duplicate keys, merge keys (`<<`), anchors, aliases,
  dates, binary or set values; at most 64 KiB (never read further). Component paths must be canonical
  (`services/web`, not `./services/web/`) and unique.
- Fail closed: an invalid snapshot, `sentinel.yaml` or findings file (including enrichment outside the Finding
  contract, or nested too deeply), or `--out` naming any input or a directory, writes nothing and exits 3.
  `sentinel evaluate` refuses an `--enrichment-snapshot` that is not a valid snapshot; with none, both commands use
  the same empty snapshot, so "no snapshot" has a single digest.

## `sentinel score` (risk engine, B3)

```bash
uv run sentinel score --findings out/findings.ndjson --out out/findings.scored.ndjson
```

- Sets `risk` on every finding: `score` (0-100, rounded to 0.1), `priority` (P0-P4), `factors` (S, E, X, R) and the
  `model_version` of `policies/risk-model.yaml`, with `risk = 100 x S x E x X x R` (SPEC section 6.2).
- Missing enrichment never lowers a score: E < 1 only when KEV was read and does not list the CVE (EPSS alone,
  with KEV unknown, counts as E = 1.0), no exposure counts as X = 1.0, no
  reachability analysis as R = 1.0 (`unknown` is for an analysis that could not decide). Every score stays at most
  `100 x severity_weight`, and a finding with no enrichment scores exactly that, like an unscored one at the gate.
- SAST counts as taint-mode (`SAST_TAINT`) until findings say which kind they are; a category the model does not
  list counts as E = 1.0. Reachability applies to SCA and CONTAINER only.
- Fail closed: findings that are not Finding v1, or an invalid risk model, write nothing and exit 3.
- `cvss_baseline()` gives the CVSS-only score on the same scale, the baseline the evaluation compares with (B8).

## `sentinel evaluate` (release gate, B4)

```bash
sentinel evaluate --findings out/findings.v1.ndjson \
  --repo NOURHANE-EHOUARI/sentinelci --commit "$(git rev-parse HEAD)" --context pr \
  --tool-version gitleaks=8.24.0 -o out/decision.v1.json
```

Runs the OPA policies in `policies/` and writes a Decision record (`schemas/decision.v1.json`, `schema_version` 1.1).

- Exit code: `0` PASS or WARN, `1` BLOCK, `2` usage error, `3` no decision could be made (bad input,
  OPA missing, failing or timing out; same code as `sentinel normalize` for untrusted input). Treat `3`
  as blocked: the gate fails closed, and an older decision file at the
  output path is deleted before evaluation starts.
- OPA is a pinned binary (`uv run sentinel tools install opa`, from `tools.lock.toml`): pass `--opa`, set
  `SENTINEL_OPA`, or put `opa` on `PATH`. It runs with an empty environment and without non-deterministic
  built-ins (clock, network, randomness, `opa.runtime`): a policy using one fails to compile.
  `sentinel policy capabilities -o <file>` writes the same restriction for `opa check/test` (`make policy`).
- `--evaluated-at` (RFC 3339, default now) is the only time the policy sees, so a decision can be replayed.
  Same inputs give a byte-identical file, including `decision_id`, which is a UUIDv5 of the subject,
  time, input digests and engine version.
- Recorded evidence: digests of the findings file, policy bundle (all files in `policies/` except
  `*_test.rego`), waivers file as read (empty content when there is none), enrichment snapshot (the empty
  snapshot `{}` until B2 lands) and optional SBOM; the risk
  model version; versions of every tool that reported a finding, given with `--tool-version`, and OPA.
- `--baseline <findings.ndjson>` (base-branch findings): in `pr` context only findings the change introduces
  can block; a known secret counts as new when it appears in another file (`location` or any of its
  `other_locations`). Release ignores the baseline.
- `--tool-status <json>` (`schemas/tool-status.v1.json`): every tool that is not `ok` becomes an SC-010 BLOCK in
  the decision, so a failed scan still produces a record.
- Required scanners (`policies/required_tools.rego`, part of the policy bundle, so read from the base branch):
  gitleaks in `pr` and `release`, none in `local`. A required tool left out of the tool status, or no tool
  status at all in a context that requires tools, is an SC-010 BLOCK (`Scanner missing` /
  `Tool status missing`): a workflow that drops a scanner cannot turn its silence into a pass.
- The decision is `schema_version` 1.2 (with `baseline_digest` / `tool_status_digest`) when either option is
  given, 1.1 otherwise.
- Rules implemented so far: SC-001 (secret introduced by the change, not waived), SC-002 (P0 finding, BLOCK),
  SC-003 (KEV-listed, fixable, internet-facing or exposure unknown), SC-005 (invalid waiver), SC-006 (P1 finding, WARN), SC-009
  (HIGH/CRITICAL CI workflow issue), SC-010 (scanner failure or missing, malformed gate input) and SC-011
  (misconfiguration that exposes the service by itself, `policies/exposing.rego`). Waivers and
  PR diff-awareness apply to every finding rule; each finding is reported under its most specific rule only.
- Priority is `risk.priority` from the risk engine (B3), trusted only when `risk.model_version` is the
  bundle's risk model. An unscored finding, or one scored with another model, counts at its worst case,
  `100 x severity_weight` banded (CRITICAL and HIGH are P0), so missing or foreign scores never let it through.
- Verdict: BLOCK if any BLOCK violation, else WARN if any WARN violation (exit 0), else PASS.

### Replay

```bash
uv run sentinel evaluate ... --store out/evidence      # also keep every input and the decision
uv run sentinel replay <decision-id> --store out/evidence
uv run sentinel replay out/decision.v1.json --store out/evidence
uv run sentinel replay --all --store out/evidence                # every stored decision (nightly job)
```

- `evaluate --store DIR` writes every input exactly as digested to `DIR/sha256/<hex>` (findings, waivers, baseline,
  tool status, enrichment snapshot, SBOM, each policy file), the policy bundle manifest (its digest is the
  recorded `policy_bundle_digest`) and the decision to `DIR/decisions/<id>.json`. If the evidence cannot be
  stored, no decision is written (exit 3).
- `replay` re-evaluates from the store only, policy included, and compares the whole record, `decision_id`
  included. Exit 0 identical, 1 differs (each differing field is listed as `recorded -> replayed`), 3 cannot
  replay (missing or tampered evidence, malformed record, Decision 1.0).
- Scanner versions are passed back as recorded (scanners do not run again); the OPA version is the running
  binary's, so an OPA or engine upgrade shows up as a difference.
- Before anything else, a record's `decision_id` must be the one its own subject, `evaluated_at`, inputs and
  `engine_version` give; an edited record cannot be replayed (exit 3), so editing a version can never turn
  "differs" into "skipped". (A record edited *and* re-identified is caught only once decisions are signed, A4.)
- `--all` replays every decision in the store and skips those recorded with another engine or OPA version
  (listed as `skipped`). Exit 3 if any cannot be replayed, the store holds none or nothing was compared (every
  decision skipped; `--allow-all-skipped` accepts that, as after an engine bump), else 1 if any differs.
- The nightly job (`.github/workflows/replay-nightly.yml`) replays last night's corpus with today's engine,
  then records a fresh one with `eval/replay/corpus.py`. So a change to what the engine decides for the same
  inputs needs an engine version bump (`sentinelci.__version__`).

### Waivers

`--waivers` (default `.sentinel/waivers.yaml` when it exists) follows `schemas/waivers.v1.json`:

```yaml
version: 1
waivers:
  - id: waiver-2026-001                 # unique, recorded in the decision's waivers_applied
    finding_id: 3f1c9a7e...             # one finding by fingerprint, or:
    # vulnerability: CVE-2026-12345     # a vulnerability (CVE, GHSA, OSV id) in one package,
    # purl: pkg:pypi/example-lib        # any version (purl without version)
    owner: "@Hiba-elouazi"
    justification: Fake demo credential listed in the ground truth.
    expires_at: 2026-12-31T00:00:00Z    # RFC 3339 date-time, at most 90 days after evaluation
```

- A waiver applies to the findings it targets until `expires_at`. Expired waivers simply stop applying.
- An invalid waiver (missing owner, justification or expiry, expiry more than 90 days after
  `--evaluated-at`, unknown field, duplicate id, no or ambiguous target, purl with a version) never
  applies, and SC-005 blocks with every reason. The policy checks entries, not the loader, so the
  reasons reach the decision record.
- A file that cannot be read (bad YAML, wrong top-level shape, `version` other than 1) means no decision:
  exit code `3`.

## `sentinel attest` and `sentinel verify` (release attestations, A4)

ADR-0010. The attest job of the release workflow signs four in-toto statements about the image digest
(release decision, CycloneDX SBOM, vulnerability scan, SLSA v1 provenance) with the pinned Cosign and a key pair,
and writes them as Sigstore bundles under `<out>/attestations/`:

```bash
uv run sentinel attest registry.local/demo-shop/shop-api@sha256:<digest> \
  --decision out/decision.v1.json --findings out/findings.ndjson --sbom out/sbom.cdx.json \
  --key env://COSIGN_PRIVATE_KEY --out out/evidence
```

- It refuses (exit `3`, nothing signed) a BLOCK or non-`release` decision, a decision about another image,
  findings or an SBOM other than the ones the decision recorded (`inputs.findings_digest`, `inputs.sbom_digest`),
  an SBOM without a CycloneDX `serialNumber`, and a run outside GitHub Actions or on another repository or commit
  than the decision's. All four bundles are written, or none.
- `--key` is a key file or `env://VAR`; only that variable and `COSIGN_PASSWORD` reach Cosign. Private mode
  (ADR-0006): no transparency-log upload.

```bash
uv run sentinel verify registry.local/demo-shop/shop-api@sha256:<digest> --evidence out/evidence \
  --key cosign.pub --repo NOURHANE-EHOUARI/sentinelci \
  --builder-id https://github.com/NOURHANE-EHOUARI/sentinelci/.github/workflows/<release workflow>@refs/heads/main
```

- Prints a trust report: every attestation signed by the key and about this digest; a valid release decision
  about this image, from `--repo`, not BLOCK; provenance from `--builder-id`, built from the decision's commit;
  a vulnerability result naming the decision, its findings and its SBOM; that SBOM's `serialNumber`.
- Exit code `0` trusted, `1` not trusted (any check failed), `3` the verification could not run (for example
  a Cosign binary that does not match `tools.lock.toml`). Offline: the evidence directory and the public key
  are all it needs.

## `sentinel scan pipelines` (CI workflows, A1)

```bash
uv run sentinel scan pipelines demo-shop --repo-root . --out out/pipelines.ndjson \
  --repo NOURHANE-EHOUARI/sentinelci --commit "$GITHUB_SHA" --context pr
```

- zizmor, a runtime dependency of the CLI (`uv.lock`). Right before it runs, the binary of the CLI's own
  environment (never one from `PATH`) must be one that a wheel pinned in `tools.lock.toml` carries
  (`[python_tools.zizmor]`, at the pinned version): another version, a replaced binary, or zizmor missing
  exits `3` (SC-010).
- The scanned repository cannot configure or silence it: `--no-config`, `--no-ignores` (a finding covered by an
  inline `# zizmor: ignore[...]` comment is kept, and its message says so), `--collect=all` (`.gitignore` is not
  honoured), `--offline`, and a minimal environment.
- Inputs: what GitHub runs (every YAML file under `.github/workflows/`, every `action.yml` / `action.yaml`,
  `.github/dependabot.yml`) must load (`--strict-collection`), or exit `3`. Any other YAML file with a top-level
  `jobs:` key is audited too; one zizmor cannot load as a GitHub workflow (another CI's file) is skipped, named
  in a warning, and never counted as audited. `--persona=regular`: zizmor's default audits.
- Findings are category PIPELINE. A finding about a whole job or file is one per rule, file and job; any other
  also hashes the code it is about: the line holding the expression or action reference, a trigger or
  permission's value, a Dependabot entry's setting with its `package-ecosystem`. So a new expression, trigger or
  Dependabot entry is a new finding, while a moved line, an added step or an edit to another line of the same
  script keeps the id. The same code twice in a job is one finding with `other_locations`. No workflow code is
  kept (only its hash). A HIGH one that the pull request introduces blocks it (SC-009).
