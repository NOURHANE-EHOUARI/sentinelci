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
- `--service-context <sentinel.yaml>`: the same base-branch file given to `sentinel enrich --config`. Its exposure
  shaped the scores, so the decision records its digest (`inputs.service_context_digest`, Decision 1.3) and
  `--store` keeps it for replay. An invalid file is never recorded (exit 3). Its `policy_profile` picks the profile:
  `strict` makes any P1 an SC-006 BLOCK (`policies/profiles.rego`).
- `--vex <json>` (default `.sentinel/vex.json` if present, from the base branch): OpenVEX `not_affected`
  statements (`schemas/vex.v1.json`, justification required). A covered package finding counts for no rule and is
  listed in `vex_applied` (Decision 1.4); the command prints a `VEX not_affected:` line. A statement of any other
  status about the same finding disputes `not_affected` whatever the order, so remove an earlier
  `under_investigation` or `affected` statement when you add `not_affected`. Like a waiver, `not_affected` applies
  for 90 days after it was made (its `last_updated` or `timestamp`, else the document's `timestamp`), and a
  statement or document dated after `--evaluated-at` blocks (SC-010). Products are package purls (`pkg:oci` is
  refused: an image matches no finding). An invalid document, a duplicate JSON key, or one over 4 MiB exits 3.
- Required scanners (`policies/required_tools.rego`, part of the policy bundle, so read from the base branch):
  gitleaks and trivy in `pr` and `release`, none in `local`. A required tool left out of the tool status, or no tool
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

## `sentinel scan sca` (dependency vulnerabilities, A1)

```bash
uv run sentinel tools grype-db --db-dir .sentinel/grype-db --report out/grype-db.json  # before the scan (network)
uv run sentinel scan sca . --db-dir .sentinel/grype-db --out out/sca.ndjson \
  --repo NOURHANE-EHOUARI/sentinelci --commit "$(git rev-parse HEAD)" --context local
uv run sentinel normalize grype grype.json --scan-root demo-shop --out out/sca.ndjson \
  --repo NOURHANE-EHOUARI/sentinelci --commit "$(git rev-parse HEAD)" --context local
```

- One Syft run, as for `sentinel sbom`, also writes Syft's own format; the pinned Grype matches that SBOM. Grype
  never reads the scanned tree, and runs from a private working directory and home with
  `scanners/configs/grype.yaml` passed explicitly, so a `.grype.yaml` (ignore rules, VEX, `only-fixed`) or a
  `GRYPE_*` variable cannot hide a vulnerability.
- Offline: the database is the directory given in `--db-dir` (Grype's cache directory, filled beforehand), checked
  against its own hash; nothing is downloaded during the scan. A database built more than five days ago fails the
  scan; `--allow-stale-db` accepts it, for replays and tests only. The summary line names the database (schema,
  build time and checksum).
- `sentinel tools grype-db` fills that directory, and is the only step that uses the network. It runs the
  verified Grype with the same configuration, which pins the update URL (`https://grype.anchore.io/databases`):
  the latest database, or `--archive`, either a local file (Grype imports a private copy, digested first, with
  no network) or an `https://` URL that names its digest (`?checksum=sha256:<hex>`, checked by Grype; no
  credentials in the URL). The download sees the job's proxy and CA variables (`HTTPS_PROXY`, `NO_PROXY`,
  `SSL_CERT_FILE`, …) and nothing else of its environment. Whatever the update exits with, the result counts only
  if `grype db status`, run offline afterwards, calls the database valid; otherwise exit code `3` and no
  `--report`. The report records the Grype binary, the database (schema, build time, checksum) and a local
  archive's digest.
- Findings (category SCA): one per (vulnerability id, purl base). `rule_id` is Grype's id of the matched record
  (a GHSA for a language package), related CVE ids are in `cve`, other ids in `aliases`. Every file the package
  was found in is a place (`location`, then `other_locations`), relative to the repository root
  (`--repo-root`, or `--scan-root` for `normalize grype`). Severity is Grype's; Negligible counts as INFO and
  Unknown as HIGH, with the raw value in `severity_source`. The report's CVSS, EPSS and KEV are not copied:
  `sentinel enrich` adds them from the dated snapshot.
- Exit code `3`, with no findings file, when a tool fails or does not match the lock, the database is missing,
  invalid or stale, the report names another Grype version, or its recorded configuration shows anything that
  hides matches (ignore rules beyond Grype's built-in kernel-header rules, VEX, exclusions, `only-fixed`,
  `only-notfixed`, `ignore-wontfix`, a distro override, `by-cve`). An image report is refused by
  `normalize grype` (CONTAINER findings need the image digest: the image adapter).

**Registry mode.** With `--push`, `sentinel attest` also signs the image itself (`cosign sign`) and attaches
the four statements to it in its registry (`cosign attest`), always by digest. That copy is what Kyverno reads
at admission (A5). `sentinel verify` without `--evidence` reads it back:

```bash
uv run sentinel attest <registry>/demo-shop/shop-api@sha256:<digest> ... --out out/evidence --push
uv run sentinel verify <registry>/demo-shop/shop-api@sha256:<digest> --key cosign.pub \
  --repo NOURHANE-EHOUARI/sentinelci --builder-id <release workflow ref>
```

- The trust report gains a first check, `signature: the image itself`: a `cosign sign` statement about this
  digest. Cosign 3 stores every signature and attestation as a Sigstore bundle (an OCI referrer of the image),
  and `cosign verify` accepts any statement the key signed about the digest as a signature, an attestation
  included. So the check looks for a statement of type `https://sigstore.dev/cosign/sign/v1`.
- A re-run of the attest job, GitHub's "Re-run jobs" included, attaches the same statements again: the
  predicates read neither the clock nor the run attempt. Each still counts as one attestation. Two different
  statements of the same type are ambiguous, and that attestation fails.
- **One release per digest per registry.** Before signing anything, `attest --push` derives the public key
  (`cosign public-key`) and refuses (exit `3`, nothing signed) when the registry already holds a different
  statement of one of the four types, signed by the same key, about this digest. A second release would make
  `sentinel verify` refuse the image as ambiguous, while Kyverno, which reads one statement per type, could
  still admit it. Cosign skips a bundle it cannot fetch and then reports nothing attached, so the check also
  counts the bundles the `sha256-<hex>` tag index lists (with the pinned crane) and refuses when Cosign
  verified fewer: one could not be read, or another key signed it. A registry with the OCI referrers API is
  not counted (crane cannot list it). To release the digest again, remove the old release first: on a registry
  without the OCI referrers API, `crane delete <repository>:sha256-<hex>`.
- Trust is per digest; the repository name is informational. A plain copy of the image to another repository
  carries no attestation, but a copy that includes the `sha256-<hex>` index (`crane copy` of both, or
  `cosign save` / `cosign load`) is the same release, and is trusted there too.
- `--registry-http` allows plain HTTP for a local registry only: a loopback host (`localhost`, `127.0.0.1`),
  or a single-label host with a port (kind's `kind-registry:5000`). Any other host is refused (exit `3`),
  since the image and the registry credentials would cross the network in clear. A single-label name is still
  resolved through the machine's DNS search domains, so on a network that has one, `registry:5000` can reach a
  remote host: use such a name only where it names the local registry (kind's network). Registry credentials
  come only from `DOCKER_CONFIG` (the directory of a Docker `config.json`), when it is set; no other variable
  reaches Cosign.
- With `--push`, a registry failure while pushing is exit `3`, and no bundle is kept. The registry may then
  hold part of the set, which is not trusted. Re-running the same release completes it.
- An unavailable registry: when the connection is refused, `verify` reports every check failed (exit `1`).
  When the registry accepts the connection and never answers, Cosign's 120 s timeout ends the run (exit `3`).
  Both refuse the image.


## `sentinel sbom` (SBOMs, A4)

```bash
uv run sentinel sbom demo-shop --name demo-shop --cyclonedx out/sbom.cdx.json --spdx out/sbom.spdx.json
uv run sentinel sbom out/image-oci --source oci-dir --name demo-shop/shop-api \
  --image-digest "sha256:<manifest digest>" --cyclonedx out/image.cdx.json --spdx out/image.spdx.json
```

- The pinned Syft, verified against `tools.lock.toml` right before it runs, in a private working directory and home
  with `supplychain/configs/syft.yaml` passed explicitly: the target's `.syft.yaml` is never loaded, so the scanned
  repository cannot hide a package. Offline (no enrichment, remote license lookup, Go tooling or git clone; the
  proxy variables point at a closed port). No file catalog: the CycloneDX SBOM lists packages only, and the SPDX
  SBOM still lists the files each package owns or was found from (paths in the image or the tree, never the
  machine's).
- `--source`: `dir` (default; `--base-path` stops links above the tree), or the OCI image layout the build wrote,
  with one image manifest: `oci-dir` (a directory) or `oci-archive` (a tar of one). Never a registry pull.
  - An image needs `--image-digest`, its manifest digest, and both SBOMs must name it (CycloneDX
    `metadata.component.version`, the SPDX root package's `versionInfo`), or exit `3`.
  - A Docker archive is not accepted: Syft names it by a digest it computes itself, which no registry knows.
  - A plain `docker save` tar from Docker's containerd image store holds a nested index that Syft cannot read as
    an `oci-archive`. The release workflow (A4c) is to write the layout with BuildKit's OCI exporter.
- An SBOM is not reproducible: every run gets a new `serialNumber`, timestamp and SPDX namespace. Generate it
  once per build, and pass that same file to `sentinel evaluate --sbom` and to `sentinel attest`, which refuses
  an SBOM the decision did not record.
- Exit code `3`, with neither file written, when Syft fails (its own error message is the reason) or does not
  match the lock, or writes something other than a CycloneDX document with a `serialNumber` (what
  `sentinel attest` binds, ADR-0010) and an SPDX document. An output inside the target, a directory, the same
  file for both, or a path that cannot be cleared is refused before anything is written.
- The package count it prints leaves out the operating-system component Syft adds for an image.

## `sentinel upload` (findings to the platform, M1)

Sends one run's findings to the SentinelCI platform (the B1 ingestion API, `schemas/openapi.yaml`): first
`POST /api/v1/runs`, then the NDJSON exactly as the scan wrote it.

```bash
SENTINEL_API_TOKEN=... uv run sentinel upload --findings out/findings.ndjson --api-url http://localhost:8000 \
  --repo NOURHANE-EHOUARI/sentinelci --commit <sha> --context local
```

- **A report, never a decision.** It runs after the verdict and never changes it: exit `0` when the platform
  recorded exactly these findings (with `--resume`, also when it already had them), `4` when it did not. It
  never exits with the gate's codes, `1` or `3`, and never with a traceback: a malformed answer, an unusable
  URL or an unexpected error is exit `4` too, with one line that names no secret.
- **The token** comes only from `SENTINEL_API_TOKEN`. It is never an argument and is never printed, not even
  in an error: if the platform's answer quotes it back, the message shows `<SENTINEL_API_TOKEN>` instead. It
  must be visible ASCII (no space, line break or non-ASCII character). In CI the step runs only in a job that
  runs no repository code.
- **The URL** is `https://`, or `http://` on the loopback (`localhost`, `127.0.0.1`, `[::1]`). It is ASCII
  (an international host name in its `xn--` form) and holds no credentials, query, fragment, white space or
  control character. A redirect is refused, because it would
  carry the token elsewhere. Plain `http://` never goes through a proxy (`http_proxy` is ignored), since the
  proxy would see the token in clear text; `https://` goes through `HTTPS_PROXY`, which only sees a `CONNECT`.
- **Time limits:** 60 s for each network operation, and 120 s for each request as a whole, so a platform that
  answers one byte at a time cannot hold the step.
- **The findings are checked first**, as the API checks them: Finding v1, each id once, each about the run
  given by `--repo/--commit/--context` (and `--ref/--run-id` when the findings carry them). A bad file never
  leaves an empty run behind.
- **The platform's `findings_sha256`** must be the sha256 of the bytes sent.
- **Resuming.** Once the run exists, any failure names it, a lost or malformed answer included, and
  `--resume <run id>` finishes it without creating another (or confirms that the platform has these findings).
  A run that already holds other findings (another sha256 or another count) is refused, and so is a run about
  another repo, commit, context, ref or run id: the message names the fields that differ. When the findings are
  larger than the platform's upload limit, the message says so: `--resume` cannot help, and the run stays empty.
- **CI runs resume themselves.** With `--run-id`, the platform answers the same CI run again with 409 and the
  run it has (API 1.1.0), so the same command again finishes or confirms that run, with no `--resume`. The run
  id is free text: in GitHub Actions it is `<run id>/<run attempt>` (the scan's `--run-id` too, since the
  findings carry it), so a re-run of the job is a new run, as it is a new scan and a new decision. A run with no
  `--run-id` (a local run) is recorded anew each time.


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

## `sentinel remediate` (verified remediation loop, A6)

```bash
uv run sentinel remediate kubernetes --findings out/findings.ndjson --repo-root . --out out/proposal.json
uv run sentinel remediate apply --proposal out/proposal.json --findings out/base.ndjson --repo-root .
uv run sentinel remediate check --proposal out/proposal.json --base-root out/base --patched-root out/patched
uv run sentinel remediate verify --proposal out/proposal.json --before out/base.ndjson \
  --after out/patched.ndjson --decision out/patched-decision.json --tool-status out/patched-tool-status.json \
  --build-ok --tests-ok --out out/result.json
```

- `kubernetes` proposes (`schemas/patch-proposal.v1.json`), it never applies. It hardens the workloads of the
  manifests that Trivy flagged, for the rule ids it knows (each edit checked against the pinned Trivy), and
  leaves alone what the fix would have to choose for the application (hostPath volumes, image tags, resource
  limits, added capabilities). Comments, key order and quoting are kept, and so are `---` / `...` markers; a
  file it cannot edit without reformatting, with CRLF line endings, or with a workload kind it does not edit
  is named in a warning and left alone. With nothing to fix, it writes no file and exits `0`.
  - **It can change how a workload runs**: a non-root UID/GID (10001; a UID or GID above 10000 is kept), a
    read-only root file system and dropped capabilities can stop a workload that writes into its image, owns
    files by another UID or needs a capability. The proposal's rationale says so. `--build-ok` and
    `--tests-ok` come from the build and unit tests, which do not run the workload: there is no cluster
    deploy test yet.
- `dockerfile` does the same for Dockerfiles:
  - **USER.** `USER 10001:10001` is added to the final stage after its last RUN and USER, before the next
    CMD/ENTRYPOINT or at the end, so every RUN still runs as the user it ran as. A USER line is never
    rewritten. The final stage is the last FROM: an image built with `--target` an earlier stage is not
    changed (Trivy checks the last stage too).
  - **ADD → COPY**, only when ADD would do nothing more. ADD unpacks a local tar by its content, so every
    source must be in the repository (next to the Dockerfile, then at the root) and be a directory or a plain
    file that is neither a tar nor compressed. A URL, a git source, a glob, a variable, a missing source or an
    ADD-only flag keeps ADD (COPY's `--chown`, `--chmod`, `--link` and `--exclude` are fine). A zip is copied:
    ADD never unpacks one.
  - **apt-get.** `apt-get install` gets `--no-install-recommends`.
  - **What it leaves alone.** An instruction that carries a finding the edit does not resolve is not edited:
    Trivy names a Dockerfile finding by its instruction's text, so the other finding would get a new
    fingerprint. Only the findings an edit resolved are claimed; a file where nothing could be resolved is
    reported as "nothing this fixer can resolve". The base image's tag or digest, a HEALTHCHECK and a script
    piped to a shell are left alone too, and so is a file with an `escape` directive, a heredoc or CRLF line
    endings.
  - **It can change what the image does**: files it writes at run time must be writable by UID 10001, and an
    image that needs root at run time breaks. The rationale says so.
- `apply` turns a proposal into one commit on a new `sentinel/fix/<id>` branch of a local clone, and prints
  the branch, the commit, the base and the diff's sha256 as JSON. The bot's workflow pushes it and opens the
  pull request.
  - **What it never does:** push, or change the working tree, the index or the current branch. Nothing is
    checked out: the commit is built on a temporary index with plumbing commands (`read-tree`,
    `apply --cached`, `write-tree`, `commit-tree`, `update-ref`), so no smudge or clean filter, fsmonitor or
    hook the clone configures can run. What in the clone's `.git/config` could run code is overridden on the
    command line (`core.hooksPath`, `core.fsmonitor`, `commit.gpgsign`), and so are line-ending and white-space
    rewrites (`core.autocrlf`, `apply.whitespace`), so the commit is exactly base + diff; the user's and system
    configuration are not read, nor are the caller's `GIT_*` variables.
  - **What it checks first:** the proposal id is recomputed from its strategy, attempt, findings and diff, so
    the branch name and the trailers identify the content. The id covers those four only, not `created_at` or
    the rationale (the commit date and message): a second proposal with the same id is refused anyway, because
    its branch already exists. Every finding it claims must be in `--findings`
    (the base scan), and every file it changes must be where one of them was found. The diff changes exactly
    the files the proposal lists, each a regular file at the base. It creates, deletes, renames or makes
    executable no file, and does not retarget a symbolic link (git applies a new link target as an in-place
    edit, so the file mode at the base is what tells them apart). The diff must apply to the base.
  - **The commit** carries `Sentinel-Proposal`, `Sentinel-Strategy`, `Sentinel-Diff: sha256:<hex>` and one
    `Sentinel-Finding` trailer per finding. Its dates are the proposal's `created_at`, so the same proposal on
    the same base is the same commit.
  - **Ownership:** git's `safe.directory` comes from the user's configuration, which is not read. A clone owned
    by another user (a container job on a runner) is refused as "dubious ownership": exit `3`, fail closed.
  - A branch exists once per proposal. Exit `3`, with nothing created, otherwise.
- `verify` writes a `VerificationResult` (`schemas/verification-result.v1.json`): VERIFIED only if the patched
  commit builds, its tests pass, every target is gone, no new finding of severity MEDIUM or higher appeared,
  and its decision is not BLOCK. Exit `0` VERIFIED, `1` REJECTED (a retry is left) or FAILED (the third
  attempt), `3` when an input cannot be trusted (nothing is written). In detail:
  - a target is gone when its fingerprint is gone and no new fingerprint of the same tool and rule appears in
    its file (a renamed container moves a finding, it does not fix it); a base finding that rises to MEDIUM or
    higher counts as new;
  - exit `3` for a proposal whose id does not match its content, that claims findings `--before` does not
    have, or whose diff does anything but edit, in place, the files those findings are in. Each hunk is read
    to its line counts, as git reads it: a `---`/`+++` pair after the last hunk (which git applies as one more
    file) is refused;
  - exit `3` for a decision not made on `--after` (`inputs.findings_digest`), not in pr context, or without the
    tool status; for a `--tool-status` that is not the one the decision recorded, or that does not show the
    scanner of every target `ok`: a scan that failed, was skipped or never ran must not vouch for the patch;
  - `--out` can never be one of the inputs.
- `check` builds and tests an infrastructure-as-code proposal for `verify`, on the trees of the base and the
  patched commit (exported with `git archive`, never checked out), and prints `{proposal_id, strategy,
  build_ok, tests_ok, problems}`. A manifest or a Dockerfile has no compiler or unit test of its own, so:
  - **build**: every edited file still parses as what it was, into the same resources. A manifest keeps its
    documents, each with the same apiVersion, kind, name and namespace; a Dockerfile keeps its stages (the same
    FROM lines) and holds only Dockerfile instructions. A scanner reports nothing in a file it cannot parse,
    so without this a broken file would make its findings "gone";
  - **tests**: the patch changes only what its strategy may change. A manifest read as data is the same once
    the pod's and every container's `securityContext` and the pod's host namespaces are set aside; a Dockerfile
    is the same line for line once its added `USER 10001:10001` lines are skipped (each an instruction of its
    own after the final stage's last RUN), except ADD → COPY and an added `--no-install-recommends`. Whether
    the new settings are right is the scanners' part: a weaker one is a new finding;
  - manifests are read with a safe loader that refuses aliases and duplicate keys;
  - exit `0` when both hold, `1` when one does not (the problems name the file and why), `3` when they cannot
    be checked honestly: a strategy with no build or tests defined here (an LLM code fix, B6), a file that is
    not a regular file of both trees, a base file this check cannot read.

The bot (`.github/workflows/sentinel-remediate.yml`, ADR-0013) chains them: `propose` (read-only) scans, runs
the fixers and `apply`; `publish` (no repository code) pushes each branch and opens its pull request; `verify`
(read-only, the scanned commit's pipeline) rebuilds each pull request's commit, scans both commits with the
scanners the pr gate requires, runs `check`, the gate in pr context and `verify`; `report` (no repository code)
comments each result and sets the `sentinelci/remediation` commit status.

## `sentinel admission-policy` (Kyverno admission of releases, A5)

Writes the Kyverno `ImageValidatingPolicy` (`policies.kyverno.io/v1`, Kyverno 1.19) that admits a Pod only if
every image matching the glob is a release `sentinel verify` would trust. It takes the same parameters as
`sentinel verify`:

```bash
uv run sentinel admission-policy --key cosign.pub --repo NOURHANE-EHOUARI/sentinelci \
  --builder-id <release workflow ref> --image-glob kind-registry:5000/demo-shop/* \
  --registry-http --out deploy/kyverno/release-evidence.yaml
```

- **What it requires**, checked in this order (the first that fails is the reason given):
  - the image signature (`cosign sign`) and the four attestations, each signed by the key;
  - a release decision with a non-BLOCK Decision v1 verdict (`PASS` or `WARN`, a `schema_version` of the
    Decision v1 contract, rendered from it, and no violation other than `WARN`), about this digest, from
    `--repo`;
  - provenance from `--builder-id`, built from the decision's commit (every source of the repository);
  - a vulnerability result naming the decision, its findings and its SBOM;
  - that SBOM, a CycloneDX document with the `serialNumber` the result names.
- **Why the signature is required as an attestation.** `verifyImageSignatures` accepts any statement the key
  signed about the digest, an attestation included (see registry mode above). So the policy requires a
  statement of type `https://sigstore.dev/cosign/sign/v1`.
- **Which images.** `--image-glob` is `<registry>/<path>*`, with one trailing `*`. It is matched as a prefix of
  the lower-cased image reference, because registry host names ignore case: `LOCALHOST:5000/...` is checked
  too. With `--registry-http`, the registry must be local (a loopback host, or a single-label host with a port
  such as `kind-registry:5000`), as for `sentinel verify`.
- **Digests.** An image without a digest is refused (`verifyDigest`). In a cluster, `mutateDigest` first pins
  a tag to the digest it resolves to.
- **Scope.** Pod creation and updates, with Kyverno's autogen, so a Deployment, Job or CronJob with a refused
  image is refused itself when applied; and, in a second document, the `pods/ephemeralcontainers` subresource
  that `kubectl debug` uses. Every container is checked, init and ephemeral too. An image outside the glob is
  not this policy's business: restricting which registries may run at all is a separate policy. Kyverno's
  default install excludes `kube-system` and its own namespace (`resourceFilters` and the webhook
  `namespaceSelector`). Whoever can create Pods there is out of scope until the cluster install (A5b) narrows
  that.
- **Timeout.** Each admission makes five registry verifications. The webhook timeout is set to the API
  server's maximum (30 s), and a timeout denies (`failurePolicy: Fail`).
- **The key file** must hold exactly one PEM public key and nothing else. The policy is committed, so a private
  key next to the public one would be committed with it. `--out` can never be the key file.
- **Where it is weaker than `sentinel verify`.** Admission refuses every case the tests cover, and `sentinel
  verify` refuses them too. But CEL reads one statement per type (`extractPayload`) and checks fields, so it
  does not check:
  - the full Decision v1 schema, beyond the verdict, the version and the violations;
  - the vulnerability result's schema and its totals;
  - a second, different statement of the same type, which `sentinel verify` refuses as ambiguous.
    `sentinel attest --push` refuses to attach a second release of a digest; someone holding the key could
    still attach one with Cosign directly (ADR-0010 decision 4).
- **Keys.** Private mode only: a key pair. The keyless attestor (GitHub mode) comes with keyless
  `sentinel verify`, after the repository goes public.
- **Values are checked before they are written** (exit `3`, nothing written): they end up in YAML and in CEL
  string literals.
- **Tests.** `kyverno apply` (pinned in `tools.lock.toml`) evaluates the policy as the admission controller
  does, against a real registry. Every case `sentinel verify` refuses there, admission refuses too (the tests
  compare the two verdicts, not the reasons).
