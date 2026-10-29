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
- `--record DIR` saves every response; `--offline DIR` answers from those files only (a request never recorded
  counts as an outage). This gives the offline fixtures for demos, evaluation and tests.

## `sentinel enrich` (enrichment, B2)

```bash
uv run sentinel enrich --findings out/findings.ndjson --snapshot out/enrichment-snapshot.json \
  --config sentinel.yaml --out out/findings.enriched.ndjson
```

- Offline: applies an enrichment snapshot (`schemas/enrichment-snapshot.v1.json`) and the service context
  (`sentinel.yaml`, `schemas/sentinel-config.v1.json`) to findings. Pass the same snapshot to
  `sentinel evaluate --enrichment-snapshot` so the decision records its digest.
- Package findings (SCA, CONTAINER): `cvss` and `epss` (highest among the finding's ids and their aliases), `kev`
  (only when the KEV feed was read), `fix_available` (true from the finding or OSV, false only when OSV knew the
  vulnerability and fixes none of the package). Every finding: `exposure` of its `sentinel.yaml` component
  (longest matching path), else the top-level exposure.
- Unknown stays absent; the risk engine treats absent as the worst case. Without `--snapshot` or `--config`,
  nothing from that source is added.
- Read `sentinel.yaml` from the base branch in PR mode: a change must not lower its own exposure.
- Fail closed: an invalid snapshot, `sentinel.yaml` or findings file writes nothing and exits 3.

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
- OPA is a pinned binary (version and SHA-256 in `.github/workflows/ci.yml`): pass `--opa`, set
  `SENTINEL_OPA`, or put `opa` on `PATH`.
- `--evaluated-at` (RFC 3339, default now) is the only time the policy sees, so a decision can be replayed.
  Same inputs give a byte-identical file, including `decision_id`, which is a UUIDv5 of the subject,
  time, input digests and engine version.
- Recorded evidence: digests of the findings file, policy bundle (all files in `policies/` except
  `*_test.rego`), waivers file as read (empty content when there is none), enrichment snapshot (the empty
  snapshot `{}` until B2 lands) and optional SBOM; the risk
  model version; versions of every tool that reported a finding, given with `--tool-version`, and OPA.
- Rules implemented so far: SC-001 (secret, not waived), SC-005 (invalid waiver) and SC-010 for
  malformed gate input.

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
