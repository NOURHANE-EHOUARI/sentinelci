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
- `kev: {listed: false}` only for CVEs the snapshot's KEV lookup covered (`sources.kev.cves`); otherwise KEV
  stays unknown. Package URLs are compared in canonical form (PyPI names per PEP 503).
- `sentinel.yaml` is read with a restricted YAML loader: no duplicate keys, anchors, aliases, dates, binary or
  set values; at most 64 KiB. Component paths must be canonical (`services/web`, not `./services/web/`) and
  unique.
- Fail closed: an invalid snapshot, `sentinel.yaml` or findings file (including enrichment outside the Finding
  contract), or `--out` naming the input or a directory, writes nothing and exits 3. `sentinel evaluate`
  refuses an `--enrichment-snapshot` that is not a valid snapshot; with none, both commands use the same empty
  snapshot, so "no snapshot" has a single digest.

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
  `--store` keeps it for replay. An invalid file is never recorded (exit 3).
- Required scanners (`policies/required_tools.rego`, part of the policy bundle, so read from the base branch):
  gitleaks in `pr` and `release`, none in `local`. A required tool left out of the tool status, or no tool
  status at all in a context that requires tools, is an SC-010 BLOCK (`Scanner missing` /
  `Tool status missing`): a workflow that drops a scanner cannot turn its silence into a pass.
- The decision is `schema_version` 1.2 (with `baseline_digest` / `tool_status_digest`) when either option is
  given, 1.1 otherwise.
- Rules implemented so far: SC-001 (secret introduced by the change, not waived), SC-005 (invalid waiver) and
  SC-010 (scanner failure, malformed gate input).

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
