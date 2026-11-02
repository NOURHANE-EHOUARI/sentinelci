# demo-shop ground truth

`findings.yaml` lists every seeded weakness of `demo-shop/` (the **seeds**) and every file that looks risky but
is safe (the **controls**). The evaluation harness (B8) compares scanner and gate output with it: recall per
category, false positives on controls, and later ranking (NDCG) and correlation (ARI).

> Format status: **draft v1**, proposed with the first Track A seeds (A9). The schema is owned by B9 and may
> change. When it settles, it moves to `schemas/ground-truth.v1.json` with fixtures, like every contract.

## Format

```yaml
version: 1
seeds:
  - id: GT-SECRET-001             # GT-<CATEGORY>-<NNN>, unique; CANARY for prompt-injection canaries (B9)
    owner: A9                     # A9 (infra, deps, secrets) or B9 (application code, canaries)
    category: SECRET              # a Finding v1 category (schemas/finding.v1.json)
    title: GitHub token in the shop-api settings
    location: {path: services/shop-api/config/settings.yaml, line: 8}   # relative to demo-shop/
    fake: true                    # required for SECRET: every secret is fake and says so in the file
    expected:
      gate: SC-001                # the gate rule this seed should trigger, when one applies
      detections:                 # detections verified with the pinned tools
        - {tool: gitleaks, rule: github-pat}
  - id: GT-IAC-004
    # ...
    known_miss: >-                # required when expected.detections is empty, forbidden otherwise: which
      Trivy 0.76.1 does not ...   # pinned tool and version misses the seed, the forms tried, and why
    expected:
      detections: []
controls:
  - id: GT-CLEAN-001
    owner: A9
    category: SECRET
    title: Settings template with environment placeholders
    location: {path: services/shop-api/config/settings.example.yaml}
    must_not_detect: [gitleaks]   # any finding by these tools in this file is a false positive
```

Matching rules for the harness:

- A seed is **detected** when any listed `(tool, rule)` reports it in the seed's file. Secrets also match on
  the line, because Gitleaks reports exact lines. Other tools point at different lines for the same resource:
  Trivy at the attribute.
- Other findings in a seeded file are real but unlisted issues. They count neither as hits nor as false
  positives. Only controls measure false positives.
- Every seeded file names its ground-truth id in a comment, so a reader of the file knows it is deliberate.
  For npm, where JSON has no comments, `package.json` names them in its `description`.
- An SCA seed is detected when the tool reports its `vulnerability` on its `package` (the purl), wherever the
  tool locates it: Grype points at the lockfile (`package-lock.json`), the seed at the manifest line that
  declares the dependency, where a developer would fix it.
- A seed with `known_miss` can't be detected. The evaluation counts it as a false negative in its category's
  recall: it stays in the denominator, and the report lists it with its reason. It is never excluded or
  reweighted.
- When the still-missed check fails, record the detection in `expected.detections` and remove `known_miss`.
  Never change the seed, the check or the scanner configuration to keep it missed.

SCA seeds carry four more fields:

```yaml
    package: pkg:pypi/lxml@4.6.2          # the purl Syft catalogs
    vulnerability: GHSA-jq4v-f5q6-mjqq    # the id Grype reports
    cve: CVE-2021-28957                   # its CVE alias: the key of the enrichment snapshot
    kev: false                            # listed in CISA KEV (from the feed fixtures)
    imported: false                       # optional: first-party code imports it (true) or never does (false)
```

The SCA seeds are the seven packages of the offline feed fixtures (`eval/feeds/`) and `lodash-es`, which
lodash's advisory also names, so enrichment, scoring and the gate run on them with no network. Their `expected.gate` is what the engine gives with those fixtures and
no `sentinel.yaml` (an unknown exposure counts as internet-facing): it changes with the service context, the
risk model or the policies, and the checks below say so when it does. `imported: false` marks a dependency the
service declares and never imports (B9's code must keep it that way). `imported: true` is added once B9's
code imports the package.

Fields planned for later tasks, optional today: `relevance` (0–3, for NDCG@10 against the CVSS baseline) and
`group` (shared root cause, for ARI).

## Checks

`tests/demo_shop/test_ground_truth.py` keeps this file honest:

- structure: unique ids, existing paths and lines, fake secrets, and the ids present in the seeded files;
- zizmor on every CI example;
- the pinned Gitleaks and Trivy with SentinelCI's own configuration, when `SENTINEL_TOOLS_DIR` is set.

Gitleaks must report exactly the secret seeds: 5 out of 5, and nothing on the controls. A seed that no pinned
tool detects has `detections: []` and a `known_miss` saying why (GT-IAC-004, ADR-0012). It counts as a miss in
the evaluation. The Trivy test checks, seed by seed, that it is still missed: any Trivy finding in its file
fails the test and names the rules, so a tool upgrade that catches it shows up. Only IaC seeds can be known
misses for now; another category gets the same check with its first one.

`tests/demo_shop/test_sca_seeds.py` keeps the SCA seeds honest:

- always: each manifest declares the seeded version at the seed's line (and the npm lockfile pins it); each
  seed is a case of the feed fixtures, and the recorded OSV advisory of its id lists that version as affected;
  enrichment gives it its CVSS, EPSS and KEV status offline; the reachability analysis (B2) agrees with
  `imported`; with OPA, the engine gives each seed its `expected.gate`;
- with `SENTINEL_TOOLS_DIR`: the pinned Syft catalogs each seed's purl from its service;
- with `SENTINEL_GRYPE_DB_DIR` as well: the pinned Grype, on that SBOM, reports each seed's id, as the
  pipeline runs it. Grype needs its vulnerability database, which the test never downloads:

```bash
mkdir -p /tmp/grype-db
GRYPE_DB_CACHE_DIR=/tmp/grype-db <tools>/bin/grype db update
SENTINEL_TOOLS_DIR=<tools> SENTINEL_GRYPE_DB_DIR=/tmp/grype-db uv run pytest tests/demo_shop/test_sca_seeds.py
```
