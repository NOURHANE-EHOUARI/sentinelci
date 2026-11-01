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
  Trivy at the attribute, Checkov at the block.
- Other findings in a seeded file are real but unlisted issues. They count neither as hits nor as false
  positives. Only controls measure false positives.
- Every seeded file names its ground-truth id in a comment, so a reader of the file knows it is deliberate.

Fields planned for later tasks, optional today: `relevance` (0–3, for NDCG@10 against the CVSS baseline),
`group` (shared root cause, for ARI), and for SCA `package` (purl), `vulnerability`, `kev`, `imported`.

## Checks

`tests/demo_shop/test_ground_truth.py` keeps this file honest:

- structure: unique ids, existing paths and lines, fake secrets, and the ids present in the seeded files;
- zizmor on every CI example;
- the pinned Gitleaks and Trivy with SentinelCI's own configuration, when `SENTINEL_TOOLS_DIR` is set.

Gitleaks must report exactly the secret seeds: 5 out of 5, and nothing on the controls. Checkov detections
were verified with Checkov 3.4.0. They are checked automatically once its adapter is pinned (A1).
