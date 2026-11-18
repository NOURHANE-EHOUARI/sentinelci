# Correlation measurement (A7)

`make eval-correlation` measures the correlator (`sentinel_ai.correlate`, SPEC section 8) on the findings of a
`make eval` run, against true root causes. It reports the ARI, the alert reduction and the ablation
(each configuration of the stages) that SPEC section 17 asks for, in `out/eval/correlation.json` and
`correlation.md`. The same inputs give the same report, byte for byte; every input is named by its sha256.

## The labels

- A finding that detects a seed (`eval/detection/score.py`, B8's matching rules) has the seed's root cause.
- Every other finding of `make eval` is labelled in [`root-causes.yaml`](root-causes.yaml) with **what one fix
  resolves**: the twelve Trivy findings of shop-api's missing security context are one root cause (one
  block), the four of its missing resources another. A root cause can join a seed when the same edit fixes
  both (the hostPath volume of GT-IAC-005, the public access block of GT-IAC-001).
- An SCA finding about a package that a seed detects in the same manifest has that seed's root cause too: one
  upgrade fixes every advisory of the package. Grype reports several advisories per seeded package, and
  `root-causes.yaml`'s matchers (tool, file, rule) cannot tell lodash from lodash-es in one lock file, so this
  rule is in `run.py`. lodash and lodash-es stay two root causes (two upgrades).
- A finding no label covers stays in the run but out of the ARI, and is counted (`labelled` in the report).

The labels were written from each finding's tool, file and rule, before the embedding stage ever ran on
them, and are never changed to improve a score. **Two exceptions, said here:**
- The SCA package rule and RC-DOCKER-002 (the release Dockerfile's missing HEALTHCHECK, which had been missed)
  were added in the review of #90, after the dedup and structural scores had been seen and before any
  embedding score. Without them, the structural stage's right merges (one package's advisories) were all
  unlabelled, so its ARI could only see its wrong ones.
- **The half rule changed after the first measurement (SPEC 1.1.98), with A9b (SPEC 1.1.130).** Its two new
  Dockerfiles' DS-0026 findings are RC-DOCKER-003 and -004, labelled like RC-DOCKER-001 and -002 and written
  before any correlation score on these findings (no threshold can run on this ground truth until the
  recalibration). Under the rule as it stood ("in this file's order"), `services/reports/Dockerfile` sorts
  before `services/shop-api/`: RC-DOCKER-003 would take calibration, and RC-DOCKER-001 and -002 would swap
  halves. The `appended: true` clause, added then, puts root causes added after the first measurement last
  instead, so the measured split stays as it was; `tests/eval/test_correlation.py` enforces it.

**Alert reduction moves with A9b, with no change to the correlator.** `requirements.block.txt` now pins
requests 2.30.0 as well as pyyaml 5.3.1 (GT-CONTAINER-002), so Grype reports each of requests' four advisories
in two manifests: one finding each, with a second place in `other_locations` (pyyaml already had two). That
adds 4 places and no group, so `1 - groups / places` rises: on a `make eval` of 17 November, without stage 2b,
the whole run's dedup+structural reduction goes from 25.5% to 28.0% and the test half's from 39.5% to 43.8%
(dedup only: 0.0% to 8.3%), while the ARI moves by less than 0.001 (Hiba's review of #161). A comparison
across that change compares different inputs, not two correlators.

## What each number can see

The report gives, next to each ARI, how many findings are labelled, with how many root causes, and how many
pairs of findings share one: with few same-root pairs, an ARI mostly measures whether those few merge. It
also gives the ARI without SCA, where the truth ("one upgrade") is stage 2a's own package key, so that SCA
does not hide the other categories. And it measures the stages that have no parameter to tune (dedup,
structural) on the **whole run**: the halves split root causes, not findings, so the test half's share of the
findings and of the SCA ones is whatever the split gives (a seeded package brings all its advisories, eight
for GT-SCA-006 alone), and its alert reduction is not demo-shop's. The report counts both shares, and SPEC
section 3's 40 % is read on the whole run.

## No tuning on the test set

The root causes are split once into a calibration half and a test half: [`split.yaml`](split.yaml) for the
seeds (in each category, sorted by id, alternating; a test checks the file follows that rule), `half` in
`root-causes.yaml` for the others (a joined seed's half, else alternating in file order). Each half is the run without the other half's labelled
findings.

1. **Calibrate** on the calibration half, with the pinned embedding model (ADR-0009) on a local Ollama:

   ```bash
   ollama pull qwen3-embedding:0.6b        # its digest must be ADR-0009's
   make eval DB_DIR=...                    # out/eval/findings/: every scanner must have run
   make eval-correlation-calibrate         # writes eval/correlation/threshold.json
   ```

   A `make eval` in which a scanner failed or was skipped (no `<tool>.ndjson`, SCA without `DB_DIR`) is
   refused: the correlation is measured on every scanner's findings or not at all. It picks the stage 2b
   threshold with the best ARI (a tie goes to the highest, which merges least) and
   records the model and its digest, the inputs, and whether the threshold is at the edge of the grid (0.5
   to 0.95: then the best ARI may lie outside it, and the report says so; the grid is never widened after
   the test half is seen). **Commit `threshold.json` before measuring the test half.**

2. **Measure** the test half with the committed threshold: `make eval-correlation`. A threshold calibrated
   with another model or digest is refused, and so is one calibrated on other halves: another ground truth,
   split or root causes moves findings between them, so after a label edit, calibrate again. A threshold
   that is not what `--calibrate` wrote is refused too: its own curve must be on today's grid, and the
   threshold must be that curve's best ARI (a tie going to the highest), with the ARI and the edge it
   recorded, so a hand edit of the file cannot move it. Findings of
   another `make eval` run (a new Grype database, say) give another calibration half but leak nothing of
   the test half: the report says "of another `make eval` run". So does a threshold calibrated with another
   correlator version (`threshold.json` records it): stage 2b embeds that version's texts, and the report
   says "with correlator X, not Y". The ARI-vs-threshold curve on the test half is reported as sensitivity
   only.

Without Ollama, or with `--no-embedding`, the stages without a model (dedup, structural) are still measured
and the others say why they were not.

## What the numbers mean

- **ARI** (adjusted Rand index): 1 when the groups are exactly the true root causes, about 0 for a random
  grouping. Keeping four findings of one root cause apart scores 0 as surely as merging two root causes.
- **Alert reduction**: `1 - groups / places`, where the places are what the tools reported: each finding and
  each of its `other_locations` (the normalizer merges one tool's places of one risk). SPEC section 3 targets
  40% or more.
