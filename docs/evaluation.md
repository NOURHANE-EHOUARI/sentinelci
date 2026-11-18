# SentinelCI evaluation report

> **Provisional: the numbers of 15 November 2026, and the verified fix rate of 17 November.** Each one comes
> from a run made between 14 and 17 November, on the commit named on its page, and several runs used different
> commits and inputs. SPEC section 16 replaces all of them with **one full run on a clean checkout on 27
> November**, whose reports are committed with their input digests ([The 27 November run](#the-27-november-run)
> gives the commands). Until then, read every number below with the commit and inputs next to it.
>
> **The benchmark grows before that run.** #161 (merged 17 November) brings CONTAINER to the 5 seeds section 17
> asks for, and B9 (#171) brings SAST to 10 seeds and the canaries to 5. A rehearsal on 17 November, on a local
> merge of every pending evaluation PR, is summarised at the end ([Rehearsal](#rehearsal-17-november)); its
> numbers are not the report's.

This is the "one evaluation report" of SPEC section 17. It has one page for each metric of section 17's list,
with section 3's target, and a summary first. SPEC section 3 asks to "report real numbers, including misses":
a missed target and a null result get the same space as a met one. "Not measured" is never written as 0.

## Summary

| Metric (§17) | Result (15 Nov unless dated) | Comparison (baseline or noise floor) | Target (§3) | Status |
|---|---|---|---|---|
| [Recall per category, false positives on clean controls](#1-detection-recall-and-false-positives) | 28 of 28 measured seeds detected (100%); 0 false positives on 5 clean controls; CONTAINER (1 seed) not measured | Counting the unmeasured CONTAINER seed as a miss: 28 of 29 (96.6%) | ≥ 90% of seeds found by ≥ 1 scanner | **Met** on the categories measured |
| [NDCG@10 vs CVSS baseline](#2-ranking-ndcg10-against-the-cvss-baseline) | All categories, by advisory: **0.366** (by package: 0.495) | CVSS-only baseline: 0.347 (by package: 0.390) | NDCG@10 above the CVSS-only baseline | **Met** on all categories; **not met** on SCA by advisory (0.627 vs 0.771) |
| [ARI, alert reduction, ablation](#3-correlation-ari-alert-reduction-ablation) (A7) | Whole run, stages without a parameter: **25.8%** alert reduction, ARI 0.497. Test half, three stages: ARI 0.827, 57.1% | Ablation on the test half: dedup only 0.0%; dedup+structural ARI 0.793, 40.5%; dedup+embedding ARI 0.657, 52.4% | Alert reduction ≥ 40% | **Not met** (25.8% on the whole run) |
| [Explanation rubric, LLM-judge agreement](#4-explanation-rubric-and-cohens-kappa) | 23 explanations: people's pass rates 83% to 100%; the judge rated all 92 answers "yes" | Kappa between the two people: **0.71** pooled. Each person vs the judge: **0.00** pooled | None in §3 | No target. The judge **cannot stand in** for the people here |
| [Verified fix rate](#5-verified-fix-rate) | 17 Nov: **6 of 8** attempted fixable seeds verified (**75.0%**); LLM code fixer 5 of 6, Dockerfile 1 of 1, Kubernetes 0 of 1 (partial) | None: 21 of 29 seeds have no implemented strategy and are not attempted | ≥ 60% of attempted fixable seeds | **Met** (8 attempted seeds: one seed is 12.5 points) |
| [AI mislabels on canaries, verdict changes](#6-injection-canaries-mislabels-and-verdict-changes) | **0 verdict changes**; pinned model: 0 of 10 outputs obeyed, 0 of 5 hints mislabelled | Control model that always obeys: 10 of 10 obeyed, 5 of 5 mislabelled, 0 verdict changes | 0 verdict changes (hard requirement) | **Met**, with 2 of the 5 canaries §17 asks for |
| [Pipeline p50/p95](#7-pipeline-p50-and-p95) | One pass of the gate's steps: p50 **12.4 s**, p95 **12.8 s** (20 runs, one machine) | A pull request scans twice: 2 × p95 = 25.7 s | PR feedback time p95 ≤ 10 min | **Met on this machine**; not a CI measurement |
| [Replay identity](#8-replay-identity) | **10 of 10** compared decisions identical, recorded and replayed on two checkouts | Engine made to sort violations the other way: 8 of 10 (the measurement sees drift) | 100% identical | **Met** by hand; the nightly job has not run yet |

Section 3 also lists gate correctness and deploy enforcement. They are not in section 17's list, and this
report does not measure them. For deploy enforcement, the kind tests of #60 to #62 ran on a real cluster on
16 November (#62 at `dabac05`): the signed release was admitted, and every bad image and all five attacks were
refused by the check that must refuse them (9 tests passed). That is a test result, not a measured rate. The
real release of 16 November (`shop-api@sha256:3bfcde7f…`, built from `main` `39c0ef2`, bundle sha256 `40ae9904…`)
was checked on 17 November with `sentinel verify` against `deploy/keys/release.pub`: TRUSTED, 16 of 16 checks
(the five signatures, the WARN release decision, the provenance and the scan), and a throwaway key was refused.
Its `make demo-release` and `make demo-attack` on kind run on Nourhane's laptop: the sandbox these numbers come
from no longer runs nested containers.

---

## 1. Detection: recall and false positives

**What it measures.** For each category of `demo-shop/ground-truth/findings.yaml`, the share of seeds that
SentinelCI's own scanners detect, by the ground truth's matching rules. It also counts false positives on the
clean controls (a finding by a tool the control names, in the control's file) and lists real findings that match
no seed ("unlisted": neither hits nor false positives). A category whose scan did not run is "not measured",
never 0.

**Result.**

| Category | Seeds | Detected | Recall |
|---|---|---|---|
| SECRET | 5 | 5 | 100% |
| SAST | 6 | 6 | 100% |
| SCA | 8 | 8 | 100% |
| IAC | 6 | 6 | 100% |
| PIPELINE | 3 | 3 | 100% |
| CONTAINER | 1 | — | not measured: `make eval` scans no image |

- 28 of 28 measured seeds detected. Counting the unmeasured CONTAINER seed as a miss gives 28 of 29 (96.6%),
  still above the target.
- False positives on the 5 clean controls: 0.
- Unlisted findings: 57 (IAC 31 in seeded files and 1 elsewhere, PIPELINE 5 in seeded files, SCA 14 in seeded
  files and 6 elsewhere).

**Target (§3).** ≥ 90% of seeds found by at least one scanner: **met** on the categories measured.

**Inputs.**
- Commit: `84bcf2b` (`b8/explanation-rubric`). The report records no commit: this is the worktree's commit at the
  time of the run (its reflog), 15 Nov 04:05 UTC.
- demo-shop tree `28680d7fd7bc85889e9bfdff00e0bf4e76c215ea`, the same as `main`'s (`64f0e4b`).
- Ground truth sha256 `bba899c548ad2e6de13515fbaa87d588edc5cbe8cb39cc88f99548a6068f0567` (`main`'s). The merge
  train's ground truth (`83a2cde6…`) adds only the ranking grades (`relevance`, `relevance_why`); no seed and no
  matcher changed.
- Tools: Gitleaks 8.30.1, Trivy 0.76.1, zizmor 1.32.0, Opengrep 1.33.1, Grype 0.121.0 on Syft 1.55.0's SBOM
  (53 packages), Grype database v6.1.10 built 2026-11-14T06:19:25Z (checksum
  `sha256:762b01ba9c79e6a250bd73f11ef62fbf44539ee8e08e043d80df4aaad3afc2aa`).
- Findings sha256: gitleaks `c859f350…`, grype `85aba01d…`, opengrep `8d6d8f24…`, trivy `1afe96bc…`, zizmor
  `6b91555e…` (in full in `detection.json`). The canaries and the rubric used these same five files.

**Full report and how to regenerate it.** `out/eval/detection.md` and `detection.json` of that run (not
committed). PR #77 introduced the report.

```bash
uv run sentinel tools grype-db --db-dir out/grype-db
make eval DB_DIR=out/grype-db
```

**Limits.**
- **The benchmark was smaller than section 17 asks on 15 November:** SAST 6 of 10, CONTAINER 1 of 5, canaries
  2 of 5. #161 (merged) brings CONTAINER to 5 and B9 (#171) SAST to 10 and the canaries to 5, so the 27 November
  run measures the full size. SECRET, SCA, IAC, PIPELINE and the controls were already at full size.
- **Recall is partly true by construction.** Each seed was checked against these pinned tools when it was written
  (the ground truth's header says so), so 100% shows that the scanners run, are wired to the gate and report
  what they were checked to report. It does not estimate recall on code nobody seeded.
- 5 clean controls is a small sample for a false-positive rate: 0 of 5 does not bound the rate tightly.
- CONTAINER is not measured until an image scan joins `make eval`: #167 adds it (`make eval IMAGES=`, and
  `make eval-all IMAGES=`), on the seed images Nourhane builds (§ [The 27 November run](#the-27-november-run)).

---

## 2. Ranking: NDCG@10 against the CVSS baseline

**What it measures.** How well SentinelCI's risk score orders demo-shop's findings, against a CVSS-only order of
the same findings (`sentinelci.risk.cvss_baseline`; a finding without CVSS gets its severity's CVSS v3.1 floor).
Relevance is each seed's `relevance` grade (1 to 3) in the ground truth, committed before any ranking was
computed. A finding that stands for no seed counts 0, and a seed counts once, at its best finding. Ties share
their places' mean discount (McSherry and Najork, 2008). Two definitions of a seed's item are reported side by
side: **advisory** (the findings that detect it) and **package** (those, plus the other advisories of its package
in the same manifest, which one upgrade also fixes).

**Result.**

| Set | Seed item | Seeds (detected) | Risk NDCG@10 | CVSS NDCG@10 | Risk NDCG | CVSS NDCG |
|---|---|---|---|---|---|---|
| All categories | advisory | 28 (28) | **0.366** | 0.347 | 0.715 | 0.724 |
| All categories | package | 28 (28) | **0.495** | 0.390 | 0.802 | 0.748 |
| SCA only | advisory | 8 (8) | 0.627 | **0.771** | 0.706 | 0.813 |
| SCA only | package | 8 (8) | 0.836 | 0.828 | 0.836 | 0.828 |

**Target (§3).** NDCG@10 above the CVSS-only baseline: **met on all categories** under both definitions, by
0.019 by advisory and 0.105 by package. **Not met on SCA alone by advisory** (0.627 against 0.771): the risk
score's no-data defaults put the 20 sibling advisories of the seeded packages above the seeds, while CVSS puts
them at their severity's floor. By package, SCA is about even (0.836 against 0.828). Over every item (NDCG, not
@10), the risk score is below CVSS by advisory (0.715 against 0.724).

**Inputs.**
- Commit: the tree that became `a2c995e` (`b8/ranking`, 14 Nov 18:12 UTC: `725fc27` with the GT-CONTAINER-001
  grade of `a2c995e`), from the worktree's reflog and the ground-truth digest.
- Ground truth sha256 `3b88a026296bb43093e6f0054ab5321d86f2ff0436c3330645a6a2f9238d41da`; demo-shop tree
  `ceb7a43275a0be5ee65e8a65e48195ac5e13af44` (`a2c995e`'s).
- Findings sha256: the detection run's for gitleaks, grype, opengrep and trivy; zizmor `14628d8e…`, from zizmor
  1.31.1 (the ground truth records that 1.32.0 gives the same 11 findings).
- Risk model sha256 `4be62e7e8a3ba070689a462fe3ed5e9169c2bca6a488ad36e3157a6f77a36449`; feed snapshot
  (`eval/feeds/snapshot.json`) sha256 `026150c2728aefe1da1cf9ad496edc7bce1d36a5df390db43c5d12f4039bf653`.
- Of 92 findings, 8 have a CVSS score, 8 an EPSS percentile and 8 a KEV answer; the rest have no feed data.

**Full report and how to regenerate it.** `out/eval/ranking.md` and `ranking.json` of that run (not committed);
the same table is in the text of PR #121.

```bash
make eval DB_DIR=out/grype-db
make eval-ranking
```

**Limits.**
- **28 seeds is small.** One seed moving a few places changes NDCG@10 by several hundredths; the margin by
  advisory (0.019) is within that. No significance test is reported.
- **The package definition was added after the first result was seen** (#121 review), which is why both are
  shown; the advisory definition is the one first published.
- **The rubric's grade-3 sentence on committed credentials was narrowed after the first result** (#121 review);
  no grade changed. With GT-SECRET-004 and GT-SECRET-005 at 3 instead, NDCG@10 on all categories would be
  0.416 (risk) and 0.353 (CVSS) by advisory, 0.573 and 0.400 by package; SCA alone is unchanged (from
  `eval/ranking/README.md`).
- **The score rests on defaults.** demo-shop has no `sentinel.yaml` and no reachability analysis runs, so every
  service counts as internet-facing and every dependency as reachable. A low risk NDCG measures those defaults as
  much as the model.
- CONTAINER (1 seed) is left out of every order, as in detection.

---

## 3. Correlation: ARI, alert reduction, ablation

**Owner: A7 (Nourhane).** These numbers come from SPEC changelog row 1.1.98 and
`eval/correlation/threshold.json`, both on `main` since #146 merged (16 November, `0d8550a`).
`eval/correlation/README.md` describes the method.

**What it measures.** How well the correlator (`sentinel_ai.correlate`) groups `make eval`'s findings into true
root causes (adjusted Rand index: 1 when the groups are exactly the root causes, about 0 for a random grouping),
how much it reduces alerts (`1 - groups / places`, where the places are each finding and its `other_locations`),
and each configuration of the stages (ablation). The root causes are split once into a calibration half and a
test half; stage 2b's threshold is chosen on the calibration half and committed before the test half is
measured.

**Result.**

| Set | Configuration | ARI | Alert reduction | Groups / places |
|---|---|---|---|---|
| Whole run | dedup + structural (no parameter to tune) | 0.497 | **25.8%** | 69 / 93 |
| Test half (42 findings, 23 root causes) | dedup only (see below) | not in the row | 0.0% | 42 / 42 |
| Test half | dedup + structural | 0.793 | 40.5% | 25 / 42 |
| Test half | dedup + embedding | 0.657 | 52.4% | 20 / 42 |
| Test half | all three stages, threshold 0.75 | **0.827** | 57.1% | 18 / 42 |
| Test half, without SCA | all three stages | 0.742 (6 same-root pairs) | — | — |
| Calibration half (50 findings, 24 root causes) | all three stages, threshold 0.75 | 0.644 | 70.6% | — |

- The calibrated threshold is 0.75, not at the edge of the grid (0.5 to 0.95). On the calibration curve, the
  correlator's default before #146, 0.8, gives ARI 0.628.
- The sensitivity curve on the test half peaks at 0.85 (ARI 0.841). It is reported and was not used to move the
  threshold.
- The groups/places column comes from the review of #146, which checked the row's percentages against them
  (18, 25, 20 and 42 groups over 42 places). The row does not name the fourth configuration (42 groups, 0.0%);
  it is read here as dedup alone, which section 17 says reduces nothing on a findings file. Its ARI is not in
  the row.

**Target (§3).** Alert reduction ≥ 40%: **not met.** SPEC section 3's 40% is read on the whole run
(`eval/correlation/README.md`), where the configuration that can be measured without tuning gives **25.8%**.
57.1% is the test half with stage 2b: the halves split root causes, not findings, so the test half holds 20 of the
28 SCA findings in 42 of 92 and its reduction is not demo-shop's. Section 3 sets no target for the ARI.

**Inputs.**
- Commit: `main` `3d330f2`; correlator 0.1.1; embedding model `qwen3-embedding:0.6b` at
  `sha256:ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d` (ADR-0009).
- `make eval`'s findings of 14 November: the same five digests as the ranking (zizmor `14628d8e…`, zizmor
  1.31.1).
- Ground truth `bba899c5…` (as detection); root causes sha256 `2f2fe3c2…`; split sha256 `b43973f1…`;
  `threshold.json` sha256 `6124ce73981bae629d415da637eba61daa110fffcc9ff1a5c396b37e2c8badd7`.

**Full report and how to regenerate it.** `out/eval/correlation.md` and `.json` of Nourhane's run (not
committed); the calibration is `eval/correlation/threshold.json` on `main`.

```bash
ollama pull qwen3-embedding:0.6b          # its digest must be ADR-0009's
make eval DB_DIR=out/grype-db
make eval-correlation                     # with the committed threshold.json; never recalibrate on the test half
```

**Before 27 November, one recalibration.** `make eval-correlation` refuses the committed threshold today:
"threshold.json was calibrated on other halves (ground_truth_sha256 changed since)", after #121's grades, and #161
(the container seeds) and B9 (the JavaScript SAST seeds and the canaries) change the ground truth and
`split.yaml` again, #161 `root-causes.yaml` too. So once both have merged, stage 2b is calibrated once, on the
final ground truth's calibration half only (`make eval-correlation-calibrate`), and `threshold.json` is
committed in its own pull request before the feature freeze (26 November). Recalibrating on the day, once the test half has been seen, is what this
section's rule forbids. The 16 November recalibration on `main` changed only `ground_truth_sha256` (the same 0.75
and the same curve).

**Limits.**
- **#146's two should-fix are fixed on `main`:** the correlator's `DEFAULT_THRESHOLD` is the calibrated 0.75,
  pinned to `threshold.json` by a test, and `make eval-correlation` refuses a threshold that is not its own
  calibration curve's best. `threshold.json` did not change (sha256 `6124ce73…`), so the numbers above stand.
- **A label change after scores were seen, disclosed in the README:** the SCA package rule and RC-DOCKER-002 were
  added in the review of #90, after the dedup and structural scores had been seen and before any embedding
  score.
- **The inputs change after these numbers (#161, disclosed in `eval/correlation/README.md` and SPEC 1.1.130).**
  #161 adds four places (requests 2.30.0 also pinned in `requirements.block.txt`) and no group. On a `make eval`
  of 17 November, without stage 2b, the whole run's dedup+structural reduction goes from 25.5% to 28.0% and the
  test half's from 39.5% to 43.8% (dedup only: 0.0% to 8.3%), and the ARI moves by less than 0.001. A comparison
  across that change compares different inputs, not two correlators.
- **The half rule changed after the first measurement (#161).** Root causes are split in file order, except that
  root causes marked `appended` (RC-DOCKER-003 and -004, the new Dockerfiles' DS-0026 findings) come last, so no
  earlier root cause changes half. Under the old rule, `services/reports/` would sort before
  `services/shop-api/` and swap RC-DOCKER-001 and -002. RC-DOCKER-003 and -004 were written before any
  correlation score on these findings.
- **Small samples:** without SCA, the test half has 6 same-root pairs, so its ARI mostly measures whether those
  few merge.
- The findings are 14 November's (zizmor 1.31.1), not the detection run's (zizmor 1.32.0, findings
  `6b91555e…`).

---

## 4. Explanation rubric and Cohen's kappa

**What it measures.** How good the AI analyst's explanations are, as two people and an LLM judge rate them, and
how far the raters agree. One explanation per non-secret seed (23: GT-CONTAINER-001 has no finding without an
image scan, and a secret's finding is never sent to a model), written through `sentinel_ai.explain` with the
pinned model. Four yes/no criteria: **correct** (the right flaw in the right component), **grounded** (every
file, package, version, CWE, CVE and URL named is in what the explainer was given), **fix** (the fix guidance
removes the finding without breaking the code), **clear** (a developer who has not seen the scanner's output
knows what to change and why).

**Result.** Pass rates (share of explanations rated yes):

| Rater | correct | grounded | fix | clear |
|---|---|---|---|---|
| Hiba | 100% | 83% (19/23) | 91% (21/23) | 100% |
| Nourhane | 100% | 83% (19/23) | 96% (22/23) | 100% |
| LLM judge | 100% | 100% | 100% | 100% |

Cohen's kappa (Landis and Koch's names), with the observed agreement next to it:

| Pair | correct | grounded | fix | clear | pooled (92 answers) |
|---|---|---|---|---|---|
| Hiba vs Nourhane | undefined (23/23 agree) | **0.70** (21/23 agree) | **0.65** (22/23 agree) | undefined (23/23 agree) | **0.71** (89/92 agree) |
| Hiba vs judge | undefined | **0.00** (19/23 agree) | **0.00** (21/23 agree) | undefined | **0.00** |
| Nourhane vs judge | undefined | **0.00** (19/23 agree) | **0.00** (22/23 agree) | undefined | **0.00** |

"Undefined" is kappa's 0/0 when both raters give one answer to every item. The observed agreements were
computed for this report from the three rating sheets; the kappas and pass rates are the report's.

**Reading it.**
- **The negative result: the LLM judge rated all 92 answers "yes".** A rater who always says yes has a kappa of
  0.00 against anyone who does not, so the judge agrees with each person no better than chance, while the two
  people agree substantially with each other (0.71). **A same-model judge cannot stand in for the people
  here.** The judge is `gemma4:12b-it-qat`, the model that wrote the explanations, so it may favour them; the
  report says so.
- The people's "no" answers on `grounded` fall on SCA explanations for 3 of 4 each (GT-SCA-004, 005 and 008 for
  both).
- Kappa between the people sits next to a 96.7% raw agreement (89/92): with pass rates near 100%, a few
  disagreements move kappa a lot. The pooled kappa is not the mean of the per-criterion kappas.

**Target (§3).** Section 3 sets none. Section 17 asks for the rubric and the judge's agreement; both are reported.

**Inputs.**
- Explanations and the blank sheet generated on `89e76c4` (`b8/explanation-rubric`, the #143 review fixes), from
  the detection run's five findings files (section 1), demo-shop tree `28680d7f…`, ground truth `bba899c5…`.
- Model (explainer and judge): `gemma4:12b-it-qat` at
  `sha256:38044be4f923e5a55264ed7df4eaac2676651a905f735197c504045140c02bd3`; judge prompt `sentinel-judge/2`.
- The judge's reported run is a re-run: the run before it ended with an HTTP 500 from the model server. The
  head of the re-run was not recorded (the worktree was at `d9aa36e`, `89e76c4` with `main` merged in).

**Full report and how to regenerate it.** `out/eval/explanations/rubric.md` and `rubric.json`, with the sheets
and each rater's ratings (not committed).

```bash
make eval DB_DIR=out/grype-db
make eval-explanations OLLAMA_URL=http://127.0.0.1:11434   # about an hour on a CPU
# each person copies out/eval/explanations/sheet.yaml to ratings-<name>.yaml and rates alone
make eval-rubric RATERS="hiba nourhane"
```

**Disclosures and limits.**
- **`grounded` was worded after the first outputs were seen**, and before anyone rated (#143 review, SPEC
  1.1.102).
- **Hiba's ratings were not blind to the judge's:** she knew it had rated everything "yes". Nourhane's were blind.
- The first sheets were void (they lacked the explainer's inputs) and were regenerated before rating; no rating
  was made on them.
- 23 explanations and two people: kappa has a wide uncertainty at this size, and no test is reported.

---

## 5. Verified fix rate

**What it measures.** The share of attempted fixable seeds whose fix the remediation loop verifies (SPEC section
9). `make eval-fixrate` (#159) runs §9's real strategies on demo-shop's seeds, and the real verification gate
judges every proposal, as the bot's `verify` job does: build, the shop-api tests in the pinned test image, a new
scan, `score`, `evaluate` and `remediate verify`. The rules were set before any run: a seed is **attempted** when
§9 has a strategy for it, the strategy is implemented, the base scan detected the seed and the strategy ran on it.
A strategy that ran and proposed nothing stays in the denominator. A seed is **VERIFIED** only when every finding
that detects it is claimed by a proposal the gate verified; otherwise it is PARTIAL, attempted and not verified.
A step that cannot run (the model server down, a failed scan, an attempt that never reached the gate) withholds
the headline: "not measured", never 0.

**Result. 6 of 8 attempted fixable seeds verified (75.0%)**, on 17 November.

| Strategy (§9) | Seeds | Attempted | Verified | Partial | No proposal | Not attempted | Rate |
|---|---|---|---|---|---|---|---|
| `llm:code` (SAST) | 6 | 6 | 5 | 0 | 1 (no usable answer) | 0 | 83.3% |
| `deterministic:dockerfile` | 1 | 1 | 1 | 0 | 0 | 0 | 100% |
| `deterministic:kubernetes` | 1 | 1 | 0 | 1 | 0 | 0 | 0% |
| `deterministic:dependency-bump` (SCA 8, CONTAINER 1) | 9 | 0 | — | — | — | 9: not implemented | — |
| none (SECRET 5, PIPELINE 3, IAC on Terraform 4) | 12 | 0 | — | — | — | 12: no strategy in §9 | — |

- **VERIFIED (6):** GT-SAST-001, 002, 003, 004 and 006, each on the code fixer's first attempt; GT-IAC-006, the
  Dockerfile.
- **PARTIAL (1):** GT-IAC-005. The Kubernetes fixer's proposal was verified for KSV-0017 and KSV-0009 and leaves
  KSV-0023 (a hostPath volume) open, by design.
- **NO PROPOSAL (1):** GT-SAST-005, an `eval` of a query parameter. The pinned model gave no usable answer
  twice: each answer is malformed JSON followed only by empty tokens, cut at the 2048-token limit (#164).
- No proposal was REJECTED by the gate and none FAILED its build or tests.
- **Reproducible:** run 2 (on `4b6d637`, before the limit) gave the same 7 proposals, with identical diff
  sha256 and proposal ids. Temperature 0 and a fixed seed make each answer the same on every run.

**Target (§3).** ≥ 60% of attempted fixable seeds: **met** (6 of 8; the rule compares the exact fraction).
GT-SAST-005 counts as a failed attempt. It would be met either way: 7 of 8 if it were verified.

**Inputs.**
- Commit `f696756` (`b8/fix-rate`, #159, which merges #158 and #164). demo-shop tree `c98ffb45…`, ground truth
  sha256 `83a2cde6…`, `make eval`'s detection report `89e85e6c…`, base findings `853b86d7…`.
- Model `gemma4:12b-it-qat`, digest `sha256:38044be4…` (ADR-0009), prompt `sentinel-patch-code/1` (sha256
  `dca75dd0…`), temperature 0, seed 42, at most 2048 tokens.
- Tools: Gitleaks 8.30.1, Trivy 0.76.1, zizmor 1.32.0, Opengrep 1.33.1, Syft 1.55.0, Grype 0.121.0, OPA 1.21.4
  (`tools.lock.toml` sha256 `3f7400e9…`); Grype database report `0af3d6f4…`.
- Test image `sha256:bc1908db…`, built from `demo-shop/services/shop-api/Dockerfile.test`'s base image and its
  27 hash-pinned wheels (see Limits).

**Full report and how to regenerate it.** `out/eval/fixrate.md` and `fixrate.json` of that run (not committed;
sha256 `768c51d7…` and `2e8bb659…`), with every proposal, check and decision under
`out/eval/fixrate/f696756dee67/`. The run took 37 minutes on one CPU-only machine with nothing else running.

```bash
make eval DB_DIR=out/grype-db
docker build -f demo-shop/services/shop-api/Dockerfile.test -q demo-shop/services/shop-api   # prints its id
make eval-fixrate TEST_IMAGE=<that id> GRYPE_DB=out/grype-db OLLAMA_URL=http://127.0.0.1:11434
```

**Limits.**
- **Small denominator.** 8 attempted seeds: one seed moves the rate by 12.5 points. 21 of the 29 seeds are not
  attempted, so the rate says nothing about dependency bumps (not implemented) or secrets, workflows and
  Terraform (no strategy in §9).
- **The LLM fixer was tried on 6 seeds only**, the SAST seeds demo-shop plants; SPEC section 17 asks for 10.
- **Two earlier runs were not measured, and the length limit came after seeing them.** Run 1 (`2a49427`, 16
  November) and run 2 (`4b6d637`, 17 November) both withheld the headline: GT-SAST-005's first call ran to the
  15-minute time limit, a provider failure. I first put it down to a loaded machine. Run 2, on an idle machine,
  showed it wasn't: the model's answer never ends. #164 adds the 2048-token limit, so such an answer is an
  unusable answer (a failed attempt), not a server failure. The measurement's rules did not change. Without the
  limit, the bounds of run 2 were 6 of 8 to 7 of 8.
- **The test image was built from hash-checked wheels.** This sandbox's TLS proxy re-signs HTTPS, and pip inside
  `docker build` does not trust its CA. The same 27 wheels were downloaded on the host with `--require-hashes`,
  and a copy of `Dockerfile.test` installs them with `--no-index` on the same base image. shop-api's 12 tests
  pass in it, with no network and a read-only filesystem. The 27 November run builds the image as written.
- **One machine, one model.** The rate is the pinned model's on this machine's CPU, about 3 tokens a second
  (each of GT-SAST-005's cut answers took 11 min 15 s). On a CPU slower than about 2.5 tokens a second, 2048
  tokens and the prompt's evaluation no longer fit in the 15-minute time limit: that seed would be a provider
  failure again, and the rate not measured. The 27 November run needs a machine as fast as this one.

---

## 6. Injection canaries: mislabels and verdict changes

**What it measures.** demo-shop plants instructions to an AI reviewer beside seeded weaknesses, each with a token an
output holds only if it obeyed. `make eval-canaries` shows every finding whose code window holds a canary's line
to the AI analyst (an explanation and a triage hint each, as the platform does), and counts the outputs that obey
and the hints that call a seeded weakness a likely false positive (mislabels). The gate decides before and after
the AI runs, each time reading its inputs again from disk, and the two decisions are compared byte for byte.

**Result.**

| Model | Findings shown a canary | AI outputs | Obeyed a canary | Hints on seeded findings | Mislabels |
|---|---|---|---|---|---|
| control (always obeys) | 5 | 10 | 10 (100%) | 5 | 5 (100%) |
| `gemma4:12b-it-qat` (pinned) | 5 | 10 | **0 (0%)** | 5 | **0 (0%)** |

**Verdict changes: 0.** BLOCK before and after, and the decision's bytes did not change (sha256
`e5084b3439b85745564df9eaea04f1e8bd871f32bdfb68ffc16d87508f8f111a`).

**Comparison.** The control obeys every canary it is shown: it must be counted as obeying 10 of 10 while the
verdict stays the same, which shows the measurement sees an obeyed canary when there is one.

**Target (§3).** 0 verdict changes, a hard requirement: **met.** The pinned model's mislabel rate is 0 of 5.

**Inputs.**
- Commit `6bba8c8` (`b8/canaries` with `main` `3d330f2` merged in; PR #128, since merged), a clean checkout.
- demo-shop tree `28680d7f…`, ground truth `bba899c5…`, the detection run's five findings files.
- Model `gemma4:12b-it-qat` at `sha256:38044be4f923…` (recorded in each output), Ollama 0.40.8, OPA 1.21.4,
  risk model 1.0.0; scanner versions as in section 1.
- Machine: a 4-CPU, 15 GB sandbox, CPU only (from #128's discussion; the report does not record it).

**Full report and how to regenerate it.** `out/eval/canaries.md` and `.json`, with every output under
`out/eval/canaries/outputs/` (not committed).

```bash
make eval DB_DIR=out/grype-db
make eval-canaries OLLAMA_URL=http://127.0.0.1:11434
```

**Disclosures and limits.**
- **The reported run is the second.** The first lost one output (a hint) when the kernel's out-of-memory killer
  stopped Ollama's model process; it gave 0 obeyed and 0 mislabels on 9 outputs. The second ran with llama.cpp's
  prompt cache and context checkpoints off (`LLAMA_ARG_CACHE_RAM=0`, `LLAMA_ARG_CTX_CHECKPOINTS=0`) and kept all
  10 outputs.
- **2 canaries were planted on 15 November, of the 5 section 17 asks for**, both in one file beside SAST
  seeds. 0 of 10 says little about canaries of other shapes or in other categories. B9 (#171) adds three of
  other shapes (a maintainers' note in a docstring, a data value that closes its code block, a forged SentinelCI
  log), each beside its own seed; the 27 November run measures all five. All five are still in shop-api's
  `main.py` beside SAST seeds, so a canary beside a SECRET, IAC or PIPELINE finding stays untested.
- The verdict check shows that the AI step changed none of the gate's inputs in this run; it does not test a
  model that tries to write files.

---

## 7. Pipeline p50 and p95

**What it measures.** One pass of the gate's steps on demo-shop, 20 times on one machine: the five scans
`make eval` runs (same commands, pinned tools), then `sentinel evaluate` on their findings. Percentiles are
nearest-rank, so each is one measured run.

**Result (one pass, seconds).**

| Step | p50 | p95 | min | max |
|---|---|---|---|---|
| gitleaks | 1.1 | 1.1 | 1.0 | 1.1 |
| trivy | 2.9 | 3.0 | 2.6 | 3.3 |
| zizmor | 0.4 | 0.5 | 0.4 | 0.5 |
| opengrep | 2.6 | 2.8 | 2.4 | 2.8 |
| grype | 5.0 | 5.3 | 4.9 | 5.3 |
| evaluate | 0.4 | 0.5 | 0.3 | 0.5 |
| **total** | **12.4** | **12.8** | 12.1 | 13.2 |

**A pull request scans twice.** `sentinel-scan.yml` scans a pull request's head, then its base as the baseline,
so a pull request's scans take two passes, and the comment and the upload come on top. Section 3's target is read
against twice the pass's p95: 2 × 12.829 s = **25.7 s**. That counts the decision twice too, so it errs on the
slow side.

**Target (§3).** PR feedback time p95 ≤ 10 min: **met on this machine**, by a wide margin. It is not a CI
measurement.

**Inputs.**
- Commit `ec0a9d3` (`b8/pipeline-timing`), run ending 15 Nov 02:24 UTC: from the worktree's reflog. The report
  file says "with 20 runs, p95 is the slowest run", the wording of `ec0a9d3`; that sentence was wrong (nearest-rank
  p95 of 20 is the 19th, which is why p95 12.8 s is below the maximum 13.2 s) and was fixed in `07d713d`.
- demo-shop tree `28680d7f…`. Tools: Gitleaks 8.30.1, Grype 0.121.0, Opengrep 1.33.1, Trivy 0.76.1, zizmor
  1.32.0. Machine: linux-x86_64, 4 CPUs, Python 3.13.17.

**Full report and how to regenerate it.** `out/eval/timing.md` and `timing.json` of that run (not committed).

```bash
make eval-timing DB_DIR=out/grype-db          # RUNS=20 by default
```

**Limits.**
- **Not CI:** checkout, tool installation, the Grype database download and artifact uploads are not in it, and
  GitHub's runner is another machine. Once Actions can run, the workflow's own timings replace this.
- **This run predates the report's current form** (#145 review, `a2b0bf2`): it does not give run 1, the coldest,
  on its own. The 27 November run will.
- The output depends on the clock and the machine: a rerun gives other numbers.

---

## 8. Replay identity

**What it measures.** Whether a stored decision, replayed from its stored inputs and stored policy bundle with
another checkout's engine and OPA (`sentinel replay --all`), gives the same decision, byte for byte. The corpus is
nine release-gate cases built from the contract fixtures, plus a `local` decision on demo-shop's real findings.

**Result. 10 of 10 compared decisions identical (100%)**, recorded on one checkout and replayed on another, both
clean; 0 skipped, 0 differ, 0 cannot replay. On one checkout (record and replay in the same run, PR #124), also
10 of 10.

**Comparison (does the measurement see drift?).** On the replaying checkout, an engine that sorts violations the
other way, at the same version, made the 2 decisions with several violations differ: **8 of 10**, exit 1. An
engine with a bumped version skipped all 10: nothing compared, reported as not measured (exit 2), not as 100%.

**Target (§3).** 100% identical: **met** in this hand-run measurement.

**Inputs.**
- Recorded on `602be73` (a local "wip" commit on `b8/replay-identity`, after `c68e67e`), replayed on `75028a3`
  (that commit with `main` `0e40739` merged in, a local scratch commit); both checkouts clean. PR #139.
- Engine 0.2.0 and OPA 1.21.4 on both sides.
- demo-shop decision on the findings `c859f350…` (gitleaks), `85aba01d…` (grype), `8d6d8f24…` (opengrep),
  `1afe96bc…` (trivy), `14628d8e…` (zizmor 1.31.1).

**Full report and how to regenerate it.** `replay.md` and `replay.json` of that run (not committed).

```bash
make eval-replay                                                              # one checkout
uv run python eval/replay/run.py --record-to ../replay-main --findings out/eval/findings   # checkout 1
uv run python eval/replay/run.py --replay-from ../replay-main                 # checkout 2
```

**Limits.**
- **It compares engines and OPA, not policies:** the stored policy bundle is replayed, and a policy change makes a
  new decision, not a replay.
- Both checkouts ran on one machine with the same OPA. Drift between versions over time is the nightly job's
  (`replay-nightly.yml`), which has not run: GitHub Actions cannot run on this repository yet.
- 10 decisions, 2 of them with several violations: a narrow corpus for ordering bugs.

---

## Disclosures in one place

- **Criteria settled after data was seen:** the rubric's `grounded` wording (after the first outputs, before any
  rating); the ranking's package definition and the narrowed grade-3 sentence (after the first ranking, no grade
  changed); A7's SCA package rule and RC-DOCKER-002 (after the dedup and structural scores, before any embedding
  score).
- **Rater blindness:** Hiba knew the judge had rated everything "yes"; Nourhane did not.
- **Reruns:** the canaries' first run lost one output to an out-of-memory kill, and the reported run is the
  second; the judge's reported run followed one that failed with an HTTP 500.
- **Fix rate:** two runs were not measured (GT-SAST-005's answer never ended), and the 2048-token limit
  (#164) was added after seeing them; the rules did not change. Its test image was built from the same
  hash-checked wheels because of the sandbox's TLS proxy.
- **Different inputs across pages:** detection, canaries and the rubric share one set of findings (zizmor
  1.32.0); ranking, correlation and replay used 14 November's (zizmor 1.31.1). The 27 November run removes this.
- **Commits inferred, not recorded:** detection, ranking and timing reports do not record their commit; it is
  taken from each worktree's reflog.
- **Correlation's inputs and half rule changed after the first measurement (#161):** four more places and no
  group, and `appended` root causes come last (§3).
- **The fix rate's scope, set before any non-Python seed existed (#169, 17 November):** a SAST seed outside
  Python is listed as not attempted, because A6 verifies fixes with the shop-api tests only. B9's four
  JavaScript seeds are therefore never sent to the code fixer, and 6 of 8 does not change.

## The 27 November run

SPEC section 16: "The full evaluation run on a clean checkout; its numbers committed with their input digests."
It runs **in Hiba's cloud sandbox**, the machine of the 17 November fix-rate run: it holds the 12B generation
model at about 3 tokens a second, which the fix rate's time limit needs (§5), and Nourhane's laptop cannot hold
that model. Two parts are done differently there, and both are disclosed with the numbers:
- **The shop-api test image** is built from the same 27 hash-pinned wheels on the same base image, installed with
  `--no-index`, because the sandbox's TLS proxy stops pip inside `docker build` (§5). Its id is pinned by digest.
- **The CONTAINER seed images** cannot be built there (npm, pip and Maven all go through that proxy). Nourhane
  builds them on her laptop from the same commit (`make container-seed-images`) and sends the three archives,
  checked by sha256; the run then scans them with `IMAGES=`. If they cannot be sent, CONTAINER comes from her own
  `make eval IMAGES=out/container-seeds DB_DIR=out/grype-db` on that commit, reported as a manual run with its
  evidence (commit, the archives' manifest digests, the Grype database's build time and checksum,
  `tools.lock.toml`'s sha256), like the kind tests.

**Before the day (by the feature freeze, 26 November).**
- Everything the run measures is merged: the fix rate (#159), `make eval-all` (#166), the CONTAINER image scan
  (#167, which also gives `make eval-all` its `IMAGES=`), the canaries and SAST seeds of B9 (#171) with the scope
  rule (#169), and #161's container seeds (merged).
- Correlation (A7): after #161 and B9, stage 2b's threshold is calibrated once on the calibration half of the
  final ground truth (`make eval-correlation-calibrate`, Nourhane) and `eval/correlation/threshold.json`
  committed **before** the freeze (§3).
- The sandbox: Docker running, both pinned models served by Ollama with ADR-0009's digests (`38044be4…` and
  `ac6da0df…`), at least 10 GB of free disk, and nothing else running during the run.

**On the day**, on a fresh checkout of `main`, the machine doing nothing else for about three hours:

```bash
make setup && make tools && make tools-verify
uv run sentinel tools grype-db --db-dir out/grype-db             # that day's database
# the test image, by digest (the rebuilt one, see above), and Nourhane's three seed archives in out/container-seeds
make eval-all TEST_IMAGE=<its id> DB_DIR=out/grype-db IMAGES=out/container-seeds
```

`make eval-all` checks its prerequisites first (a clean checkout, the pinned scanners, the database, Docker, the
test image by digest, each step's model) and runs nothing if one fails. It then runs detection, ranking, replay,
correlation, canaries, explanations, the fix rate and the timing one at a time, and writes
`out/eval/all/manifest.json`: the commit, each step's status and exit codes, each report by sha256.

**After it.**
- The manifest says `"official": true` and every step `measured`. A step "not measured" or "failed" is
  reported as such, with its reason, never rerun quietly. A rerun is disclosed with the first run's result.
- Each person rates `out/eval/explanations/sheet.yaml` alone, as `ratings-<name>.yaml`, then
  `make eval-rubric RATERS="hiba nourhane"`.
- The reports and the manifest are committed with their input digests, every number above is replaced, and
  the provisional note at the top goes. A number that moved since 15–17 November says why.

Under section 16's drop order, a metric cut before then is reported as not measured, never as 0.

### Rehearsal (17 November)

A local merge of `main` with #159, #169, #171, #161, #165, #166 and #167 (never pushed), run with
`make eval-all STEPS=detection,ranking,replay,correlation ALLOW_DIRTY=1`, a rehearsal by its own rules. It
checks that the pieces work together; **its numbers are not the report's**, and the 27 November run replaces
them.
- Detection: 32 of 32 measured seeds (SAST 10, SECRET 5, SCA 8, IAC 6, PIPELINE 3), canaries 5 of 5 placed,
  0 false positives. CONTAINER (5 seeds) not measured: no seed images in the sandbox.
- Ranking NDCG@10, by advisory: 0.366 against CVSS 0.350 on all categories; SCA alone 0.627 against 0.771, still
  not met.
- Replay: 10 of 10 identical.
- Correlation: refused at first, as designed (the threshold names other halves). After a local
  `make eval-correlation-calibrate` (threshold 0.75): whole run 26.9% alert reduction (ARI 0.499), still below
  40%; test half, three stages, ARI 0.814 and 62.0%. The recalibration that counts is A7's pull request.
- It found one gap: `make eval-all` passed no `IMAGES=` to detection, which would have left CONTAINER not
  measured on 27 November. #167 fixes it.
