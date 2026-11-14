# Ranking report (B8)

`make eval-ranking` measures how well SentinelCI's risk score orders demo-shop's findings, against a CVSS-only
baseline (SPEC section 17, "NDCG@10 vs CVSS baseline"). It runs after `make eval` and reads its findings.

```bash
make eval DB_DIR=.sentinel/grype-db     # the findings, SCA included
make eval-ranking                       # out/eval/ranking.json and out/eval/ranking.md
uv run python eval/ranking/run.py --findings out/eval/findings --out out/eval
```

## What it does

1. **Enrich** the findings with the committed feed snapshot, `eval/feeds/snapshot.json`. That file holds the
   recorded EPSS, KEV and OSV answers for the seeded packages, the same ones the gate's fixtures use. It uses
   no network. The report says how many findings got a CVSS score, an EPSS percentile and a KEV answer. The
   other advisories Grype reports for the seeded packages have no recorded answer.
2. **Score** them with this checkout's policy bundle (`sentinel score --policy-dir policies`). demo-shop has
   no `sentinel.yaml` and no reachability analysis runs. So every service counts as internet-facing, and every
   dependency as reachable. The risk model's defaults never lower a score.
3. **Rank the same items two ways:**
   - by the risk score;
   - by the CVSS-only baseline (`sentinelci.risk.cvss_baseline`). A finding without CVSS falls back to the
     lower bound of its severity's CVSS v3.1 rating: CRITICAL 90, HIGH 70, MEDIUM 40, LOW 1.

## How it is scored

- **Relevance** is each seed's `relevance` grade in the ground truth, 1 to 3. The rubric is in
  `demo-shop/ground-truth/README.md` ("Ranking relevance"). The grades were committed before any ranking was
  computed, in their own commit.
- **A seed is ranked once,** at the best place any finding that detects it reaches. The detection rules are
  `eval/detection/score.py`'s.
- **A finding that detects no seed** is ranked on its own, with gain 0. It is a real issue that the ground
  truth does not grade, so it can only push graded seeds down.
- **A seed no finding detects** is missing from both orders, but it stays in the ideal order. So it lowers
  both the same way.
- **A seed of a category no scan measured** is left out of both orders and of the ideal one, and the report
  lists it as not measured. `make eval` scans no image, so a CONTAINER seed could not have been found. It is
  not a miss, the same rule as the detection report.
- **Ties share their places:** each item in a tie gets the mean discount of the places the tie spans
  (McSherry and Najork, 2008). No arbitrary order inside a tie changes the result, and the report prints the
  places a tie spans.
- **NDCG@10 and NDCG over every item,** for all categories and for SCA alone, where the baseline is pure CVSS.
  Gains are `2^grade - 1`.

## Reading it

- **28 seeds is a small benchmark.** One seed moving a few places changes NDCG@10 by several hundredths. The
  report gives no significance test.
- **The scores rest on what the inputs say.** A low risk NDCG here measures the defaults (no exposure, no
  reachability), not only the model. For example, an unknown exposure counts as internet-facing, and a
  dependency that is never imported counts as reachable. The ground truth records `imported`, but the risk
  model has no reachability input to read it from.
- **Never change a grade or the rubric to move the number.** A grade changes only by a reviewed pull request
  that says why, and the report names the ground truth by its digest.

The same inputs give the same report, byte for byte. There is no clock, and every input is named by its sha256:
the ground truth, each tool's findings file, the feed snapshot and the risk model.
