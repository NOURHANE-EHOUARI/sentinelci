# Pipeline timing (B8)

SPEC section 3 sets "PR feedback time: p95 <= 10 min", and section 17 asks for pipeline p50 and p95.
`make eval-timing` measures one pass of the gate's steps on this machine, and writes `out/eval/timing.json`
and `out/eval/timing.md`.

```bash
make eval-timing DB_DIR=out/grype-db            # 20 runs
make eval-timing DB_DIR=out/grype-db RUNS=5
```

Each run does the gate's steps in order on demo-shop: the five scans `make eval` runs (the same commands and
pinned tools), then `sentinel evaluate` on their findings (`local` context, the repository's policies). The
report gives each step's p50, p95, min and max, and the total's. Percentiles are nearest-rank, so each one is
a measured run. With 20 runs, p95 is the 19th fastest; with fewer than 20, it is the slowest, and the
report says which. Run 1 is also given on its own: it is the coldest (tool caches, the page cache of the
Grype database), as a CI job always is.

**A pull request scans twice.** `sentinel-scan.yml` scans a pull request's head, then its base as the
baseline (only what the change introduces can block). So a pull request's scans take two passes, and the
comment and the upload come on top. The report gives one pass, and checks SPEC section 3's target against
twice its p95. That counts the decision twice too, so it errs on the slow side.

**What it doesn't measure.** It is not a CI run. A CI job also checks out the repository, installs the pinned
tools, downloads the Grype database and uploads artifacts, on GitHub's runner. Those costs are not here. The
report names the machine (platform, CPUs, Python) and the tool versions.

A step that fails stops the measurement (exit 2), since a time for a scan that did not run would be too fast.
The Grype database is needed (`DB_DIR`): SCA is one of the gate's steps.

Unlike B8's other reports, the output changes from run to run: it is a measurement of time.
