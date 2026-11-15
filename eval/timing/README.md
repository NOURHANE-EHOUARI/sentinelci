# Pipeline timing (B8)

SPEC section 3 sets "PR feedback time: p95 <= 10 min", and section 17 asks for pipeline p50 and p95.
`make eval-timing` measures them on this machine and writes `out/eval/timing.json` and `out/eval/timing.md`.

```bash
make eval-timing DB_DIR=.sentinel/grype-db            # 20 runs
make eval-timing DB_DIR=.sentinel/grype-db RUNS=5
```

Each run does the gate's steps in order on demo-shop: the five scans `make eval` runs (the same commands and
pinned tools), then `sentinel evaluate` on their findings (`local` context, the repository's policies). The
report gives each step's p50, p95, min and max, and the total's. Percentiles are nearest-rank, so each one is
a measured run; with fewer than 20 runs, p95 is the slowest run, and the report says so.

**What it doesn't measure.** It is not a CI run. A CI job also checks out the repository, installs the pinned
tools, downloads the Grype database and uploads artifacts, on GitHub's runner. Those costs are not here. The
report names the machine (platform, CPUs, Python) and the tool versions.

A step that fails stops the measurement (exit 2), since a time for a scan that did not run would be too fast.
The Grype database is needed (`DB_DIR`): SCA is one of the gate's steps.

Unlike B8's other reports, the output changes from run to run: it is a measurement of time.
