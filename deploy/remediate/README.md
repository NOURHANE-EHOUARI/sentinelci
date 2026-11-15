# LLM code fixes on the laptop (`make remediate-code`, ADR-0014)

The model that writes code patches runs on the laptop, never in a workflow, and every patch is verified the way
the bot's IaC patches are (ADR-0013): scanned like a pull request, judged by the gate, built, and tested in a
sandboxed container. The tests are the service's behaviour tests (`tests/`, they must pass on the patch) and
the target finding's own security test (`security_tests/test_<rule>.py`, it must fail on the base code and
pass on the patch): the weakness is gone, not only the scanner's sight of it. Nothing leaves the laptop unless
you ask for it.

## Before the first run

1. `make setup` and `make tools` (the pinned scanners and OPA).
2. The local model, pinned by digest (ADR-0009): `ollama pull gemma4:12b-it-qat`. The provider checks the
   digest before every prompt and refuses another one.
3. Docker, and the image of the service's tests, pinned by digest. For shop-api it is `Dockerfile.test` (B9):
   the release image's base by digest and its wheels with hashes, plus pytest and its HTTP client, without
   the application. `docker build -f demo-shop/services/shop-api/Dockerfile.test -q demo-shop/services/shop-api`
   prints its local id (`TEST_IMAGE=sha256:...`; `name@sha256:...` works too). The patched code only ever runs
   there: no network, read-only, no capability, as `nobody`, with limits (1 GiB of memory and no swap
   beyond it, 256 processes, 2 CPUs) and a time limit.
4. Check out `main` as it is on GitHub, with a clean working tree. The run refuses anything else.
5. Network for one download: each run prepares Grype's vulnerability database in `out/grype-db`
   (`sentinel tools grype-db`, checked against its listing's checksum), the only download besides `git
   fetch`. If it cannot be prepared, the run stops before anything is scanned or proposed.

## Run

```bash
make remediate-code TEST_IMAGE=<pinned image>                  # every SAST finding of main
make remediate-code TEST_IMAGE=<pinned image> FINDING=<id>     # one finding
make remediate-code TEST_IMAGE=<pinned image> PUBLISH=1        # also push VERIFIED branches and open their PRs
make remediate-code TEST_IMAGE=<pinned image> API_URL=http://localhost:8000   # record each attempt
```

For each finding, up to three attempts: a REJECTED patch is proposed again with its diff and what rejected
it, redacted and clipped by the fixer, which keeps the end: the tests' log first (the base run is labelled
"expected to fail"), then the check's problems, then each new finding the patch brought (tool, rule,
severity and place), then the verification's summary, so the reasons are never cut. A finding that no patch
could ever verify (no behaviour tests next to its file, no security test for its rule) is not sent to the
model at all: it is recorded as `not verifiable`. The evidence of each step is in
`out/remediate-code/<commit>/`: `proposal.json`, the scans, `check.json` (each test run's selection, exit code and pytest summary, and the end of the test output),
`decision.json`, `result.json`, and `summary.json` for the whole run.

`PUBLISH=1` pushes only VERIFIED branches, with your own git credentials, and opens each pull request with your
own `gh` login. The pull request says that it was verified by the tests and the scanners, not by a person, and
shows each test run with pytest's summary (the behaviour tests, the security test on the base and on the
patch), as text in a code block, since the log is also the patched code's own output: you or your reviewer
still read it. The bot never merges and never approves.

`API_URL` sends every attempt to the platform's Remediation page; the token comes only from
`SENTINEL_API_TOKEN`.

## What is never verified

- a service with no `tests/` directory next to its code, or a finding whose rule has no
  `security_tests/test_<rule>.py` (shop-api has one per SAST seed, B9);
- a security test that does not fail on the base code (it proves nothing about the fix);
- a run whose pytest summary does not show the tests passing (an early exit, a skip, a deselection, an
  xfail) or, on the base code, failing, or that holds more than one summary line (pytest prints one). This
  raises the bar without making the run tamper-proof: the patched code runs inside pytest, so it can end the
  run early, print its own summary or change what pytest reports (a hook turning a failure into a pass),
  which is one more reason a person reads every diff. Running the app outside pytest's process is a
  follow-up of #108;
- a patch that edits `tests/` or `security_tests/` (both always come from the base commit);
- a file that is not Python;
- anything the test container could not run (no Docker, an image that is not there): nothing is verified
  then, which is not the same as a failed test.
