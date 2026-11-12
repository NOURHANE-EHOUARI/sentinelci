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
   there: no network, read-only, no capability, as `nobody`, with limits and a time limit.
4. Check out `main` as it is on GitHub, with a clean working tree. The run refuses anything else.

## Run

```bash
make remediate-code TEST_IMAGE=<pinned image>                  # every SAST finding of main
make remediate-code TEST_IMAGE=<pinned image> FINDING=<id>     # one finding
make remediate-code TEST_IMAGE=<pinned image> PUBLISH=1        # also push VERIFIED branches and open their PRs
make remediate-code TEST_IMAGE=<pinned image> API_URL=http://localhost:8000   # record each attempt
```

For each finding, up to three attempts: a REJECTED patch is proposed again with its diff and what rejected
it, redacted and clipped by the fixer, which keeps the end: the tests' log first, then the check's problems,
then the verification's summary, so the reasons are never cut. The evidence of each step is in
`out/remediate-code/<commit>/`: `proposal.json`, the scans, `check.json` (with the end of the test output),
`decision.json`, `result.json`, and `summary.json` for the whole run.

`PUBLISH=1` pushes only VERIFIED branches, with your own git credentials, and opens each pull request with your
own `gh` login. The pull request says that it was verified by the tests and the scanners, not by a person: you
or your reviewer still read it. The bot never merges and never approves.

`API_URL` sends every attempt to the platform's Remediation page; the token comes only from
`SENTINEL_API_TOKEN`.

## What is never verified

- a service with no `tests/` directory next to its code, or a finding whose rule has no
  `security_tests/test_<rule>.py` (shop-api has one per SAST seed, B9);
- a security test that does not fail on the base code (it proves nothing about the fix);
- a patch that edits `tests/` or `security_tests/` (both always come from the base commit);
- a file that is not Python;
- anything the test container could not run (no Docker, an image that is not there): nothing is verified
  then, which is not the same as a failed test.
