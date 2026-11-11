# LLM code fixes on the laptop (`make remediate-code`, ADR-0014)

The model that writes code patches runs on the laptop, never in a workflow, and every patch is verified the way
the bot's IaC patches are (ADR-0013): scanned like a pull request, judged by the gate, built, and tested in a
sandboxed container. Nothing leaves the laptop unless you ask for it.

## Before the first run

1. `make setup` and `make tools` (the pinned scanners and OPA).
2. The local model, pinned by digest (ADR-0009): `ollama pull gemma4:12b-it-qat`. The provider checks the
   digest before every prompt and refuses another one.
3. Docker, and an image for the service's tests, pinned by digest: Python, pytest and the service's
   dependencies (`TEST_IMAGE=name@sha256:...`, or a local image id `sha256:...`). The patched code only ever
   runs there: no network, read-only, no capability, as `nobody`, with limits and a time limit.
4. Check out `main` as it is on GitHub, with a clean working tree. The run refuses anything else.

## Run

```bash
make remediate-code TEST_IMAGE=<pinned image>                  # every SAST finding of main
make remediate-code TEST_IMAGE=<pinned image> FINDING=<id>     # one finding
make remediate-code TEST_IMAGE=<pinned image> PUBLISH=1        # also push VERIFIED branches and open their PRs
make remediate-code TEST_IMAGE=<pinned image> API_URL=http://localhost:8000   # record each attempt
```

For each finding, up to three attempts: a REJECTED patch is proposed again with its diff and what rejected
it (redacted and clipped by the fixer). The evidence of each step is in `out/remediate-code/<commit>/`:
`proposal.json`, the scans, `check.json` (with the end of the test output), `decision.json`, `result.json`,
and `summary.json` for the whole run.

`PUBLISH=1` pushes only VERIFIED branches, with your own git credentials, and opens each pull request with your
own `gh` login. The pull request says that it was verified by the tests and the scanners, not by a person: you
or your reviewer still read it. The bot never merges and never approves.

`API_URL` sends every attempt to the platform's Remediation page; the token comes only from
`SENTINEL_API_TOKEN`.

## What is never verified

- a service with no `tests/` directory next to its code (shop-api needs its tests, B9);
- a patch that edits the tests;
- a file that is not Python;
- anything the test container could not run (no Docker, an image that is not there): nothing is verified
  then, which is not the same as a failed test.
