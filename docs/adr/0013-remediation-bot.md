# ADR-0013: The remediation bot proposes without write access and publishes without running repository code

- Status: proposed
- Date: 2026-11-10
- Builds on: ADR-0008 (base-branch pipeline), ADR-0011 (the key stays off GitHub); the commands of #41, #42 and
  #48 (`sentinel remediate kubernetes`, `dockerfile`, `apply`, `verify`)

## Context

SPEC section 9 asks for a bot that turns findings into pull requests: PROPOSED → PATCH_READY → PR_OPEN →
VERIFYING → VERIFIED | REJECTED | FAILED, "never merges", "verification jobs get no secrets". The fixers and
`apply` exist. What remains is where they run, and what may push. Facts checked on 2026-11-10:

- Pushing a branch and opening a pull request needs a token that can write. CLAUDE.md forbids giving one to a
  job that runs repository code. The fixers and `apply` are repository code, and so is everything `uv sync`
  installs.
- `main` has no server-side protection (private phase). A token that can push to a `sentinel/fix/` branch can
  push to `main` too. Only the workflow token is safe to use: it lasts for one run and lives only in that run.
  A personal access token would be a repository secret that any branch's workflow could read (ADR-0011).
- A pull request opened with the workflow token does not start `pull_request` workflows. Workflows started by
  `workflow_dispatch` with that token do run.
- `git bundle` carries commits between jobs as data. A bare repository that fetches from a bundle runs no hook,
  filter or attribute of the repository: nothing is checked out.

## Decision

1. **Two jobs** (`.github/workflows/sentinel-remediate.yml`, by hand only).
   - **`propose`** has a read-only token and no secret. It runs the pinned Trivy, `scan iac` and the fixers,
     then `remediate apply`, which commits each proposal on its own `sentinel/fix/<id>` branch of the clone
     with plumbing commands (#48). It hands over each proposal, `apply`'s output and a git bundle of that
     branch.
   - **`publish`** has the write token (`contents` and `pull-requests`) and runs no repository code: no
     checkout, no Python, no package. Its one script uses the runner's git, jq and gh.
2. **`publish` trusts nothing `propose` says.** It fetches the scanned commit and the bundle into an empty bare
   repository, and accepts a proposal only if all of these hold:
   - the branch is under `sentinel/fix/`;
   - the bundle holds exactly that branch, at the commit `apply` reported;
   - that commit has exactly one parent, the scanned commit;
   - its `Sentinel-Proposal` trailer is the proposal's id;
   - it edits in place exactly the files the proposal lists, and changes no file mode;
   - the proposal is one the bot could have made: its id is a UUID and its branch is `sentinel/fix/` plus the
     id's first 12 hex digits; its strategy is `deterministic:kubernetes` (files `*.yaml`, `*.yml`) or
     `deterministic:dockerfile` (the fixer's `DOCKERFILE_NAMES` rule), anything else refused until B6 says
     what a model's patch may touch; every file is inside the scanned directory (`inputs.path`, checked again
     here with the same rule as in `propose`), and none is under `.github/` or `.sentinel/` or named
     `sentinel.yaml`; the attempt is 1 to 3 and every finding id is a sha256.

   What the pull request shows comes only from checked values; the rationale is printed as text in a fenced
   block, capped at 2,000 characters, so no mention, link, image or closing keyword renders. Each refusal, and
   each failed push or pull request, fails the run and names the proposal; the other proposals are still
   published. A tampered propose job can therefore make at most a pull request that edits, in place, files of
   the scanned directory that its strategy can fix, and that pull request is then judged like any other.
3. **Idempotent.** A proposal's branch is named after its content (#48). If the branch already exists, nothing
   is pushed or opened again.
4. **The pull request is the job record** (PR_OPEN). The bot never merges and never approves. The repository
   setting "Allow GitHub Actions to create and approve pull requests" must be on, for creation only.
5. **Verification is dispatched, not triggered (next step, with the A3 wiring).** The workflow token cannot
   start the pull request's own checks. So `publish` will dispatch a verification run (`actions: write`, the
   only extra permission) on the fix branch. That run:
   - scans the base and the patched commit with the base commit's pipeline (ADR-0008);
   - evaluates the patched scan in pr context;
   - runs `sentinel remediate verify` with no secret;
   - hands its VerificationResult to a job without repository code, which comments VERIFIED, REJECTED or
     FAILED on the pull request.

   A REJECTED proposal is retried at most twice (attempts 2 and 3) by the next run, with the CI's feedback for
   the LLM strategy (B6).

## Consequences

- The only code that holds a write token is about sixty lines of shell in the workflow file. They are tested by
  running them, extracted from the YAML, against a local origin and a recording `gh`, including seven ways a
  compromised propose job could change its output (`cli/tests/remediation/test_bot_workflow.py`).
- The bot opens pull requests against the default branch's infrastructure as code (demo-shop's seeds, for the
  demo). Those pull requests remove seeds, so they are never merged: they show the loop.
- Until the verification run exists, a bot pull request stays PR_OPEN. Its checks run when someone starts
  them by hand.
- Not decided here: storing the remediation jobs in the platform (B1's job queue). The pull request and its
  verification comment are the record until then.
