# ADR-0008: Pull requests are judged by the base branch's pipeline

- Status: proposed (accepted when the A3 pipeline PR is merged)
- Date: 2026-10-29

## Context

The release gate trusts several files that live in this repository: `tools.lock.toml` (which scanner binaries
may run), the scanner configurations packaged with the CLI, the `sentinel` CLI itself, the Rego policies and
`.sentinel/waivers.yaml`. A workflow that checks out the pull request head and runs `uv sync` + `sentinel`
from it lets the change under review choose all of these. The pull request could then:

- repoint a scanner to its own release and hash in the lock (raised by Hiba in the review of PR #2);
- patch the scanner adapter or the policy so that its findings disappear;
- add a waiver for its own new secret.

A one-line hash change or a new waiver is easy to miss in review, whereas a changed workflow file is visible.

GitHub runs the workflow definitions of the pull request's merge commit for `pull_request` events, including
reusable workflows called with `./` or `$/`. A pull request can therefore always edit
`.github/workflows/*.yml` itself. That edit shows up in review, under CODEOWNERS.

## Decision

1. Every job of `sentinel-scan.yml` checks out the **pipeline** at the base commit
   (`github.event.pull_request.base.sha`, or the pushed commit outside pull requests): CLI, lock, scanner
   configurations, policies and waivers. The pull request head is checked out only as **data** to scan, in a
   separate directory, and no job runs its code. `gate` and `report` never check it out at all.
2. Tools are installed in `$RUNNER_TEMP`, outside both checkouts, and `sentinel` re-verifies each binary
   against the base lock right before it runs.
3. Waivers come from the base commit. A waiver added by a pull request applies once it is reviewed and merged,
   never to the pull request that adds it.
4. The PR comment warns when the pull request changes pipeline files (`.github/workflows`, `tools.lock.toml`,
   `policies/`, `cli/`, `.sentinel/`, `pyproject.toml`, `uv.lock`), because those changes are not what judged
   it.
5. Least privilege per job: `scan` and `gate` read only. `report` may write one PR comment. No job gets a
   secret.

## Consequences

- A pipeline change is exercised only after merge. The `demo-shop` workflow also runs on pushes to `main` that
  touch the pipeline, so a broken change shows up right away.
- Diff-aware PR mode for secrets comes from scanning the pull request's commits (`base..head`). Other
  categories will compare fingerprints with a base-branch baseline (B4).
- Residual risk: the workflow YAML itself still comes from the pull request (GitHub's model). Mitigations: the
  warning in the comment, CODEOWNERS review of `.github/`, and zizmor in CI. Once the repository is public,
  rulesets with required workflows can pin the gate to `main`.
