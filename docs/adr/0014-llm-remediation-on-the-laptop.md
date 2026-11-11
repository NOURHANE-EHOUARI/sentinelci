# ADR-0014: The LLM code fixer runs on the laptop, and its patches are verified by tests in a container

- Status: proposed
- Date: 2026-11-11
- Builds on: ADR-0009 (local models), ADR-0011 (the laptop as the private phase's trusted machine), ADR-0013 (the
  remediation bot); B6's `sentinel_ai.patch.propose_code_fix` (#81) and B5's `OllamaProvider` (#83)

## Context

SPEC section 9 gives SAST findings to the LLM code fixer (B6), and A6 must consume it: PROPOSED → PATCH_READY →
PR_OPEN → VERIFYING → VERIFIED | REJECTED (retried twice with CI feedback) | FAILED. ADR-0013 left the `llm:code`
strategy out of the bot ("anything else refused until B6 says what a model's patch may touch"). B6 now says it:
one SAST finding with a line, in one regular UTF-8 file, edits inside the lines that were sent, no suppression
comment, no secret in or out, the file still parses, and A6's own `check_proposal` and `git apply --check`.
Facts checked on 2026-11-11:

- The model is `gemma4:12b-it-qat` (ADR-0009): 8.5 GB loaded, about 2 minutes per answer on a laptop CPU. A
  private repository's hosted runner has 2 vCPU and 7 GB of memory, so it cannot run it, and sending the scanned
  code to a hosted model is what ADR-0009 rules out.
- The verification gate needs "tests pass". The infrastructure strategies define their own tests
  (`sentinel remediate check`, ADR-0013 decision 6); a code patch needs the service's tests. shop-api has none
  yet, and its code must never run outside a container (CLAUDE.md).
- GitHub Actions cannot run before 1 December, and the release already runs on the laptop (ADR-0011).

## Decision

1. **Where.** `make remediate-code` runs on the laptop, like `make release`: a clean checkout at `origin/main`,
   the pinned scanners, and the pinned generation model on the local Ollama (digest checked before any prompt,
   #83). The bot workflow keeps refusing `llm:code` (ADR-0013): no workflow runs a model.
2. **Propose.** For each SAST finding of the scan (or the one named with `FINDING=<id>`), `propose_code_fix`
   gives a `PatchProposal` or says why not (`unavailable`, `not sent`: recorded, nothing else happens).
   `sentinel remediate apply` commits it on its `sentinel/fix/` branch with plumbing commands, as for the other
   strategies.
3. **Verify, with the bot's own gate.** Both commits are scanned with the scanners the pr gate requires; the
   gate is evaluated on the patched commit in pr context with the scanned commit as baseline; then
   `sentinel remediate verify`. For `llm:code`, `sentinel remediate check` defines:
   - **build**: every edited file still parses (`ast.parse` for Python, which runs nothing);
   - **tests**: the service's tests (`tests/` next to its code) run in a container from a pinned image, with no
     network, a read-only root file system, no capability, as `nobody`, with a time limit (the sandbox of
     `eval/model-selection/bench.py`). A service without tests fails this check, so its patches are never
     VERIFIED.
4. **Retries.** A REJECTED patch is proposed again (attempts 2 and 3) with `Feedback`: the previous diff and the
   end of the failing check's log, both redacted and clipped by B6. After the third, FAILED.
5. **Publish only what a person can review.** The laptop pushes the branch and opens the pull request with the
   person's own `gh` login, as they would by hand. The pull request carries the proposal, the verification result
   and the gate's decision. The bot never merges and never approves, so a VERIFIED `llm:code` patch is still a
   pull request a person reviews. Each attempt is recorded on the platform (`sentinel upload-remediation`,
   Remediation page, A8).

## Consequences

- shop-api needs tests: one per SAST seed that a correct fix makes pass and the seeded code fails (B9), plus a
  few for the service's behaviour. They run only in the container.
- A patch can only be as good as those tests and the scanners: the gate checks that the finding is gone, that no
  new finding of MEDIUM or more appears and that the tests pass, not that the fix is the right one. The review
  is the last check, which is why the bot never merges.
- Nothing here needs a write token in a workflow or a secret in CI. The laptop holds the person's own GitHub login,
  as for every pull request they open.
- Once the repository is public and Actions run, `make remediate-code` stays the way to run the model; only the
  verification of its pull requests could move to the bot's `verify` job.
