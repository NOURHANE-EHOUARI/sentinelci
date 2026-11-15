# Verified fix rate (B8)

`make eval-fixrate` measures SPEC section 3's "Verified fix rate: >= 60% of attempted fixable seeds" on
demo-shop. It runs the real remediation strategies of SPEC section 9 on the seeds of
`demo-shop/ground-truth/findings.yaml`, and the real verification gate judges every proposal. It writes
`out/eval/fixrate.json` and `out/eval/fixrate.md`, and keeps every step's evidence (proposals, scans, checks,
decisions, results) under `out/eval/fixrate/<commit>/`.

```bash
make eval                                                      # first, on a clean checkout
make eval-fixrate TEST_IMAGE=<shop-api test image, pinned>     # OLLAMA_URL= if Ollama is not on the loopback
```

## What runs, per seed

| Seed | Strategy (SPEC section 9) | How |
|---|---|---|
| IAC, Kubernetes manifest (KSV rules) | `deterministic:kubernetes` | as the bot (`sentinel-remediate.yml`) |
| IAC, Dockerfile (DS rules) | `deterministic:dockerfile` | as the bot |
| SAST | `llm:code` | as `make remediate-code` (ADR-0014) |
| SCA, and CONTAINER (a package in the image) | `deterministic:dependency-bump` | not implemented: not attempted |
| SECRET, PIPELINE, IAC on Terraform | none | not attempted |

- **The base** is this checkout's HEAD, which must be clean (its CLI, policies and waivers judge, as the
  scanned commit's pipeline does in the bot) and hold the demo-shop tree `make eval` scanned
  (`out/eval/detection.json`). It is copied into a bare repository whose `attr.tree` is the empty tree,
  exported whole with `git archive --worktree-attributes`, and scanned in pr context with every scanner the
  pr gate requires (Gitleaks, Opengrep, Syft then Grype, Trivy, zizmor), Grype's database prepared once by
  `sentinel tools grype-db`. This is `make remediate-code`'s own code, without its origin/main precondition:
  the evaluation runs on the checkout it measures.
- **The deterministic fixers** run as the bot's `propose` job: `sentinel remediate kubernetes|dockerfile` on
  the base commit's IaC findings, one proposal per strategy across all its files. The proposal then goes
  through the bot's `verify` job's steps: `remediate apply` on the bare copy, the patched commit exported
  whole, scanned (Gitleaks on the new commit, the other scanners on the tree), `remediate check` with the same
  IaC findings (the fixer is re-run: the proposal must be its output), `score`, `evaluate` in pr context with
  the base as baseline, and `remediate verify`. One attempt: a deterministic fixer gives the same proposal
  again, so the bot never retries it. A seed's outcome is that of the proposal that claims its findings.
- **The LLM code fixer** runs once per finding that detects a SAST seed, through `make remediate-code`'s loop:
  a finding no patch could verify (no behaviour tests, no security test for its rule) is not sent; otherwise
  up to three attempts, a REJECTED one fed back with its diff and what rejected it, each verified with
  `remediate check --test-image` (the service's tests and the rule's security test in the sandboxed
  container), `score`, `evaluate` and `remediate verify`.

The gate decides; the model never does. Nothing is pushed or published, and no pull request is opened.

## The rate, and what "attempted" means

**Rate = VERIFIED seeds / attempted seeds**, against the target of 60%, with one row per strategy.

A seed is **attempted** when section 9 has a strategy for it, that strategy is implemented, the base scan
detected it, and the strategy was run on its findings. Section 3 counts the "attempted fixable seeds": the
seeds the remediation loop was given to fix, not those it chose to propose a fix for. So a strategy that ran
and proposed nothing for a seed is an attempt that failed, and stays in the denominator: a fixer that declines
the hard cases does not raise its own rate.

Per seed:

- **VERIFIED**: every finding that detects the seed is claimed by a proposal the gate verified.
- **PARTIAL**: a verified proposal claims some of them and leaves another open (the Kubernetes fixer leaves
  hostPath volumes alone, by design). Attempted, not verified. This rule was set before any run, knowing the
  fixers' documented scope, not after seeing a result.
- **REJECTED** or **FAILED**: the gate's own outcome on the last attempt, with the conditions that failed
  (build OK, tests pass, target fingerprint gone, no new finding >= MEDIUM, verdict != BLOCK). REJECTED is
  the outcome of an attempt that left retries (a deterministic proposal, or an LLM retry the model could not
  answer); FAILED, of the third.
- **NO PROPOSAL**: the strategy ran and proposed nothing for it (the fixer left it open, the model gave no
  usable answer, the file was not sent, no patch of it could be verified). Attempted, not verified.
- **Not attempted**, listed with the reason, counted neither way: no strategy in section 9 (secrets, CI
  workflows, Terraform), a strategy that is not implemented (the dependency bump: SCA, and the image's
  package; each row shows the fixed versions Grype reports), or not detected by the base scan.

A seed whose `make eval` detection differs from the base scan's is flagged; the remediation works from the
base scan.

## Not measured, never 0%

A step that could not run makes its seeds **not measured**: the headline is withheld and the run exits 2.
This covers no detection report or another demo-shop tree, a dirty checkout, Grype's database that cannot be
prepared, a scan that fails, no test image or one not pinned by digest, no Docker, a model server that is
down or serves another digest, and any attempt that did not reach the gate (a check that could not run its
container, no decision). A result that breaks the gate's invariant (VERIFIED with a failed condition, or the
reverse) is not measured either. Once the code fixer hits such a step, the remaining SAST findings are not
run. The run exits 0 when the rate was measured, whether the target is met or not: the report says which.

## Evidence

`fixrate.json` names its inputs by sha256: the ground truth, `make eval`'s detection report and findings
files, demo-shop's git tree, the base commit and its findings, `tools.lock.toml` and Grype's database report;
the tools' versions as the base scan reported them, OPA's, the test image, and the model with its digest,
prompt version and prompt sha256. Each attempt records its proposal id and its diff's sha256. There is no
clock in the report. The deterministic fixers give the same proposals on the same inputs; the model may not,
so its proposals are named by their ids.

## Needs, and time

The pinned tools (`make tools`), network for Grype's database, Docker with the shop-api test image
(`docker build -f demo-shop/services/shop-api/Dockerfile.test -q demo-shop/services/shop-api` prints its id),
and the pinned model on Ollama (`ollama pull gemma4:12b-it-qat`). Each verification scans the patched commit
with every scanner, so a run is one base scan, two IaC verifications and one to three LLM attempts per SAST
seed: about 45 minutes to 2 hours on a laptop CPU, most of it the model's generation and the scans.
