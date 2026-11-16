# SentinelCI — Project Specification

**Version 1.1 — 28 October 2026.** Section numbers are stable; tasks and prompts reference them
(for example "implement task A2 as described in §13.1").

> **How to read this document.** In 30 minutes: §1, §4, §13 (contracts), your track in §15, then the Sprint 0
> checklist in §20. Everything else is reference material.

## Changelog

| Version | Change |
|---|---|
| 1.1.129 | A10 the switch to public, step 1 of ADR-0016: `CLAUDE.md`'s "Repository status" says the public rules (everything pushed is public, `main` protected server-side with the three `ci.yml` checks required, fork workflows approved by hand, read-only default workflow permissions, alerts on `demo-shop/` closed with their reason, never waived) and what stays until step 2 (the laptop's key pair, the in-toto provenance, no code-scanning upload, kind's local registry). The README's status line, the release docs and the threat model follow: `main`'s protection replaces the no-protection residual risk, which becomes "a GitHub setting the owner can turn off"; the laptop signer's and the repository secrets' rows name step 2; the blocked-Actions row is gone. ADR-0016 records the scans before the switch: the history (989 commits, 120 branches, 185 pull-request refs) and the 44 workflow artifacts, no real secret. |
| 1.1.120 | Threat model after #114 (§18, A10): T4's status is main for all six required scanners in `pr` and `release` (Gitleaks, Trivy and zizmor, then Opengrep, Syft and Grype with #114), and the residual risk "Opengrep, Syft and Grype are not required scanners yet" is closed: a pull request that deletes one of their steps, or a release scan stopped before one of them reports, is SC-010. |
| 1.1.108 | B4 waivers (#126 review, nits on `2f9fbf4`): a waivers file nested too deeply for YAML's composer (a `RecursionError`) is refused as an `EvaluationError`, "waivers file is nested too deeply to be read", instead of a crash: `PUT /api/v1/waivers/{sha256}` answers 422 and `sentinel evaluate` fails closed with that reason. YAML gives up before the JSON copy on any such file, so only the composer is guarded; a test searches the deepest file the loader reads through the PUT itself and checks that no depth answers 500, and `sentinel evaluate` on a too-deep file exits 3 with the reason and writes no decision (#157 review). The U+0000 refusal walks keys as well as values, and a case with the escape in a key pins it. No API version change: a request that answered 500 now answers 422, which the contract already lists. |
| 1.1.104 | ADR-0016 (proposed, both of us): the repository goes public right after the merge train (22 November at the latest) in two steps, amending ADR-0006. Step 1 at the switch: a Gitleaks scan of the whole history first (15 Nov: 11 findings, none a real secret), branch protection on `main`, approval for fork pull requests' workflows, Dependabot security updates off with `demo-shop/`'s alerts closed as an intentionally vulnerable target (never a waiver), push protection bypassed only for a new listed fake; key-pair signing, the Cosign provenance attestation and the reporting stay. Step 2 after v1.0.0, if time allows: ADR-0006's GitHub mode (keyless signing, artifact attestations, code-scanning upload, public images). The history scan covers every branch and every pull request's head, and runs again on the day, after the last merge. Review of #144: the decision is its own PR; `CLAUDE.md`'s repository status changes in the switch PR on the 22nd, with that day's scan. Branch protection binds the admin too ("Do not allow bypassing"), and the default workflow permissions are read. The residual risk is named: a commit a force-push removed is still served by its SHA. Brought forward (both of us, 15 November): the switch follows the merge train, and its checklist adds the logs and artifacts of past Actions runs, checked before the switch, and one workflow started by hand right after it. |
| 1.1.103 | §16 roadmap (both of us, 15 Nov): the project ends on 30 November instead of 17 January. Merge train 16–22 Nov, then going public after a checklist (Gitleaks on the whole history, demo-shop's fake secrets against GitHub's secret scanning, branch protection, approval for fork pull requests; key-pair signing kept at first); verified fix rate and A5 by 26 Nov (feature freeze); the full evaluation run on 27 Nov; v1.0.0, the demo video and the README on 28–30 Nov. The drop order is §16's, with the GitHub sync and the LLM judge first; a cut metric is reported as not measured. The original sprint plan is kept in §16 for the record. |
| 1.1.102 | B8 explanation rubric (§17: "explanation rubric + LLM-judge agreement (Cohen's kappa)"): `make eval-explanations` writes one explanation per non-secret seed of demo-shop's ground truth (of the first finding `make eval` reported for it, through `sentinel_ai.explain`, the pinned model; a secret's finding is never sent) and a rating sheet whose ratings are all blank, then the LLM judge's ratings. Four yes/no criteria: correct, grounded, fix, clear. Two people rate each explanation alone; `make eval-rubric` gives each rater's pass rates and Cohen's kappa between the two people and between each person and the judge, per criterion and pooled, and says "undefined" when both raters give one answer to every item. A sheet with a blank or non-boolean answer, a missing item, or another explanation than the one generated is refused (exit 2). Nothing fills in a person's rating. Review of #143: each item of the sheet holds what the explainer was given (the finding as sent, the code around it or none, the references it could cite), the judge is sent the same blocks, and a sheet that shows another input is refused, since `grounded` and `fix` are judged against it; `grounded` names the references shown (worded after the first outputs were seen, before any rating); a kappa of 0 is "slight" on Landis and Koch's scale, and the report says what the pooled kappa is. |
| 1.1.101 | B8 pipeline timing (§3, §17): `make eval-timing` runs the gate's steps on demo-shop, in order, RUNS times (default 20): the five scans `make eval` runs, with the same commands and pinned tools, then `sentinel evaluate` on their findings. It reports each step's and the total's p50, p95, min and max (nearest-rank, so each is a measured run), against §3's PR feedback time target (p95 <= 10 min), with the machine and the tool versions. It is not a CI measurement: checkout, tool downloads, the Grype database and artifact uploads are not in it, and the report says so. A step that fails stops the measurement (exit 2). Review of #145: the report gives one pass of the gate's steps, and says that a pull request scans its head and then its base as the baseline (`sentinel-scan.yml`), so its scans run twice; §3's target is checked against twice the pass's p95. Run 1, the coldest, is also given on its own. |
| 1.1.100 | B5c and B1 (§11, migration 0011, #111 review): the worker logs in as its own role, `sentinel_worker`, never as the database owner. The role can read runs and findings, claim and finish explanation requests (`SELECT`, and `UPDATE` on their state only: `status`, `reason`, `explanation_sha256`, `updated_at`, so a request can't be moved to another finding, #140 review), and record explanations (`INSERT`, and `SELECT` on the two columns the insert reads back): it cannot write a run, a finding or a decision, read a decision, a waiver, a release, a remediation, a correlation or an explanation's text, delete anything or change the schema. The migration creates it without a login or a password; `python -m sentinel_api.migrate` gives it a login with `SENTINEL_WORKER_DATABASE_PASSWORD`, hashed on the client (SCRAM), so the server never sees the password. Compose generates `WORKER_DATABASE_PASSWORD` (`make compose-env` adds it to an older `.env`), gives it to the API and the worker, and no longer gives the worker the owner's password. A role belongs to the server: it is created once, and going below 0011 takes this database's rights back and keeps the role. |
| 1.1.99 | A10 self-gate (#141 review, nit 2): `cli/tests/supplychain/test_verify.py`'s private-key case builds its PEM armor at run time (`private_key_pem`), like #141's `fake_pem`. Its literal header made Gitleaks match from line 188 to the public-key header at line 564, so any edit in between changed the fingerprint and blocked the self-gate until the value was waived again. No finding is left there, so `self-2026-006` is dropped; a real key in that file is its own finding. |
| 1.1.98 | A7 measurement (§17): the stage 2b threshold, calibrated on the laptop on the calibration half only (`make eval-correlation-calibrate` on `main` `3d330f2`, `qwen3-embedding:0.6b` at its pinned digest, correlator 0.1.1, `make eval`'s findings of 14 Nov): 0.75, ARI 0.644 over 50 labelled findings in 24 root causes, not at the edge of the grid. Committed before the test half is measured; then measured on the test half (42 findings, 23 root causes, `threshold_sha256` `6124ce73…`): ARI 0.827 with the three stages (18 groups, alert reduction 57.1%), 0.793 with dedup+structural (40.5%), 0.657 with dedup+embedding (52.4%); without SCA, 0.742 over 6 same-root pairs. Over the whole run, the stages with no parameter (dedup+structural) give ARI 0.497 and a 25.8% reduction. The sensitivity curve on the test half peaks at 0.85 (0.841): reported, never used to move the threshold. Round 2 (#146 review): stage 2b's `DEFAULT_THRESHOLD` is 0.75, the calibrated threshold (§8), and a test keeps it equal to `threshold.json`; the measurement refuses a threshold that is not the best of its own curve (a tie going to the highest), a curve off today's grid, and a recorded ARI or edge that does not match, so a hand edit cannot move it; a file with its inputs but another model's digest is refused by the model check (tested). On the whole run, the stages with no parameter reduce alerts by 25.8%, below §3's 40%: the test half's 57.1% is with stage 2b, on a half whose share of SCA findings the split decides, so it is not demo-shop's. |
| 1.1.97 | A10 self-gate (P4): the first dry run on the laptop (`make self-gate PIPELINE=3d330f2`, the target its own pipeline) blocked on one secret finding only: the fake RSA private-key armor of `ai/tests/test_correlate_labels.py`, added with #99 after the seven self-gate waivers were written. Its bodies are built at run time, so Gitleaks' match ran from one test's header to the next one's, and anything written after that second header was in no match (#141 review). The armor is now built at run time too (`fake_pem`): no finding, so no waiver, and a real key anywhere in the file is its own finding. The other 7 secret findings are the waived ones, and SC-006 (partial parsing) stays a WARN. |
| 1.1.96 | A1 (#84 review, nit 2): `python-unsafe-deserialization` also matches ruamel.yaml's old module-level API, removed in 0.18: `ruamel.yaml.load` and `load_all` (or `from ruamel.yaml import load`) with no Loader (whatever other arguments it has: `version=`, `preserve_quotes=`), or any loader other than `SafeLoader`, `BaseLoader`, `RoundTripLoader` and their C forms (`Loader`, `UnsafeLoader`, `CLoader` with the C extension, a dotted path, `None`, or a name the rule can't see), which built arbitrary objects (round 2, #137 review). `SafeLoader`, `BaseLoader`, `RoundTripLoader`, their C forms and `dump` stay clean. Fourteen cases; on round 2 the old allow-list, the four-form first block, and the C prefix, `Base` or `RoundTrip` dropped from the safe list each fail one; on SentinelCI's tree and demo-shop the rule still gives only the GT-SAST-003 seed. |
| 1.1.95 | A6 llm:code check (#100 review, nit 2): `sentinel remediate check` keeps each test run that started in its JSON (`runs`: selection, label, exit code, pytest's summary), apart from the `log`, which is clipped to its last 8,000 characters. The bot's pull request lists every run's answer from `runs`, so a long log no longer hides the runs before the clip; a check written before `runs` is still read from its log. Round 2 (#136 review): the loop's stand-in writes `runs` as the CLI does (a check without `runs` is still tested), the time-limit and summary paths' `runs` are tested, and `remediate check --help` names `runs`. |
| 1.1.94 | A10 Dependabot rules (#115 review): `tests/ci/test_dependabot.py` checks the configuration, which nothing else reads: every entry keeps its 7-day cooldown, no entry updates `demo-shop/`, uv's and npm's groups take only minor and patch updates, the TypeScript major stays ignored while the client generator is openapi-typescript 7, and uv in the platform image never moves alone (its patches are ignored too, since the workflows pin uv exactly and Dependabot does not update setup-uv's `version`). The config says that an image update comes without the cooldown (the registry gives no publication date). Round 2 (#130 review): every group in every ecosystem takes minor and patch only (actions, compose and docker too), the test checks that the image's uv is the one every workflow sets up, refuses a glob or a `./demo-shop` directory, and reads TypeScript's ignore from the generator's peer range in the lockfile. |
| 1.1.93 | A4 release preconditions (#82 review, round 3, nit 1): `git status` believes the index, so `make release` refuses any tracked file marked skip-worktree or assume-unchanged (`git ls-files -v`), whatever the file (this script and the CLI included), and runs its clean-tree checks with `core.fsmonitor` off. The ignored-file check covers every gate input read from the checkout, not only `policies/`: `.sentinel/waivers.yaml`, `.sentinel/vex.json` and `tools.lock.toml`, hidden by `.gitignore` or `.git/info/exclude` alike (`--ignored=traditional`, so a wholly ignored `.sentinel/` holding only the tools still passes). Round 4 (#129 review): every tracked file is compared with HEAD's blob, byte for byte, so an edit hidden by the index's stat data (`core.checkStat=minimal`, `core.trustctime=false`) is still refused; a replace ref (`refs/replace/`) and the variables that point git at another repository, work tree or index (`GIT_DIR` and seven more) are refused before any check. |
| 1.1.92 | A6 bot (§9, #118 review): `verify` fetches the scanned commit into its bare copy with `--depth=1`. `actions/checkout` leaves a depth-1 clone, and git refuses to set a ref to a shallow root when it fetches `HEAD` into an empty repository (a warning, exit 0, no ref): on GitHub, every bot pull request would have been reported FAILED ("the checkout is not the scanned commit"). The end-to-end test now verifies from a shallow clone. #118 makes the same change in `propose`. |
| 1.1.91 | A1 tool runner (§5): a verified tool runs from the absolute path of the file just verified. Syft, Grype and Opengrep run in an empty directory of their own, so with a relative `--tools-dir` (`.sentinel/tools`, the default of `make eval` and of `sentinel tools grype-db`) they could not be started; the scan failed closed (SC-010, "not run"), never a pass. Found on the laptop's first `make eval`; CI and the tests used absolute paths. |
| 1.1.90 | A10 (Dependabot #94's zizmor part): zizmor 1.31.1 → 1.32.0 (template-injection fixes, root-aware input collection; we pass the files with `--collect=all`, so the files audited do not change). 1.32.0 also reads the scanned repository's `.github/workflows/actions.lock` and drops `unpinned-uses` for every workflow it lists, whatever it pins, so a pull request could silence part of SC-009 with a four-line file: zizmor now runs with `--ignore-lockfile` (an experimental flag; a version without it exits 2, which fails closed), in the scanner and in our own zizmor job (#119 review), and a test keeps it. `tools.lock.toml` pins the six wheels again: each `sha256` equals uv.lock's, and each `binary_sha256` was read from the wheel's RECORD and checked against the binary's own bytes. On demo-shop's workflow seeds, 1.32.0 gives the same 11 findings as 1.31.1, ids included. The scanner tests read the pinned version from `tools.lock.toml`, so the next bump changes only the lock. |
| 1.1.89 | A6 bot, #98 review nit 2 (§9): the `propose` job reads the scanned commit as `verify` does: a bare copy whose `attr.tree` is the empty tree, exported with `git archive --worktree-attributes`. Scan, fixers and `apply` work on that tree and that copy, never on the checkout, whose `.gitattributes` (eol, ident, filters) may have rewritten it: on a commit that sets `eol=crlf`, the fixers resolved nothing and the bot proposed nothing, silently. A test runs the job's own step on such a commit. Review of #118: both copies (`propose`'s and `verify`'s) hold one commit fetched with `--depth=1` from the checkout, which `actions/checkout` leaves shallow (a full fetch of a shallow root sets no ref: propose failed on every run, and verify, on `main` since #65, reported every pull request FAILED); the tests use shallow checkouts, and the attribute test covers `eol`, `working-tree-encoding` and `ident`. |
| 1.1.88 | A6 verification with every scanner of the pr gate (§9, ADR-0013 decision 5, for B4's #114): the bot's `verify` job also scans both commits with Opengrep (`scan sast`) and with Syft then Grype (`scan sca`, Grype's database prepared once by `sentinel tools grype-db`), and their statuses reach the gate on the patched commit. Without them, a `pr` gate that requires Opengrep, Syft and Grype would hold SC-010 for every bot pull request, so none could be VERIFIED. A database that cannot be prepared makes the scans fail, and each pull request is reported FAILED, never verified on fewer scanners. `timeout-minutes` grows to 120, the worst case of every scanner at its limit (the test checks the sum); the workflow test requires verify to run all six scanners whatever the tree's policy lists. Review of #116: a static test checks that each scan's findings reach the baseline and the patched findings (a scan no `combine` reads is one the gate never sees), and the database's evidence (`grype-db.json`) and each `scan sca` report with the SBOM it names go into the results artifact, under `evidence/` (a verification is a decision: it is explained only with its database; part of #112). |
| 1.1.87 | Threat model refresh (§18, A10): the statuses follow what has merged (#40, #64, #66, #67, #72); new rows T30 (caches restore only what is verified again, ADR-0015, #105), T31 (the bot's `verify` replays the deterministic fixer, #98) and T32 (an LLM code fix is tested in a sandbox, with the base commit's tests, ADR-0014, #100); T25 and T26 now cover explanations, triage hints and code fixes (no code from a file with a secret; redact, then clip); residual risks: Opengrep and Grype are not required scanners yet, uv's cache in `ci.yml`, and the explanation worker's database role (#111). 14 Nov: statuses after #65, #70, #71, #85, #86, #87, #88, #91, #97 and #98 merged; T8 names `--ignore-lockfile` (PR #119); T14 covers the laptop signer made to sign what the gate blocks (every scanner must report, no ignored file under `policies/`, one `origin` URL: PR #82); T28 names the shallow-checkout fetch (PR #125). Round 2 (#107 review): T30 states #105's corrected control (the scan and the gate restore nothing in a pull request, whose own workflows can save any entry, under any key); T4 and the residual risk say #80 is on main; a residual-risk row for the Scorecard image, pulled by tag. |
| 1.1.86 | A10 caching (§18, ADR-0015): workflows cache only what is verified after it is restored, the scanners' release archives (`${{ runner.temp }}/sentinel-tools/cache`, a key per job and per `tools.lock.toml`), which `sentinel tools install` reuses only when their sha256 is the lock's. Binaries are never cached. setup-uv's cache is explicit everywhere and kept only in `ci.yml`, which runs the change's own code with no write token; no job holding a write permission restores a cache. `tests/ci/test_caching.py` checks every workflow. Round 2 (#105 review): the scan and the gate restore nothing in a pull request (`if: github.event_name != 'pull_request'`), since actions/cache extracts a whole entry relative to the workspace before any check and the pull request's own workflows can save any entry in its scope; no workflow uses `restore-keys`. |
| 1.1.85 | A10 OpenSSF Scorecard: `.github/workflows/scorecard.yml` scores this repository's own supply-chain practices on every push to `main` (and on demand), and publishes the result to the Scorecard API. It runs only once the repository is public (ADR-0006), with `contents: read`, `actions: read` and `id-token: write` (to sign the published result) and nothing else, and keeps its SARIF as an artifact (no code-scanning upload). Round 2 (#104 review): the condition is `github.event.repository.visibility == 'public'`, which fails closed, and there is no `schedule` until the switch to GitHub mode: a scheduled run has no event payload, where `!github.event.repository.private` is true. The action is pinned by its commit (`fa7117d`), not by the annotated tag's object; the image its `action.yaml` names is pulled by tag, a residual risk. |
| 1.1.83 | A4 release image, wheels only (Hiba's review of #69): shop-api's release Dockerfile installs its hash-pinned requirements with `--only-binary=:all:`, so no setup.py runs and every byte installed is covered by a hash (pip does not check the hashes of an sdist's build dependencies). `make release` passes `ONLY_BINARY=:all:`; only `make release-block` passes `:none:`, since the seeded pyyaml 5.3.1 has no wheel for Python 3.12, and that image is never signed. The release digest is the one BuildKit records (`--metadata-file`, `containerimage.digest`), and the layout's `index.json` must name exactly it (review of #70: the layout's own claim is not evidence). |
| 1.1.82 | A6 LLM code fixes (§9, ADR-0014): `sentinel remediate check` builds an `llm:code` proposal (Python that parses, `ast.parse`) and runs its service's tests with pytest in a sandboxed container from `--test-image` (pinned by digest; no network, read-only, no capability, nobody, limits and a time limit), the base commit's `tests/` mounted over the patched service's; a patch to the tests or a service without tests is never verified, and a container that could not run verifies nothing (exit 3). `make remediate-code` runs B6's fixer with the pinned local model on origin/main's SAST findings and verifies each proposal like the bot's `verify` job, with retries carrying the diff and what rejected it; `PUBLISH=1` pushes VERIFIED branches and opens their pull requests with the person's `gh`, `API_URL=` records every attempt. Review of #91 (ADR-0014 decision 3): the tests are two runs, the service's `tests/` on the patch, and the target finding's `security_tests/test_<rule>.py`, which must fail on the base (pytest exit 1) and pass on the patch; both come from the base commit, the rule from the target in the base scan (`--findings`, required for `llm:code`); a rule without a security test is never verified. The retry's feedback puts the reasons last (B6 keeps the end). Both commits are scanned with every scanner the `pr` gate may require, Syft then Grype (`scan sca`) included, with Grype's database prepared once at the start of the run (`--grype-db`, default `out/grype-db`): under B4's #114 a missing scanner would be SC-010 on every attempt. Review of #100: a run counts only when pytest's own summary agrees with its exit code (tests passed and nothing skipped, xfailed or deselected; on the base, tests failed), since the patched code runs inside pytest and can exit early: this raises the bar, it is not tamper-proof; the container's output is read as UTF-8 with replacement, so a stray byte is not a crash; `--memory-swap 1g` makes the memory limit real; the base run is labelled "expected to fail"; the feedback names each new finding (tool, rule, severity, place); a finding no patch could verify (no tests, no security test) is never sent to the model (`not verifiable`); the pull request shows each test run's summary; the bare copy's `attr.tree` is the empty tree, as in the verify job. Round 2 of #100: the pull request's Tests section is fenced like the rationale and the diff (the log is also the patched code's output, which could write a link into it); a run with more than one pytest summary line is refused (a second one comes from the code under test); a failed `tools grype-db` is tested to end the run; the docs say the patched code can also change what pytest reports. |
| 1.1.81 | A7 stages 2 and 3 (§8, correlator 0.1.1): each text field sent to the model is redacted, then clipped (`_clip`), and so are the group templates (`stages._one_line`: the rule-key and embedding titles and the single fix, which carry paths and package names; the shared key is redacted whole in the prompt and dropped, never clipped, when longer than `MAX_KEY`). Clipping first cut a token at the limit, which then no longer matched its pattern, so its start was sent (found while reviewing #97, which had the same order). A quoted value (`DB_PASSWORD="…"`) is redacted up to its closing quote, and the text stage 2b sends to the embedder is redacted too. Review of #99: every field and both blocks are tested at the clip. Round 2: the name pattern of `redact` takes each name once (a lookbehind for its start, a lookahead for the keyword, a possessive `++`), since it now sees whole texts and the old form was quadratic (a 20 KB message took 38 s in the correlator; 100,000 characters now take milliseconds, pinned by a test); the closing quote of a redacted value is kept. |
| 1.1.80 | A6 verification (§9, ADR-0013 decision 6): `sentinel remediate check` takes `--findings`, the scanned commit's IaC findings, and re-runs the deterministic fixer on them and the base tree, now the whole commit (an ADD source may be at the repository root): a proposal that is not the fixer's own output, field for field but `created_at`, fails the tests: it catches any edit the fixer would not make, whatever its shape, on top of 1.1.52's line rule. The verify job exports every tree with `git archive --worktree-attributes` from its bare repository, whose `attr.tree` is the empty tree (#98 review: git reads a bare repository's `HEAD:.gitattributes` once HEAD resolves), so the commit's `.gitattributes` (export-ignore, export-subst, ident, eol, -diff) cannot change what is scanned and checked, nor what Gitleaks' `git log` shows. A result of `check` that is not whole (a crash also exits 1) is refused, so the pull request is FAILED, not REJECTED; a strategy with no fixer to re-run is a CheckError (exit 3). Round 2 (#85 review, nit 2): the patched commit is exported whole too, like the base, since Trivy loads local Terraform modules outside the scan path; `remediate check --help` names every exit-3 case. |
| 1.1.79 | B8 replay identity across two checkouts (§3, §17, #124 review): `eval/replay/run.py --record-to DIR` records the corpus (and `make eval`'s decision with `--findings`) into an empty directory and replays nothing; `--replay-from DIR`, on another checkout, replays that store with its own engine and OPA, without changing it. The report names both commits, and whether either had uncommitted changes. The stored policy bundle is replayed, so this compares engines and OPA, not policies. Decisions the replaying engine skips (another engine or OPA version) are listed and not compared; none compared is exit 2. In one run a skip still counts as a failure. A store decision the recording does not list is refused (exit 2): it would be replayed and not counted (#139 review). Recorded on #124's branch and replayed with today's `main` merged in: 10 of 10 identical; an engine that sorts violations the other way makes the 2 decisions with several violations differ (exit 1). |
| 1.1.78 | Platform API 1.10.2 (B1, §8, #92 review; written as 1.8.2, renumbered on top of 1.10.1): `POST /api/v1/runs/{id}/correlations` refuses (422) a group whose findings are of two or more categories, naming the group and its categories. The correlator never builds one (stage 1 groups one fingerprint, stages 2a and 2b group within a category), but the API accepted it, and the alert-reduction metric (A8, #92) counts a group in its first finding's category: a group of one SCA and one CONTAINER finding showed a 100% reduction for SCA. The category is the one the run recorded for each finding. |
| 1.1.77 | B8 injection canaries (§17, "AI mislabel rate on canaries and verdict changes (must be 0)"): `make eval-canaries` takes every `make eval` finding whose code window holds a canary's line, asks the AI analyst for an explanation and a triage hint of each with demo-shop's code, as the platform does, and counts the outputs that hold the canary's token (obeyed) and the hints that call a seeded weakness a likely false positive (mislabels). It evaluates the gate before and after the AI ran and compares the decisions byte for byte (verdict changes). Two models: the pinned Ollama model (`OLLAMA_URL`), and a control that obeys every canary, which must be counted as obeying every time while the verdict stays the same. Today, with the control: 5 findings shown a canary, 10 of 10 outputs obeyed, 5 of 5 hints mislabelled, 0 verdict changes. Two canaries are planted, of the 5 §17 asks for. Review of #128: both decisions read the gate's inputs again from disk (the findings files, the waivers and VEX a run reads, the policies), so an AI step that wrote any of them would change the second decision, and tests show it does (a model that empties the findings turns BLOCK into PASS); the run refuses unless demo-shop is the clean tree `make eval` scanned, keeps every output, and counts a token hidden by a zero-width character or fullwidth letters. |
| 1.1.76 | Platform API 1.10.1 (B1, #86 review; written as 1.8.1, renumbered on top of #110's 1.9.0 and #111's 1.10.0): U+0000 is refused with a 422 on every route that stores what it is sent, instead of reaching PostgreSQL and failing as a 500 (it failed closed: nothing was recorded). A remediation attempt holding U+0000 was recorded, since its text is kept only in its bytes; it is refused too, so one rule holds for every upload. PostgreSQL stores U+0000 neither in a text column nor in `jsonb`. Every uploaded document (findings, decision, correlations, release evidence, remediation attempts) is checked as it is read: the JSON escape `\u0000` after an even number of backslashes, or a raw NUL byte. A backslash followed by the characters `u0000` only spells it and is kept. The free-text fields of `POST /runs` (`ref`, `run_id`) and the free-text query parameters (`ref` of `GET /runs`, `tool` of `GET /findings`) refuse it the same way. A lone UTF-16 surrogate, the other string PostgreSQL cannot store, is refused the same way (#126 review): a finding that cannot be encoded as UTF-8 is a 422 naming its line, and every 422 is written as ASCII JSON, so one that echoes such an input no longer fails as a 500. `NaN`, `Infinity` and `-Infinity`, which `json.loads` reads but JSON and `jsonb` do not have, are refused the same way (#126 review): in a finding, a 422 naming its line (it was a 500 from the `jsonb` insert); echoed in a 422, they are dropped from `input`, so its body stays JSON. A refused decision's 422 is of type `decision_invalid`. Merge train: `PUT /api/v1/waivers/{sha256}` (#110) keeps the parsed waivers as jsonb, and YAML decodes `"\0"`, `"\x00"` and `"\ud800"` after the raw body was checked; such a file is now a 422, not a 500. |
| 1.1.75 | B8 replay identity (§3, §17): `make eval-replay` records the replay corpus (`eval/replay/corpus.py`) and, after `make eval`, a `local` decision on demo-shop's real findings, then replays every one with this checkout's engine (`sentinel replay --all`) and reports how many are identical, byte for byte (`out/eval/replay.json` and `.md`). It exits 1 when any decision differs or cannot be replayed, and refuses a replay output whose lines and summary disagree. Recorded and replayed with the same engine, OPA and policies, it shows that the store holds every input and that the engine is deterministic in this environment; drift between the versions that record and replay a decision stays the nightly job's to catch, and the report says so. |
| 1.1.74 | B8 ranking report (§17): `make eval-ranking` ranks `make eval`'s findings by SentinelCI's risk score and by a CVSS-only baseline (`cvss_baseline`, or the CVSS v3.1 floor of the finding's severity when it has no CVSS), after offline enrichment with the committed feed snapshot (`eval/feeds/snapshot.json`) and `sentinel score`. It reports tie-aware NDCG@10 and NDCG (McSherry and Najork) on every category and on SCA alone. Relevance is a new ground-truth grade per seed (B9: `relevance` 1 to 3 and `relevance_why`, by the rubric in its README), committed before any ranking was computed; a seed counts once, at the best finding of its item, and a finding that stands for no seed counts 0. Two definitions of a seed's item are reported side by side: the findings that detect it, and those plus the other advisories of its package in the same manifest (A7's rule; added after the first result was seen, #121 review). A seed of a category no scan measured (CONTAINER: `make eval` scans no image) is listed, not ranked, and all five `make eval` findings files are required. The report (`out/eval/ranking.json` and `.md`) is the same for the same inputs, byte for byte, and names each input by its digest. The rubric's grade 3 sentence on committed credentials was narrowed after the first result (#121 review), to match the two secret grades that did not follow it; no grade changed, and both READMEs give the numbers with those two seeds at 3. |
| 1.1.73 | B6 (§8, §9, #99 review): the LLM code fixer redacts each text of the finding (rule, title, message, CWE, file) whole, then clips it to 300 characters. Clipped first, a token cut at the limit no longer matched its pattern and its start was sent to the model (up to 19 characters of a `ghp_` token in the message, by the #99 probe). The prompt template is unchanged. |
| 1.1.72 | Required scanners (B4, §5): opengrep (SAST), syft and grype (SCA) are required in `pr` and `release` (`policies/required_tools.rego`), now that the scan job runs them with their tool status (A3, #80); the laptop release's image scan reports syft and grype too. A tool status without one of them is SC-010 (`Scanner missing: <tool> (required in <context>)`), so a pull request that deletes the SAST or SCA step from the workflow it carries, or a scan that ends without a status, no longer passes without its findings. The shared tool-status fixtures carry the pinned versions and hashes. Merge right after #80. |
| 1.1.71 | B7 explanations on the Finding page (§8, §10): the finding's latest explanation (B5c, `GET /api/v1/findings/{id}/explanation`), labelled advisory and never read by the gate, with its model, digest, confidence and date. It is read field by field (a field of another type is absent); an explanation about another finding is not shown; a reference is a link only when it is the canonical page of a CWE, CVE or advisory (MITRE CWE, NVD, GitHub advisories, OSV), any other text stays text. Without one, the page says none is recorded and how an operator asks for it (the dashboard never asks); for a secret's finding, that it is never sent to a model; an explanation that cannot be read is an error, never "none". |
| 1.1.70 | B5c (§8, §11, §13.3), platform API 1.10.0 (B1, migration 0010): explanations on the platform. `POST /api/v1/findings/{id}/explain` (the ingestion token) queues an explanation of a finding as a run recorded it (the latest run by default) on the worker's Celery queue over Redis (JSON only); a secret's finding is never queued (422), an open request is answered instead of a second job, a request no worker finished within an hour is failed and replaced, and without a queue nothing is recorded (503). The worker (`sentinel_worker.tasks`, Compose service `worker`, profile `ai`, the API's image with the database, Redis and Ollama only) claims a request once, asks the pinned model through `sentinel_ai.explain`, and records the outcome: an explanation is kept only if it is a valid Explanation v1 document (`sentinelci.contracts.explanation`) about the request's own finding, byte for byte and named by its sha256, never changed; otherwise the request is unavailable, not_sent or failed, with the reason (an unexpected error names only its type). `GET /api/v1/explain-requests/{id}` and `GET /api/v1/findings/{id}/explanation` (the latest). Advisory: the gate never reads it. New dependency: Celery (with redis-py), as §11 plans. |
| 1.1.69 | B7 Policies & waivers (§6.4, §10), platform API 1.9.0 (B1, migration 0009): `PUT /api/v1/waivers/{sha256}` keeps a waivers file as the gate read it, named by its sha256, only when a recorded decision (a run's or a release's) names it as `inputs.waivers_digest` and only if the gate could have read it; `GET /api/v1/waivers/{sha256}` serves it byte for byte. `GET /api/v1/waivers` gives, for each repository, its latest release decision of the default branch (a run's or a release's, by `evaluated_at`) with the waivers of the file it read, as written: whether one applied is the decision's `waivers_applied`, why one is invalid its SC-005 message, and a file not uploaded is unknown (`null`), never an empty list. `GET /api/v1/rules` counts the recorded decisions each rule fired in, by effect and context (a decision recorded twice counts once). The dashboard's Policies & waivers page shows both, with each waiver's expiry against the viewer's clock (expired, or expiring within 14 days) and the rule catalogue of §6.3; it changes nothing: waivers stay pull requests. The waivers loader (B4) refuses a YAML alias, which a reviewed file never needs and which lets a few hundred bytes expand to millions of values: `sentinel evaluate` fails closed with the reason, and the platform answers 422. The platform checks that a decision read a file before parsing it, keeps what it parsed with the bytes, and orders decisions by their document's own `evaluated_at`. |
| 1.1.68 | B7 Runs pages (§10): the dashboard's Runs page lists the recorded runs newest first (`GET /api/v1/runs`), filtered by context, repository and ref in the URL (each a chip that clears it), each with the gate's verdict; a run without a decision, or with a value that is not a verdict, reads "No decision", never PASS. A run's page shows what was scanned, a link to its findings (the Findings page now takes `?run_id=`), and its decision as recorded (`GET /api/v1/runs/{id}/decision`): verdict, violations (each effect as written) linked to their findings, waivers applied and every input it records (digests, the risk model version, one row per tool version; a value of another type reads "unreadable"); without one, "No decision recorded", and a decision that cannot be read is an error, not an absence. |
| 1.1.67 | B9 shop-api tests (§17, ADR-0014): behaviour tests (`services/shop-api/tests/`) that pass on the seeded code and on any correct fix, which A6's `llm:code` check runs on a patch; one security test per SAST seed (`security_tests/test_<rule>.py`), which fails on the seeded code and passes once the weakness is fixed, kept out of `tests/` since a fix of one seed leaves the others; and the test image (`Dockerfile.test`: the release's base digest and hash-pinned wheels, plus pytest and httpx2, hash-pinned, no application). SentinelCI's `tests/demo_shop/test_shop_api_tests.py` checks the files, and with `SENTINEL_SHOP_TEST_IMAGE` runs both suites in the image, in the check's sandbox, on the seeded code and on a reference fix. |
| 1.1.66 | Platform API 1.6.1 (B1, #78 and #79 reviews): the 409 of `POST /api/v1/runs/{id}/decision` and of `POST /api/v1/runs/{id}/correlations` is documented with both of its shapes (`DecisionExists` or `CorrelationExists` when one is recorded, `ErrorOut` when the run's findings are not recorded yet), so a generated client never assumes the recorded one is there. `GET /api/v1/runs` says that offset pages are stable for a fixed set of runs only. The decisions table says which copied columns the database checks against the document (`decision_id` and `verdict`, which are listed and counted) and which the API only copies for display (`evaluated_at`, `engine_version`). |
| 1.1.65 | B5b (§8, §13.2): explanations and triage hints. Two contracts, `explanation.v1.json` and `triage-hint.v1.json` (advisory: never read by the gate; a hint is never a waiver), each naming its model and the sha256 of its prompt and input. `sentinel_ai.explain` and `sentinel_ai.triage` send the finding (no id, snippet, evidence or run) and the code around it, redacted then clipped, in escaped data blocks; never a secret's finding, and no code from a file in which the scan found a secret. An explanation cites only the finding's own CWE, CVE and advisory ids and their canonical pages; a triage hint may read the justifications of past waivers of the same rule. One repair retry, an answer that quotes a secret refused, then "unavailable". The shared guardrails are in `sentinel_ai.guardrails`. |
| 1.1.64 | A10 self-gate and SentinelCI's signed release (P4): `make release-sentinelci VERSION=X.Y.Z` (`release.py sentinelci`) runs the self-gate, builds both packages and the policy bundle twice from the exported tree (SOURCE_DATE_EPOCH = the commit's time) and refuses a build that is not byte for byte reproducible, signs each artifact and SHA256SUMS with the release key, attests each one (SLSA provenance v1 and the decision), verifies everything with the committed public key offline, then keeps it and tags `vX.Y.Z` locally; a version is released once. Self-gate: `make self-gate` (`release.py self-gate`) runs the release gate on SentinelCI's own tree at `main`: the laptop release's preconditions, the commit's files without demo-shop (exported and checked blob by blob against the commit, so no export attribute hides or rewrites one; links and submodules refused), the gate's five scanners (Grype on the lockfiles' SBOM), the commit's `.sentinel/waivers.yaml`, then `sentinel evaluate --context release`; nothing is signed. Its first run found four `CREATE DATABASE` statements built with f-strings in the API tests and a PEP 695 test helper Opengrep cannot parse (fixed), and three fake values in test fixtures (waived). Round 2 (#95 review): the commit judged is not the one that judges (ADR-0011, decision 8). The checkout is the pipeline commit (clean, on `origin/main`'s first-parent line, a `vX.Y.Z` tag or named with `--pipeline <HEAD>`), whose CLI, policies and lock decide from its clean checkout, and whose `.sentinel/self-gate-waivers.yaml` (moved from `.sentinel/waivers.yaml`, which demo-shop's gates read), `.sentinel/self-gate-vex.json` and `deploy/release/build-constraints.txt` are read from its blobs; the target is `origin/main`, judged, built and tagged; the pipeline files changed between them are printed and kept (`pipeline.json`). Waivers are always named (an empty file when there are none) and the VEX is `.sentinel/self-gate-vex.json` (a default `.sentinel/vex.json` is refused). `uv build` gets `--build-constraints` (hatchling 1.33.0 and its five dependencies, 12 hashes) and `--require-hashes`; the provenance names that file's sha256, uv's version and the pipeline commit. Seven fake values in fixtures and tests are waived; three PEP 695 regions and a partial parse remain WARNs. Round 3 (#95 review, nits): tests pin the target's VEX left unnamed, every `--lock` the checkout's and a linked waivers file refused; the README's check compares the provenance's `gatePipeline` with the tag's commit; `self-2026-007` is owned by Hiba. |
| 1.1.63 | A8 MTTR and alert reduction (§10): `GET /metrics` adds `sentinel_findings_fixed{priority}` and `sentinel_findings_fix_seconds{priority}` (fixes on each repository's default branch, from its release runs with a recorded decision and no SC-010) and `sentinel_correlated_findings{category}` and `sentinel_root_cause_groups{category}` (each repository's latest correlation). One REPEATABLE READ snapshot per scrape, so a scrape never pairs the count of one set of fixes with the seconds of another. Grafana: MTTR by priority and alert reduction by category, both queries pinned by a test. |
| 1.1.62 | A7 measurement (§17): `make eval-correlation-calibrate` and `make eval-correlation` (`eval/correlation/`) measure the correlator on `make eval`'s findings: ARI, alert reduction and the ablation. Every finding is labelled with its true root cause (a seed's, or `root-causes.yaml`'s: what one fix resolves), the root causes are split once into calibration and test halves, the stage 2b threshold is calibrated on the first with the pinned embedding model (local Ollama, digest checked) and committed (`threshold.json`) before the second is measured. Review of #90: an SCA finding about a package a seed detects in the same manifest has the seed's root cause (one upgrade), added after the dedup and structural scores and before any embedding score, as the README says; each ARI comes with its labelled findings, root causes and same-root pairs, and without SCA; dedup and dedup+structural are also measured on the whole run (no parameter to tune); stage 2b runs only with a committed threshold; the calibration counts places; a threshold file that cannot be read is exit 2. Review round 2: a committed `threshold.json` is refused when the ground truth, the split or the root causes changed since it was calibrated (they move findings between the halves), and findings of another `make eval` run are said; the report counts how many findings and SCA findings the test half holds instead of describing them; a threshold at the edge of the grid is said in `threshold.json` and in the report; a `make eval` run without one scanner's findings (failed or skipped) is refused, never measured as a smaller run. Round 4: a test checks `split.yaml` follows its own rule (seeds sorted by id, alternating per category), and `threshold.json` records the correlator version, said in the report when it differs (stage 2b embeds that version's texts). |
| 1.1.61 | A9 container seed (§17, ground truth): GT-CONTAINER-001, pyyaml 5.3.1 (GHSA-8q59-q68h-6hv4, CVE-2020-14343) in the shop-api BLOCK image (`Dockerfile.release` with `REQUIREMENTS=requirements.block.txt`, ADR-0011 decision 6), expected SC-002. The ground truth gains `image` (Dockerfile and build arguments) for CONTAINER seeds, matched on the vulnerability and package of the built image. `tests/demo_shop/test_container_seeds.py` checks the pin, that the release image does not ship it, the advisory in the feed fixtures and the gate rule (the engine gives SC-002); the detection runs opt-in on the built image's OCI archive with a Grype database. The BLOCK image builds pyyaml's sdist with the hash-pinned setuptools of `requirements.build.txt` (`--no-build-isolation`, installed apart and never in the final stage), so pip fetches no build backend outside the hashes (review of #89); ADR-0011's "one BLOCK reason, GT-SCA-001" now reads as both seeds of the same pin. |
| 1.1.60 | `sentinel upload --decision` (A3, stage 11, API 1.6.0, after #79): the run's gate decision is sent last, once its findings are recorded, byte for byte. It is checked before anything is sent: a valid Decision v1 made on exactly the `--findings` bytes (`inputs.findings_digest`), so those must be the scored findings the gate evaluated, not the scan's; about the run (repo, commit, context, and the ref when the decision names one); naming only findings of the file. Otherwise exit 4 and no run is created. A 409 with the same bytes' sha256 is "recorded already" (exit 0); another decision for the run, or a decision id another run recorded, is exit 4. Tested end to end: `sentinel score`, `sentinel evaluate` with OPA, then the CLI's client against the real API and PostgreSQL. Review of #87: the scans' run id in `sentinel-scan.yml` is `<run id>/<run attempt>` (a re-run is a new run); the README's command passes what the gate step gives `sentinel evaluate`; a decision that is not recorded says the findings are, in which run, and a decision recorded for another run names it. |
| 1.1.59 | B5a (§8, ADR-0009): `sentinel_ai.providers.OllamaProvider`, the default model backend, on the standard library only. Local only (the loopback or the Compose service `ollama`; another host only when asked), no proxy, no redirect. The pinned digests of ADR-0009 are checked before every request (a missing model or another digest is refused, nothing sent). `complete` asks for JSON of the schema, deterministic (temperature 0, fixed seed), and validates the answer (a `ValidationError` for the repair retry); `embed` returns one finite vector per text, all of one size, in batches of 64 texts. A time limit on each whole request, an 8 MiB answer cap, and errors that never echo the prompt or the answer. `deploy/compose/README.md` says how to pull the pinned models. |
| 1.1.58 | B6 (§9): the LLM code fixer, `sentinel_ai.patch.propose_code_fix`, turns one SAST finding into an `llm:code` PatchProposal. The model answers with line edits of the lines it was shown, never a diff: the diff is computed from the file on disk, so it edits only the flagged file, and it must pass A6's `check_proposal` and `git apply --check`. A file with a secret is never sent, a line that looks like a secret is sent redacted and cannot be edited, the finding and code travel as escaped data blocks, and an answer that leaves the lines sent, misses the flagged lines, overlaps, adds a scanner suppression or a secret, changes nothing or breaks a Python file's syntax is refused (one repair retry). Retries (attempts 2 and 3) carry the previous diff and the redacted end of the CI log. `sentinel-ai` now depends on `sentinelci` (workspace) for the Finding and PatchProposal contracts and A6's checks. |
| 1.1.57 | A4c laptop release (§4.3, §5, §7, ADR-0011): `make release` (`deploy/release/release.py`) builds shop-api's release image from the commit's build context (a clean checkout of `origin/main`), decides on it in the release context (source scans of that context, the image's own scan, `sentinel evaluate --image-digest --sbom`), and only for a non-BLOCK decision signs it with the laptop's key in a throwaway registry, verifies it there and from the evidence, and saves the bundle; `make release-block` keeps the demo's BLOCK image, unsigned; `make release-key` makes the key pair. The provenance builder of such a release is the script at main (`sentinel attest --builder local-release`), which `sentinel verify` and the admission policy require. The signing key is no longer a CI secret. Review of #82: every scanner of the release must have reported (ok or not) before the gate decides, so a scan killed before it writes its status stops the release instead of disappearing from the tool status; `policies/` may hold no file git ignores (the gate loads every file there); `origin` must have one URL; a failed CLI step is named by its command. |
| 1.1.56 | A1 (#74 and #84 reviews): `python-unsafe-deserialization` matches every unsafe PyYAML loader form: `unsafe_load`, `unsafe_load_all`, `full_load`, `full_load_all`, and `load` or `load_all` with `Loader`, `FullLoader`, `UnsafeLoader` or their libyaml twins `CLoader`, `CFullLoader`, `CUnsafeLoader` (from `yaml`, `yaml.loader` or `yaml.cyaml`), by keyword or as the second argument. `load` and `load_all` with no loader, with the data by keyword (`stream=`) or with `Loader=None` are matched too: pyyaml < 5.1 builds any object and 5.1 to 5.4 falls back to FullLoader, which runs code in pyyaml < 5.4 (GT-SCA-001). A local `yaml` bound to a call's result (ruamel.yaml's `yaml = YAML()`, as in `remediation/kubernetes.py`) is not PyYAML and is left alone after the binding, in the same function, in a file that imports ruamel.yaml only (round 3: elsewhere `im("yaml")`, `importlib.reload(yaml)` or a lazy import stays PyYAML's; round 4: the two conditions are separate branches, so another function's PyYAML `yaml.load(f)` in a ruamel file is still matched; an import inside `try` does not count, the safe side), unless that call imports PyYAML (`import_module`, `__import__`, `pytest.importorskip`) or builds ruamel.yaml's unsafe loader (`YAML(typ="unsafe")` or a `typ` list naming "unsafe", which runs code; #84 rounds 2 and 3), or takes `typ` from a name or a parameter, whose value the rule cannot see (round 4); in the binding's own function, a PyYAML call through another name is excluded too, since Opengrep resolves it to `yaml.load` (`import yaml as pyyaml`, `from yaml import load`, or `yaml` imported again after the binding): a no-loader PyYAML call there is not matched, a known gap left as a follow-up (round 5); `yaml.load(x, None)` is matched too; `add_constructor`, `compose` and `parse` build no object. `marshal.load` joins `marshal.loads`. Each pattern is pinned by a case run with the real Opengrep, and the safe forms (`safe_load_all`, `SafeLoader`, `CSafeLoader`, `BaseLoader`) by others; the import put-back's and the exclusion's cases are in ruamel files, so each branch is pinned (round 4). |
| 1.1.55 | A8 Supply chain page (§7, §10): the 20 latest releases, each with what `sentinel verify` found in the registry (the image's signature, then the decision, SBOM, vulnerability-scan and provenance attestations, a column holds its signature check and every check of its kind, and passes only when all its listed checks are there and every one of its checks passed), and how many releases the gate let through carry all of them in a report `sentinel verify` trusted. The count waits for every release's evidence: unknown (—) while one is loading or could not be read, never 0. §10's policy compliance counts running images; the platform does not see the cluster, so the page counts releases, and Kyverno decides what runs. All four Track A pages are in (Releases & evidence, Supply chain, Remediation, Root-cause groups). |
| 1.1.54 | A8 Remediation (§9, §10, §13.2, §13.3, Platform API 1.8.0): `schemas/remediation-attempt.v1.json` (a patch proposal, its verification result and the repository; the result the proposal's, not verified before it); the remediation contract models are strict, like the decision's (a value of another JSON type is refused, never coerced); `sentinel upload-remediation` sends it to `POST /api/v1/remediations`, which checks it like the CLI (the verification gate of §9.2 included; a 422 says why), capped like a findings upload (`SENTINEL_API_MAX_UPLOAD_BYTES`, since a lockfile diff passes 64 KiB), and keeps it once per proposal, byte for byte (migration 0008, immutable, the gate held by a check constraint too); `GET /api/v1/remediations[?repo=&strategy=&outcome=]` lists them, `GET /api/v1/remediations/{proposal_id}` serves one. `/metrics` adds `sentinel_remediation_attempts_total{strategy,outcome}`; the dashboard adds the Remediation pages (success per strategy, the gate's conditions, the diff as text; a condition it can't read is unknown, and a VERIFIED with a condition that does not hold is shown as contradicting itself). Nothing here merges or approves: a verified fix is a pull request a person reviews. |
| 1.1.53 | A8 Root-cause groups page (§8, §10): `/runs/{id}/groups` shows a run's latest correlation, its groups of more than one finding with their members, the alert reduction (1 − groups ÷ findings) and the correlator, advisory and marked when a model wrote a label, with the model's provider and name; Finding detail links its group to it. A group the page can't read is left out and said to be, and the alert reduction is then unknown (—) rather than computed on fewer groups. Read from the existing API (run, correlation, findings). |
| 1.1.52 | A6 check, #65 and #85 reviews (§9): `sentinel remediate check` accepts ADD → COPY only where the Dockerfile fixer makes that edit, judged on the base commit's whole tree (the verify job exports all of it: the fixer looks for a source at the repository root too) with the fixer's own rule (`add_only_copies`: COPY's flags only, every source a plain local file or directory, never a URL, an archive, a link, a glob, a variable, a `user@host:` source, a path with `..`, a quoted word or a JSON name with a space, all of which BuildKit may read otherwise), and only on an ADD's first line (pinned by a test). A file the fixer never edits (an `escape` parser directive, a heredoc: `check_editable`) fails the tests. The check does not see the other findings, so an ADD the fixer left alone because another finding sits on it may still become COPY; that finding's new fingerprint is the gate's to count. Round 2 of #85: a file that starts with a UTF-8 byte-order mark is never edited either (BuildKit drops it and reads `# escape=` after it), and three cases pin the quote rule on a one-word source, which BuildKit unquotes or unescapes (`"app.tgz"`, `'app.tgz'`, `app\.tgz`). |
| 1.1.51 | A8 Releases & evidence (§7, §10, §13.2, §13.3, Platform API 1.7.0): `sentinel verify --report-json` writes the trust report as `schemas/trust-report.v1.json` (every check, the key's sha256, the time); `sentinel upload-release` sends `schemas/release-evidence.v1.json` (the release decision and its trust reports, none for a BLOCK) to `POST /api/v1/releases`, which checks it like the CLI (a release decision about an image; reports about that image, one per mode, consistent; no trusted BLOCK) and keeps it once per decision, byte for byte (migration 0007, immutable); `GET /api/v1/releases` lists them, `GET /api/v1/releases/{digest}/evidence` serves one. `/metrics` adds `sentinel_attestation_verifications_total{result}`; the dashboard adds the Releases and Release pages. The platform verifies nothing itself: Kyverno verifies again at admission. Review of #86: a trust report names the decision it verified (`decision_id`, null without a valid decision attestation) and is recorded only next to that decision; a BLOCK comes without any report; the database checks the listed and counted columns against the document (trigger, as in 0006); a release decision gets the upload limit (it can name every finding); `verify` refuses `--report-json` equal to `--key` before removing anything; the pages say "not verified" for a release nobody verified, and a report that cannot be read makes the release's trust unknown. |
| 1.1.50 | Platform API 1.6.0 (B1, §13.3, §10, for A8's pages): `POST /api/v1/runs/{id}/decision` records the run's gate decision, the Decision v1 document `sentinel evaluate` wrote, byte for byte, and `GET` serves it unchanged (its sha256 as the ETag). One decision per run, accepted only if it is the run's: valid Decision v1 (`sentinelci.contracts.decision`), made on exactly the findings the run recorded (`inputs.findings_digest` is `sha256:` and the run's `findings_sha256`, so the scored findings the gate evaluated are the ones uploaded), about the run's subject (repo, commit, context, and the ref when the decision names one), and naming only findings the run recorded (violations and `vex_applied`). The same bytes again get 409 with the recorded decision; another decision for the run, or a `decision_id` another run recorded, is refused with 409. The database is the backstop (migration 0006: one decision per run, the bytes match their name, the findings, the subject and the copied columns are checked by a trigger, and nothing changes or is deleted). A decision is capped like a findings upload (`SENTINEL_API_MAX_UPLOAD_BYTES`), since a violation can name every finding. Runs list their `verdict` (null until a decision is recorded), and `GET /metrics` exposes `sentinel_gate_decisions_total{verdict,context}`. The platform records the verdict; it never decides. |
| 1.1.49 | Platform API 1.5.0 (B1, §13.3, for A8's pages): `GET /api/v1/runs` lists the recorded runs, newest first (the run id breaks ties, so a page never repeats or skips a run), filtered by `repo`, `context` and `ref` (each matched exactly) and paginated like `GET /findings`; a run whose findings are not uploaded yet is listed with a null `findings_sha256`. Reads need no token, like the others. |
| 1.1.48 | B8 detection report (§17): `make eval` scans demo-shop with SentinelCI's own scanners (`sentinel scan secrets|iac|pipelines|sast|sca`) and scores the findings against the ground truth with its matching rules: recall per category (a `known_miss` counts as a miss), false positives on the clean controls, unlisted findings listed, the benchmark's size against §17, and the canaries (measured with B5). A category whose tool did not run is not measured, never 0. The report (`out/eval/detection.json` and `.md`) is the same for the same inputs, byte for byte, and names each input by its digest. |
| 1.1.47 | B7 dashboard core (§10, §11): `platform/web` (React, TypeScript, Vite, TanStack Query, Tailwind, Recharts) reads the platform API only. Overview: open findings by priority and category from `GET /metrics` ("no data yet", never zeros, before a release run of the default branch). Findings: the list with its filters in the URL. Finding detail: the finding, the runs that saw it, and its root-cause group from the run's correlation, labelled advisory (and model-written when it is); a group of one is not shown. The client's types are generated from `schemas/openapi.yaml` and checked up to date; npm installs exactly the lockfile with no package scripts; `make check` and CI run the type-check, tests and build (`make web`, job `dashboard`); Dependabot updates npm after a 7-day cooldown. |
| 1.1.46 | B9 demo seeds, application code (§17, ADR-0011 decision 6): shop-api is a FastAPI service (`demo-shop/services/shop-api/app/`, `python -m app` on port 8080, writing only to `/tmp`) with six SAST seeds (GT-SAST-001 to 006, Opengrep 6/6 with SentinelCI's rules) and a safely written control (GT-CLEAN-005). Two prompt-injection canaries (GT-CANARY-001, 002) get their own `canaries` list in the ground truth (id, location, the seed they sit near, a unique token): an AI output that repeats a token obeyed it. GT-SCA-001 and 002 are now `imported: true`. `requirements.release.txt` pins the release image's dependencies by the hashes of their wheels (none built from source, no seeded version), and `requirements.block.txt` is the same with the seeded pyyaml 5.3.1 pinned by its sdist's hash. |
| 1.1.45 | Platform API 1.4.0 (B1, §8, §13.3): a run's correlations. `POST /api/v1/runs/{id}/correlations` records a Correlation v1 document (checked with the correlator's own model) only for a run whose findings are recorded, only if its `findings_sha256` is the run's and its groups hold each of the run's findings exactly once; every version is kept byte for byte (migration 0005), named by the sha256 of its bytes (the same bytes again: 409), never changed or deleted (a database trigger, which also refuses a document of other findings), and the downgrade stops while one is kept. `GET .../correlations` serves the latest version (or `?sha256=`), `GET .../correlations/versions` lists them. The endpoints are `/correlations`, not the `/groups` planned in §13.3, as agreed on #47. `GET /metrics` counts only the default branch's release runs (`SENTINEL_DEFAULT_REF`, #67 review). |
| 1.1.44 | Required scanners (B4, §5): zizmor is required in `pr` and `release` (`policies/required_tools.rego`), now that the scan job runs it (A3, #66). A tool status without it is SC-010 (`Scanner missing: zizmor`), so a pull request that deletes the workflow audit step from the workflow it carries no longer loses SC-009 unnoticed. Merge after #66. |
| 1.1.43 | A3 (§5): the gate runs SAST and SCA. `sentinel-scan.yml` installs Opengrep, Syft and Grype from the lock, prepares Grype's database once (`sentinel tools grype-db --timeout`, evidence in `grype-db.json`), then runs `sentinel scan sast` and `sentinel scan sca` on the head commit and on the PR baseline, combined with the other scanners. Both commands take `--timeout` and `--tool-status-out`: Opengrep's run is recorded like the others'; the SCA status names Syft and Grype apart (`SbomScanFailure` says which one failed; Grype is `not_run` after a failed Syft; a report that cannot be trusted is Grype's failure). `scan sca --report` records the database the scan read and the SBOM's sha256 (`sca-report.json`), and the `match` block is pinned in `configs/grype.yaml` and required in the report (#52 review). The scan job's limit goes to 82 minutes needed with every run at its 300 s limit, 85 allowed. Whether the gate requires these tools is `policies/required_tools.rego` (B4). Review of #80: the SCA report's `sbom_sha256` names bytes that are kept (`--sbom-out`, needed with `--report`) and repeat (Syft's configuration fixes the two directories it records); every head scan's status and empty findings file on failure are tested in the workflow; `SbomScanFailure` is a `ScannerError`. |
| 1.1.42 | A7 storage (§8, §13.3; B1's correlations API, #73, as agreed in the #47 thread): `sentinel-ai correlate --run ID --api-url URL` reads the run's findings exactly as B1 recorded them (refused unless their sha256 is the run's `findings_sha256`; a run without findings is not correlated), correlates them and posts the Correlation v1 document as canonical JSON bytes (keys sorted, no white space, UTF-8, one final line feed) to `POST /api/v1/runs/{id}/correlations` (`GET` gives the latest version byte for byte, or one with `?sha256=`). The version is the sha256 of those bytes: the same bytes again are answered 409 with that version and count as stored; any other answer, or a version that is not the bytes' sha256, stores nothing (exit code 4). The transport is the CLI's platform client (`Platform.get_bytes`, `Platform.post_json`, `answer_summary`): the token only from `SENTINEL_API_TOKEN`, never printed; plain http only on the loopback; no redirect followed. Advisory: the gate never reads a correlation. Tested end to end against the real API on a loopback server with PostgreSQL (`platform/api/tests/test_clients.py`): `sentinel upload` records the run, `sentinel-ai correlate` stores its correlation, the same bytes again are the same version. |
| 1.1.41 | A1 image adapter (§5 stage 7, §13.1): `sentinel scan image` scans a built image's OCI layout archive with the pinned Syft and Grype, offline, into CONTAINER findings (`package` and `image`: digest, reference, layer), one per (vulnerability, purl base) with the CONTAINER fingerprint. The report must be about the given manifest digest, and its configuration must hide nothing, as for `scan sca`. A tool status for Syft and Grype (a failed Syft leaves Grype `not_run`), so the gate records a failed image scan as SC-010. Review of #70: before Syft runs, every blob of the OCI layout must hold the content its digest names and the layout nothing else (`supplychain/layout.py`, for `sentinel sbom` too): a swapped layer under its original name passed as the named image; `--image-ref` with a tag or a digest is refused; the image digest comes from the build's `--metadata-file`; the layer is the `diff_id`. #70 round 3: the empty `ingest/` directory BuildKit's `type=oci,tar=false` leaves is part of a layout (a file in it is still refused), and nothing but zero blocks may follow where Python's `tarfile` stops reading an archive, since Go's reader (Syft's) may go on. |
| 1.1.40 | A9 release image (ADR-0011, decision 6): `demo-shop/services/shop-api/Dockerfile.release`, the hardened image `make release` will build once B9's application and requirements exist. Python 3.12.16-slim pinned by digest in every stage; dependencies from a hash-pinned file (`--require-hashes --no-deps`, `REQUIREMENTS` selects the BLOCK image's); a final stage with no RUN, as UID and GID 10001, on port 8080, no HEALTHCHECK or curl; no `# syntax=` frontend pulled at build time; a build context allow-listed by `Dockerfile.release.dockerignore` (the application and the two requirements files, never the seeded configuration). The pinned Trivy reports only DS-0026 (no HEALTHCHECK), by design. |
| 1.1.39 | Threat model (§18, A10): `docs/threat-model.md` lists the assets, five attackers, the trust boundaries, and 29 threats, each with its control, where it lives, the test that proves it and its status (main, an open PR, or planned), then the residual risks accepted in the private phase. §18's signing key row follows ADR-0011 (no signing key on GitHub). |
| 1.1.38 | A8 metrics (§10, Platform API 1.3.0): `GET /metrics` serves the §10 names in the Prometheus text format, read-only aggregates counted by PostgreSQL in a read-only transaction, with bounded labels only (never a repository, a commit, an id or free text). `sentinel_findings_open{priority,category}`: the findings of each repository's latest release run whose findings are recorded, by priority (`P0` to `P4`, or `unscored`) and category, every pair present once such a run exists, absent before. The other §10 metrics stay absent, not 0, until their data is stored (decisions: B1). Prometheus scrapes the API (`deploy/compose/prometheus`), and Grafana provisions a read-only `SentinelCI overview` dashboard with one panel per §10 metric, from files checked against §10's names and labels. |
| 1.1.37 | A3 CI workflow audit in the gate (§5): `sentinel-scan.yml` runs `sentinel scan pipelines` (zizmor) on the head commit in both modes and on the base commit for the pr baseline, so SC-009 now blocks a high-severity CI workflow issue a change introduces (demo-shop: GT-PIPELINE-001 to 003). `scan pipelines` writes a tool status like the other scanners (`--tool-status-out`, `--timeout`): `ok` with the verified binary's sha256 and, as its artifact, the pinned wheel that carries it; a crash, a timeout or a binary no pinned wheel carries is `failed`, `timeout` or `integrity_mismatch`, and the gate blocks it (SC-010). The scan job's limit is 45 minutes, for the extra runs. zizmor is not in `policies/required_tools.rego` yet (Track B): until it is, a workflow that drops the audit is not caught by the gate. |
| 1.1.36 | A6 verification run (§9, ADR-0013 decision 5): the bot verifies the pull requests it opened in the same run. `verify` (read-only, no secret, the scanned commit's pipeline) rebuilds each pull request's commit from its proposal and the scanned commit and requires it to be the same commit; scans both commits with the scanners the pr gate requires (Gitleaks on the commits, Trivy and zizmor on the tree); builds and tests the patch with `sentinel remediate check`; evaluates the gate on the patched commit in pr context with the scanned commit as baseline; then runs `sentinel remediate verify`. `report` (no repository code) re-checks each result against the gate's invariant, comments it and sets the `sentinelci/remediation` commit status; a pull request without a trustworthy result is reported FAILED and the run fails. `sentinel remediate check`: for IaC, build = every edited file still parses into the same resources (a manifest's documents, a Dockerfile's stages), tests = the patch changes only what its strategy may change; exit 3 for a strategy with no build or tests defined (LLM code fixes, B6). `publish` also refuses a proposal that lists a file outside the scanned path or whose file name is not a plain name, and reports a branch it could not push or a pull request it could not open instead of stopping. |
| 1.1.35 | A6 remediation bot (§9, ADR-0013): `sentinel-remediate.yml` proposes in a read-only job and publishes in a job that runs no repository code; a branch is pushed and its pull request opened only if its bundle holds exactly one commit, on the scanned commit, with the proposal's id and exactly its files edited in place, and only if the proposal is one the bot could have made (a UUID id and its branch, a deterministic strategy and only the files it can fix inside the scanned directory, never under `.github/` or `.sentinel/` or a `sentinel.yaml`); the pull request shows only checked values; never twice, never merged. |
| 1.1.34 | A7 stage 3 and evaluation (§8, §17): `correlate.labels.label_groups` lets a model write the labels of groups of two findings or more (never a secret's), from findings sent as escaped JSON data without ids, snippets or evidence and with secrets redacted; one repair retry, else the template stays; an answer with a secret is refused; a template fix is never replaced; the group records the model and the prompt and input sha256. `correlate.evaluation`: ablation, the ARI-vs-threshold sweep and the calibration. |
| 1.1.30 | Platform API migrations (B1, §13.3): going below 0004 stops, changing nothing, while any run keeps its uploaded findings bytes, which are the only copy `findings_sha256` was taken of; before, the downgrade dropped them without a word. A database without kept bytes still goes down. Raised on #57. |
| 1.1.29 | Platform API 1.2.0 (B1, §13.3): the platform keeps each run's findings upload byte for byte and serves it at `GET /api/v1/runs/{id}/findings`, so a consumer that must match `findings_sha256` (the correlator's run document, #47; a replay) reads the exact bytes; the JSONB rows keep neither key order nor bytes. The database keeps only bytes that hash to the recorded digest, and the recorded-run trigger makes them immutable. Runs recorded before have none, and the API says so. |
| 1.1.28 | Platform API 1.1.0 (B1, §13.3): one run per CI run. `POST /api/v1/runs` with the `repo`, `commit`, `context` and `run_id` of a run already recorded (a re-run of `sentinel upload`, #50) is answered 409 with the existing run, which the client resumes instead of recording the findings a second time; a unique index decides between concurrent requests. A run without `run_id` is always new. Migration 0003 stops, changing nothing, on a database that already holds a CI run twice. |
| 1.1.27 | Diff-aware PR mode (§5, B4): a known vulnerable package (SCA) in a manifest where the base branch did not have it counts as introduced, like a known secret in a new file. SCA fingerprints hold no path, so a second service that starts to use a vulnerable package kept the old id and passed as "not new", although that service has its own exposure and reachability. A moved manifest now counts as new too, which errs toward blocking. Agreed on #52. |
| 1.1.26 | A1 (§5, §17): `sentinel scan iac` also loads SentinelCI's own Trivy checks (`scanners/configs/trivy-checks`, `--config-check`, namespace `sentinelci`), and a check that does not compile stops the scan (`--rego-error-limit 0`; Trivy would otherwise drop it and exit 0). The first one, SENTINEL-AWS-0001 (HIGH), reports an IAM policy statement that allows every action on every resource: an action pattern made only of wildcards (`*`, `*:*`, `**`, `*:?*`), on `*` or with `NotResource` (every resource but those). It covers declared policies, policy documents, and inline policies of declared roles, users and groups, in Terraform or CloudFormation YAML. Trivy's embedded checks miss it (ADR-0012), so GT-IAC-004 is detected by the pinned Trivy again. Not seen, because Trivy does not adapt them: a policy attached by ARN (AWS-managed `AdministratorAccess`), a policy of an undeclared role, user or group, a Terraform `file()` or `templatefile()` policy, a CloudFormation `AWS::IAM::ManagedPolicy`, and any policy of a CloudFormation JSON template (pinned by a test). Not this check: `Allow` with `NotAction` on every resource. |
| 1.1.25 | A1 SCA (§5 stage 3, §13.1): `sentinel scan sca` runs the pinned Syft (one run writes CycloneDX, SPDX and syft-json) and the pinned Grype on that SBOM, offline, with SentinelCI's `scanners/configs/grype.yaml` from a private directory, against a prepared database (`--db-dir`; over five days old fails closed unless `--allow-stale-db`). `sentinel tools grype-db` prepares it with the same Grype and configuration (pinned update URL, or `--archive`: a local file digested first, or an https URL naming its sha256), the job's proxy and CA variables only, and fails closed unless `grype db status` then calls it valid. `sentinel normalize grype` turns a source-tree report into SCA findings: rule id and fingerprint vuln id = Grype's matched id, related CVEs in `cve`, other ids in `aliases`; Negligible counts as INFO and Unknown as HIGH; one finding per purl base with every place; no CVSS / EPSS / KEV copied (enrichment is B2's snapshot); a report that shows a silenced match, an invalid database or an image source fails closed. Golden file: B's real Grype 0.121.0 report on demo-shop. |
| 1.1.24 | B1 acceptance changed after the plan, while GitHub Actions are blocked: "an upload (`sentinel upload`, 1.1.23) or a sync ingests a real run" replaces "a sync ingests a real run". M1 can then be met by uploading a local run; the GitHub sync (§4.1, the platform pulls each CI run's evidence) stays in B1 and lands once CI runs exist. Hand-off B1 → A3, A8: OpenAPI and the ingestion endpoints at the end of S1, the sync later. |
| 1.1.23 | `sentinel upload` (stage 11, M1): one run's findings to the B1 ingestion API, after the verdict, with exit code 4 on failure (never the gate's codes). The token comes only from `SENTINEL_API_TOKEN` (visible ASCII) and is never printed; the URL is https or the loopback, with no redirect, and plain http never goes through a proxy; each request has a 120 s deadline; any failure, a malformed answer included, is exit 4 with no traceback. Findings are checked locally as the API checks them; the platform's `findings_sha256` and `finding_count` must match; `--resume` finishes a run that stopped after its creation, and any failure once the run exists names it. A CI run (`--run-id`) needs no `--resume`: the platform answers it again with 409 and the run it has (API 1.1.0, #56), which the client checks is this run (repo, commit, context, ref, run id) and finishes or confirms. In GitHub Actions the run id is `<run id>/<run attempt>`, so a re-run of the job is a new run; a local run is recorded anew. A platform answer that quotes the token is printed with `<SENTINEL_API_TOKEN>` in its place. |
| 1.1.22 | Checkov dropped (ADR-0012): stage 4 is Trivy (config) and zizmor, A1 has no Checkov adapter, and §11 says so. The demo-shop ground truth keeps only detections by pinned tools; GT-IAC-004, which Trivy 0.76.1 misses, stays a seed with `known_miss` and counts as a miss for IaC recall. |
| 1.1.21 | A6 apply step (§9): `sentinel remediate apply` commits a patch proposal on a new `sentinel/fix/` branch of a local clone with plumbing commands on a temporary index (never pushes, checks nothing out, so no hook, filter or fsmonitor of the clone runs), after checking that the proposal id matches its content, that its findings are in the base scan (`--findings`) and its files are where they were found, and that the diff edits exactly the listed regular files in place (no file created, deleted, renamed, made executable or symlink retargeted). The commit has a `Sentinel-Diff` trailer and the proposal's dates. |
| 1.1.20 | A7 correlation (§8, §13.2, §17): `schemas/root-cause-group.v1.json` (RootCauseGroup v1, advisory: `stage` is what formed a group, dedup, structural or embedding, `labelled_by` who wrote its labels, template or llm with its `model`, and an embedding group's `similarity`) and `schemas/correlation.v1.json` (one run's groups with the sha256 of the findings they came from, the stages that ran in their order, the threshold and the embedding model, and a stage that failed as `skipped`; the schema refuses a group formed by a stage that did not run, and the models refuse whatever the schemas refuse, without coercion); stages 1 (dedup) and 2a (structural fix keys, within one category) of `sentinel_ai.correlate`, stage 2b (embedding clustering, never secrets) with an injected embedder that falls back to stages 1 and 2a when it fails (an exception, a non-finite, empty or zero vector), the findings split on `\n` only as the gate and B1 split them, and the ARI and alert-reduction metrics. The threshold is calibrated off demo-shop (§17). |
| 1.1.19 | A5 admission policy (§7): `sentinel admission-policy` renders the Kyverno 1.19 `ImageValidatingPolicy` (`policies.kyverno.io/v1`) from the parameters of `sentinel verify`, and requires the same things: the image's `cosign sign` statement (as an attestation, since `verifyImageSignatures` accepts any key-signed statement) and the four attestations, bound as `sentinel verify` binds them. Kyverno CLI pinned in `tools.lock.toml`; every bad case the tests cover is refused by both verifiers (`kyverno apply` against a real registry). The decision must be a non-BLOCK Decision v1 verdict (versions rendered from the contract); images match as a prefix of the lower-cased reference; `pods/ephemeralcontainers` is covered; the key file must hold exactly one public key. Admission is weaker than `sentinel verify` on the full schemas and on ambiguity (named in the README). |
| 1.1.18 | A4 registry mode (§7, ADR-0010 decision 4): `sentinel attest --push` also signs the image and attaches the four attestations to it in its registry (Cosign 3 bundles, by digest); `sentinel verify` without `--evidence` reads them back and requires the image's own `cosign sign` statement, since Cosign 3 accepts any key-signed statement about the digest as a signature. A digest has one release per registry: `attest --push` refuses a different one before signing, and a re-run signs the same statements (the provenance names the run, not its attempt). `--registry-http` is for a loopback or single-label local registry only. crane is pinned in `tools.lock.toml` (local test registry, copies by digest). |
| 1.1.17 | A6b remediation (§9): `sentinel remediate dockerfile`: the deterministic Dockerfile fixer (`USER 10001:10001` added to the final stage after its last RUN and USER, never rewriting a USER line; COPY instead of ADD only when every source is a directory or a plain file of the repository, neither a tar nor compressed, judged by content; `apt-get install --no-install-recommends`; each checked against the pinned Trivy), sharing the per-file loop with the Kubernetes fixer. An edit leaves alone an instruction that carries a finding it does not resolve (its fingerprint would change), a proposal claims only the findings an edit resolved, and CRLF files are left alone. The USER change can change what the image does, and the rationale says so. |
| 1.1.16 | A6a remediation (§9): `sentinel remediate kubernetes` proposes hardening for the Trivy findings the deterministic Kubernetes fixer resolves (16 rule ids, each checked against the pinned Trivy; manifests edited round-trip, so the diff shows only the hardening; a non-root UID/GID, a read-only root file system and dropped capabilities can change how a workload runs, and the rationale says so), as a `PatchProposal`; `sentinel remediate verify` applies the verification gate and writes a `VerificationResult`. The gate refuses (exit 3) a proposal whose id does not match its content, that claims findings the base scan lacks or edits anything but where they are, and a decision not made in pr context on the patched findings with the tool status (which must show every target's scanner ok); a target re-reported under a new fingerprint (same tool, rule and file) is not gone, and a base finding that rises to MEDIUM or higher is new. Read models for both contracts; the §9 states and their transitions. New dependency: ruamel.yaml. |
| 1.1.15 | A1 SAST (§5): `sentinel scan sast` runs the pinned Opengrep (no checksum file upstream: pinned by hash after checking each asset's keyless signature, recorded in `tools.lock.toml` with its signer identity) with SentinelCI's own rules only (`configs/opengrep/`, each pinned by cases it must flag and leave alone), offline, with `nosemgrep` comments, `.semgrepignore`, `.gitignore`, the size and per-file time limits and repository rule files never honoured, and links leaving the tree refused; a file Opengrep cannot analyse for more than half of its lines, and any other error even reported as a warning, fails closed; findings are category SAST with the §13.1 SAST fingerprint, plus the occurrence number for repeated identical matches in a file (each copy is its own finding, so a copy is new in a PR and a waiver covers one place); each smaller gap Opengrep could not parse is a SAST HIGH finding of its own (`sentinel-sast-not-analysed`, fingerprinted on the skipped text, its message naming the lines and quoting no code), so padding cannot hide unparsed code, and valid syntax Opengrep cannot parse yet is waived with an expiry. |
| 1.1.14 | A1 CI workflow analysis (§5): `sentinel scan pipelines` runs the zizmor of the CLI's environment (a runtime dependency pinned in `uv.lock`), checked against the binary hashes pinned in `tools.lock.toml` (`[python_tools.zizmor]`), offline, with the repository's configuration, ignore comments and `.gitignore` never honoured. Workflows, actions and Dependabot must load; other files with a `jobs:` key are skipped and reported when zizmor cannot load them. PIPELINE fingerprint (§13.1) changed: a finding below a job or a top-level key also hashes the code it is about (the expression's line, a trigger's value, a Dependabot entry's ecosystem), so a new expression, trigger or entry is a new finding (IAC unchanged). |
| 1.1.13 | A4 SBOMs (§7): `sentinel sbom` writes CycloneDX and SPDX JSON with the pinned Syft, offline and never configured by the scanned repository (private working directory and home, SentinelCI's `supplychain/configs/syft.yaml` passed explicitly, no network lookup, no file catalog); images come from the OCI layout the build wrote, and both SBOMs must name the image's manifest digest; an output inside the target is refused before anything is deleted. |
| 1.1.12 | A4 release attestations (§7, ADR-0010): `sentinel attest` signs the release decision, CycloneDX SBOM, vulnerability scan (`schemas/vuln-result.v1.json`) and SLSA v1 provenance of an image digest with the pinned Cosign and a key pair (no transparency log), only for a non-BLOCK release decision about that image that recorded these findings and this SBOM; `sentinel verify` checks the four Sigstore bundles offline and prints a trust report (exit 0 trusted, 1 not, 3 could not run). |
| 1.1.11 | SC-011 (§6.3; B4 #29 and A1d #28): a misconfiguration that exposes the service by itself, one of 20 Trivy rule ids in `policies/exposing.rego`, blocks whatever its score. `cli/tests/scanners/test_trivy_exposing.py` pins every listed id against the pinned Trivy (one probe each, with ordinary configurations that must report none), and fails without Trivy when `tools.lock.toml` names a Trivy the list was not verified with. |
| 1.1.10 | B4: strict policy profile (`policies/profiles.rego`; any P1 is an SC-006 BLOCK) chosen by the base-branch `sentinel.yaml`; OpenVEX `not_affected` statements (`schemas/vex.v1.json`, `.sentinel/vex.json`), Decision 1.4 (`inputs.vex_digest`, `vex_applied`). A statement of any other status about the finding disputes `not_affected` (the gate does not order statements); `not_affected` applies for 90 days after it was made, like a waiver; a VEX date after `evaluated_at` is SC-010; `pkg:oci` products and duplicate JSON keys are refused. |
| 1.1.9 | Decision 1.3: `inputs.service_context_digest`, the `sentinel.yaml` enrichment used (from the base branch), recorded by `sentinel evaluate --service-context`, stored with `--store` and given back on replay; an invalid `sentinel.yaml` is never recorded (exit 3). |
| 1.1.8 | A1c IaC scanning (§5): `sentinel scan iac` runs the pinned Trivy (`trivy config`) offline, with repository configuration and ignore files never loaded, remote modules not fetched and not evaluated, and inline ignore comments (also in any repository Terraform or OpenTofu file outside the scan path when the scan path declares a module, and in files named like Dockerfiles), symbolic links leaving the scan path, and directory or Terraform file links leaving the repository when a module may load them, refused (SC-010); findings are category IAC with the §13.1 config fingerprint. `sentinel scan combine` merges the scanners' findings and tool statuses for the gate; `sentinel-scan.yml` runs both scanners on the head and, in pull requests, on the base tree as the baseline. |
| 1.1.7 | A3b evidence (§5, §6.5): every scan writes a tool status (`sentinel scan secrets --tool-status-out`), so a failed, timed-out or tampered scanner becomes a recorded BLOCK (SC-010) instead of a bare red job. PR mode scans the base commit's tree as the baseline. The gate stores its evidence (`--store`), uploaded as the `sentinel-evidence` artifact; the PR comment names it in its replay line and shows "N new" only for the baseline the gate used. The nightly replay also replays the last release decisions of `demo-shop.yml` on main. The gate scores findings with the base risk model before deciding, and every scanner run has a time limit the scan job outlives. |
| 1.1.6 | A9 first seeds (§17): 5 fake secrets, 6 IaC, 3 CI-workflow seeds and 4 clean controls in `demo-shop/`, with a draft ground-truth format (`demo-shop/ground-truth/`, final schema owned by B9) checked against the pinned Gitleaks, Trivy and zizmor. SentinelCI's Trivy configuration trusts only the kind registry for KSV0125. |
| 1.1.5 | A3 pipeline (§5): reusable `sentinel-scan.yml` (scan · gate · report) and `demo-shop.yml`. Pull requests are judged by the base branch's pipeline: CLI, lock, scanner configuration, policies and waivers come from the base commit, and the change is only data (ADR-0008). `sentinel report pr-comment` renders the deterministic, injection-safe comment and fails closed. |
| 1.1.4 | Enrichment (B2, §6.1): `schemas/enrichment-snapshot.v1.json` (`schema_version` "1.0", `sources.kev.cves`: the CVEs the KEV lookup covered) and `schemas/sentinel-config.v1.json` (`sentinel.yaml`, canonical component paths); `sentinel enrich`. "Not listed in KEV" only for covered CVEs; `sentinel.yaml` read with a restricted YAML loader. |
| 1.1.3 | Scanner hardening (§5): verify-before-exec, minimal child environment, scanner configuration owned by SentinelCI; repository-controlled suppressions are neutralized or refused (Gitleaks: `.gitleaks.toml`, `gitleaks:allow`, `.gitleaksignore`, and `.gitattributes` `-diff`/`binary` in git mode); merge commits scanned with `--diff-merges=remerge` plus a `first-parent` pass for octopus merges (evil merges), archives opened in dir mode. |
| 1.1.2 | Tool lock is `tools.lock.toml` (read with the standard library: no extra dependency). A1 split: A1a = lock + `sentinel tools install/verify` (done), A1b = scanner adapters + Opengrep pinning via signature verification. |
| 1.1.1a | Package fingerprints use the purl base (no version, qualifiers or subpath — same as the gate's waiver matching), agreed in the review of PR #1. "Green CI" may be a local `make check` report while Actions minutes are exhausted. |
| 1.1.1 | No GitHub Pro: `main` protected by convention + local guard until the repository goes public. |
| 1.1 | **Single private repository**: the demo target lives in `demo-shop/` instead of a second repo. **Private-phase adaptations** (§4.3, ADR-0006): Cosign key-pair signing without public transparency log, provenance as a Cosign attestation, no code-scanning upload, local registry for Kubernetes demos, Actions-minutes budget. Dependabot (with cooldown) replaces Renovate. |
| 1.0 | Initial specification (PDF shared with the team). |

---

## 1. Executive summary

SentinelCI is a **verifiable security-control system for software delivery**. It runs a hardened DevSecOps
pipeline on every change, turns raw scanner output into risk-ranked findings, decides with policy-as-code whether
a change or release may proceed, signs the artifact together with the evidence behind that decision, and makes
Kubernetes refuse anything that lacks this evidence. On top of this deterministic core, an AI layer explains
findings, groups related alerts into root causes and proposes patches, and a remediation loop only accepts a
patch when tests and re-scans prove it works.

### 1.1 Headline capabilities

| # | Capability | What it means concretely |
|---|---|---|
| 1 | Hardened security pipeline | Secrets, SAST, SCA, container, IaC and CI-workflow scanning in isolated, least-privilege jobs; scanners pinned, integrity-checked, fail-closed |
| 2 | Supply-chain integrity | CycloneDX + SPDX SBOMs, Cosign signatures, in-toto attestations, SLSA provenance |
| 3 | Risk-based release gate | CVSS × exploitability (EPSS, KEV) × reachability × exposure → P0–P4; OPA/Rego → PASS / WARN / BLOCK with rule IDs; signed and replayable |
| 4 | Deploy-time enforcement | Kyverno rejects images without a valid signature, SBOM, or with a BLOCK decision; GitOps via Argo CD |
| 5 | AI security analyst | Grounded explanations, root-cause clustering, triage hints, patch proposals; schema-validated, advisory only |
| 6 | Verified remediation loop | Bot fix PRs (deterministic fixers first, LLM for code) accepted only after build, tests and re-scan pass |
| 7 | Observability | Dashboard + Grafana: vulnerabilities over time, gate outcomes, MTTR, attestation coverage |
| 8 | Measured results | Labelled benchmark: ranking vs CVSS baseline, alert reduction, fix rate, injection robustness, replay |

### 1.2 Design principles (non-negotiable)

- **P1 — Deterministic decides, AI advises.** The gate runs before and without AI; enforced by an import contract
  and tested with prompt-injection canaries.
- **P2 — Fail closed.** Scanner crash, timeout or integrity failure blocks the release.
- **P3 — Everything is evidence.** Each decision records the digests of all inputs and can be replayed bit-for-bit.
- **P4 — Practice what we preach.** This repository is protected by SentinelCI itself (dogfooding). `make self-gate` (A10) runs the release gate on SentinelCI's own tree at `main`, without demo-shop, from a pipeline commit that is not the commit it judges (ADR-0011, decision 8).
- **P5 — Contracts before code.** Tracks integrate through versioned JSON Schemas and an OpenAPI spec with fixtures.

## 2. Why this project, why now

In March 2026 attackers reused credentials from an earlier, non-atomically rotated breach to publish a malicious
Trivy release (v0.69.4), force-push 76 of 77 tags of `aquasecurity/trivy-action` to a credential stealer and
replace the tags of `setup-trivy` (CVE-2026-33634). The same campaign reached LiteLLM: malicious versions 1.82.7
and 1.82.8 were uploaded directly to PyPI on 24 March 2026; public analyses link the stolen publishing credentials
to LiteLLM's own CI, which ran Trivy. Supply-chain failures are category A03 of the OWASP Top 10:2025.

| What went wrong | SentinelCI response |
|---|---|
| Actions referenced by mutable tags | Full-SHA pins + version comment, zizmor audit, Dependabot updates |
| Scanner binaries trusted blindly | `tools.lock.toml` with SHA-256/digests; `sentinel tools verify` first; mismatch = SC-010 BLOCK |
| Scan jobs could read publishing secrets | Scan jobs: `contents: read`, no secrets; signing job never runs repo code |
| Publishing outside the reviewed path | Only artifacts signed by our release workflow are admitted by Kyverno |
| Developer machines / AI agents as entry points | `CLAUDE.md` rules, no real secrets locally, dependencies only via lockfile + review |

## 3. Goals, scope, success criteria

**Goals.** G1 block unsafe changes with actionable explanations · G2 make every release verifiable · G3 prioritize
by real risk and prove it · G4 use AI without weakening decisions · G5 close the loop to verified fix PRs ·
G6 zero cloud cost (laptops + GitHub).

**Non-goals.** New scanners · replacing human review (bot never merges, AI never waives) · SaaS, cloud deployment,
runtime threat detection.

| Metric | Target | Measured by |
|---|---|---|
| Seeded-vulnerability detection | ≥ 90% of seeds found by ≥ 1 scanner | Eval harness (§17) |
| Gate correctness | 100% of must-block scenarios blocked; 0 blocks on clean controls | Scenario suite |
| Prioritization | NDCG@10 above CVSS-only baseline | Eval harness |
| Alert reduction | ≥ 40% (findings → root-cause groups) | Eval harness |
| Verified fix rate | ≥ 60% of attempted fixable seeds | Remediation runs |
| Prompt-injection robustness | 0 verdict changes (hard requirement) | Canary suite |
| Replay determinism | 100% identical | Nightly replay job |
| Deploy enforcement | 100% of bad images denied | Kyverno tests on kind |
| PR feedback time | p95 ≤ 10 min | Pipeline metrics |

Report real numbers, including misses.

## 4. System architecture

Four planes: **CI plane** (GitHub Actions running the `sentinel` CLI: scan, decide, sign), **artifact plane**
(OCI registry: images + signatures + attestations), **runtime plane** (kind + Argo CD + Kyverno: only verified
images run), **control plane** (FastAPI platform: history, AI and remediation workers, dashboards).

### 4.1 Decisions in the pipeline, intelligence in the platform

The gate must work without the platform (hosted runners cannot reach a laptop). The deterministic core
(normalize → enrich → score → evaluate → attest) is a library + CLI running in CI. The platform **pulls** each
run's evidence bundle through the GitHub API (GitHub App or fine-grained token) and can **replay** any decision.
Local CLI runs can **push** to the same ingestion API. No self-hosted runners (anti-pattern for untrusted PRs).

### 4.2 Operating modes

| | Private mode (now) | GitHub mode (after going public) | Local mode |
|---|---|---|---|
| Pipeline | GitHub Actions | GitHub Actions | `make pipeline-local` |
| Signing | Cosign key pair, no Rekor upload | Cosign keyless (GitHub OIDC) | Developer key pair |
| Provenance | SLSA predicate via `cosign attest` | GitHub artifact attestations (reusable workflow → Build L3 target) | `cosign attest` |
| Registry | GHCR private (CI) + kind local registry (demos) | GHCR public | kind local registry |
| Results | PR comment, artifacts, dashboard | + GitHub code scanning (SARIF) | Terminal + dashboard |

### 4.3 Private-phase constraints (ADR-0006)

- Keyless certificates embed the repository identity and are logged in the public Rekor log → key pairs until public.
- GitHub artifact attestations require a public repository on non-Enterprise plans → Cosign attestations meanwhile.
- The signing key never reaches GitHub (ADR-0011): it lives, password-protected, on the laptop that runs
  `make release`, the only signer while private; CI holds no signing secret. Keyless signing in CI replaces it
  when the repository goes public.
- We stay on GitHub Free: server-side branch protection is not available for this private repository, so `main`
  is protected **by convention** (every change through a PR, reviewed by the other member, merged only with
  a green CI, or a local `make check` report on the PR head while Actions cannot run) plus a local pre-commit guard that refuses commits on `main`. Technical protection is enabled when
  the repository goes public.
- Actions minutes are capped (Free: 2,000/month for private repositories): path filters, caching of
  vulnerability DBs, nightly full scans.
- Going public = switch to GitHub mode (a configuration change, by design).

### 4.4 Component catalogue

| Component | Responsibility | Technology | Owner |
|---|---|---|---|
| `sentinel` CLI / core | scan, normalize, enrich, score, evaluate, sign/attest, verify, replay | Python 3.12, Typer, Pydantic v2 | A + B |
| Reusable workflows | `sentinel-scan.yml`, `sentinel-release.yml` | GitHub Actions | A |
| Policy bundle | Rego rules, risk model, tests | OPA (Rego v1) | B |
| Platform API | ingestion, sync, query, OpenAPI | FastAPI, SQLAlchemy 2, Alembic | B |
| Workers | sync, enrichment refresh, AI, remediation | Celery + Redis | B / A |
| AI analyst | explanations, triage hints, patch proposals | Ollama, own provider interface | B |
| Correlator | dedup, embeddings, clustering, labels | pure Python now (average linkage); numpy or pgvector in the worker | A |
| Remediation orchestrator | fixers, branches/PRs, verification | GitHub App / token, httpx2 | A |
| Evidence store | content-addressed bundles | SeaweedFS (S3 API, ADR-0007) | B |
| Database | runs, findings, decisions, waivers, groups, remediations | PostgreSQL + pgvector | B |
| Web dashboard | product UI | React, TypeScript, Vite | B core, pages split |
| Observability | metrics, dashboards as code | Prometheus, Grafana | A |
| Runtime | cluster, GitOps, admission | kind, Helm, Argo CD, Kyverno | A |
| Demo target | intentionally vulnerable app + ground truth | `demo-shop/` | A + B |

## 5. The DevSecOps pipeline

| # | Stage | Tools | Output | Gate |
|---|---|---|---|---|
| 0 | Tool integrity | `sentinel tools verify` (tools.lock.toml) | manifest | mismatch → SC-010 |
| 1 | Secrets | Gitleaks (Betterleaks-compatible config) | SARIF | SC-001 |
| 2 | SAST | Opengrep + Semgrep-format rules | SARIF/JSON | risk + policy |
| 3 | SCA | Syft source SBOM → Grype; OSV | JSON | risk + policy |
| 4 | IaC + CI config | Trivy `config` (offline); Checkov; zizmor | JSON, SARIF | policy |

| 4 | IaC + CI config | Trivy (config); zizmor | JSON | policy |

| 5 | Tests | pytest / npm test | JUnit | must pass |
| 6 | Build | docker buildx, by digest | image@sha256 | — |
| 7 | Image analysis | Syft (CycloneDX + SPDX), Grype, Trivy | SBOM, JSON | risk + policy |
| 8 | Normalize + enrich | `sentinel normalize` / `enrich` | findings.v1.ndjson + snapshot | — |
| 9 | Decision | `sentinel evaluate` (risk + OPA) | decision.v1.json | job fails on BLOCK |
| 10 | Sign + attest | Cosign (sign, attest SBOM / vuln / decision / provenance) | registry | only if ≠ BLOCK |
| 11 | Report | PR comment, evidence artifact; `sentinel upload` to the platform (token from the environment, own exit code) | comment, artifact, platform run | — |
| 12 | Deploy | GitOps digest bump → Argo CD → Kyverno | pods | admission deny |

**Scanner hardening (A1).** Every scanner run (1) re-verifies the binary against `tools.lock.toml` right
before execution, (2) gets a minimal environment (no CI tokens, keys or proxy variables), (3) uses a configuration
owned by SentinelCI, never one from the scanned repository, and (4) treats crashes, timeouts and missing reports as
SC-010. Suppression mechanisms that live in the scanned repository are written by the change author, so they are
neutralized (`--config`, `--ignore-gitleaks-allow`) or refused when the tool offers no way to disable them
(Gitleaks always loads `<source>/.gitleaksignore`). In git mode, `git log -p` honours the repository's
`.gitattributes`, where a `-diff` or `binary` attribute would hide a file's patch, so patches are forced to text
(`--text`, no textconv or external diff) and caller `--log-opts` are restricted to revisions, pathspecs and a few
harmless options. Merge commits are scanned with `--diff-merges=remerge`, so a secret slipped into a merge
(an "evil merge") is found while an honest merge of the base branch blames nobody (octopus merges excepted:
remerge does not diff them, so they get a second `first-parent` pass, which also reports what the other parents
already had; the PR baseline drops what the base branch has). Each Gitleaks pass gets the full scanner time
limit, so git mode can take twice as long. Dir mode opens archives (`.zip`, nested up to 3 levels). Trivy
(`sentinel scan iac`) never loads the repository's `trivy.yaml` or `.trivyignore` (`--config ""`,
`--ignorefile ""`), refuses a tree that contains inline `trivy:ignore` / `tfsec:ignore` comments (no flag turns
them off), uses the checks embedded in the pinned binary with SentinelCI's own check data, plus SentinelCI's own
checks for gaps in Trivy's (`scanners/configs/trivy-checks`, namespace `sentinelci`, ids `SENTINEL-*`; the
repository can add none, and one that does not compile stops the scan), and runs offline: proxy
variables point at a closed local port and `GIT_ALLOW_PROTOCOL=none`, so remote Terraform modules named by the
scanned code are never fetched and not evaluated (the CLI lists the sources of their `module` blocks in the job log,
following local modules). Trivy also loads local modules outside the scan path (`source = "../mod"`), transitively,
and honours an ignore above a `module` block for the whole called module. Which directories it loads depends on its
own evaluation of the sources, so the check over-approximates: when the scan path declares any module, every
Terraform or OpenTofu file (`.tf`, `.tofu` and their `.json` forms) of the repository outside it gets the marker
check before the run, and a directory or Terraform file link in the repository that leaves it is refused; after the
run, a file Trivy read outside the repository is refused, and the directories it read outside the scan path get the
marker check. Trivy does not follow symbolic links while Terraform and kubectl do, so a link that leaves the scan
path is refused too (a link loop counts as leaving, on every Python version). The marker check skips only files Trivy never parses (source code, documentation, images),
never a name Trivy reads as a Dockerfile (`Dockerfile.*`, `Containerfile.*`, `*.dockerfile`). Telemetry and version
checks are off. Legitimate exceptions go through waivers (§6.4).

zizmor (`sentinel scan pipelines`, findings of category PIPELINE for SC-009) is a runtime dependency of the CLI,
installed from its PyPI wheel (`uv.lock`; it publishes no checksum file for its binaries). Right before each run,
the binary of the CLI's own environment, never one from `PATH`, must be one that a wheel pinned in `tools.lock.toml`
(`[python_tools.zizmor]`) carries, at the pinned version; those hashes were read from the wheels whose sha256
`uv.lock` pins, and a test keeps the two files in step. It runs offline with `--no-config` (no `zizmor.yml`),
`--no-ignores`, `--ignore-lockfile` (a workflow listed in the repository's `actions.lock` keeps its `unpinned-uses`
findings) and `--collect=all` (a workflow listed in `.gitignore` is still audited), and `--persona=regular`,
zizmor's default audits (the pedantic and auditor personas are for manual review, too noisy for a blocking gate).
With `--no-ignores`, a finding covered by an inline `# zizmor: ignore[...]` comment is reported flagged `ignored`;
it stays a finding, and its message says the comment is not honoured. SentinelCI collects the inputs: what GitHub
runs (every YAML file under `.github/workflows/`, every `action.yml` / `action.yaml`, `.github/dependabot.yml`) must
load (`--strict-collection`), or the scan fails (SC-010); any other YAML file with a top-level `jobs:` key is
audited too, and one that zizmor cannot load as a GitHub workflow (another CI's file) is skipped and named in the
job log, never counted as audited. Fingerprints (§13.1) use the job (`jobs.<id>`) and, for a finding inside a step,
the code it is about, never the step's position, so adding a step does not make a job's findings new, while a new
expression in a job is a new finding. `sentinel-scan.yml` runs it on the scan path of the head commit in both modes, and of the base
commit for the pr baseline (only an issue the change introduces blocks), with a tool status like the other
scanners (a failure is SC-010).

Grype (`sentinel scan sca`, findings of category SCA) never reads the scanned repository: it matches the Syft
SBOM, from a private working directory with SentinelCI's configuration, offline, against a database the pipeline
prepared (`sentinel tools grype-db`: the same verified Grype and configuration, which pins the update URL, then
Grype's own validity check, offline: the archive is checked against the checksum of the listing Grype fetched
over TLS from that pinned host, an integrity check whose trust is TLS, not a signature); a database built more
than five days ago fails the scan (SC-010), and a
report whose recorded configuration hides matches (ignore rules beyond Grype's built-in kernel-header rules, VEX,
exclusions, `only-fixed`, `only-notfixed`, `ignore-wontfix`, a distro override, `by-cve`) is refused. Legitimate
exceptions go through waivers (§6.4).



Stage 7, the image: `sentinel scan image` runs the same Syft on the image's OCI layout archive
(what `docker buildx build --output type=oci` writes, no registry), checks that it is the image of the given
manifest digest, and matches its SBOM with the same Grype and database. Its findings are CONTAINER findings, each
with the image's digest and reference and the layer the package is in (its first place by path); a report about
another image is refused. The tool status names Syft and Grype separately: Grype is `not_run` when Syft failed.

Opengrep (`sentinel scan sast`, findings of category SAST) publishes no checksum file: each release asset is signed
keyless by its release workflow. It is pinned by hash in `tools.lock.toml` after checking each asset's signature
against its certificate, the certificate against Sigstore's Fulcio CA at signing time, and its identity
(`signer_identity`, the GitHub Actions issuer); a reviewer re-checks with the transparency log. It runs SentinelCI's
own rules only (`configs/opengrep/*.yaml`, each pinned by cases it must flag and cases it must leave alone; fixed
messages, so no code reaches a finding), from a private working directory and home, offline. The scanned repository
cannot silence it: `--disable-nosem` (a match under a `# nosemgrep` comment is reported, flagged, and its message
says the comment is not honoured), `--x-ignore-semgrepignore-files`, `--no-git-ignore`, `--max-target-bytes=0` (no
file is skipped for its size) and `--timeout=0` (no rule is dropped for a slow file; the run keeps the scanner time
limit); repository rule files are never loaded, and a link that leaves the scan target, or loops, is refused.
Opengrep chooses files by extension: `.py`, `.pyi`, `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts` and `.tsx`, plus an
executable file whose `#!` line names `python` or `node`; anything else (a script without an extension that is not
executable, `.mts`, `.cts`, `.pyw`, notebooks) is not scanned, and the guarantees above cover only these files.
`sentinel tools install`/`verify` check only the pinned sha256; the signature fields of the lock are not read. Any
error Opengrep reports fails closed, even a warning (too many matches in a file, out of memory: Opengrep then drops
the file's results), except a file it could parse only in part: that fails closed too when more than half of the
file's lines were not analysed (all of them when it could not parse the file at all), since one line of syntax
Opengrep does not know can hide a whole file. Each smaller gap (overlapping or adjacent spans merged) is a finding
of its own, so blank lines or a long docstring around unparsable code cannot hide it: rule
`sentinel-sast-not-analysed`, SAST HIGH (unscored, so P0: it blocks until fixed or waived), fingerprinted like a
match on the skipped text with the same occurrence numbering (§13.1), with a message that names the lines and
quotes no code. Valid modern syntax Opengrep cannot parse yet (a PEP 695 `def f[T]`, some TypeScript constructs)
shows up this way until Opengrep catches up: the way out is a reviewed waiver with an expiry, never a scanner
flag.

Stage 7, the image: `sentinel scan image` runs the same Syft on the image's OCI layout archive
(what `docker buildx build --output type=oci` writes, no registry), checks that it is the image of the given
manifest digest, and matches its SBOM with the same Grype and database. Before Syft runs, every blob of the
layout must hold the content its digest names, the layout must hold nothing else, and the manifest's config and
layers must all be there: Syft checks the manifest, not the layer bytes. The digest comes from the build
(`--metadata-file`), never from the layout's own `index.json`. Its findings are CONTAINER findings, each with
the image's digest, its reference (a repository: a tag or a digest in it is refused) and the layer the package
is in (its first place by path). That layer is the layer's `diff_id`, the digest of its uncompressed tar as the
image config lists it, as Trivy names layers, not the digest of the compressed blob. A report about another
image is refused. The tool status names Syft and Grype separately: Grype is `not_run` when Syft failed.



**Job isolation.** `scan` (runs repo code; `contents: read`; no secrets) · `build` (runs Dockerfile;
`packages: write` on main only; PR builds never push) · `gate` (no repo code; calls EPSS/KEV/OSV) · `attest`
(GitHub mode only, OIDC only here; in private mode signing is `make release` on the laptop, ADR-0011) · `report`
(`pull-requests: write`). In PR mode every job checks out
the pipeline (CLI, `tools.lock.toml`, policies, waivers) at the **base** commit and the change only as data to
scan; tools live in `$RUNNER_TEMP` (ADR-0008).

**PR mode (diff-aware):** only findings new to the PR (fingerprints not in the base-branch baseline) can block. A
known secret also counts as new in a file where the base did not have it, and so does a known vulnerable package in
a manifest where the base did not have it: both fingerprints hold no path (§13.1), and a new place has its own
exposure. Every place counts: `location` plus `other_locations`, Finding 1.1. The baseline is the base commit's
tree, exported with `git archive` outside the pipeline checkout and scanned in dir mode by the same pinned scanners.
If it cannot be produced, every finding counts (the strict side). The PR comment shows "N new" only when the gate
used that baseline (checked against `inputs.baseline_digest`), with the gate's own definition of new.
**Scanner failures** (any mode): each scanner writes a tool status (`schemas/tool-status.v1.json`) on success and on
failure, and the scan job keeps going, so a failed, timed-out or tampered scanner becomes a recorded BLOCK (SC-010)
with its reason. A missing tool status is SC-010 too. Each scanner run has a time limit (`--timeout`, 300 s in
`sentinel-scan.yml`), and the scan job's own limit outlives the sum of its runs, so a slow scanner ends as a
recorded `timeout`, not as a killed job.
**Scanners of the gate:** Gitleaks (secrets), Opengrep (SAST, SentinelCI's rules only), Syft then Grype (SCA),
Trivy (IaC) and zizmor (CI workflows), each on the head commit and on the PR baseline, each with its tool status:
the SCA status names Syft and Grype apart, and Grype is `not_run` when Syft failed. Grype's database is the only
download of a scan: `sentinel tools grype-db` prepares it once, before any scan, and its evidence (schema, build
time, checksum) is kept with the scan outputs; the scans themselves are offline, and a database that could not be
prepared makes them fail (SC-010). The SCA scan also writes what it read (`sca-report.json`: the Syft and Grype
binaries, the database Grype matched against and the SBOM's sha256) and the SBOM itself (`sca-sbom.syft.json`),
kept with the evidence: the same tree gives the same SBOM bytes (Syft's configuration fixes the paths it records)
and other findings with another database. Grype's CPE matching (`match` block) is pinned in its configuration and
required in its report.
**Scoring:** the gate job scores the findings with the base commit's risk model (`sentinel score`, §6.2) before
`sentinel evaluate`; the decision records, and the PR comment shows, the scored findings. A scoring failure means no
decision (exit 3).
**Release mode:** full evaluation, then signing. In this single repo, `demo-shop/` is scanned by its own workflow
calling `$/.github/workflows/sentinel-scan.yml` (GitHub's self-repository syntax: the workflow at the running
commit); the self-scan of SentinelCI excludes `demo-shop/`.

Example deterministic PR comment:

```
SentinelCI  verdict: BLOCK   policy bundle 1.3.0 · risk model 1.0.0 · decision 0193f2c4-…
  SC-001  Hard-coded secret                    demo-shop/services/shop-api/app/config.py:12   P0
  SC-003  Known-exploited CVE, fix available   example-lib 1.2.0 -> 1.2.4                     P0
Findings: 2 P0 · 3 P1 · 7 P2 · 21 P3 (33 total, 12 new)   Replay: sentinel replay 0193f2c4-…
AI advisory: in the dashboard (advisory only — does not affect the verdict)
```

## 6. Risk engine and release gate

### 6.1 Enrichment sources

| Signal | Source | Used for |
|---|---|---|
| CVSS | OSV.dev advisories (NVD fallback) | S |
| EPSS score + percentile | FIRST EPSS API `api.first.org/data/v1/epss` (daily) | E |
| Known exploited | CISA KEV JSON feed | E = 1.0, SC-003 |
| Fixed versions, aliases | OSV.dev | fix_available, remediation target |
| Reachability | static import analysis (Python AST, JS imports) | R |
| Service context | `sentinel.yaml` (exposure, environment, data class) | X, policy profile |

Each run stores a content-addressed **enrichment snapshot**; replay never uses live feeds.

Implementation (B2): fetching (network) and applying (offline) are separate. The fetchers write a snapshot
(`schemas/enrichment-snapshot.v1.json`), keyed by vulnerability id and dated by the feeds; a feed that could not be
reached is absent, so its values stay unknown. `sentinel enrich --snapshot --config sentinel.yaml` applies it to
package findings (CVSS and EPSS: the highest among the finding's ids and their aliases; KEV; fix availability) and
gives every finding the exposure of its `sentinel.yaml` component (longest matching path). Unknown stays absent:
the risk engine counts it as the worst case. `sentinel.yaml` (`schemas/sentinel-config.v1.json`) is read from the
base branch, like the policies and waivers, so a change cannot lower its own exposure.

Fetchers (B2, `sentinel snapshot`): OSV by id (one extra round for the aliases it reveals), EPSS in batches of
100 CVEs, and the KEV catalogue filtered to those CVEs; HTTPS to those three hosts only. The CVSS 3.0/3.1 base
score is computed from the OSV vector (highest vector wins). Each feed is all or nothing: a failure leaves the
feed out with a warning, never a partial feed; KEV is read before EPSS, and EPSS is left out when KEV could not
be read (EPSS alone would lower the risk of a listed vulnerability); the KEV catalogue is trusted whole or not at
all; redirects are never followed. `--record` / `--offline` capture and replay the feed answers (raw bytes and
their sha256, gzip-compressed) as offline fixtures; in CI they come from the base commit or a trusted store, like the
policies. `eval/feeds/` holds committed fixtures: 7 real vulnerable packages (Maven, PyPI, npm; KEV-listed and not;
alias chains), their recordings and the snapshot they give, checked offline by the tests. The NVD fallback for CVSS is not implemented yet: an id without a 3.x vector in OSV keeps an
unknown CVSS, which the risk engine counts as the worst case.

"Known no" is written only for what was checked: `kev: {listed: false}` only when the KEV lookup covered every
CVE id of the finding (`sources.kev.cves`), and `fix_available: false` only when OSV knew the vulnerability and
fixes none of the package (package URLs compared in canonical form). A KEV outage therefore leaves KEV unknown,
never "not listed", and the risk engine counts unknown as the worst case. `sentinel.yaml` is a reviewed trust
boundary: it is read with a YAML loader that refuses duplicate keys, anchors and aliases, and tags beyond plain
scalars, lists and mappings, and is limited to 64 KiB; component paths are canonical and unique. Residual risk:
where a change puts its files decides their path-scoped exposure (a file under an `offline` component is scored
as offline), so changes to `sentinel.yaml` and new top-level directories deserve a reviewer's eye.

Reachability (B2, `sentinel enrich --source`): static import analysis of the scanned tree for PyPI and npm SCA
findings, never executing it. `imported` when first-party code imports the package, or when a lockfile shows that
an imported package depends on it at runtime; nothing otherwise (the worst case, R = 1.0). `not_imported` is not
claimed: libraries load packages themselves (FastAPI templates load jinja2, PyJWT's RS256 loads cryptography)
through optional dependencies a lockfile does not record, so it needs per-library evidence first. CONTAINER
findings, `MAL-` advisories and npm packages with install scripts get no answer. In PR mode the base and the head
are both analysed and `imported` must hold in both, so a change cannot lower its own score by adding an import.
`reachable` would need call-graph analysis, a stretch goal (§16). Residual risk: a deliberately written import that
nothing uses gives `imported` (R 0.9 instead of 1.0); a missed import only leaves the worst case.

### 6.2 Risk model

`risk = 100 × S × E × X × R` clamped to [0, 100]. For CVEs: `E = 1.0` if KEV-listed else
`E = 0.4 + 0.6 × epss_percentile`. Weights live in `policies/risk-model.yaml`:

```yaml
version: 1.0.0
severity_weight: {CRITICAL: 1.0, HIGH: 0.75, MEDIUM: 0.45, LOW: 0.2, INFO: 0.05}
exploitability:
  kev: 1.0
  epss_floor: 0.4
  non_cve: {SECRET: 1.0, SAST_TAINT: 0.8, SAST_PATTERN: 0.5, IAC: 0.5, PIPELINE: 0.7}
exposure: {internet-facing: 1.0, internal: 0.7, offline: 0.5}
reachability: {reachable: 1.0, imported: 0.9, unknown: 0.8, not_imported: 0.4}
priority_bands: {P0: 70, P1: 50, P2: 30, P3: 10}   # below 10 -> P4
```

| Same CRITICAL CVE (EPSS pct 0.95, not KEV) in… | X | R | Score | Priority |
|---|---|---|---|---|
| Internet-facing API importing the package | 1.0 | 0.9 | 87 | P0 |
| Internal service importing it | 0.7 | 0.9 | 61 | P1 |
| Offline batch job never importing it | 0.5 | 0.4 | 19 | P3 |

Implementation (`sentinel score`, B3): the score is rounded to 0.1 and banded from the rounded value; `factors`
records S, E, X and R. Missing enrichment never lowers a score (E < 1 only when KEV was read and the CVE is not
listed, so a KEV outage next to a working EPSS feed cannot lower E; no exposure: X = 1.0; no
reachability analysis: R = 1.0, while `unknown` is for an analysis that ran and could not decide), so every score
stays at most `100 × severity_weight`, the bound the gate uses for unscored findings, and a finding with no
enrichment scores exactly that bound. Every priority band floor lies in (0, 100]. R applies to SCA and CONTAINER only; SAST counts as `SAST_TAINT` until findings carry the
analysis kind; a category without a `non_cve` weight counts as E = 1.0.

### 6.3 Rule catalogue

| Rule | Verdict | Condition |
|---|---|---|
| SC-001 | BLOCK | Secret detected (new in PR, or anywhere in a release image), not waived |
| SC-002 | BLOCK | Any P0 finding without valid waiver |
| SC-003 | BLOCK | KEV-listed vulnerability with a fix, internet-facing service (an unknown exposure counts as internet-facing) |
| SC-004 | BLOCK | Release image missing signature, SBOM or provenance |
| SC-005 | BLOCK | Invalid waiver (no owner / justification / expiry, or expiry > 90 days) |
| SC-006 | WARN | P1 findings (BLOCK above threshold in strict profile) |
| SC-007 | WARN | Base image not pinned by digest, or container runs as root |
| SC-008 | WARN | Copyleft licence in a distributed component |
| SC-009 | BLOCK | High-severity CI workflow issue introduced by the PR |
| SC-010 | BLOCK | Scanner failure, timeout or tool-integrity mismatch; a required scanner (`policies/required_tools.rego`) missing from the tool status, or no tool status where one is required (`pr`, `release`); malformed gate input |
| SC-011 | BLOCK | Misconfiguration that exposes the service by itself, introduced by the PR (privileged pod, host namespaces, root mounts or kernel modules; a public bucket, database or dataset; SSH, RDP or database ports open to the internet): a short list of Trivy rule ids in `policies/exposing.rego`, matched on Trivy findings only, whatever the finding's score |

Priority-based rules (SC-002, SC-006) read `risk.priority` (B3), only when `risk.model_version` is the bundle's
risk model (`inputs.risk_model_version`); an unscored finding, or one scored with another model, counts at its
worst case, `100 × severity_weight` banded, so CRITICAL and HIGH are P0 until scored. Each finding is reported under its most
specific rule (SC-001, SC-003, SC-009 or SC-011 before SC-002/SC-006). SC-011 exists because the exposure factor
X discounts a misconfiguration by its service's exposure, while a privileged pod or a public bucket creates the
exposure itself; every other misconfiguration keeps its risk-model priority (IaC weight 0.5). Waivers and diff-aware PR mode apply to every finding
rule; a not_affected VEX statement covers its package findings the same way (§6.4).
**Profiles** (`policies/profiles.rego`): `policy_profile` of the base-branch `sentinel.yaml`, given to `sentinel
evaluate --service-context`; `default` (or none) keeps SC-006 a WARN, `strict` makes any P1 an SC-006 BLOCK (the
threshold, `p1_block_above: 0`, is policy data). An unknown profile is malformed input (SC-010). Not yet
implemented: SC-004 (A4 attestations), SC-007, SC-008.

exposure itself; every other misconfiguration keeps its risk-model priority (IaC weight 0.5). The listed ids are
pinned against the pinned Trivy (`cli/tests/scanners/test_trivy_exposing.py`, which also records Trivy 0.76.1's
blind spots), so a Trivy bump that renames a check fails a test instead of turning SC-011 off. Waivers and diff-aware PR mode apply to every finding
rule. Not yet implemented: SC-004 (A4 attestations), SC-007, SC-008, the strict profile and VEX.


Policy rules use `input.evaluated_at`, never `time.now_ns()`. Reference implementation of the verdict logic
(verified with OPA 1.21):

```rego
package sentinel.gate

import rego.v1

now := time.parse_rfc3339_ns(input.evaluated_at)

waived(f) if {
	some w in input.waivers
	w.finding_id == f.id
	time.parse_rfc3339_ns(w.expires_at) > now
}

block contains v if {
	some f in input.findings
	f.category == "SECRET"
	not waived(f)
	v := {"rule": "SC-001", "finding": f.id, "msg": "Hard-coded secret"}
}

verdict := "BLOCK" if count(block) > 0
else := "WARN" if count(warn) > 0
else := "PASS"
```

### 6.4 Waivers and VEX

Waivers in `.sentinel/waivers.yaml` (finding id or vuln + purl, owner, justification, expiry ≤ 90 days), added by
PR and approved by CODEOWNERS; expired waivers stop applying. OpenVEX statements for "not affected":
`.sentinel/vex.json` (`schemas/vex.v1.json`, an OpenVEX v0.2.0 subset), read from the base branch like the waivers
and recorded by digest. A `not_affected` statement (a justification is required) covers a package finding when one
of its vulnerability ids is one of the finding's ids and one of its products is the finding's package (the purl base
for every version, or one version when the purl names it); a covered finding counts for no rule and is listed in
`vex_applied`. A statement of any other status about the finding disputes `not_affected`, whatever their order (the
gate does not order statements; fail closed): a document must not keep an earlier statement of another status about
the same product and vulnerability, so remove it when you add `not_affected`. Like a waiver, a `not_affected`
statement applies for 90 days after it was made (its `last_updated` or `timestamp`, else the document's), and a
statement or document dated after `evaluated_at` blocks (SC-010). Products are package purls: a statement covers that
package in every image and context gated with this repository, and `pkg:oci` products are refused. Aliases are taken
as written, so reviewers check them. Secrets are never covered. The AI may
draft a waiver PR; only a human approval makes it effective.

### 6.5 Decision record and replay

Schema: `schemas/decision.v1.json`. Fields: `decision_id`, `evaluated_at`, `subject` (repo, ref, commit, image
digest, context), `verdict`, `violations` (rule, effect, finding ids, message), `waivers_applied`, `vex_applied`
(since 1.4, when VEX was given), `inputs`
(digests of findings, SBOM, enrichment snapshot, policy bundle, waivers file (since 1.1), base-branch findings
baseline and tool status (since 1.2, when given), service context `sentinel.yaml` (since 1.3, when given), VEX
document (since 1.4, when given); risk
model version;
tool versions),
`engine_version`. The schema enforces verdict consistency (BLOCK ⇒ at least one BLOCK violation; PASS ⇒ none).
Attached to the image as an in-toto attestation, predicate type
`https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1`. `sentinel replay` re-evaluates from
digests and must be identical; checked nightly.

**Evidence store (replay input).** Content-addressed: `sha256/<hex>` holds every input exactly as digested
(findings, waivers, baseline, tool status, enrichment snapshot, SBOM, each policy file) and each policy bundle
manifest (`<sha256>  <path>` per file, sorted; its digest is `policy_bundle_digest`); `decisions/<id>.json` holds
decisions. Written by `sentinel evaluate --store`; every read is checked against its digest. `sentinel replay
<id | file>` takes all inputs from the store, policy included, and compares the whole record (exit 0 identical,
1 differs, 3 missing or tampered evidence). Recorded scanner versions are passed back as evidence; the OPA and
engine versions are the running ones, so an upgrade shows up as a difference. Every `sentinel-scan.yml` run
uploads its store as the `sentinel-evidence` artifact, and the PR comment's replay line names it. Proposed: the
evidence bundle (A4) and the platform evidence store (SeaweedFS, ADR-0007) carry the same `sha256/<hex>` layout,
so replay works on either.

**Nightly replay** (`.github/workflows/replay-nightly.yml`): replays the last successful night's corpus with
today's engine (`sentinel replay --all`), replays the `sentinel-evidence` artifacts of the last five
`demo-shop.yml` runs triggered by a push to main (not pull-request runs: a pull request can edit the workflow that
uploads its evidence), then records a fresh corpus (`eval/replay/corpus.py`: fixed gate cases covering PASS,
SC-001, SC-005 and SC-010), replays it in a fresh process and uploads it. `--all` skips decisions recorded with
another engine or OPA version (after checking that the record's `decision_id` matches its own subject, time,
inputs and engine version, so an edited version cannot turn a difference into a skip) and fails on any
difference, on missing evidence, on an empty store and when nothing was compared (every decision skipped; the
previous-night and release steps accept that with `--allow-all-skipped`, so an engine bump night says so in its
summary). Consequence: a change to what the engine decides for the same inputs must come with an engine version
bump.

## 7. Supply-chain integrity and deploy-time enforcement

- **SBOM:** Syft → CycloneDX JSON (primary) + SPDX JSON, for source and image (`sentinel sbom`: the pinned Syft,
  verified before it runs, in a private working directory and home with SentinelCI's own configuration passed
  explicitly, so the scanned repository's `.syft.yaml` is never loaded; offline, no remote lookup or tooling;
  no file catalog; images read from the OCI layout the build wrote (a directory or a tar of one), never pulled,
  and both SBOMs must name the image's manifest digest (`--image-digest`); `--base-path` stops links above the
  tree; a CycloneDX document without `serialNumber` or an SPDX document that is not one fails closed).
- **Signing:** Cosign v3 (Sigstore bundle format). Private mode: key pair, no transparency-log upload, on the
  release laptop only (`make release`, ADR-0011: from a clean checkout of `origin/main`, the build context taken
  from the commit, signed only after a non-BLOCK release decision on the built digest, in a throwaway local
  registry, then saved as a bundle). GitHub mode: keyless, identity = release workflow path + ref. Always sign
  digests, never tags.
- **Attestations:** SLSA provenance, CycloneDX SBOM, vulnerability scan, release decision (ADR-0010: one
  in-toto statement each about the image digest, signed by `sentinel attest` only for a decision that is not
  BLOCK; it checks that the decision is about this image and recorded these findings and this SBOM, and
  the vulnerability result, `schemas/vuln-result.v1.json`, names the decision, the findings and the SBOM's
  CycloneDX `serialNumber`, so the four are bound together).
- **`sentinel verify <image@digest>`:** checks signature, provenance, SBOM, decision; prints a trust report; must
  fail on unsigned, wrong key/identity, modified image, missing or BLOCK decision (automated tests). Each
  attestation must be signed by `--key` and about this digest; the decision must be a release decision about
  this image from `--repo`; the provenance must come from `--builder-id` and the decision's commit; the
  vulnerability result and the SBOM must be the decision's. Exit 0 trusted, 1 not trusted, 3 could not run.
  Offline from the evidence directory's Sigstore bundles (`--evidence`), or from the registry (the image's
  `cosign sign` statement and the four attestations `sentinel attest --push` attached, A4d).
- **Kyverno ImageValidatingPolicy** (`policies.kyverno.io/v1`, Kyverno 1.19, rendered by
  `sentinel admission-policy`): match our images (a prefix of the lower-cased reference), attestor = our
  public key (private mode; a keyless identity comes with keyless `sentinel verify` in GitHub mode), require
  the image signature and the four attestations bound as `sentinel verify` binds them (a non-BLOCK Decision v1
  verdict about this digest, from our repository; provenance from the release builder, in private mode the
  release script at main, `deploy/release/release.py@refs/heads/main`, and from the decision's commit; the
  vulnerability result and SBOM of that decision), `mutateDigest: true`. CEL reads one statement
  per type, so admission is weaker than `sentinel verify` on the full Decision v1 and vuln-result schemas and
  on ambiguity (a second statement of a type). Negative tests with `kyverno apply` against a real registry,
  then on kind in CI.

## 8. AI layer

AI runs after the decision is stored, writes only advisory tables, and every output is schema-validated and traced.

| Capability | Input | Output | Owner | Evaluated by |
|---|---|---|---|---|
| Explain | finding + code window + CWE + advisory | Explanation {summary, impact, exploit_scenario, fix_guidance, references, confidence} | B | rubric + LLM-judge agreement |
| Triage hint | finding + context + past waivers | TriageHint {likely_false_positive, rationale, confidence} | B | precision on labelled FPs |
| Correlate | all findings of a run | RootCauseGroup (`schemas/root-cause-group.v1.json`) {title, root_cause, finding_ids, single_fix} | A | ARI, alert reduction |
| Patch | finding + file + explanation (+ CI logs) | PatchProposal (`schemas/patch-proposal.v1.json`) | B | verified fix rate |

- **Provider interface** `sentinel_ai.providers.LLMProvider` (`complete(system, user, schema)`, `embed(texts)`).
  Default: local models via Ollama, `gemma4:12b-it-qat` for generation and `qwen3-embedding:0.6b` for
  embeddings, pinned by digest (ADR-0009, measured in `eval/model-selection/`). No multi-provider gateway dependency.
  Implemented (B5a): `sentinel_ai.providers.OllamaProvider`, on the standard library only. It talks to the
  loopback or the Compose service `ollama` (another host only when asked, `allow_remote`), never through a proxy,
  and refuses redirects. Before every request it checks the server's digest of the model against ADR-0009: a
  missing model or another digest is refused and nothing is sent. `complete` asks for JSON of the schema
  (`format`), at temperature 0 with a fixed seed, and validates the answer itself (a `ValidationError` is for the
  caller's repair retry); `embed` returns one finite vector per text, all of one size, in batches of 64 texts.
  Every request has a time limit on the whole request (checked while the answer is read) and an 8 MiB answer
  cap, and a `ProviderError` never holds the prompt or the answer.
- **Grounding:** offline CWE catalogue, OSV advisory text, code window; references must come from the context.
- **Guardrails:** import contract; untrusted text in delimited data blocks; schema validation with one repair
  retry, else "unavailable"; secret redaction before any prompt; model/prompt/input hash logged; injection
  canaries prove verdict invariance.
  Implemented (B5b): `sentinel_ai.explain.explain_finding` (Explanation v1) and `sentinel_ai.triage.triage_finding`
  (TriageHint v1), on the guardrails of `sentinel_ai.guardrails`. The finding goes without its id, snippet,
  evidence or run, every text redacted then clipped; with a checkout, the 15 lines around it go too (redacted, a
  regular UTF-8 file inside the repository only, and never from a file in which the scan found a secret, since
  `redact` cannot know every secret Gitleaks finds); a secret's finding is never sent. Each block is JSON lines with
  `<` and `>` escaped, and each prompt names its blocks as data (triage's also says that a comment calling the
  code safe is not evidence). An explanation may cite only the finding's CWE, CVE and advisory ids and their
  canonical pages (MITRE CWE, NVD, GitHub advisories, OSV), listed to the model in a `<references>` block. A triage
  hint may read, as precedent, the justifications of past waivers of the same rule (never their owner or id).
  Schema validation with one repair retry, an answer that quotes a secret refused, then "unavailable"; each output
  names its provider, model (and digest when pinned) and the sha256 of its prompt and input. Grounding from an
  offline CWE catalogue and OSV advisory text come next.
  Implemented (B5c): explanations on the platform. `POST /api/v1/findings/{id}/explain` queues a job
  (`sentinel.explain`, Celery over Redis, JSON only; never for a secret's finding), and the worker
  (`sentinel_worker.tasks`, the Compose service `worker`) claims the request once, asks the pinned model, and
  records the outcome. An explanation is kept only if it is a valid Explanation v1 document about the request's
  own finding, byte for byte and named by its sha256, and never changes; a request that gets none says why
  (unavailable, not_sent or failed, an unexpected error by its type only). Without a checkout on the platform,
  no code window is sent: the finding and its references only.
- **Correlation (A7):** stage 1 fingerprint dedup → stage 2a structural fix keys within one category (the same
  package, the same advisory under any of its ids, the same rule in the same file; deterministic) → stage 2b
  embeddings (pgvector) + average-linkage clustering within a category, never for secrets (each is rotated on
  its own) → stage 3 LLM labels and single fix for the groups it is given (it labels, it never forms groups);
  each stage measured separately (ARI, alert reduction). Stage 3 (`correlate.labels`) is given the groups of
  two findings or more, never one with a secret; each finding goes as one JSON line in a `<findings>` data
  block, with `<` and `>` escaped, without its id, snippet or evidence, and with anything that looks like a
  secret redacted. The answer must validate (one line each, the contract's lengths), with one repair retry,
  else the group keeps its template labels; an answer that quotes a secret is refused; a template's fix is
  never replaced. A labelled group records the provider, the model and the sha256 of the prompt and of its
  input. A template fix is proposed only when one change resolves every member; a model's fix only fills a
  group that had none, and is advice that no stage verifies. The group's template title and shared key go in a
  `<group>` data block, escaped like the findings, and the prompt names both blocks as data. Redaction covers
  known token prefixes, `Bearer`/`Basic` values, a URL's password and any assignment whose name holds password,
  secret, token, key or credential (single or double quotes, prefixed names such as `DB_PASSWORD`). A run's groups travel in a correlation document (`schemas/correlation.v1.json`) with the sha256 of
  the findings they came from (computed on the bytes B1 recorded, `GET /api/v1/runs/{id}/findings`), the stages
  that ran, the threshold and the embedding model; if the embedder fails, stages 1 and 2a are kept and the
  document records the embedding stage as `skipped`, with the failure, so an outage never reads as an
  ablation. The 2b threshold (`DEFAULT_THRESHOLD` = 0.75) is the one calibrated on the calibration half (§17, `eval/correlation/threshold.json`, A7), and a test keeps the two equal.
  B1 records the document (`POST /api/v1/runs/{id}/correlations`) only if it is a valid Correlation v1 document,
  its `findings_sha256` is the run's, and its groups hold each of the run's findings exactly once, each group
  within one category (as stages 2a and 2b build them; the alert-reduction metric counts a group in its
  category). Each version is kept byte for byte, named by its sha256 (the same bytes again: 409 with that version), never changed or
  deleted; `GET` serves the latest, or a version by `?sha256=`. The gate never reads it.
  `sentinel-ai correlate --run ID` stores it on the platform (`correlate.store`, §13.3): the findings it
  reads must be the bytes B1 recorded, and the document it posts is canonical JSON whose sha256 is the
  version. Stages 1 and 2 are deterministic, so a rerun on the same findings is the same version (409, already
  recorded); with embeddings, only while they are stable; stage 3 is a model's text, so a rerun is a new
  version even with the same model and prompt. The latest version can be a degraded one
  (`correlator.skipped`): readers show it as such, never as an ablation.

## 9. Verified remediation loop

States: PROPOSED → PATCH_READY → PR_OPEN → VERIFYING → VERIFIED | REJECTED (retry ≤ 2 with CI feedback) | FAILED.

| Strategy | Applies to | How |
|---|---|---|
| Dependency bump | SCA with fixed version | minimal fixed version, regenerate lockfile |
| Dockerfile fixer | container hygiene | non-root USER, COPY for plain local ADD sources, `apt-get --no-install-recommends` (base digest pin and `curl \| sh`: later, they need a registry or the application) |
| Kubernetes fixer | manifest findings | runAsNonRoot, readOnlyRootFilesystem, drop ALL, limits |
| LLM code fixer (B6) | SAST | diff restricted to flagged files; retried with CI logs |

**Verification gate (all must hold; encoded in `schemas/verification-result.v1.json`):** build OK · tests pass ·
target fingerprint gone · no new ≥ MEDIUM finding · verdict ≠ BLOCK. Bot uses `pull_request` (never
`pull_request_target`), verification jobs get no secrets, the bot never merges.

Implemented (A6a, A6b): `sentinel remediate kubernetes`, `sentinel remediate dockerfile` and `sentinel remediate
verify`. The Dockerfile fixer adds `USER 10001:10001` to the final stage after its last RUN and USER (a USER line is
never rewritten), turns ADD into COPY only when ADD would do nothing more (sources judged by their content in the
repository: no tar, nothing compressed, no URL, glob or variable), and adds `--no-install-recommends`; an
instruction that carries another finding is left alone, and only the findings an edit resolved are claimed. Its
USER change can still break an image that writes as root at run time. The Kubernetes fixer maps each
Trivy rule id it resolves to one edit (privileged, privilege escalation, capabilities, non-root UID and GID,
read-only root file system, seccomp profile, host namespaces), each checked against the pinned Trivy: the edit makes
that rule's finding disappear and adds none. What the fix would have to choose for the application (hostPath
volumes, image tags, resource limits, added capabilities) is left alone, and those findings stay open. Some edits
can still change how a workload runs: a non-root UID/GID (a UID or GID above 10000 is kept), a read-only root file
system and dropped capabilities can stop a workload that writes into its image, owns files by another UID or needs
a capability. The rationale names them, and "build OK" does not include a cluster deploy test yet. A file with a
workload kind the fixer does not edit is left alone, so no finding on it is claimed.

Implemented (B6): the LLM code fixer, `sentinel_ai.patch.propose_code_fix`, a library the remediation loop (A6)
calls with one SAST finding, the scan's findings, the checkout and a provider (§8.1). The model never writes a
diff: it answers with line edits of the lines it was shown (`CodeFix`), and the diff is computed from the file on
disk, so it edits only the flagged file. Only a SAST finding of the scan, with a line, in a regular UTF-8 file
inside the repository (no symbolic link on its path, lines counted on line feeds only) is sent; a file in which a secret was found is never sent. The finding (without its id,
snippet or evidence) and the code go as JSON lines in `<finding>` and `<code>` blocks, `<` and `>` escaped, named
as data in the prompt; a file over 400 lines is sent as a 400-line window around the finding, and nothing is sent
past 60 000 characters. A line that looks like a secret is sent redacted and cannot be edited. An answer is
refused, and asked again once with the reason, when an edit leaves the lines sent, overlaps another, misses the
flagged lines, adds a scanner suppression (`nosemgrep`, `nosec`, `noqa`...) or something that looks like a
secret, changes nothing, or leaves a Python file that no longer parses (a file the parser cannot handle is
never a crash); the proposal must then pass A6's
`check_proposal` and `git apply --check`. A rejected proposal is retried (attempts 2 and 3) with its diff and the
redacted end of the CI log in a `<previous_attempt>` block. The outcome records the sha256 of what was sent, and
the proposal names its model and prompt version (`sentinel-patch-code/1`). There is no model behind it until B5's
provider; the guardrails are tested with a scripted one.
Manifests are edited round-trip (comments, order and quoting kept); a file whose layout cannot be reproduced exactly
is left alone. A proposal touches only flagged files and its diff applies with `git apply`. The gate verifies only
a proposal it could verify honestly (its id matches its content; its findings are in the base scan; its diff edits,
in place, only the files they are in, each hunk read to its line counts as git reads it) against the decision made
on the patched scan (`inputs.findings_digest`), in pr context, with the tool status it recorded, which must show
the scanner of every target `ok`. A target is gone only when no new fingerprint of the same tool and rule appears
in its file. A failing patch is REJECTED while an attempt is left (at most three), FAILED after the last one.
`sentinel remediate apply` (A6c) commits a proposal on a new `sentinel/fix/` branch of a local clone with plumbing
commands on a temporary index (no checkout, so no hook, filter or fsmonitor of the clone runs, and nothing is
pushed), after the same proposal check as the gate against the base findings and a check that the diff applies to
the base and edits regular files in place.

The bot (A6d, ADR-0013, `.github/workflows/sentinel-remediate.yml`, by hand only) splits the work in two jobs. A
read-only `propose` job scans the commit as it is committed (a bare copy whose `attr.tree` is the empty tree, exported
with `git archive --worktree-attributes`, never the checkout), runs the fixers and `apply`, and hands over each branch
as a git bundle.
A `publish` job, the only one with a write token, runs no repository code (the runner's git, jq and gh only):
it pushes a branch and opens its pull request only if the bundle holds exactly that `sentinel/fix/` branch, one
commit on the scanned commit, carrying the proposal's id and editing in place exactly the files the proposal
lists, and only if the proposal is one the bot could have made (a UUID id and its branch; a deterministic
strategy and only the files it can fix, inside the scanned directory, never under `.github/` or `.sentinel/` or
a `sentinel.yaml`; a sha256 per finding). The pull request shows only checked values, the rationale as fenced
text. A tampered propose job can therefore make at most a pull request that edits, in place, files of the
scanned directory that its strategy can fix. An existing branch is not opened twice. The workflow token's pull requests
start no workflow by themselves, so the same run verifies them (A6e). A read-only `verify` job, with the scanned
commit's pipeline and no secret, rebuilds each pull request's commit from its proposal and requires it to be the
same commit, scans both commits with the scanners the pr gate requires, builds and tests the patch, evaluates the
gate on the patched commit in pr context (the scanned commit as baseline) and runs `sentinel remediate verify`. A
`report` job, which runs no repository code, re-checks each result against the gate's invariant, comments it on its
pull request and sets the `sentinelci/remediation` commit status; a pull request without a trustworthy result is
reported FAILED. For the IaC strategies, `sentinel remediate check` defines the build (every edited file still
parses into the same resources: a manifest's documents, a Dockerfile's stages) and the tests (the patch changes only
what its strategy may change: a manifest's pod and container security settings; a Dockerfile's added `USER
10001:10001` after the final stage's last RUN, ADD → COPY only where the fixer makes it (COPY's flags, plain local
sources of the base commit's whole tree: never a URL, an archive or a link), `--no-install-recommends`; a file the
fixer never edits fails). The tests also re-run the deterministic fixer on the scanned commit's whole tree and IaC
findings: the proposal must be its output, field for field but `created_at` (a deterministic fixer gives the same
proposal on the same input), which catches any edit the fixer would not make, whatever its shape, including an ADD
it left alone because another finding sits on it, or one that claims fewer findings. `verify` fetches the scanned
commit into a bare repository whose `attr.tree` is the empty tree and exports every tree whole with `git archive
--worktree-attributes`, so the scanned commit's `.gitattributes` cannot drop or rewrite what is scanned and checked,
or hide a diff from Gitleaks, whatever HEAD becomes, and the base and the patched commit are scanned on trees of the
same shape. For `llm:code` (ADR-0014), the build is that every edited file is Python and still parses, and the tests
are two (ADR-0014 decision 3): the service's behaviour tests (the nearest `tests/` above the edited file) pass on the
patched code, and the target finding's own security test (`security_tests/test_<rule>.py`) fails on the base code and
passes on the patched code, so the weakness is gone, not only the scanner's sight of it. Both test directories come
from the base commit, mounted read-only over the patch's, and each run is pytest in a throwaway container from an
image pinned by digest: no network, read-only, no capability, as nobody, with memory, process and time limits. A run
counts only when pytest's own summary agrees with its exit code: tests passed and none skipped, or, on the base, tests
failed, and only one summary line. A patch to either test directory, a service without behaviour tests or a rule
without a security test is never verified. The LLM code fixer runs on the laptop (`make remediate-code`, ADR-0014):
each proposal goes through the same steps as the bot's `verify` job with origin/main's CLI, policies and waivers; a
REJECTED attempt is proposed again with its diff and what rejected it (attempts 2 and 3); `PUBLISH=1` pushes a
VERIFIED branch and opens its pull request with the person's own `gh`, which a person reviews.

## 10. Dashboard and observability

Pages: Overview, Findings, Finding detail, Runs, Policies & waivers (B) · Releases & evidence, Supply chain,
Remediation, Root-cause groups (A).

| Metric | Definition |
|---|---|
| MTTR (per priority) | mean(fixed_at − first_seen_at) |
| Gate block rate | BLOCK ÷ all decisions, per context |
| Policy compliance | % running images with signature + SBOM + provenance + non-BLOCK decision |
| Remediation success | VERIFIED ÷ attempted, per strategy |
| Alert reduction | 1 − groups ÷ raw findings |

Prometheus names: `sentinel_gate_decisions_total{verdict,context}`, `sentinel_findings_open{priority,category}`,
`sentinel_pipeline_stage_duration_seconds{stage}`, `sentinel_remediation_attempts_total{strategy,outcome}`,
`sentinel_ai_request_duration_seconds{task,model}`, `sentinel_attestation_verifications_total{result}`,
`sentinel_findings_fixed{priority}`, `sentinel_findings_fix_seconds{priority}` (MTTR is their ratio),
`sentinel_correlated_findings{category}`, `sentinel_root_cause_groups{category}` (alert reduction is
`1 - groups / findings`).

MTTR is measured on each repository's release runs of its default branch whose findings and decision are
recorded: a finding is fixed when a run reports it and the next such run does not (in the order the runs were
recorded, not the commits' order), and its time to fix runs from the first run of that streak to the run that no
longer reports it. A run whose decision holds SC-010 is skipped: a failed scanner is no evidence that a finding is
gone. MTTR covers every fix since the first such run; when an older run's decision is recorded late, that run
becomes evidence and a fix can move earlier, so MTTR can go down. Alert reduction counts the findings of each repository's
latest correlated release run against the groups of its latest correlation version (A7), by category.

Implemented (A8a): the platform API's `GET /metrics` (`platform/api/src/sentinel_api/metrics.py`) serves only
these names, with only these labels, in the Prometheus text format. Values are counted by PostgreSQL in one
read-only REPEATABLE READ transaction per scrape (one snapshot, so a ratio's two halves come from the same rows),
and no row is loaded. A metric whose data the platform does not store yet is absent, never 0, so
Grafana shows "No data" rather than "0 BLOCK". Exposed so far: `sentinel_gate_decisions_total`, the gate decisions
recorded (`POST /api/v1/runs/{id}/decision`), by verdict and the run's context; and `sentinel_findings_open`, the findings of each
repository's latest release run of its default branch whose findings are recorded (`ref` equal to
`SENTINEL_DEFAULT_REF`, default `refs/heads/main`: a manual release run on another branch is not counted), by
priority (`P0` to `P4`, or `unscored` before scoring) and category. Prometheus scrapes it, and Grafana provisions the read-only
`SentinelCI overview` dashboard (`deploy/compose/grafana/provisioning/dashboards/`): open findings, gate block rate,
remediation success, attestation verifications, stage and AI durations.

Implemented (B7a): the dashboard (`platform/web`) has its core pages, Overview (from `sentinel_findings_open`), Findings
and Finding detail (with the finding's root-cause group, advisory); Track A's pages use the same layout and the
client generated from `schemas/openapi.yaml`.

Implemented (B7b): Runs and a run (its verdict and decision as recorded, "No decision" never shown as PASS), and
Policies & waivers: for each repository, the waivers its latest release decision of the default branch read (owner,
justification, target, expiry, whether the decision applied it, and the decision's SC-005 reasons), and the rule
catalogue of §6.3 with how many recorded decisions each rule fired in. The page reads; waivers stay pull requests.

## 11. Technology stack

| Layer | Choice |
|---|---|
| CI/CD | GitHub Actions (reusable workflows); Jenkins as stretch |
| Core | Python 3.12, uv workspace (locked with hashes), Typer, Pydantic v2 |
| Secrets / SAST | Gitleaks (Betterleaks-compatible) / Opengrep + Semgrep-format rules |
| SCA / container | Syft → Grype; Trivy (pinned, verified) as second engine; OSV |
| IaC / CI config | Trivy `config` (A1c) / Checkov / zizmor |

| IaC / CI config | Trivy (config) / zizmor (Checkov dropped, ADR-0012) |

| Signing / provenance | Cosign v3 (key pair now, keyless later); GitHub attestations after going public |
| VEX / policy / admission | OpenVEX / OPA (Rego v1) / Kyverno ImageValidatingPolicy |
| Backend / data | FastAPI, SQLAlchemy 2, Alembic, Celery, Redis / PostgreSQL + pgvector, SeaweedFS (S3) |
| AI | Ollama (local), own provider interface |
| Frontend | React, TypeScript, Vite, TanStack Query, Tailwind, Recharts |
| Observability / runtime | Prometheus, Grafana / Docker, Compose, kind, Helm, Argo CD |
| Quality | pytest, Hypothesis, ruff, mypy (strict), import-linter, pre-commit, Dependabot (cooldown), zizmor |

Pin exact versions (`tools.lock.toml`, `uv.lock`, chart versions); never use `latest`.

## 12. Repository layout

```
.github/workflows/   ci.yml (this repo) · sentinel-scan.yml · sentinel-release.yml · demo-shop.yml · replay-nightly.yml
cli/src/sentinelci/  scanners(A) normalize(A) enrich(B) risk(B) policy(B) supplychain(A) report(A)
platform/api         (B)      platform/worker (B; remediation jobs A)      platform/web (B core; pages split)
ai/src/sentinel_ai/  providers, prompts, explain, triage, patch, guardrails (B) · correlate (A)
policies/            (B) *.rego, *_test.rego, risk-model.yaml
schemas/             (shared) contracts + fixtures
deploy/              (A) compose, kind, helm, kyverno, argocd, grafana
eval/                (B) harness, datasets, reports
demo-shop/           (A+B) INTENTIONALLY VULNERABLE: services/, infra/, gitops/, examples/bad-workflows/, ground-truth/
docs/                spec/, adr/
tools.lock.toml      (A) pinned scanner versions + checksums
```

## 13. Contracts between the two tracks

Contracts live in `schemas/`, are validated in CI (`tests/contracts`), and are versioned (breaking change → v2).

### 13.1 Finding v1 — `schemas/finding.v1.json`

Required: `schema_version`, `id`, `tool`, `rule_id`, `category` (SECRET | SAST | SCA | CONTAINER | IAC | PIPELINE |
LICENSE), `title`, `severity` (CRITICAL | HIGH | MEDIUM | LOW | INFO), `run`. Conditional: SECRET ⇒ `location` +
`evidence.secret_hash` (raw secrets are never stored); SAST/IAC/PIPELINE ⇒ `location`; SCA/LICENSE ⇒ `package`;
CONTAINER ⇒ `package` + `image`. Optional blocks `enrichment` (B2) and `risk` (B3). Paths must be relative and
cannot contain `..`. No pattern-checked field (ids, digests, paths, purls) may contain a line break, in any validator.

**Several locations (1.1, additive).** One finding (one `id`) can be seen in several places, e.g. the same secret
in two files. `location` is the first one by (path, start line); `other_locations` lists every other one, sorted
the same way, without duplicates and never truncated. It is only allowed in a `schema_version` 1.1 finding and
only next to `location`. A finding seen in one place may stay 1.0. Consumers that compare locations (diff-aware PR
mode in the gate, SPEC section 6.5) read `location` plus `other_locations`.

**Fingerprint rules:**
- SCA / CONTAINER: `sha256(category | vuln id | purl base)` where *purl base* = the purl without version,
  qualifiers or subpath (same definition as `purl_base` in `policies/gate.rego`). After a bump the finding disappears; base-image point releases, other
  architectures and Grype/Trivy qualifier differences keep the same fingerprint. Waivers use the same purl base.
  The *vuln id* is the scanner's id of the record that matched, which is also the finding's `rule_id` (a GHSA for
  a Grype language match, stable when a CVE is assigned later); the related CVE ids go to `cve` and the other ids
  to `aliases`, through which enrichment (B2) and correlation (A7) join tools.
- SAST: `sha256(rule id | path | hash of normalized snippet)` — survives line shifts.

- SAST: `sha256(rule id | path | hash of normalized snippet)` — survives line shifts — plus the occurrence number
  for repeated identical matches in a file: in line order, the first keeps that id and the n-th (n ≥ 2) is
  `sha256(<that id> | n)`, its own finding. A copy of a vulnerable line is then new in a PR, and a waiver covers
  one place. Code Opengrep could not parse (rule `sentinel-sast-not-analysed`) uses the same formula, with the
  skipped lines as the snippet.

- SECRET: `sha256(rule id | sha256(secret value))`.
- IAC: `sha256(rule id | path | resource)`.
- PIPELINE: about a whole job or file, `sha256(rule id | path | job id, or "workflow" for the file)`; any other
  finding (below a job, or at or below a top-level key), `sha256(rule id | path | job id or top-level key |
  sha256(normalized code))`, the code being the source text the finding is about, normalized like a SAST snippet
  with the spaces inside `${{ }}` dropped:
  - an expression or an action reference: only the line(s) of the step holding it, so an edit to another line
    of the same `run:` script keeps the id;
  - a top-level key itself: its value (`on: pull_request_target` is the trigger, as in the list and mapping
    forms, which give the same id);
  - a Dependabot entry: the flagged line and the entry's `package-ecosystem`. Two entries of the same ecosystem
    with the same setting (in different directories) still share one id, the second as an `other_location`.
    zizmor names no ecosystem for an insufficient `cooldown`, so two entries with the same short cooldown share
    one (MEDIUM) id;
  - an expression zizmor gives no route for (`overprovisioned-secrets`, `unredacted-secrets`): the `${{ }}`
    expression itself (job id "workflow"). The same expression in another job shares the id, as zizmor names no
    job; a finding about the whole file (the workflow-level `excessive-permissions`) hashes no code;
  - otherwise the text zizmor points at (a step, a permission).

  The same line in two steps of one job (or of one action) is one finding, the second place an `other_location`:
  the job is the trust boundary, since code run by the first step already controls the later steps of the job
  (`$GITHUB_ENV`, the workspace).
  A job holds many steps: a new expression, trigger or Dependabot entry must be a new finding, and a waiver
  must not cover it. Line moves, re-indentation and added steps keep the fingerprint; a position (a step or
  entry index) is never part of it.

### 13.2 Other contracts

| Contract | Producer → consumer | Content |
|---|---|---|
| `decision.v1.json` | B4 → A4, A5, B1 | §6.5 |
| `tool-status.v1.json` | A3 → B4 | per tool: version, hashes, status (`ok` … `not_run`), detail; any non-`ok` status → SC-010; required in `pr`/`release`, and must list every required scanner |
| `patch-proposal.v1.json` | B6 / A6 fixers → A6 | finding ids, strategy, diff, files, rationale, model (required for `llm:code`) |
| `verification-result.v1.json` | A6 → B1, B8 | gate outcome; VERIFIED only if every condition holds |
| `explanation.v1.json` | B5 (`sentinel_ai.explain`) → B1, B7, B8 | finding id, summary, impact, exploit scenario, fix guidance, references (only the finding's own CWE, CVE and advisory ids and their canonical pages), confidence, model with prompt and input hashes. Advisory: never read by the gate |
| `triage-hint.v1.json` | B5 (`sentinel_ai.triage`) → B1, B7, B8 | finding id, likely false positive, rationale, confidence, model with prompt and input hashes. Advisory: never a waiver, never read by the gate |
| `root-cause-group.v1.json` | A7 correlator → B1, B7, B8 | finding ids (sorted, one group each), stage that formed it, title, root cause, single fix or null; `model` for stage `llm` only. Advisory: never read by the gate |
| evidence bundle layout | A4 → B1 | `manifest.json` (sha256 of each file, signed) + decision, findings, snapshot, SBOMs, raw outputs; `attestations/<kind>.sigstore.json` (ADR-0010) |
| `vuln-result.v1.json` | A4 attest → `sentinel verify`, Kyverno (A5), B1 | `scanner.result` of the vulnerability attestation: decision id, findings digest, SBOM digest and `serialNumber`, totals by severity and category, tool versions |
| `trust-report.v1.json` | A4 `sentinel verify --report-json` → A8 | one verification of an image digest: mode (registry or evidence), repository, builder id, sha256 of the public key, time, every check (name, ok, one-line detail), trusted exactly when every check passed |
| `remediation-attempt.v1.json` | A6 report / `sentinel upload-remediation` → B1 (`POST /api/v1/remediations`), A8 pages | a patch proposal and its verification result, with the repository; the result is the proposal's (same id and attempt) and not verified before it; recorded once per proposal |
| `release-evidence.v1.json` | A4 `make release` / `sentinel upload-release` → B1 (`POST /api/v1/releases`), A8 pages | a release decision (Decision v1, release context, with the image digest) and its trust reports, at most one per mode, each naming that decision, none for a BLOCK; recorded once per decision |
| `openapi.yaml` | B1 → A3, A6, A8, B7 | Platform API |
| `sentinel.yaml` (`sentinel-config.v1.json`) | target → B2, B4 | service, exposure, environment, data_classification, owners, policy_profile; optional `components` (path, exposure, data class) |
| `enrichment-snapshot.v1.json` | B2 fetchers → B2 apply, evidence store | per vulnerability id: aliases, CVSS, fixed versions per purl base, EPSS, KEV; dated sources |

### 13.3 Platform API v1 (first cut)

`POST /api/v1/runs` (409 with the existing run for a CI run already recorded) · `GET /api/v1/runs` (newest first, `repo`, `context`, `ref`, paginated) · `POST /api/v1/runs/{id}/findings` (NDJSON) · `GET /api/v1/runs/{id}/findings` (the exact upload) · `POST /api/v1/runs/{id}/artifacts` ·
`POST /api/v1/sync/github` · `GET /api/v1/findings[/{id}]` · `POST /api/v1/findings/{id}/explain` (queues an explanation, B5c), `GET /api/v1/explain-requests/{id}` and `GET /api/v1/findings/{id}/explanation` (the latest, byte for byte; advisory) ·
`POST /api/v1/runs/{id}/correlations`, `GET /api/v1/runs/{id}/correlations[?sha256=]` and `GET /api/v1/runs/{id}/correlations/versions` (Correlation v1 documents, scoped by run, kept byte for byte, advisory) ·
`POST|GET /api/v1/runs/{id}/decision` (the run's Decision v1, one per run, made on the run's recorded findings and about its subject, kept byte for byte) ·
`PUT|GET /api/v1/waivers/{sha256}` (a waivers file a recorded decision read, kept byte for byte), `GET /api/v1/waivers[?repo=]` (the waivers each repository's latest default-branch release decision read) and `GET /api/v1/rules` (how many recorded decisions each rule fired in) ·
`POST /api/v1/remediations` (Remediation attempt v1, once per proposal, kept byte for byte), `GET /api/v1/remediations[?repo=&strategy=&outcome=]` and `GET /api/v1/remediations/{proposal_id}` (A) · `POST /api/v1/releases` (Release evidence v1, once per decision, kept byte for byte), `GET /api/v1/releases[?repo=&verdict=]` and `GET /api/v1/releases/{digest}/evidence[?decision_id=]` (the release recorded last without `decision_id`: the order of recording, not of the decisions) (A) ·
`GET /metrics` · `GET /healthz`.

## 14. Engineering workflow

- Trunk-based, branches `<task-id>/<name>` (e.g. `a2/normalizer-grype`), Conventional Commits, squash merge.
- `main` is protected by convention during the private phase (§4.3): PR + approval by the other member + green
  `ci` before merge; no direct push, no force push. Enforced by branch protection once public.
- **Cross-review rule:** the reviewer must be able to explain the change.
- **Definition of done:** tests (core decision logic ≥ 80% coverage, policies ≥ 90% `opa test --coverage`),
  docs updated, CI green, contracts valid, reviewed.
- ADRs for significant decisions (`docs/adr/`).
- Rhythm: Monday 30-min sync, Thursday async update, short demo at the end of each sprint.
- Claude Code: one task = one branch = one session; plan first, tests first; review every diff and every new
  dependency; never paste real tokens.

## 15. Task division

Vertical ownership; each track has DevOps, security, backend/UI and an AI component. Size points S=1, M=2, L=3:
**Track A = 22, Track B = 22.**

### 15.1 Track A — Pipeline, Supply Chain & Runtime

| ID | Task | Deliverables / acceptance | Sprint | Size |
|---|---|---|---|---|
| A1 | Scanner integration | Adapters (Gitleaks, Opengrep, Grype, Trivy, zizmor; no Checkov, ADR-0012) → `out/raw/`; `tools.lock.toml` + `sentinel tools verify`. Accept: fixture test per adapter; tampered binary → SC-010; crash → SC-010 | S1 | M |
| A2 | Normalizer & fingerprints | SARIF/JSON → Finding v1, §13.1 fingerprints, cross-tool dedup. Accept: golden files; schema-valid; byte-identical output | S1 | M |
| A3 | Hardened reusable pipeline | `sentinel-scan.yml` with job isolation, PR diff-aware + main modes, deterministic PR comment, SHA pins, demo-shop workflow. Accept: fake secret PR blocked; zizmor clean | S1–S2 | L |
| A4 | Supply chain & release | `sentinel-release.yml`: build by digest, SBOMs, Cosign sign + attestations (SBOM, vuln, decision, provenance), signed evidence bundle, `sentinel verify`. Accept: verify fails on the 4 bad cases | S2 | L |
| A5 | Runtime enforcement | kind + registry, Helm, Argo CD, Kyverno policy, GitOps digest bump. Accept: bad images denied by automated tests; good release deploys | S3 | L |
| A6 | Remediation orchestration | Bot, deterministic fixers, PR creation, verifier, retries, state machine; consumes B6. Accept: never VERIFIED with failing test / new finding; never merges | S4 | L |
| A7 | AI alert correlation | §8 correlator and `correlation.v1.json` (B1 serves it under `/api/v1/runs/{id}/correlations`), pgvector. Accept: ARI + alert reduction with ablation, threshold calibrated on a split of the seeds fixed first (the calibration half), never on the test half | S3 | M |
| A8 | Observability & pages | Prometheus metrics, Grafana as code, pages Releases, Supply chain, Remediation | S3–S4 | M |
| A9 | Demo seeds: infra & deps | Dockerfiles, K8s, Terraform, vulnerable/unused deps, fake secrets + ground truth | S0–S1 | S |
| A10 | Hardening & v1.0.0 | Self-gating, Scorecard, caching, signed v1.0.0, switch to GitHub mode when public | S5 | S |

### 15.2 Track B — Risk Intelligence, Policy & AI Platform

| ID | Task | Deliverables / acceptance | Sprint | Size |
|---|---|---|---|---|
| B1 | Platform backend | FastAPI, PostgreSQL + Alembic, SeaweedFS (S3), Celery + Redis, GitHub sync, OpenAPI in `schemas/`. Accept: `make up`; an upload or a sync ingests a real run (changed in 1.1.24); contract tests | S1 | L |
| B2 | Enrichment | EPSS, KEV, OSV, reachability, `sentinel.yaml`; snapshots + offline fixtures | S2 | M |
| B3 | Risk engine | §6.2 model, bands, factor breakdown, CVSS baseline. Accept: property tests (monotonicity, bounds) | S2 | M |
| B4 | Policy & decisions | Rego SC-001…SC-010, profiles, diff-aware mode, waivers + VEX, Decision v1, `evaluate`, `replay`; minimal SC-001 for S1. Accept: coverage ≥ 90%; replay identical | S1–S2 | L |
| B5 | AI analyst | Provider (Ollama), prompts, retrieval, explanation + triage, redaction, injection isolation, metrics | S3 | L |
| B6 | AI patch generator | LLM fixer → PatchProposal, scope restriction, `git apply --check`, retries | S4 | M |
| B7 | Dashboard core & pages | React scaffold, typed client from OpenAPI, Overview, Findings, Finding detail, Policies | S1–S4 | L |
| B8 | Evaluation harness | §17 metrics, reproducible `make eval` report | S3–S5 | L |
| B9 | Demo seeds: app code | SAST seeds, injection canaries, ground-truth schema | S0–S1 | S |

### 15.3 Hand-offs

| Producer → consumer | Artifact | Needed by | Mock until then |
|---|---|---|---|
| Shared → all | schemas + fixtures | end S0 | — (done in Sprint 0) |
| A2 → B2, B3, B4 | findings NDJSON | mid S1 | fixtures |
| B1 → A3, A8 | OpenAPI + ingestion (sync later, 1.1.24) | end S1 | local JSON |
| B4 → A4, A5 | Decision v1 | mid S2 | fixture decision |
| A4 → A5, B1 | evidence bundle | end S2 | sample bundle |
| B5 → A7 | LLMProvider | start S3 | fake provider (see `ai/tests`) |
| B6 → A6 | LLM patches | mid S4 | deterministic fixers first |
| A9 + B9 → B8 | ground truth | end S1 | — |

## 16. Roadmap

Agreed on 15 November (both of us): the project ends on **30 November**, not 17 January. Everything built or in
review by then is kept; what is not started is cut in the order below. The original plan, for the record: S0
2–8 Nov (M0), S1 9–22 Nov (M1), S2 23 Nov–6 Dec (M2 = MVP), S3 7–20 Dec (M3), S4 21 Dec–3 Jan (M4), S5 4–17 Jan
(M5).

| Dates | Milestone |
|---|---|
| 2–8 Nov | M0 — repo, settings, contracts, CI green (done) |
| 9–15 Nov | M1 and most of M2–M4 built: gate, risk, policy, waivers, replay, signed release, `sentinel verify`, Kyverno on kind, AI explanations, correlation, remediation, dashboards (in review) |
| 16–22 Nov | **Merge train** (every reviewed PR). The last metrics: explanation rubric and Cohen's kappa, pipeline p50/p95, one evaluation report. On the laptops: canaries with the pinned model, the correlation threshold calibrated, the first shop-api release, the kind run. Then **go public**, after the checklist below |
| 23–26 Nov | Verified fix rate on demo-shop; A5 (kind, Kyverno, Argo CD) merged or Argo CD cut; CI on GitHub on every open PR. **Feature freeze on 26 Nov** |
| 27 Nov | The full evaluation run on a clean checkout; its numbers committed with their input digests |
| 28–30 Nov | **M5** — v1.0.0, signed, with its evidence and `sentinel verify`; the 5-minute demo video (§17); final README |

**Going public** (ADR-0006 ends then, amended by its own record): before the switch, a check of the whole git
history with the pinned Gitleaks (every finding is a listed fake of `demo-shop/ground-truth/` or is fixed
first); the fake secrets of `demo-shop/` checked against what GitHub's secret scanning will report; branch
protection on `main`; fork pull requests need approval to run. Signing stays with Cosign key pairs at first;
keyless signing, code-scanning upload and GitHub artifact attestations can follow.

**Cut line:** M2 alone is a complete project. Drop order if late: GitHub sync (`POST /api/v1/sync/github`;
an upload already meets B1, 1.1.24) → the LLM judge (the people's rubric and kappa stay) → Argo CD (Kyverno on
kind stays) → correlation stage 2b numbers (reported as not measured) → stretch goals. A cut metric is reported
as not measured, never as 0. **Stretch:** Jenkins pipeline reusing the CLI, MCP server for coding agents, Check
Runs annotations, ChatOps, call-graph reachability, fine-tuned triage classifier.

## 17. Evaluation and demo

**Benchmark (`demo-shop/ground-truth/`):** secrets 5 · SAST 10 · SCA 8 (≥ 2 KEV-listed with fixes, ≥ 3 never
imported) · container 5 · IaC 6 · CI workflow 3 (under `examples/`, never executed) · injection canaries 5 · clean
controls 5. Choose concrete package versions in Sprint 0 from the current KEV catalogue and OSV.

**Metrics:** recall per category and false positives on clean controls · NDCG@10 vs CVSS baseline · ARI + alert
reduction + ablation · explanation rubric + LLM-judge agreement (Cohen's kappa) · verified fix rate · AI
mislabel rate on canaries and verdict changes (must be 0) · pipeline p50/p95 · replay identity.

**Correlation, without tuning on the test set.** The stage 2b threshold and the embedding model are chosen on a
labelled set that is not the one they are tested on (hand-labelled findings of one or two other vulnerable
applications, scanned in a container, or a split of demo-shop's seeds fixed before any score is looked at:
A7 uses the split), then committed with the model's digest before the test half is measured. On demo-shop, the ARI-vs-threshold curve, with stage 2b on and off, is reported as
sensitivity only. Alert reduction counts raw tool reports (`out/raw/`, so stage 1 merges the tools) against
groups; a findings file already has one finding per fingerprint, so stage 1 alone reduces nothing there.
Findings with no ground-truth seed are left out of the ARI and listed. `sentinel_ai.correlate.evaluation`
computes them: `ablation` (each configuration of stages), `sweep` (the curve), `calibrate` (the best ARI, a
tie going to the highest threshold, which merges least); the embedder is called once per text for a sweep.

Implemented (A7 measurement): `make eval-correlation-calibrate` and `make eval-correlation`
(`eval/correlation/`) on the findings of `make eval`. A finding that detects a seed has the seed's root
cause; every other finding is labelled in `root-causes.yaml` with what one fix resolves (a manifest's missing
security context is one root cause for its twelve findings), written before the embedding stage ran on them,
so the ARI sees right merges as well as wrong ones. The root causes are split once into a calibration half
and a test half (`split.yaml` for the seeds, alternating by category; `half` for the others). Calibration
picks the threshold on its half and writes `threshold.json` with the model and its digest, committed before
the test half is measured; a threshold of another model is refused. Alert reduction counts the places the
tools reported (each finding and its `other_locations`), since the raw reports are not kept.

Implemented (B8a): the detection report, `make eval` (`eval/detection/`): recall per category, false positives on
the clean controls, and unlisted findings, from SentinelCI's own findings; categories whose tool did not run are
not measured. With the pinned tools, a Grype database and #40's `scan sast`: 28 of 28 seeds detected, no false
positive.

**Demo (5 min):** context (2026 incident) → BLOCK on a PR → understand (score factors, AI advisory) → fix (bot PR,
VERIFIED) → release (signed, `sentinel verify`, Argo CD, Kyverno admits) → attack (bad image denied) →
manipulate the AI (verdict unchanged) → prove (`sentinel replay`, Grafana).

## 18. Risks

| Risk | Mitigation |
|---|---|
| Laptop resources | Compose profiles; small quantized model on the stronger machine |
| Direct push to `main` (no server-side protection while private) | Team convention, local pre-commit guard, CI on every push to `main` |
| Actions minutes (private) | Path filters, caches, nightly full scans |
| Signing key (private phase) | Never on GitHub: a laptop signer with a password-protected key, run only from a clean tree at `origin/main` (ADR-0011); keyless signing in CI when public |
| External APIs down | Snapshots and offline fixtures |
| Scanner noise | Diff-aware gating, risk scoring, correlation, waivers |
| Integration drift | Contracts + fixtures in CI; weekly sync |
| Scope creep | MVP cut line; milestone demos |
| Vulnerable demo code misused | Local only, fake secrets, loud labelling |
| Our own supply chain | SHA pins, tools verify, Dependabot cooldown, zizmor, review of dependencies |
| AI hallucinations | Grounding, schemas, advisory only, deterministic verification, evaluation |

The threats to SentinelCI itself (who attacks, which control answers, where it is tested, what remains) are
in `docs/threat-model.md`.

## 19. CV and interview kit

Replace every [X] with a measured number. Track A: hardened reusable pipeline designed against the 2026 Trivy
compromise · SBOMs, Cosign signing, attestations and SLSA provenance enforced by Kyverno · verified auto-
remediation ([X]% verified fixes) · [X]% triage reduction via dedup + embedding clustering. Track B: OPA risk-based
gate combining CVSS, EPSS, KEV, reachability and exposure; signed, replayable decisions · LLM analyst with
schema-constrained outputs and injection isolation (0 verdict changes across [X] canaries) · NDCG@10 from [X] to
[X] vs CVSS baseline · FastAPI/PostgreSQL control plane and React dashboard.

## 20. Sprint 0 checklist

| # | Action | Status |
|---|---|---|
| 1 | Private repo, collaborator invited | done |
| 2 | Scaffold: uv workspace, packages, Makefile, CI (SHA-pinned, zizmor), CODEOWNERS, Dependabot, CLAUDE.md | done |
| 3 | Contracts: finding, decision, patch proposal, verification result + fixtures + tests | done |
| 4 | Spec v1.1 + ADRs in `docs/` | done |
| 5 | Repository settings: require SHA-pinned actions, read-only default workflow token, Dependabot alerts (branch protection deferred to the public phase, convention + local guard meanwhile) | to do (owner) |
| 6 | Choose and pin tool versions in `tools.lock.toml` | done (A1a; Opengrep by signature, A1) |
| 7 | Compose skeleton (postgres+pgvector, redis, seaweedfs, ollama, api, prometheus, grafana; worker with B1, web with B7) | B |
| 8 | `demo-shop/` skeleton + ground-truth format; first seeds | A9 first seeds done (draft format v1); B9 to do |
| 9 | GitHub Project board: one issue per task id | both |
| 10 | Choose the local model and measure tokens/second | done (ADR-0009; re-run the benchmark on each laptop) |

## Appendix — Glossary

SBOM (bill of materials) · SLSA (build-integrity levels) · provenance (signed build statement) · in-toto
attestation (subject digest + typed predicate) · Sigstore/Cosign (signing ecosystem) · keyless signing (OIDC
identity instead of a long-lived key) · EPSS (exploitation probability, 30 days) · KEV (CISA known exploited) ·
VEX/OpenVEX (exploitability statements) · purl (package URL) · SARIF (scanner result format) · OPA/Rego
(policy-as-code) · admission controller (rejects resources before they run) · reachability (vulnerable code
actually used) · NDCG/ARI (ranking / clustering metrics) · fail-closed (deny on error).
