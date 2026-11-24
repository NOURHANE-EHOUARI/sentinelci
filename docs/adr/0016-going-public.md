# ADR-0016: Going public right after the merge train, in two steps

- Status: accepted by both of us with #160, merged at the switch (step 1); step 2 stays optional
- Date: 2026-11-15
- Amends: ADR-0006 (private phase), whose "when the repository goes public" paragraph this replaces
- Builds on: ADR-0011 (the signing key stays on the laptop), SPEC §16 (the roadmap to 30 November, #142)

## Context

ADR-0006 keeps the repository private "until the project is complete", and lists what changes at the switch:
branch protection, keyless signing, GitHub artifact attestations, SARIF upload to code scanning, public images.

The roadmap now ends on 30 November (SPEC §16), and GitHub Actions cannot run on this private repository until
1 December. Public repositories get Actions without the Free plan's cap. Going public right after the merge
train (22 November at the latest) gives us CI on GitHub for every remaining pull request, and branch protection on
`main`. Until then, every push waits for a local `make check` of about 15 minutes, one branch at a time.

Switching everything at once at that point would put the signing change (keyless, a new attestor in Kyverno and
`sentinel verify`) in the same week as the feature freeze. That is the riskiest part, and nothing in the project's
acceptance needs it before v1.0.0.

## Decision

The repository goes public **right after the merge train is merged, on 22 November at the latest** (both of us,
15 November), in two steps.

**Step 1, the switch:**
1. **Before the switch** (all of it, with its result in the switch PR):
   - **The logs and artifacts of past Actions runs** become public too: each failed run since Actions was blocked
     is checked (it holds no log, but its artifacts and its run page do), and anything that must not be public is
     deleted first (Nourhane, 15 November).
   - Gitleaks (the pinned version, SentinelCI's configuration) over the **whole history: every branch and every
     pull request's head**, since GitHub publishes `refs/pull/*/head` too. On a fresh clone:
     `git fetch origin '+refs/heads/*:refs/remotes/origin/*' '+refs/pull/*/head:refs/remotes/pull/*'`, then
     `sentinel scan secrets <clone> --mode git --log-opts=--all`. It runs **on the day**, after the last merge
     before the switch. Each finding is one of `demo-shop/`'s listed fakes, a known false positive of the rule
     (named), or it is fixed first. The scan of 15 November (below) shows what to expect; the switch PR replaces
     it with that day's result.
   - The fakes of `demo-shop/ground-truth/` checked against what GitHub's secret scanning reports once public.
     Each alert on a listed fake is closed as "Used in tests", naming its seed.
2. **At the switch:** make the repository public, then at once:
   - branch protection on `main`: pull requests only, one approving review, "Dismiss stale pull request
     approvals when new commits are pushed" and "Require approval of the most recent reviewable push" (so an
     approval never covers a commit pushed after it), no force-push or deletion, and "Do not allow bypassing the
     above settings", so that it binds the repository's admin too. The required checks are added only once `ci`
     has run green on GitHub (they can be picked only then); until then a local `make check` report stands in;
   - Actions: the repository's default workflow permissions set to **read**. Every workflow already sets its
     own `permissions:`, but the default is what a new or edited workflow gets if it forgets;
   - Actions: require approval for workflows from fork pull requests (outside collaborators);
   - Dependabot: version updates already exclude `demo-shop/` (`.github/dependabot.yml`, pinned by
     `test_the_intentionally_vulnerable_demo_is_never_updated`). Security updates stay **off** for the repository.
     The alerts GitHub raises on `demo-shop/`'s seeded manifests are closed in one pass, each as "Risk is
     tolerable to this project" (Dependabot's fixed reasons) with the comment "intentionally vulnerable demo
     target, `demo-shop/ground-truth/` <seed>". A closed alert is not a waiver;
   - secret scanning and push protection confirmed on; a push that adds a new fake seed is bypassed as "Used in
     tests", and the value goes into `demo-shop/ground-truth/` in the same pull request, as today;
   - private vulnerability reporting on, which `SECURITY.md` points to;
   - Scorecard's first public run looked at: with the workflow's token its Branch-Protection check sees
     force-push, deletion and the number of approvals, not the settings that need an admin token (stale-approval
     dismissal, approval of the most recent push, the required checks, the admin bypass), which are looked at
     by hand; and the image its action runs (threat model, residual risks).
   - **Right after, one workflow is started by hand** (`workflow_dispatch`), to see that Actions really runs now
     that the repository is public, despite the billing block of the private phase (Nourhane, 15 November). If it
     does not start, the local `make check` reports stay the rule until it does.
3. **What stays as in the private phase for now:** signing with the Cosign key pair on the laptop (ADR-0011), the
   SLSA provenance as a Cosign in-toto attestation, scan results in PR comments, artifacts and the dashboard, and
   the kind cluster's local registry.

**Step 2, after v1.0.0, only if there is time (not part of the 30 November scope):** ADR-0006's GitHub mode —
keyless signing via GitHub OIDC, GitHub artifact attestations, SARIF upload to code scanning, public GHCR images.
Each is its own pull request, with Kyverno and `sentinel verify` accepting both attestors first, as ADR-0006
already plans.

## The scans before the switch

`sentinel scan secrets` in git mode over every commit of every branch (891 commits on 142 remote branches), with the
pinned Gitleaks 8.30.1: **11 findings, no real secret.** Re-run by Nourhane with the pull request refs
too (#144 review: 122 branches and 144 PR refs, 893 commits, one of them reachable only from `refs/pull/59/head`):
the same 11 findings, nothing new. Run again on 15 November, before the merge train of 16 November, on a
`git clone --mirror` (120 branches, 185 pull-request refs with their `merge` refs, 989 commits): the same 11
findings in 58 places (a file and a line each), each matched by path, line and rule to `GT-SECRET-001` to `005` or
by finding ID to the self-gate's waivers (#144). Gitleaks's own report lists more entries than places (62 in Hiba's
dry run of 17 November, review of #160): places are what this record counts, and the switch PR's scan counts them
the same way.

The **workflow artifacts** (44, 348,935 bytes, none expired: `sentinel-scan`, `sentinel-decision`,
`sentinel-evidence`, `replay-corpus`) were downloaded one folder each and scanned in dir mode on 15 November: 6
findings, all `generic-api-key` on a `secret_hash` field (the sha256 the normalizer writes in place of a secret),
in 2 artifacts. Nothing was deleted (#144). The runs since Actions was blocked hold no logs.

### The switch's scan (24 November)

The switch came two days after the date above. On 21 November, Hiba's second dry run found that B9's changelog row
1.1.114 quoted the canaries' tokens, which made `main`'s self-gate block (SC-001); #180 (SPEC 1.1.119) took them
out of the tree first.

Run by Hiba on the day, after #180, #177, #179 and #181 merged: `main` at `10c3d74`, with every branch and pull
request head pushed by then (#148's and #182's included). **No finding is a real secret.** 65 Gitleaks entries in
61 places from 14 commits, the same 65 entries as the dry run of 21 November, compared one by one: the 11 findings
known since 15 November (58 places, 11 commits) and 3 places in `docs/spec/SPEC.md` from B9's commits `9d47574`,
`972717d` and the merge `90895c9`.

| Class | Findings | Where | Why it is not a secret |
|---|---|---|---|
| `demo-shop/`'s listed fakes | 5 (aws-access-token, github-pat, npm-access-token, private-key, slack-webhook-url) | `demo-shop/` | GT-SECRET-001 to 005, listed in `demo-shop/ground-truth/` |
| Fixture and test values | 6 (generic-api-key, 53 places) | `schemas/fixtures/`, `cli/tests/`, `ai/tests/` | sha256 digests and test values, each covered by a self-gate waiver (`.sentinel/self-gate-waivers.yaml`) |
| Planted test values | the canaries' tokens, 3 places | `docs/spec/SPEC.md`, in history only | the benchmark's canaries (`demo-shop/ground-truth/findings.yaml`); out of the tree since #180 |

- **Scanned:** 298 refs (113 branches, 180 `refs/pull/*/head`, 5 `refs/pull/*/merge`, no tag), 1,163 commits, of
  which Gitleaks scanned the 861 with a patch under these log options; no octopus merge.
- **The tree:** on `10c3d74`, Gitleaks over the tree without `demo-shop/` gives 53 places, all waived fixtures, none
  in `docs/`. Nourhane's `make self-gate` on `main` `66621b6` (24 November, after #180; #181 then changed only the
  correlator's threshold file and the SPEC) says **PASS**, no rule: 6 secret findings, all waived.
- **Workflow artifacts:** 0 on 24 November (the 44 of 15 November have expired), so nothing to scan.

How, as on 17 and 21 November: `git clone --mirror`, then a fetch of `+refs/pull/*/head:refs/pull/*/head` (with
GitHub's `refs/pull/*/merge` too, a superset of the refspec above); the pinned Gitleaks 8.30.1; SentinelCI's
configuration from `main` (`cli/src/sentinelci/scanners/configs/gitleaks.toml`, sha256 `8ed39cfd…`), never a scanned
branch's; suppressions neutralized as the wrapper does (`--ignore-gitleaks-allow`, an empty
`--gitleaks-ignore-path`); git with an empty `HOME` and no system config; `--redact`. The wrapper
(`sentinel scan secrets --mode git`) refuses a redacted report (fail closed), so its Gitleaks invocation ran directly,
with `--redact` added, in the wrapper's two passes:

```sh
env -i PATH=/usr/bin:/bin HOME=<empty dir> GIT_CONFIG_NOSYSTEM=1 LANG=C.UTF-8 \
  gitleaks git histscan.git --config gitleaks.toml --gitleaks-ignore-path <empty dir> --ignore-gitleaks-allow \
  --redact --report-format json --report-path pass1.json --exit-code 0 --no-banner --no-color \
  --log-opts="--text --no-textconv --no-ext-diff --diff-merges=remerge --diff-filter=tuxdb --all"
# pass 2, octopus merges: --log-opts="... --diff-merges=remerge --min-parents=3 --diff-merges=first-parent ..."
```

The kinds of known false positive:

| Kind | What it is |
|---|---|
| GT-SECRET-001 to 005 | `demo-shop/`'s five listed fakes (settings, `.npmrc`, Terraform, the TLS Secret, the Slack webhook) |
| `secret_hash`, `key_sha256` | sha256 digests in contract fixtures (finding, release-evidence, trust-report) and normalizer fixtures, named after what they hash; the `decision-id-*.json` trust-report fixtures are flagged on their `key_sha256` line |
| `ai/tests/test_analyst.py` | the fake `UNKNOWN_SECRET`, waived by `self-2026-007` |
| the canaries' tokens | planted values of the benchmark (`demo-shop/ground-truth/findings.yaml`) that B9's changelog row quoted in three commits; out of the tree since #180 |

## Consequences

- CI on GitHub runs on every pull request from the switch on, and `main` is protected server-side: the convention of
  ADR-0006 decision 6 becomes a rule.
- The signing key stays long-lived until step 2; it is rotated when keyless signing replaces it, as ADR-0006 says.
- **This ADR and the switch are two pull requests.** This one records the decision and can merge before the switch.
  The switch PR, right after the merge train, changes `CLAUDE.md`'s "Repository status" section, so that agents follow the
  public rules, and carries the history scan of that day. Until it merges, `CLAUDE.md` describes the private
  phase, which is still true.
- **The one residual risk of the switch:** once public, GitHub still serves a commit that a force-push removed
  from every ref to anyone who has its SHA. No clone holds such a commit, so no scan can check it. Our
  force-pushes were amends of our own branches, and a real secret was never allowed in the repository, so the
  risk is small, but it is not zero.
- If step 2 does not happen by 30 November, v1.0.0 ships key-signed, and the README says so.
