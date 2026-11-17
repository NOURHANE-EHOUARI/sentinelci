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
pinned Gitleaks 8.30.1: **11 findings, 59 places, no real secret.** Re-run by Nourhane with the pull request refs
too (#144 review: 122 branches and 144 PR refs, 893 commits, one of them reachable only from `refs/pull/59/head`):
the same 11 findings, nothing new. Run again on 15 November, before the merge train of 16 November, on a
`git clone --mirror` (120 branches, 185 pull-request refs with their `merge` refs, 989 commits): the same 11
findings, each matched by path, line and rule to `GT-SECRET-001` to `005` or by finding ID to the self-gate's
waivers (#144).

The **workflow artifacts** (44, 348,935 bytes, none expired: `sentinel-scan`, `sentinel-decision`,
`sentinel-evidence`, `replay-corpus`) were downloaded one folder each and scanned in dir mode on 15 November: 6
findings, all `generic-api-key` on a `secret_hash` field (the sha256 the normalizer writes in place of a secret),
in 2 artifacts. Nothing was deleted (#144). The runs since Actions was blocked hold no logs.

The switch PR re-runs the history scan on the day, after the last merge before the switch, and records it here.

| Kind | What it is |
|---|---|
| GT-SECRET-001 to 005 | `demo-shop/`'s five listed fakes (settings, `.npmrc`, Terraform, the TLS Secret, the Slack webhook) |
| `secret_hash`, `key_sha256` | sha256 digests in contract fixtures and normalizer fixtures, named after what they hash |
| `decision_id` | UUIDs in the release-evidence and trust-report fixtures |
| `ai/tests/test_analyst.py` | the fake `UNKNOWN_SECRET`, waived by `self-2026-007` |

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
