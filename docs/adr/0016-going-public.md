# ADR-0016: Going public on 22 November, in two steps

- Status: proposed (needs both signatures)
- Date: 2026-11-15
- Amends: ADR-0006 (private phase), whose "when the repository goes public" paragraph this replaces
- Builds on: ADR-0011 (the signing key stays on the laptop), SPEC §16 (the roadmap to 30 November, #142)

## Context

ADR-0006 keeps the repository private "until the project is complete", and lists what changes at the switch:
branch protection, keyless signing, GitHub artifact attestations, SARIF upload to code scanning, public images.

The roadmap now ends on 30 November (SPEC §16), and GitHub Actions cannot run on this private repository until
1 December. Public repositories get Actions without the Free plan's cap. Going public on 22 November, right after
the merge train, gives us CI on GitHub for the last week, on every pull request, and branch protection on `main`.

Switching everything at once on 22 November would put the signing change (keyless, a new attestor in Kyverno and
`sentinel verify`) in the same week as the feature freeze. That is the riskiest part, and nothing in the project's
acceptance needs it before v1.0.0.

## Decision

The repository goes public on **22 November**, in two steps.

**Step 1, on 22 November (the switch):**
1. **Before the switch** (all of it, with its result in the switch PR):
   - Gitleaks (the pinned version, SentinelCI's configuration) over the **whole history, every branch**
     (`sentinel scan secrets <repo> --mode git --log-opts=--all`). Each finding is one of `demo-shop/`'s listed
     fakes, a known false positive of the rule (named), or it is fixed first. On 15 November: 11 findings, none a
     real secret (below).
   - The fakes of `demo-shop/ground-truth/` checked against what GitHub's secret scanning reports once public.
     Each alert on a listed fake is closed as "used in tests", naming its seed.
2. **At the switch:** make the repository public, then at once:
   - branch protection on `main`: pull requests only, one approving review, no force-push or deletion, and the
     required checks once they have run green once;
   - Actions: require approval for workflows from fork pull requests (outside collaborators);
   - Dependabot: version updates already exclude `demo-shop/` (`.github/dependabot.yml`, pinned by
     `test_the_intentionally_vulnerable_demo_is_never_updated`). Security updates stay **off** for the repository.
     The alerts GitHub raises on `demo-shop/`'s seeded manifests are closed in one pass, each with the reason
     "intentionally vulnerable demo target (`demo-shop/ground-truth/`)". A closed alert is not a waiver;
   - push protection: a push that adds a new fake seed is bypassed as "used in tests", and the value goes into
     `demo-shop/ground-truth/` in the same pull request, as today.
3. **What stays as in the private phase for now:** signing with the Cosign key pair on the laptop (ADR-0011), the
   SLSA provenance as a Cosign in-toto attestation, scan results in PR comments, artifacts and the dashboard, and
   the kind cluster's local registry.

**Step 2, after v1.0.0, only if there is time (not part of the 30 November scope):** ADR-0006's GitHub mode —
keyless signing via GitHub OIDC, GitHub artifact attestations, SARIF upload to code scanning, public GHCR images.
Each is its own pull request, with Kyverno and `sentinel verify` accepting both attestors first, as ADR-0006
already plans.

## The history scan of 15 November

`sentinel scan secrets` in git mode over every commit of every branch (891 commits on 142 remote branches), with the
pinned Gitleaks 8.30.1: **11 findings, 59 places, no real secret.**

| Kind | What it is |
|---|---|
| GT-SECRET-001 to 005 | `demo-shop/`'s five listed fakes (settings, `.npmrc`, Terraform, the TLS Secret, the Slack webhook) |
| `secret_hash`, `key_sha256` | sha256 digests in contract fixtures and normalizer fixtures, named after what they hash |
| `decision_id` | UUIDs in the release-evidence and trust-report fixtures |
| `ai/tests/test_analyst.py` | the fake `UNKNOWN_SECRET`, waived by `self-2026-007` |

## Consequences

- CI on GitHub runs on every pull request from 22 November, and `main` is protected server-side: the convention of
  ADR-0006 decision 6 becomes a rule.
- The signing key stays long-lived until step 2; it is rotated when keyless signing replaces it, as ADR-0006 says.
- `CLAUDE.md`'s "Repository status" section changes in the switch PR, so that agents follow the public rules.
- If step 2 does not happen by 30 November, v1.0.0 ships key-signed, and the README says so.
