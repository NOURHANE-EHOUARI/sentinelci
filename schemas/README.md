# Contracts

JSON Schemas (draft 2020-12) shared by both tracks. See `docs/spec/SPEC.md` section 13.

| Schema | Producer → consumer |
|---|---|
| `finding.v1.json` | A2 (normalizer) → B2, B3, B4, platform |
| `decision.v1.json` | B4 (policy engine) → A4, A5, platform |
| `patch-proposal.v1.json` | A6 fixers / B6 LLM → A6 remediation loop |
| `verification-result.v1.json` | A6 → platform, B8 |
| `waivers.v1.json` | people via reviewed PRs (AI drafts only) → B4 gate, platform |

Rules:

- Every schema has `fixtures/<name>/valid/` and `fixtures/<name>/invalid/` examples; `tests/contracts` checks
  that valid ones pass and invalid ones fail. Add a fixture for every new rule you encode.
- A breaking change creates a new version (`finding.v2.json`) — never edit a released version's meaning.
- Schemas encode safety rules where possible (no raw secrets, no path traversal, VERIFIED only when every
  verification condition holds, verdict consistent with violations).
