# Contracts

JSON Schemas (draft 2020-12) shared by both tracks. See `docs/spec/SPEC.md` section 13.

| Schema | Producer → consumer |
|---|---|
| `finding.v1.json` | A2 (normalizer) → B2, B3, B4, platform |
| `decision.v1.json` | B4 (policy engine) → A4, A5, platform |
| `patch-proposal.v1.json` | A6 fixers / B6 LLM → A6 remediation loop |
| `verification-result.v1.json` | A6 → platform, B8 |

Rules:

- Every schema has `fixtures/<name>/valid/` and `fixtures/<name>/invalid/` examples; `tests/contracts` checks
  that valid ones pass and invalid ones fail. Add a fixture for every new rule you encode.
- A breaking change creates a new version (`finding.v2.json`) — never edit a released version's meaning.
- An additive change bumps the minor `schema_version` inside the same file (Finding 1.1 adds
  `other_locations`); the schema forbids the new fields in older minor versions, so a 1.0 document keeps its meaning.
- Every `pattern` starts with `^(?![^\r\n\u2028\u2029]*[\r\n\u2028\u2029])`: no line break anywhere. Without it,
  Python (`$` also matches before a final newline; `.` matches `\r`, U+2028, U+2029) and ECMA-262 validators (ajv)
  disagree, e.g. on `"<64 hex>\n"`. `tests/contracts/test_patterns.py` enforces it and compares both engines.
- Schemas encode safety rules where possible (no raw secrets, no path traversal, VERIFIED only when every
  verification condition holds, verdict consistent with violations).
