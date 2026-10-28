<!-- sentinelci:pr-comment -->
## SentinelCI verdict: 🛑 BLOCK

> [!WARNING]
> This pull request changes SentinelCI's own pipeline. This run used the pipeline of the base
> branch: the changes below take effect only after merge, so review them with care.
> `policies/gate.rego` · `tools.lock.toml`

| Rule | Effect | Issue | Finding | Location | Severity |
|---|---|---|---|---|---|
| `SC-001` | **BLOCK** | `Hard-coded secret` | `Detected a Generic API Key, potentially exposing access to various services.` · `gitleaks:generic-api-key` | ``demo-shop/@NOURHANE-EHOUARI/<img src=x>\|`#1`/conU+202Efig.py:3`` | HIGH |
| `SC-001` | **BLOCK** | `Hard-coded secret` | `Detected a Generic API Key, potentially exposing access to various services.` · `gitleaks:aws-access-token` | `demo-shop/services/shop-api/app/config.py:12` | HIGH |
| `SC-010` | **BLOCK** | `Scanner failure: opengrep timed out` | — | — | — |
| `SC-006` | WARN | `P1 finding` | `Detected a Generic API Key, potentially exposing access to various services.` · `gitleaks:generic-api-key` | `demo-shop/infra/terraform/main.tf:40` | HIGH · P1 |

**Findings:** 3 HIGH (3 total, 2 new)
**Waivers applied:** `W-2026-001`

<details><summary>Evidence</summary>

- Decision `0193f2c4-7a1e-5b3c-9d2e-4f5a6b7c8d9e`, evaluated at `2026-11-10T10:00:00Z` on `pr` commit `4b825dc642cb6eb9a060e54bf8d69288fbee4904`
- Findings `sha256:a9882325ec0ffe9a0bb4a4a544a4a1bcdcd46e9fed3604e3599a2d397f6112c1` (verified against this report)
- Policy bundle `sha256:4444444444444444444444444444444444444444444444444444444444444444` · risk model `1.0.0` · engine `0.1.0`
- Tools: `gitleaks 8.30.1` · `opa 1.21.4`
- Replay: `sentinel replay 0193f2c4-7a1e-5b3c-9d2e-4f5a6b7c8d9e`

</details>

_AI advisory is in the dashboard. It is advisory only and never changes the verdict._
