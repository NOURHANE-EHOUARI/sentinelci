# sentinelci (core library + CLI)

The deterministic core of SentinelCI. It runs inside CI and locally with the same behaviour.

| Module | Responsibility | Track | Tasks |
|---|---|---|---|
| `scanners/` | Scanner adapters and `sentinel tools verify` | A | A1 |
| `normalize/` | SARIF/JSON to Finding v1, fingerprints, dedup | A | A2 |
| `enrich/` | EPSS, KEV, OSV, reachability, service context | B | B2 |
| `risk/` | Risk model and priority bands | B | B3 |
| `policy/` | OPA evaluation, decision records, replay | B | B4 |
| `supplychain/` | SBOM, signing, attestations, verify, evidence bundle | A | A4 |
| `report/` | PR comment, SARIF export | A | A3 |

`risk/`, `policy/`, `enrich/` and `normalize/` must never import `sentinel_ai` (enforced by import-linter).
