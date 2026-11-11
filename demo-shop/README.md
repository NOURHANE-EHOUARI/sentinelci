# demo-shop — INTENTIONALLY VULNERABLE

> **Do not deploy, do not expose beyond localhost, do not reuse any of this code.**

`demo-shop` is the benchmark target for SentinelCI. It deliberately contains seeded vulnerabilities (secrets,
injection flaws, vulnerable dependencies, insecure containers and infrastructure, unsafe CI examples and
prompt-injection canaries). Every seed is documented in `ground-truth/` so the evaluation harness can measure
detection, prioritization, correlation and remediation.

Rules:

- All secrets are fake, obviously so, and listed in the ground truth.
- CI-workflow seeds live in `examples/bad-workflows/`, never under `.github/`, so they never run.
- Infrastructure code is scanned only, never applied to a real cloud.
- Ownership: infrastructure, containers, dependencies and secrets (A9); application code and canaries (B9).

Layout: `services/shop-api/`, `services/web/`, `services/reports/` (a build file only), `infra/terraform/`,
`infra/k8s/`, `gitops/`, `examples/bad-workflows/`, `examples/good-workflows/`, `ground-truth/findings.yaml`;
planned: `sentinel.yaml`, `.sentinel/waivers.yaml`.

## Seeds so far

| Category | Seeds | Where | Verified detections |
|---|---|---|---|
| Secrets (all fake) | 5 | settings, `.npmrc`, Terraform provider, Kubernetes Secret, GitOps values | Gitleaks 5/5 |
| Infrastructure as code | 6 | Terraform (S3, security group, RDS, IAM), Kubernetes, Dockerfile | Trivy 6/6 (GT-IAC-004 through SentinelCI's own check SENTINEL-AWS-0001) |
| CI workflows (never executed) | 3 | `examples/bad-workflows/` | zizmor 3/3 |
| Dependencies | 8 | `requirements.txt` (shop-api), `package.json` (web), `pom.xml` (reports): 2 CISA KEV, 3 never imported | Syft 8/8 purls; Grype 8/8 (database of 2026-11-01) |
| Application code (B9) | 6 | `services/shop-api/app/main.py`: SQL built from a query string, a shell command, YAML with FullLoader, TLS verification off, `eval`, debug mode | Opengrep 6/6 (SentinelCI's rules, #40) |
| Prompt-injection canaries (B9) | 2 | a comment beside the SQL seed, the import route's OpenAPI description | not findings: an AI output must never contain their tokens |
| Clean controls | 5 | placeholders, sensitive variable, hardened deployment, pinned workflow, `app/orders.py` (the same operations, written safely) | no detection |

shop-api (`services/shop-api/app/`, B9) is a FastAPI service: `python -m app` serves it on port 8080, and it
writes only to `/tmp` (its SQLite catalogue). It imports `yaml` (loading with FullLoader, which GT-SCA-001 is
about) and `requests`, never `lxml`. It runs only in its container: the release image (`Dockerfile.release`,
A9) installs `requirements.release.txt` (hash-pinned wheels, no seeded version), and the BLOCK image
`requirements.block.txt` (the same, with the seeded pyyaml 5.3.1). Still to come: container image seeds (A9,
with the release pipeline), and the web front end's code, which imports `lodash` (`template`), never `minimist`
or `lodash-es` (B9).

**The gate blocks this target on purpose.** A pull request that adds a seed is blocked (SC-001 for a secret),
which is how the demo shows the gate working. A release-mode scan of `main` blocks too, as long as the seeds
are present.
