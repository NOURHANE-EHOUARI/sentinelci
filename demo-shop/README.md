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

Layout: `services/shop-api/`, `services/web/`, `infra/terraform/`, `infra/k8s/`, `gitops/`,
`examples/bad-workflows/`, `examples/good-workflows/`, `ground-truth/findings.yaml`; planned: `sentinel.yaml`,
`.sentinel/waivers.yaml`.

## Seeds so far

| Category | Seeds | Where | Verified detections |
|---|---|---|---|
| Secrets (all fake) | 5 | settings, `.npmrc`, Terraform provider, Kubernetes Secret, GitOps values | Gitleaks 5/5 |
| Infrastructure as code | 6 | Terraform (S3, security group, RDS, IAM), Kubernetes, Dockerfile | Trivy 6/6 (GT-IAC-004 through SentinelCI's own check SENTINEL-AWS-0001), Checkov 6/6 |
| CI workflows (never executed) | 3 | `examples/bad-workflows/` | zizmor 3/3 |
| Clean controls | 4 | placeholders, sensitive variable, hardened deployment, pinned workflow | no detection |

Still to come: SCA seeds with KEV-listed and never-imported dependencies (A9), container image seeds (A9,
with the release pipeline), and application code, SAST seeds and injection canaries (B9).

**The gate blocks this target on purpose.** A pull request that adds a seed is blocked (SC-001 for a secret),
which is how the demo shows the gate working. A release-mode scan of `main` blocks too, as long as the seeds
are present.
