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

Planned layout: `services/shop-api/`, `services/web/`, `infra/terraform/`, `infra/k8s/`, `gitops/`,
`examples/bad-workflows/`, `ground-truth/findings.yaml`, `sentinel.yaml`, `.sentinel/waivers.yaml`.
