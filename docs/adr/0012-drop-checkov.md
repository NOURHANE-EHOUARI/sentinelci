# ADR-0012: Drop Checkov; IaC is scanned by Trivy alone

- Status: accepted (2026-11-01, agreed by Hiba and Nourhane)
- Date: 2026-11-01
- Supersedes: the Checkov rows of SPEC sections 5, 11 and 15 (A1)

## Context

The SPEC planned Checkov for stage 4 (IaC and CI configuration) next to zizmor, and the first demo-shop seeds
were checked against Checkov 3.4.0 by hand. Since then:

- Trivy is pinned and verified, and `sentinel scan iac` runs its embedded checks with SentinelCI's own
  configuration (#26). zizmor audits the CI workflows (#37). Together they cover what Checkov was planned for.
- Checkov is a Python package: pinning it would put about 96 more dependencies into the locked toolchain, each a
  supply-chain risk of its own, for a tool whose coverage is already there. A smaller toolchain is the lesson
  of the 2026 incident this project is built around (README, "Why").
- No adapter was written yet, so dropping it now costs nothing but documentation.

## Decision

1. Checkov is not part of SentinelCI: no adapter, no lock entry, no pipeline stage. Stage 4 is Trivy (config)
   and zizmor.
2. The demo-shop ground truth lists only detections by the pinned tools. The Checkov detections recorded by hand
   are removed.
3. GT-IAC-004 (an IAM policy allowing every action on every resource) stays a seed, but Trivy 0.76.1 does not
   flag it. Probes with the pinned Trivy show:
   - a fully wildcarded policy is not flagged in any of these forms: `jsonencode`, a JSON heredoc, or an
     `aws_iam_policy_document` with `actions = ["*"]`;
   - `s3:*` on `*` is flagged (AWS-0345).

   Its `expected.detections` is empty, and `known_miss` says why. It counts as a miss for IaC recall (B8 counts
   IaC with Trivy alone: 5 of 6). It is not rewritten to suit the tool.

## Consequences

- One fewer tool to pin, verify and keep up to date, and about 96 fewer dependencies.
- IaC recall on the benchmark is measured honestly with one engine, gap included. A SentinelCI-owned Trivy
  check for wildcard IAM policies could close that gap later (task A1). It would be scanner configuration owned
  by SentinelCI, never by the scanned repository.
- The ground-truth format gains `known_miss`: a seed with no verified detection must say why (B9 owns the
  format).
