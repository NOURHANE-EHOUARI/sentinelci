# ADR-0012: Drop Checkov; IaC is scanned by Trivy alone

- Status: accepted (2026-11-01, agreed by Hiba and Nourhane)
- Date: 2026-11-01
- Supersedes: the Checkov rows of SPEC sections 5, 11 and 15 (A1)

## Context

The SPEC planned Checkov for stage 4 (IaC and CI configuration) next to zizmor, and the first demo-shop seeds
were checked against Checkov 3.4.0 by hand. Since then:

- Trivy is pinned and verified, and `sentinel scan iac` (#26, open) will run its embedded checks with
  SentinelCI's own configuration. zizmor audits the CI workflows (#37, open). On the benchmark they detect every
  seed Checkov detected except GT-IAC-004 (wildcard IAM), which Trivy 0.76.1 ships only as the deprecated,
  rule-less AWS-0057.
- Checkov is a Python package: pinning `checkov==3.4.0` resolves to 95 dependencies, 76 of them new to our lock
  (`uv pip compile`, Python 3.12), each a supply-chain risk of its own, for a tool whose coverage is already
  there. A smaller toolchain is the lesson
  of the 2026 incident this project is built around (README, "Why").
- No adapter was written yet, so dropping it now costs nothing but documentation.

## Decision

1. Checkov is not part of SentinelCI: no adapter, no lock entry, no pipeline stage. Stage 4 is Trivy (config)
   and zizmor.
2. The demo-shop ground truth lists only detections by the pinned tools. The Checkov detections recorded by hand
   are removed.
3. GT-IAC-004 (an IAM policy allowing every action on every resource) stays a seed, but Trivy 0.76.1 does not
   flag it. Probes with the pinned Trivy show:
   - a fully wildcarded policy is not flagged in any of these forms: `jsonencode`, a JSON heredoc, an
     `aws_iam_policy_document` with `actions = ["*"]`, an inline role policy, or CloudFormation
     `AWS::IAM::Policy` and `AWS::IAM::ManagedPolicy`;
   - `s3:*` on `*` is flagged (AWS-0345);
   - the cause is upstream and deliberate: AWS-0057 ("IAM policy should avoid use of wildcards") is embedded but
     deprecated, with no rule left, so `--include-deprecated-checks` does not bring it back.

   Its `expected.detections` is empty, and `known_miss` says why. It counts as a miss for IaC recall (B8 counts
   IaC with Trivy alone: 5 of 6). It is not rewritten to suit the tool.

## Consequences

- One fewer tool to pin, verify and keep up to date, and 95 fewer dependencies.
- IaC recall on the benchmark is measured honestly with one engine, gap included. A SentinelCI-owned Trivy
  check for wildcard IAM policies can close that gap (task A1, proposed in #53: SENTINEL-AWS-0001). It is
  scanner configuration owned by SentinelCI, never by the scanned repository; when it lands, GT-IAC-004 lists its
  detection and loses `known_miss`.
- The ground-truth format gains `known_miss`: a seed with no verified detection must say why (B9 owns the
  format).
