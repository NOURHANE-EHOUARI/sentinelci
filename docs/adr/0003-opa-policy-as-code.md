# ADR-0003: OPA/Rego for the release gate

- Status: accepted
- Date: 2026-10-28

## Context

Release decisions must be testable, reviewable as code, explainable by rule ID, and reproducible.

## Decision

Express the gate as OPA policies in Rego v1 (`policies/`), each rule with an ID (SC-001…SC-010) and unit tests
(`opa test`). The CLI evaluates a pinned OPA binary against a JSON input that includes the evaluation timestamp.
The risk model weights live in a versioned YAML file inside the policy bundle.

## Consequences

- Policies never call `time.now_ns()`; time is an input, so `sentinel replay` is exact.
- The policy bundle digest is recorded in every decision.
- Waivers and OpenVEX statements are inputs to the policy, reviewed through pull requests.
