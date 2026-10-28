# ADR-0005: Opengrep for SAST

- Status: accepted
- Date: 2026-10-28

## Context

Semgrep Community Edition lacks cross-function taint analysis, which matters for injection findings.
Opengrep is a community fork of Semgrep CE (LGPL-2.1) that restores these capabilities while keeping the same
rule format and SARIF/JSON output.

## Decision

Run Opengrep with Semgrep-format rules (community rules plus our own). The adapter consumes standard SARIF so the
engine can be swapped for Semgrep CE with a one-line change.

## Consequences

- Better detection of taint-style vulnerabilities on the benchmark.
- We depend on a younger project; its version and checksum are pinned in `tools.lock.yaml` like every scanner.
