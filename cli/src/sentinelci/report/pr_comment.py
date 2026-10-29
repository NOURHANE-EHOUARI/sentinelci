"""The deterministic pull-request comment (SPEC section 5, task A3).

The comment is a view of a Decision v1 record, never a second decision:

- it is rendered only from a decision that passes the Decision v1 contract and whose
  `inputs.findings_digest` matches the findings file byte for byte, so the comment cannot describe other
  findings than the ones the gate evaluated;
- anything else (missing, malformed or mismatched files) produces a "no decision" comment that says the change
  is treated as blocked (rule SC-010), and the command exits 3;
- "N new" is shown only when the gate itself used a baseline (a `pr` decision with `inputs.baseline_digest`)
  and the baseline file matches that digest; "new" means what gate.rego calls `introduced`;
- the same inputs give the same bytes: rows are sorted, nothing reads the clock, and the only time shown is
  the decision's own `evaluated_at`;
- every value that comes from the scanned change is rendered through `report.markdown.code`.
"""

import hashlib
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from sentinelci.contracts.decision import Decision, Violation
from sentinelci.contracts.finding import Finding, Location
from sentinelci.report.markdown import code

MARKER = "<!-- sentinelci:pr-comment -->"
MAX_ROWS = 50
MAX_PIPELINE_CHANGES = 20
MAX_OTHER_LOCATIONS = 3
EVIDENCE_ARTIFACT = "sentinel-evidence"  # the workflow artifact holding the run's evidence store
WAIVER_FILES = frozenset({"waivers.yaml", "waivers.yml"})
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
_VERDICT_BADGE = {"BLOCK": "🛑 BLOCK", "WARN": "⚠️ WARN", "PASS": "✅ PASS"}
_EFFECT_ORDER = {"BLOCK": 0, "WARN": 1}
_FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")


class ReportError(Exception):
    """The inputs cannot support a trustworthy report: the change must be treated as blocked (SC-010)."""


@dataclass(frozen=True)
class ReportInputs:
    decision: Decision
    findings: dict[str, Finding]
    # Base-branch finding id -> the files it was seen in; only when the gate used this very baseline.
    baseline: dict[str, frozenset[str]] | None = None
    pipeline_changes: tuple[str, ...] = field(default_factory=tuple)


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_findings(data: bytes, *, source: str) -> dict[str, Finding]:
    """Finding v1 NDJSON -> {fingerprint: finding}. Any malformed line or duplicate id is an error."""
    findings: dict[str, Finding] = {}
    # Only "\n" separates records: JSON strings may hold raw U+2028/U+2029, which str.splitlines() splits on.
    for lineno, line in enumerate(data.decode("utf-8").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            finding = Finding.model_validate_json(line)
        except ValidationError as exc:
            raise ReportError(
                f"{source} line {lineno} is not a Finding v1: {exc.error_count()} error(s)"
            ) from exc
        if not _FINGERPRINT.fullmatch(finding.id):
            raise ReportError(f"{source} line {lineno}: id is not a sha256 fingerprint")
        if finding.id in findings:
            raise ReportError(f"{source} line {lineno}: duplicate finding id {finding.id[:12]}")
        findings[finding.id] = finding
    return findings


def load_inputs(
    decision_path: Path,
    findings_path: Path,
    *,
    baseline_path: Path | None = None,
    pipeline_changes_path: Path | None = None,
) -> ReportInputs:
    """Read and cross-check every input; raise ReportError rather than report on untrusted data."""
    try:
        decision_bytes = decision_path.read_bytes()
        findings_bytes = findings_path.read_bytes()
        baseline_bytes = baseline_path.read_bytes() if baseline_path else None
        changes_text = pipeline_changes_path.read_text(encoding="utf-8") if pipeline_changes_path else ""
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"cannot read the report inputs: {exc}") from exc
    try:
        decision = Decision.model_validate_json(decision_bytes)
    except ValidationError as exc:
        raise ReportError(f"the decision is not a valid Decision v1: {exc.error_count()} error(s)") from exc
    if sha256_digest(findings_bytes) != decision.inputs.findings_digest:
        raise ReportError(
            "the findings file is not the one the decision was made on (findings_digest mismatch)"
        )
    # A baseline the gate did not use (release context, or a decision without baseline_digest) is ignored: the
    # gate counted every finding, and "N new" would contradict it.
    gate_baseline = decision.inputs.baseline_digest if decision.subject.context == "pr" else None
    if (
        baseline_bytes is not None
        and gate_baseline is not None
        and sha256_digest(baseline_bytes) != gate_baseline
    ):
        raise ReportError(
            "the baseline file is not the one the decision was made on (baseline_digest mismatch)"
        )
    try:
        findings = parse_findings(findings_bytes, source="findings")
        baseline = (
            {fid: _paths(f) for fid, f in parse_findings(baseline_bytes, source="baseline").items()}
            if baseline_bytes is not None and gate_baseline is not None
            else None
        )
    except UnicodeDecodeError as exc:
        raise ReportError(f"findings are not UTF-8: {exc}") from exc
    changes = tuple(sorted({line.strip() for line in changes_text.split("\n") if line.strip()}))
    return ReportInputs(decision=decision, findings=findings, baseline=baseline, pipeline_changes=changes)


def _paths(finding: Finding) -> frozenset[str]:
    """Every file a finding was seen in (gate.rego `finding_paths`)."""
    return frozenset(place.path for place in (finding.location, *(finding.other_locations or ())) if place)


def introduced(finding: Finding, baseline: dict[str, frozenset[str]]) -> bool:
    """gate.rego `introduced` (diff-aware): unknown to the base branch, or a known secret in a new file."""
    known = baseline.get(finding.id)
    if known is None:
        return True
    return finding.category == "SECRET" and not _paths(finding) <= known


# ---------------------------------------------------------------- rendering


def _place(location: Location) -> str:
    line = f":{location.start_line}" if location.start_line else ""
    return code(f"{location.path}{line}")


def _location(finding: Finding | None) -> str:
    if finding is None:
        return "—"
    if finding.location is not None:
        others = finding.other_locations or []
        cell = " · ".join(_place(place) for place in [finding.location, *others[:MAX_OTHER_LOCATIONS]])
        hidden = len(others) - MAX_OTHER_LOCATIONS
        return cell + (f" and {hidden} more" if hidden > 0 else "")
    if finding.package is not None:
        return code(f"{finding.package.name} {finding.package.version}")
    return "—"


def _severity(finding: Finding | None) -> str:
    if finding is None:
        return "—"
    priority = (finding.risk or {}).get("priority")
    return f"{finding.severity} · {priority}" if priority in PRIORITIES else finding.severity


def _finding_cell(finding_id: str, finding: Finding | None) -> str:
    if finding is None:
        return f"{code(finding_id[:12])} (not in the findings file)"
    return f"{code(finding.title, limit=120)} · {code(f'{finding.tool.name}:{finding.rule_id}')}"


def _sort_key(finding_id: str, finding: Finding | None) -> tuple[str, int, str]:
    if finding is None:
        return ("~", 0, finding_id)  # unknown ids after known ones
    if finding.location is not None:
        return (finding.location.path, finding.location.start_line or 0, finding_id)
    return (finding.package.purl if finding.package else "", 0, finding_id)


def _rows(violations: Sequence[Violation], findings: dict[str, Finding]) -> list[str]:
    rows = []
    for violation in sorted(violations, key=lambda v: (_EFFECT_ORDER[v.effect], v.rule, v.message)):
        effect = f"**{violation.effect}**" if violation.effect == "BLOCK" else violation.effect
        rule, issue = code(violation.rule), code(violation.message, limit=120)
        if not violation.finding_ids:
            rows.append(f"| {rule} | {effect} | {issue} | — | — | — |")
            continue
        ids = sorted(set(violation.finding_ids), key=lambda i: _sort_key(i, findings.get(i)))
        for finding_id in ids:
            finding = findings.get(finding_id)
            rows.append(
                f"| {rule} | {effect} | {issue} | {_finding_cell(finding_id, finding)} | "
                f"{_location(finding)} | {_severity(finding)} |"
            )
    return rows


def _counts(findings: Iterable[Finding]) -> str:
    items = list(findings)
    priorities = [(f.risk or {}).get("priority") for f in items]
    if all(p in PRIORITIES for p in priorities):
        buckets, order = Counter(str(p) for p in priorities), PRIORITIES
    else:
        buckets, order = Counter(f.severity for f in items), SEVERITIES
    return " · ".join(f"{buckets[name]} {name}" for name in order if buckets[name])


def render_pr_comment(inputs: ReportInputs) -> str:
    decision, findings = inputs.decision, inputs.findings
    lines = [MARKER, f"## SentinelCI verdict: {_VERDICT_BADGE[decision.verdict]}", ""]

    if inputs.pipeline_changes:
        shown = inputs.pipeline_changes[:MAX_PIPELINE_CHANGES]
        more = len(inputs.pipeline_changes) - len(shown)
        lines += [
            "> [!WARNING]",
            "> This pull request changes SentinelCI's own pipeline. This run used the pipeline of the base",
            "> branch: the changes below take effect only after merge, so review them with care.",
            "> "
            + " · ".join(code(path, in_table=False) for path in shown)
            + (f" and {more} more" if more else ""),
        ]
        if any(PurePosixPath(path).name in WAIVER_FILES for path in inputs.pipeline_changes):
            lines += [
                ">",
                "> Waiver changes also take effect only after merge: a pull request cannot waive its own",
                "> findings. Merge the waiver on its own first, then re-run this check.",
            ]
        lines.append("")

    rows = _rows(decision.violations, findings)
    if rows:
        lines += [
            "| Rule | Effect | Issue | Finding | Location | Severity |",
            "|---|---|---|---|---|---|",
            *rows[:MAX_ROWS],
        ]
        if len(rows) > MAX_ROWS:
            lines.append(
                f"\n… and {len(rows) - MAX_ROWS} more rows in the decision record (workflow artifact)."
            )
        lines.append("")
    else:
        lines += ["No policy violation.", ""]

    if findings:
        total = f"{len(findings)} total"
        if inputs.baseline is not None:
            baseline = inputs.baseline
            total += f", {sum(1 for finding in findings.values() if introduced(finding, baseline))} new"
        lines.append(f"**Findings:** {_counts(findings.values())} ({total})")
    else:
        lines.append("**Findings:** none")
    if decision.waivers_applied:
        waivers = ", ".join(code(w, in_table=False) for w in sorted(decision.waivers_applied))
        lines.append(f"**Waivers applied:** {waivers}")

    subject, decision_inputs = decision.subject, decision.inputs
    tools = " · ".join(
        code(f"{name} {version}", in_table=False)
        for name, version in sorted(decision_inputs.tool_versions.items())
    )
    lines += [
        "",
        "<details><summary>Evidence</summary>",
        "",
        f"- Decision {code(decision.decision_id, in_table=False)}, evaluated at "
        f"{code(decision.evaluated_at, in_table=False)} on {code(subject.context, in_table=False)} commit "
        f"{code(subject.commit, in_table=False)}",
        f"- Findings {code(decision_inputs.findings_digest, in_table=False)} (verified against this report)",
        f"- Policy bundle {code(decision_inputs.policy_bundle_digest, in_table=False)} · risk model "
        f"{code(decision_inputs.risk_model_version, in_table=False)} · engine "
        f"{code(decision.engine_version, in_table=False)}",
        *_digest_lines(decision, baseline_verified=inputs.baseline is not None),
        f"- Tools: {tools}",
        f"- Replay: download this run's {code(EVIDENCE_ARTIFACT, in_table=False)} artifact into "
        f"{code(EVIDENCE_ARTIFACT + '/', in_table=False)}, then "
        f"{code(f'sentinel replay {decision.decision_id} --store {EVIDENCE_ARTIFACT}', in_table=False)}",
        "",
        "</details>",
        "",
        "_AI advisory is in the dashboard. It is advisory only and never changes the verdict._",
    ]
    return "\n".join(lines) + "\n"


def _digest_lines(decision: Decision, *, baseline_verified: bool) -> list[str]:
    lines = []
    if decision.inputs.baseline_digest is not None:
        checked = " (verified against this report)" if baseline_verified else ""
        lines.append(f"- Baseline {code(decision.inputs.baseline_digest, in_table=False)}{checked}")
    if decision.inputs.tool_status_digest is not None:
        lines.append(f"- Tool status {code(decision.inputs.tool_status_digest, in_table=False)}")
    return lines


def render_no_decision(reason: str) -> str:
    """Fail-closed comment: shown whenever no trustworthy decision is available."""
    return (
        "\n".join(
            [
                MARKER,
                "## SentinelCI verdict: 🛑 NO DECISION (treated as BLOCK, rule SC-010)",
                "",
                "The release gate did not produce a decision this report can trust, so the change is blocked "
                "(fail closed).",
                "",
                f"Reason: {code(reason, in_table=False, limit=300)}",
                "",
                "See the workflow run for the scanner and gate logs.",
            ]
        )
        + "\n"
    )
