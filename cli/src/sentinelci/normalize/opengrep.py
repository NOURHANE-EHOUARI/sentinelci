"""Opengrep JSON -> Finding v1, category SAST (task A2, SPEC §13.1).

The fingerprint is the SAST one: `sha256(rule | path | sha256(normalized snippet))`, the snippet being the
matched lines Opengrep reports (`extra.lines`), whitespace-normalized. A moved line or a re-indented block
keeps the id; a new match is a new finding. The same code several times in a file is one finding per place,
numbered in line order (SPEC §13.1): the first keeps the fingerprint, the n-th is `sha256(fingerprint | n)`.
A copy of a vulnerable line is then new in a pull request, and a waiver covers the one place it was reviewed
for. No code is kept: the snippet is only hashed, and the messages are the rules' fixed text (SentinelCI's
rules never interpolate code into them).

Code Opengrep could not parse, in a file it otherwise analysed (at most half of it: more fails the scan), is a
finding too: rule `sentinel-sast-not-analysed`, SAST HIGH, one per gap, fingerprinted like a match on the
skipped text (and numbered the same way), with a message that names the lines and quotes no code. A new gap is
then new in a pull request, a gap that only moved keeps its id, and a waiver for one gap never covers another.
Valid syntax Opengrep cannot parse yet shows up this way too: the way out is a reviewed waiver with an expiry,
never a scanner flag."""

import posixpath
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import occurrence_fingerprint, sast_fingerprint
from sentinelci.normalize.paths import to_repo_relative

# Opengrep's legacy and current rule severities. An unknown one is refused: SentinelCI writes the rules.
SEVERITIES = {
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
}  # fmt: skip
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
_CWE = re.compile(r"CWE-[0-9]+")
# Opengrep runs with --disable-nosem: a match on a line with a `# nosemgrep` comment is still reported,
# flagged `is_ignored`. It stays a finding: the scanned repository cannot silence a scanner.
IGNORED_NOTE = "A nosemgrep comment covers it; SentinelCI does not honour those (use a waiver)."
_RANK = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
NOT_ANALYSED_RULE = "sentinel-sast-not-analysed"
_ERROR_TYPE = re.compile(r"[A-Za-z][A-Za-z ]{0,63}")


@dataclass(frozen=True)
class ParseGap:
    """Lines Opengrep could not parse and skipped, in a file it otherwise analysed: `path` relative to the
    scanned directory, the first and last line (from 1, inclusive), Opengrep's error type, and the skipped
    text (only ever hashed)."""

    path: str
    start: int
    end: int
    error: str
    text: str


def _field(mapping: Mapping[str, Any], key: str, index: int, kind: type) -> Any:
    value = mapping.get(key)
    if not isinstance(value, kind) or (isinstance(value, str) and not value.strip()):
        raise NormalizationError(f"opengrep result {index} has no usable {key}")
    return value


def _line(position: Any, index: int, which: str) -> int:
    line = position.get("line") if isinstance(position, dict) else None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise NormalizationError(f"opengrep result {index} has no {which} line")
    return line


def _rank(severity: str) -> int:
    return _RANK.index(severity)


def normalize_opengrep(
    results: Sequence[Mapping[str, Any]],
    *,
    run: Run,
    tool: Tool,
    rules: frozenset[str],
    scan_target: Path,
    scan_root: str = ".",
    gaps: Sequence[ParseGap] = (),
) -> list[Finding]:
    """Convert Opengrep results, and the code it could not analyse (`gaps`), into Finding v1 records.
    `scan_target` is the scanned directory (result paths are absolute, under it) and `scan_root` that
    directory relative to the repository root."""
    groups: dict[str, list[tuple[str, int, int, Mapping[str, Any]]]] = defaultdict(list)
    for index, result in enumerate(results):
        rule = _field(result, "check_id", index, str)
        if rule not in rules:
            raise NormalizationError(
                f"opengrep result {index} names rule {rule!r}, which is not SentinelCI's"
            )
        extra = _field(result, "extra", index, dict)
        snippet = _field(extra, "lines", index, str)
        relative = to_repo_relative(_field(result, "path", index, str), scan_target)
        path = to_repo_relative(posixpath.join(scan_root, relative))
        start, end = _line(result.get("start"), index, "start"), _line(result.get("end"), index, "end")
        if end < start:
            raise NormalizationError(f"opengrep result {index} ends before it starts")
        _severity(extra, index)
        _metadata(extra, index)
        groups[sast_fingerprint(rule, path, snippet)].append((path, start, end, result))

    findings: list[Finding] = []
    for fingerprint, hits in groups.items():
        # One fingerprint is one rule and one file. Each place is a finding, numbered in line order; Opengrep
        # reporting the same place twice is still one finding.
        places: dict[tuple[str, int, int], list[Mapping[str, Any]]] = defaultdict(list)
        for path, start, end, result in sorted(hits, key=lambda hit: (hit[0], hit[1], hit[2])):
            places[(path, start, end)].append(result)
        for occurrence, ((path, start, end), same) in enumerate(places.items(), start=1):
            findings.append(
                _finding(occurrence_fingerprint(fingerprint, occurrence), same, path, start, end, run, tool)
            )
    findings += _gap_findings(gaps, scan_root, run, tool)
    return sorted(findings, key=lambda f: f.id)


def _gap_findings(gaps: Sequence[ParseGap], scan_root: str, run: Run, tool: Tool) -> list[Finding]:
    """One SAST HIGH finding per gap, numbered like matches: the same skipped text twice in a file is two
    findings, in line order."""
    groups: dict[str, dict[tuple[int, int], tuple[str, ParseGap]]] = defaultdict(dict)
    for gap in gaps:
        if gap.end < gap.start or gap.start < 1 or not _ERROR_TYPE.fullmatch(gap.error):
            raise NormalizationError(f"a malformed gap in what Opengrep analysed ({gap.path})")
        path = to_repo_relative(posixpath.join(scan_root, to_repo_relative(gap.path)))
        groups[sast_fingerprint(NOT_ANALYSED_RULE, path, gap.text)][(gap.start, gap.end)] = (path, gap)
    findings: list[Finding] = []
    for fingerprint, places in groups.items():
        for occurrence, (_, (path, gap)) in enumerate(sorted(places.items()), start=1):
            lines = f"line {gap.start}" if gap.start == gap.end else f"lines {gap.start}-{gap.end}"
            findings.append(
                Finding(
                    schema_version="1.0",
                    id=occurrence_fingerprint(fingerprint, occurrence),
                    tool=tool,
                    rule_id=NOT_ANALYSED_RULE,
                    category="SAST",
                    title="Code that SAST did not analyse",
                    message=(
                        f"Opengrep did not analyse {lines} of {path} ({gap.error}). SentinelCI does not skip "
                        "code silently: make it parse, or, for valid syntax Opengrep cannot read yet, waive "
                        "this finding with a reviewed expiry."
                    ),
                    severity="HIGH",
                    severity_source="SentinelCI (code not analysed)",
                    location=Location(path=path, start_line=gap.start, end_line=gap.end),
                    run=run,
                )
            )
    return findings


def _finding(
    fingerprint: str,
    results: list[Mapping[str, Any]],
    path: str,
    start: int,
    end: int,
    run: Run,
    tool: Tool,
) -> Finding:
    # Severity and its source come from the same match: the most severe one (first on a tie).
    worst = max(results, key=lambda result: _rank(SEVERITIES[_severity(result["extra"], 0)]))
    raw_severity = _severity(worst["extra"], 0)
    title, cwe, confidence = _metadata(worst["extra"], 0)
    notes = [str(worst["extra"].get("message") or title), f"Confidence {confidence.lower()}."]
    if any(result["extra"].get("is_ignored") for result in results):
        notes.append(IGNORED_NOTE)
    return Finding(
        schema_version="1.0",
        id=fingerprint,
        tool=tool,
        rule_id=str(worst["check_id"]),
        category="SAST",
        title=title,
        message=" ".join(notes),
        severity=SEVERITIES[raw_severity],  # type: ignore[arg-type]
        severity_source=f"{raw_severity} (confidence {confidence})",
        cwe=cwe or None,
        location=Location(path=path, start_line=start, end_line=end),
        run=run,
    )


def _severity(extra: Mapping[str, Any], index: int) -> str:
    severity = extra.get("severity")
    if severity not in SEVERITIES:
        raise NormalizationError(f"opengrep result {index} has an unknown severity {severity!r}")
    return str(severity)


def _metadata(extra: Mapping[str, Any], index: int) -> tuple[str, list[str], str]:
    """(title, CWE ids, confidence) from the rule's metadata, which SentinelCI's rules always carry."""
    metadata = _field(extra, "metadata", index, dict)
    title = _field(metadata, "title", index, str)
    confidence = metadata.get("confidence")
    if confidence not in CONFIDENCES:
        raise NormalizationError(f"opengrep result {index} has an unknown confidence {confidence!r}")
    cwe = metadata.get("cwe", [])
    if not isinstance(cwe, list) or not all(isinstance(c, str) and _CWE.fullmatch(c) for c in cwe):
        raise NormalizationError(f"opengrep result {index} has malformed CWE ids {cwe!r}")
    return title, sorted(set(cwe)), str(confidence)
