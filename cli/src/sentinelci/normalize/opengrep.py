"""Opengrep JSON -> Finding v1, category SAST (task A2, SPEC §13.1).

The fingerprint is the SAST one: `sha256(rule | path | sha256(normalized snippet))`, the snippet being the
matched lines Opengrep reports (`extra.lines`), whitespace-normalized. A moved line or a re-indented block
keeps the id; a new match is a new finding. Matches with the same fingerprint (the same code twice in a file)
are one finding with `other_locations` (Finding 1.1). No code is kept: the snippet is only hashed, and the
messages are the rules' fixed text (SentinelCI's rules never interpolate code into them)."""

import posixpath
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import sast_fingerprint
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
) -> list[Finding]:
    """Convert Opengrep results into Finding v1 records. `scan_target` is the scanned directory (result paths
    are absolute, under it) and `scan_root` that directory relative to the repository root."""
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
        hits.sort(key=lambda hit: (hit[0], hit[1], hit[2]))
        path, start, end, first = hits[0]
        distinct = list(dict.fromkeys((p, s, e) for p, s, e, _ in hits))
        others = [Location(path=p, start_line=s, end_line=e) for p, s, e in distinct[1:]]
        # Severity and its source come from the same match: the most severe one (first on a tie).
        worst = max(hits, key=lambda hit: _rank(SEVERITIES[_severity(hit[3]["extra"], 0)]))[3]
        raw_severity = _severity(worst["extra"], 0)
        title, cwe, confidence = _metadata(worst["extra"], 0)
        notes = [str(worst["extra"].get("message") or title), f"Confidence {confidence.lower()}."]
        if any(hit[3]["extra"].get("is_ignored") for hit in hits):
            notes.append(IGNORED_NOTE)
        findings.append(
            Finding(
                schema_version="1.1" if others else "1.0",
                id=fingerprint,
                tool=tool,
                rule_id=str(first["check_id"]),
                category="SAST",
                title=title,
                message=" ".join(notes),
                severity=SEVERITIES[raw_severity],  # type: ignore[arg-type]
                severity_source=f"{raw_severity} (confidence {confidence})",
                cwe=cwe or None,
                location=Location(path=path, start_line=start, end_line=end),
                other_locations=others or None,
                run=run,
            )
        )
    return sorted(findings, key=lambda f: f.id)


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
