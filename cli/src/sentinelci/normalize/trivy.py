"""Trivy `config` JSON report (SchemaVersion 2) -> Finding v1, category IAC (tasks A1c, A2).

- Every misconfiguration that is not `PASS` becomes a finding. SentinelCI loads no exceptions, so an
  `EXCEPTION` status would mean something silenced a check: it is reported like a failure.
- Trivy's `Target` is relative to the scanned directory; findings carry repository-relative paths.
- Fingerprint (SPEC 13.1): `rule id | path | resource`. The resource is Trivy's `CauseMetadata.Resource`
  (`aws_s3_bucket.assets`), else the first line of the cause (`- name: shop-api` for a Kubernetes container),
  else empty (a Dockerfile-wide check). It survives line shifts.
- Two failures with the same fingerprint are one finding: the first place (by path and line) is `location`,
  the others are `other_locations` (Finding 1.1).
- No code snippet is kept: the lines Trivy quotes may hold credentials (a password in a Terraform resource).
- A missing or `UNKNOWN` severity counts as HIGH (missing data never lowers risk); `severity_source` keeps
  the raw value.
"""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

from sentinelci.contracts.finding import Finding, Location, Run, Severity, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import config_fingerprint
from sentinelci.normalize.paths import to_repo_relative

_SEVERITIES: dict[str, Severity] = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
UNKNOWN_SEVERITY: Severity = "HIGH"
MAX_MESSAGE = 500


def _text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError(f"{where} has no {key}")
    return value


def _line(value: object) -> int | None:
    return value if type(value) is int and value >= 1 else None


def _resource(cause: Mapping[str, Any]) -> str:
    resource = cause.get("Resource")
    if isinstance(resource, str) and resource.strip():
        return resource.strip()
    code = cause.get("Code")
    lines = code.get("Lines") if isinstance(code, Mapping) else None
    for line in lines if isinstance(lines, list) else []:
        if isinstance(line, Mapping) and line.get("IsCause") and isinstance(line.get("Content"), str):
            return " ".join(line["Content"].split())
    return ""


def _path(scan_root: str, target: str) -> str:
    joined = target if scan_root in ("", ".") else (PurePosixPath(scan_root) / target).as_posix()
    return to_repo_relative(joined)


def normalize_trivy_config(
    results: Sequence[Mapping[str, Any]], *, run: Run, tool: Tool, scan_root: str = "."
) -> list[Finding]:
    """Convert Trivy `Results` into findings, one per (rule, path, resource), sorted by place."""
    hits: dict[str, list[tuple[Location, str, Mapping[str, Any]]]] = defaultdict(list)
    for index, result in enumerate(results):
        misconfigs = result.get("Misconfigurations")
        misconfigs = [] if misconfigs is None else misconfigs
        if not isinstance(misconfigs, list):
            raise NormalizationError(f"Trivy result #{index} has invalid Misconfigurations")
        if not misconfigs:
            continue
        path = _path(scan_root, _text(result, "Target", f"Trivy result #{index}"))
        for number, item in enumerate(misconfigs):
            where = f"Trivy result #{index} misconfiguration #{number}"
            if not isinstance(item, Mapping):
                raise NormalizationError(f"{where} is not an object")
            if _text(item, "Status", where) == "PASS":
                continue
            rule_id = _text(item, "ID", where)
            cause = item.get("CauseMetadata")
            cause = {} if cause is None else cause
            if not isinstance(cause, Mapping):
                raise NormalizationError(f"{where} has invalid CauseMetadata")
            start = _line(cause.get("StartLine"))
            end = _line(cause.get("EndLine")) if start else None
            location = Location(path=path, start_line=start, end_line=max(end or 0, start or 0) or None)
            hits[config_fingerprint(rule_id, path, _resource(cause))].append((location, rule_id, item))

    findings = [_finding(fingerprint, places, run=run, tool=tool) for fingerprint, places in hits.items()]
    return sorted(findings, key=_order)


def _order(finding: Finding) -> tuple[str, int, str, str]:
    place = finding.location  # always set for IAC findings
    return (place.path if place else "", (place.start_line or 0) if place else 0, finding.rule_id, finding.id)


def _finding(
    fingerprint: str, places: list[tuple[Location, str, Mapping[str, Any]]], *, run: Run, tool: Tool
) -> Finding:
    places.sort(key=lambda place: (place[0].path, place[0].start_line or 0, place[0].end_line or 0))
    first, rule_id, item = places[0]
    others = sorted({place[0] for place in places[1:]} - {first}, key=lambda p: (p.path, p.start_line or 0))
    raw_severity = item.get("Severity")
    severity = (
        _SEVERITIES.get(raw_severity, UNKNOWN_SEVERITY) if isinstance(raw_severity, str) else UNKNOWN_SEVERITY
    )
    message = item.get("Message")
    return Finding(
        schema_version="1.1" if others else "1.0",
        id=fingerprint,
        tool=tool,
        rule_id=rule_id,
        category="IAC",
        title=_text(item, "Title", f"Trivy {rule_id}"),
        message=message.strip()[:MAX_MESSAGE] if isinstance(message, str) and message.strip() else None,
        severity=severity,
        severity_source=raw_severity if isinstance(raw_severity, str) and raw_severity else "none",
        location=first,
        other_locations=others or None,
        run=run,
    )
