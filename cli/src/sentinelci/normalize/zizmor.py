"""zizmor JSON v1 -> Finding v1, category PIPELINE (task A2, SPEC §13.1).

One finding per (rule, file, job): the fingerprint is `sha256(rule | path | resource)`, the resource being the
job (`jobs.<id>`) or, outside jobs, the workflow's top-level key (`on`, `permissions`, `runs` of an action).
Steps are left out on purpose: adding a step must not make every later finding of the job look new in a pull
request. The other occurrences of the same rule in the same job go to `other_locations` (Finding 1.1). No
workflow code is kept: zizmor's `feature` text never reaches a finding.
"""

import posixpath
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import config_fingerprint
from sentinelci.normalize.paths import to_repo_relative

# zizmor severities; an unknown one counts as the worst a CI workflow issue can be here (fail closed).
SEVERITIES = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO", "Unknown": "HIGH"}
CONFIDENCES = ("High", "Medium", "Low", "Unknown")
# zizmor runs with --no-ignores: a finding covered by an inline `# zizmor: ignore[...]` comment is still
# reported, flagged `ignored`. It stays a finding: the scanned repository cannot silence a scanner.
IGNORED_NOTE = "An inline zizmor ignore comment covers it; SentinelCI does not honour those (use a waiver)."


def _determinations(item: Mapping[str, Any], index: int) -> tuple[str, str]:
    """(severity, confidence) as zizmor wrote them; an unknown value is refused, not guessed."""
    determinations = item.get("determinations")
    if not isinstance(determinations, dict):
        raise NormalizationError(f"zizmor finding {index} has no determinations")
    severity, confidence = determinations.get("severity"), determinations.get("confidence")
    if severity not in SEVERITIES or confidence not in CONFIDENCES:
        raise NormalizationError(f"zizmor finding {index} determinations {determinations!r} are unknown")
    return str(severity), str(confidence)


def _route(location: Mapping[str, Any]) -> list[str]:
    steps = location.get("symbolic", {}).get("route", {}).get("route", [])
    route: list[str] = []
    for step in steps if isinstance(steps, list) else []:
        if isinstance(step, dict) and isinstance(step.get("Key"), str):
            route.append(step["Key"])
        elif isinstance(step, dict) and isinstance(step.get("Index"), int):
            route.append(f"[{step['Index']}]")
        else:
            raise NormalizationError(f"zizmor route step {step!r} is neither a key nor an index")
    return route


def _resource(route: list[str]) -> str:
    if len(route) >= 2 and route[0] == "jobs":
        return f"jobs.{route[1]}"
    return route[0] if route else "workflow"


def _primary(item: Mapping[str, Any], index: int) -> Mapping[str, Any]:
    locations = item.get("locations")
    if (
        not isinstance(locations, list)
        or not locations
        or not all(isinstance(loc, dict) for loc in locations)
    ):
        raise NormalizationError(f"zizmor finding {index} has no location")
    primary = [loc for loc in locations if loc.get("symbolic", {}).get("kind") == "Primary"]
    chosen: Mapping[str, Any] = (primary or locations)[0]
    return chosen


def _place(location: Mapping[str, Any], index: int, scan_root: str) -> tuple[str, int, int]:
    key = location.get("symbolic", {}).get("key", {})
    local = key.get("Local") if isinstance(key, dict) else None
    if not isinstance(local, dict) or not isinstance(local.get("verbatim_path"), str):
        raise NormalizationError(f"zizmor finding {index} is not about a local file")
    span = location.get("concrete", {}).get("location", {})
    try:
        start_row, end_row = int(span["start_point"]["row"]), int(span["end_point"]["row"])
        end_column = int(span["end_point"]["column"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NormalizationError(f"zizmor finding {index} has no line span") from exc
    if start_row < 0 or end_row < start_row:
        raise NormalizationError(f"zizmor finding {index} has an impossible line span")
    start = start_row + 1  # zizmor rows count from 0
    # A span ending at column 0 ends with the previous line.
    end = max(start, end_row if end_column == 0 else end_row + 1)
    relative = to_repo_relative(local["verbatim_path"])  # zizmor ran on paths relative to the scan root
    return to_repo_relative(posixpath.join(scan_root, relative)), start, end


def normalize_zizmor(
    results: Sequence[Mapping[str, Any]], *, run: Run, tool: Tool, scan_root: str = "."
) -> list[Finding]:
    """Convert zizmor's JSON v1 findings into Finding v1 records (one per rule, file and job). `scan_root`
    is the scanned directory relative to the repository root, so paths come out repository-relative."""
    groups: dict[str, list[tuple[str, int, int, Mapping[str, Any]]]] = defaultdict(list)
    for index, item in enumerate(results):
        rule = item.get("ident")
        if not isinstance(rule, str) or not rule:
            raise NormalizationError(f"zizmor finding {index} has no rule (ident)")
        _determinations(item, index)
        location = _primary(item, index)
        path, start, end = _place(location, index, scan_root)
        fingerprint = config_fingerprint(rule, path, _resource(_route(location)))
        groups[fingerprint].append((path, start, end, item))

    findings: list[Finding] = []
    for fingerprint, hits in groups.items():
        hits.sort(key=lambda hit: (hit[0], hit[1], hit[2]))
        path, start, end, item = hits[0]
        distinct = list(dict.fromkeys((p, s, e) for p, s, e, _ in hits))
        others = [Location(path=p, start_line=s, end_line=e) for p, s, e in distinct[1:]]
        raw_severity, confidence = _determinations(item, 0)
        severity = max((SEVERITIES[_determinations(hit[3], 0)[0]] for hit in hits), key=_rank)
        url = item.get("url")
        notes = [f"Confidence {confidence.lower()}."]
        if any(hit[3].get("ignored") for hit in hits):
            notes.append(IGNORED_NOTE)
        if isinstance(url, str):
            notes.append(f"See {url}")
        message = " ".join(notes)
        findings.append(
            Finding(
                schema_version="1.1" if others else "1.0",
                id=fingerprint,
                tool=tool,
                rule_id=str(item["ident"]),
                category="PIPELINE",
                title=str(item.get("desc") or item["ident"]),
                message=message,
                severity=severity,  # type: ignore[arg-type]
                severity_source=f"{raw_severity} (confidence {confidence})",
                location=Location(path=path, start_line=start, end_line=end),
                other_locations=others or None,
                run=run,
            )
        )
    return sorted(findings, key=lambda f: f.id)


def _rank(severity: str) -> int:
    return ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(severity)
