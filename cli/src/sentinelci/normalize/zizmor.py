"""zizmor JSON v1 -> Finding v1, category PIPELINE (task A2, SPEC §13.1).

The resource is the job (`jobs.<id>`) or, outside jobs, the file's top-level key (`on`, `permissions`, `runs`
of an action, `updates` of Dependabot). A finding about a whole job or a whole file is one per job or file by
nature: `sha256(rule | path | resource)`. Any other finding also hashes the code it is about, the source text
zizmor points at, whitespace-normalized: `sha256(rule | path | resource | sha256(code))`. That code is
- for an expression or an action reference (zizmor's subfeature), only the line(s) holding it, so an edit to
  another line of the same `run:` script keeps the id;
- for a top-level key itself, its value: `on: pull_request_target` is the trigger, like its list and mapping
  forms;
- for a Dependabot entry, its text and the entry's `package-ecosystem`, so a second entry is a new finding;
- otherwise, zizmor's `feature` text of the primary location.
So a new expression, trigger or entry is a new finding, which SC-009 can block, while a moved line or an added
step keeps every id. Positions (a step or entry index) are never part of it. Occurrences with the same
fingerprint go to `other_locations` (Finding 1.1). No workflow code is kept: the text is only hashed.
"""

import posixpath
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import pipeline_fingerprint
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
    """`jobs.<id>`, the top-level key, or `workflow` (the whole file)."""
    if len(route) >= 2 and route[0] == "jobs":
        return f"jobs.{route[1]}"
    return route[0] if route else "workflow"


def _feature(location: Mapping[str, Any], index: int) -> str:
    feature = location.get("concrete", {}).get("feature")
    if not isinstance(feature, str) or not feature.strip():
        raise NormalizationError(f"zizmor finding {index} has no source text (feature) to identify it")
    return feature


def _subfeature_lines(location: Mapping[str, Any], feature: str) -> str:
    """The line(s) of `feature` holding zizmor's subfeature (an expression, an action reference), or the
    whole feature without one. zizmor gives the fragment and a byte offset to search from."""
    kind = location.get("symbolic", {}).get("feature_kind")
    subfeature = kind.get("Subfeature") if isinstance(kind, dict) else None
    fragment = subfeature.get("fragment") if isinstance(subfeature, dict) else None
    raw = fragment.get("Raw") if isinstance(fragment, dict) else None
    after = subfeature.get("after") if isinstance(subfeature, dict) else None
    if not isinstance(raw, str) or not raw.strip() or not isinstance(after, int) or after < 0:
        return feature  # a pattern or no fragment: the whole text, the narrower id is never guessed
    text, needle = feature.encode("utf-8"), raw.encode("utf-8")
    at = text.find(needle, after)
    if at < 0:
        return feature
    end = text.find(b"\n", at + len(needle))
    return text[text.rfind(b"\n", 0, at) + 1 : end if end >= 0 else len(text)].decode("utf-8")


def _ecosystem(item: Mapping[str, Any], entry: str, index: int) -> str:
    """The `package-ecosystem` line of Dependabot entry `entry` (`[n]`), from the finding's locations."""
    for location in item.get("locations") or []:
        if _route(location) == ["updates", entry, "package-ecosystem"]:
            return _feature(location, index)
    raise NormalizationError(f"zizmor finding {index} does not say which Dependabot entry it is about")


def _code(item: Mapping[str, Any], location: Mapping[str, Any], route: list[str], index: int) -> str | None:
    """The source text the finding is about, or None for a finding about a whole job or file."""
    if not route or (route[0] == "jobs" and len(route) <= 2):
        return None
    code = _subfeature_lines(location, _feature(location, index))
    if len(route) == 1:  # the top-level key itself: its value is what the finding is about
        key, colon, value = code.partition(":")
        if colon and key.strip() == route[0] and value.strip():
            code = value
    if route[0] == "updates" and len(route) >= 2 and route[2:] != ["package-ecosystem"]:
        code += "\n" + _ecosystem(item, route[1], index)  # a Dependabot entry is told apart by its ecosystem
    return code


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
    """Convert zizmor's JSON v1 findings into Finding v1 records (one per fingerprint). `scan_root`
    is the scanned directory relative to the repository root, so paths come out repository-relative."""
    groups: dict[str, list[tuple[str, int, int, Mapping[str, Any]]]] = defaultdict(list)
    for index, item in enumerate(results):
        rule = item.get("ident")
        if not isinstance(rule, str) or not rule:
            raise NormalizationError(f"zizmor finding {index} has no rule (ident)")
        _determinations(item, index)
        location = _primary(item, index)
        path, start, end = _place(location, index, scan_root)
        route = _route(location)
        fingerprint = pipeline_fingerprint(rule, path, _resource(route), _code(item, location, route, index))
        groups[fingerprint].append((path, start, end, item))

    findings: list[Finding] = []
    for fingerprint, hits in groups.items():
        hits.sort(key=lambda hit: (hit[0], hit[1], hit[2]))
        path, start, end, item = hits[0]
        distinct = list(dict.fromkeys((p, s, e) for p, s, e, _ in hits))
        others = [Location(path=p, start_line=s, end_line=e) for p, s, e in distinct[1:]]
        # Severity and its source come from the same occurrence: the most severe one (first on a tie).
        worst = max(hits, key=lambda hit: _rank(SEVERITIES[_determinations(hit[3], 0)[0]]))[3]
        raw_severity, confidence = _determinations(worst, 0)
        severity = SEVERITIES[raw_severity]
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
