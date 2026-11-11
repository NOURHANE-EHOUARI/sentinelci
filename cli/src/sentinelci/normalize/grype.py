"""Grype JSON report (`-o json`) of a source tree -> Finding v1, category SCA (task A1).

- Input: the pinned Grype's report on the Syft SBOM of a directory (`sentinel scan sca`). An image report is
  refused here: its findings are CONTAINER findings, which need the image digest (the image adapter).
- One finding per (vulnerability id, purl base), the SCA fingerprint of SPEC 13.1. The vulnerability id is
  Grype's `vulnerability.id`, the record that matched (a GHSA for a language package). It is `rule_id`, and
  it stays the same when a CVE is assigned later, so the fingerprint does too. The CVE ids Grype relates to it
  go to `cve`, the other ids to `aliases`: enrichment (B2) and correlation (A7) join tools and feeds on them.
- Every file the package was found in is a place. Matches with the same fingerprint (the same package in two
  services, or two versions of it) are one finding: the first place by path is `location`, the others are
  `other_locations` (Finding 1.1). The package block, fixed versions and message describe the first place.
- Severity is Grype's. `Negligible` counts as INFO: the distribution says the issue has no security
  impact worth fixing, and LOW and INFO both end in P4, so only the counts differ (review of #52).
  `Unknown` counts as HIGH (missing data never lowers risk). `severity_source` keeps the raw value. Any
  other value fails closed: a new Grype severity needs a reviewed mapping.
- The CVSS, EPSS and KEV data in the report are not copied: enrichment comes from the dated snapshot (B2)
  only, so that a decision can be replayed from its evidence.
- Nothing may have been silenced. The report records the configuration it was made with, and it must show no
  ignore rule beyond Grype's built-in kernel-header rules, no VEX document, no exclusion, none of only-fixed,
  only-notfixed or ignore-wontfix, no distro override, and by-cve off (it renames GHSA matches to CVE ids,
  which would change rule ids and fingerprints). Its database must be valid. A report that cannot show this
  fails closed, whoever produced it.
"""

import json
import posixpath
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from pydantic import ValidationError

from sentinelci.contracts.finding import Category, Finding, Location, Package, Run, Severity, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.normalize.paths import to_repo_relative

CATEGORY: Category = "SCA"
GRYPE_SEVERITIES: dict[str, Severity] = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Negligible": "INFO",
}
UNKNOWN = "Unknown"
UNKNOWN_SEVERITY: Severity = "HIGH"
MAX_TITLE = 200
MAX_MESSAGE = 500
# A vulnerability id is one printable token (GHSA-..., CVE-..., PYSEC-..., GO-..., RHSA-2026:0001).
_ID = re.compile(r"[!-~]+")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_CWE = re.compile(r"CWE-([0-9]+)")
# The schema's purl pattern, on one printable line.
_PURL = re.compile(r"pkg:([a-z0-9.+-]+)/[!-~]+")
_SHA256 = re.compile(r"sha256:[a-f0-9]{64}")


def _builtin_rule(name: str, kind: str, upstream: str) -> dict[str, Any]:
    package = {"name": name, "version": "", "language": "", "type": kind, "location": ""}
    package["upstream-name"] = upstream
    return {
        "vulnerability": "",
        "include-aliases": False,
        "reason": "",
        "namespace": "",
        "fix-state": "",
        "package": package,
        "vex-status": "",
        "vex-justification": "",
        "match-type": "exact-indirect-match",
    }


# The ignore rules Grype 0.121 adds on its own (`match-upstream-kernel-headers: false`): kernel header
# packages are not matched against kernel vulnerabilities through their upstream. Other rules hide findings.
BUILTIN_IGNORE_RULES = (
    _builtin_rule("kernel-headers", "rpm", "kernel"),
    _builtin_rule("linux(-.*)?-headers-.*", "deb", "linux.*"),
    _builtin_rule("linux-libc-dev", "deb", "linux"),
    _builtin_rule("linux-kbuild-.*", "deb", "linux.*"),
)
# Settings that hide matches, with the only value a SentinelCI report may show.
_NOT_SILENCED: dict[str, object] = {
    "only-fixed": False,
    "only-notfixed": False,
    "ignore-wontfix": "",
    "by-cve": False,
    "exclude": [],
    "vex-documents": [],
    "vex-add": [],
    "distro": "",
}


@dataclass(frozen=True)
class GrypeDatabase:
    """The vulnerability database a report was made with: evidence of what Grype knew."""

    schema_version: str
    built: str
    checksum: str | None


def load_grype_report(path: Path) -> dict[str, Any]:
    """Read a Grype JSON report."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"cannot read Grype report {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise NormalizationError("Grype report must be a JSON object")
    return data


def _object(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NormalizationError(f"{where} is not an object")
    return value


def _list(value: object, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise NormalizationError(f"{where} is not a list")
    return value


def _text(item: Mapping[str, Any], key: str, where: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise NormalizationError(f"{where} has no {key}")
    return value


def check_grype_report(report: Mapping[str, Any]) -> tuple[Tool, GrypeDatabase]:
    """Check that the report comes from Grype, silenced nothing and used a valid database (see module doc)."""
    descriptor = _object(report.get("descriptor"), "Grype report descriptor")
    if descriptor.get("name") != "grype":
        raise NormalizationError(f"not a Grype report (descriptor.name is {descriptor.get('name')!r})")
    tool = Tool(name="grype", version=_text(descriptor, "version", "Grype report descriptor"))
    configuration = _object(descriptor.get("configuration"), "Grype report descriptor.configuration")
    for key, expected in _NOT_SILENCED.items():
        if configuration.get(key, ...) != expected:
            raise NormalizationError(
                f"Grype report was made with {key} = {configuration.get(key, '(absent)')!r}, which can hide "
                f"vulnerabilities: SentinelCI runs Grype with {key} = {expected!r}, exceptions are waivers"
            )
    rules = configuration.get("ignore", ...)
    if not isinstance(rules, list):
        raise NormalizationError("Grype report lists no ignore rules: it cannot show that nothing was hidden")
    for rule in rules:
        if rule not in BUILTIN_IGNORE_RULES:
            raise NormalizationError(
                "Grype report was made with an ignore rule that is not one of Grype's built-in kernel-header "
                f"rules ({json.dumps(rule, sort_keys=True)[:300]}): SentinelCI exceptions are waivers"
            )
    return tool, _database(descriptor)


def _database(descriptor: Mapping[str, Any]) -> GrypeDatabase:
    db = _object(descriptor.get("db"), "Grype report descriptor.db")
    status = _object(db.get("status"), "Grype report descriptor.db.status")
    if status.get("valid") is not True:
        raise NormalizationError("Grype's vulnerability database was not valid for this report")
    return database_of_status(status)


def database_of_status(value: object) -> GrypeDatabase:
    """The database a Grype status object describes: a report's `descriptor.db.status`, or the output of
    `grype db status -o json`. Anything but `valid: true` is refused, with Grype's own error."""
    status = _object(value, "Grype database status")
    if status.get("valid") is not True:
        error = status.get("error")
        reason = f": {error[:300]}" if isinstance(error, str) and error.strip() else ""
        raise NormalizationError(f"Grype's vulnerability database is not valid{reason}")
    origin = status.get("from")
    checksums = parse_qs(urlsplit(origin).query).get("checksum", []) if isinstance(origin, str) else []
    checksum = checksums[0] if len(checksums) == 1 and _SHA256.fullmatch(checksums[0]) else None
    return GrypeDatabase(
        schema_version=_text(status, "schemaVersion", "Grype database status"),
        built=_text(status, "built", "Grype database status"),
        checksum=checksum,
    )


def _repo_path(scan_root: str, raw: str, where: str) -> str:
    """Repository-relative path of a file Syft named relative to the scanned directory (`/services/a.txt`)."""
    inner = raw.lstrip("/")
    if ".." in PurePosixPath(inner).parts:
        raise NormalizationError(f"{where} names a path outside the scanned directory: {raw!r}")
    joined = inner if scan_root in ("", ".") else posixpath.join(scan_root, inner)
    return to_repo_relative(posixpath.normpath(joined) if joined else joined)


def _ids(match: Mapping[str, Any], where: str) -> tuple[str, list[str], list[str]]:
    """(rule id, CVE ids, other ids) of a match."""
    vulnerability = _object(match.get("vulnerability"), f"{where} vulnerability")
    rule_id = _text(vulnerability, "id", f"{where} vulnerability")
    related = [
        _text(_object(entry, f"{where} related vulnerability"), "id", f"{where} related vulnerability")
        for entry in _list(match.get("relatedVulnerabilities"), f"{where} relatedVulnerabilities")
    ]
    for vuln_id in (rule_id, *related):
        if not _ID.fullmatch(vuln_id):
            raise NormalizationError(f"{where} has a malformed vulnerability id {vuln_id!r}")
    cves = {i.upper() for i in (rule_id, *related) if _CVE.fullmatch(i.upper())}
    others = {i for i in related if not _CVE.fullmatch(i.upper()) and i != rule_id}
    return rule_id, sorted(cves), sorted(others)


def _cwes(match: Mapping[str, Any], where: str) -> list[str]:
    entries = [match.get("vulnerability"), *_list(match.get("relatedVulnerabilities"), where)]
    found: set[str] = set()
    for entry in entries:
        for item in _list(_object(entry, where).get("cwes"), f"{where} cwes"):
            cwe = item.get("cwe") if isinstance(item, Mapping) else None
            if isinstance(cwe, str) and _CWE.fullmatch(cwe):  # NVD-CWE-Other / NVD-CWE-noinfo carry no CWE
                found.add(cwe)
    return sorted(found, key=lambda cwe: int(cwe.removeprefix("CWE-")))


def _severity(vulnerability: Mapping[str, Any], where: str) -> tuple[Severity, str]:
    raw = vulnerability.get("severity")
    if raw is None or raw == "" or raw == UNKNOWN:
        return UNKNOWN_SEVERITY, raw or UNKNOWN
    if not isinstance(raw, str) or raw not in GRYPE_SEVERITIES:
        raise NormalizationError(f"{where} has a severity SentinelCI does not map: {raw!r}")
    return GRYPE_SEVERITIES[raw], raw


def _fixed_versions(vulnerability: Mapping[str, Any], where: str) -> tuple[list[str], str]:
    fix = vulnerability.get("fix")
    fix = {} if fix is None else _object(fix, f"{where} fix")
    versions = _list(fix.get("versions"), f"{where} fix.versions")
    if not all(isinstance(v, str) and v.strip() for v in versions):
        raise NormalizationError(f"{where} has an invalid fixed version")
    state = fix.get("state")
    return list(dict.fromkeys(versions)), state if isinstance(state, str) and state else "unknown"


@dataclass(frozen=True)
class _Place:
    paths: tuple[str, ...]
    match: Mapping[str, Any]
    artifact: Mapping[str, Any]
    purl: str
    ecosystem: str
    order: tuple[str, str, str, str]


def _place(match: Mapping[str, Any], scan_root: str, where: str) -> tuple[str, _Place]:
    artifact = _object(match.get("artifact"), f"{where} artifact")
    name = _text(artifact, "name", f"{where} artifact")
    version = _text(artifact, "version", f"{where} artifact")
    purl = _text(artifact, "purl", f"{where} artifact")
    purl_match = _PURL.fullmatch(purl)
    if purl_match is None:
        raise NormalizationError(f"{where} artifact has no usable purl ({purl!r}), so no fingerprint")
    locations = [_object(loc, f"{where} location") for loc in _list(artifact.get("locations"), where)]
    paths = sorted(
        {_repo_path(scan_root, _text(loc, "path", f"{where} location"), where) for loc in locations}
    )
    rule_id, _, _ = _ids(match, where)
    order = (paths[0] if paths else "\U0010ffff", version, name, str(artifact.get("id", "")))
    place = _Place(tuple(paths), match, artifact, purl, purl_match.group(1), order)
    return package_fingerprint(CATEGORY, rule_id, purl), place


def normalize_grype(report: Mapping[str, Any], *, run: Run, scan_root: str = ".") -> list[Finding]:
    """Convert a Grype report of a directory into SCA findings, one per (vulnerability, purl base).

    `scan_root` is the scanned directory relative to the repository root: Syft names files relative to it.
    """
    tool, _ = check_grype_report(report)
    source = _object(report.get("source"), "Grype report source")
    if source.get("type") != "directory":
        raise NormalizationError(
            f"Grype report of a {source.get('type')!r} source: only directory (source tree) reports are SCA "
            "findings; an image report needs the image adapter (CONTAINER findings carry the image digest)"
        )
    root = "." if scan_root in ("", ".") else to_repo_relative(scan_root)
    groups: dict[str, list[_Place]] = defaultdict(list)
    matches = report.get("matches", ...)
    if matches is ...:
        raise NormalizationError("Grype report has no matches list")
    for index, raw in enumerate(_list(matches, "Grype report matches")):
        where = f"Grype match #{index}"
        fingerprint, place = _place(_object(raw, where), root, where)
        groups[fingerprint].append(place)
    findings = [_finding(fingerprint, places, run=run, tool=tool) for fingerprint, places in groups.items()]
    return sorted(findings, key=_finding_order)


def _finding_order(finding: Finding) -> tuple[str, str, str]:
    place = finding.location.path if finding.location else "\U0010ffff"
    return (place, finding.rule_id, finding.id)


def _summary(vulnerability: Mapping[str, Any]) -> str | None:
    description = vulnerability.get("description")
    if not isinstance(description, str):
        return None
    line = next((" ".join(text.split()) for text in description.splitlines() if text.strip()), "")
    return line or None


def _title(name: str, summary: str) -> str:
    """`name: summary`, unless the summary already starts with the package name (`urllib3: ...`)."""
    named = re.match(rf"{re.escape(name)}(?![\w.-])", summary, re.IGNORECASE)
    return _clip(summary if named else f"{name}: {summary}", MAX_TITLE)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _finding(fingerprint: str, places: Sequence[_Place], *, run: Run, tool: Tool) -> Finding:
    ordered = sorted(places, key=lambda place: place.order)
    first = ordered[0]
    where = f"Grype match for {first.purl}"
    vulnerability = _object(first.match.get("vulnerability"), f"{where} vulnerability")
    rule_id = _text(vulnerability, "id", where)
    cves: set[str] = set()
    aliases: set[str] = set()
    cwes: set[str] = set()
    for place in ordered:
        _, place_cves, place_aliases = _ids(place.match, where)
        cves.update(place_cves)
        aliases.update(place_aliases)
        cwes.update(_cwes(place.match, where))
    severity, severity_source = _severity(vulnerability, where)
    fixed, state = _fixed_versions(vulnerability, where)
    name, version = str(first.artifact["name"]), str(first.artifact["version"])
    paths = sorted({path for place in ordered for path in place.paths})
    summary = _summary(vulnerability) or rule_id
    fix_text = f"fixed in {', '.join(fixed)}" if fixed else f"no fixed version is known (fix state: {state})"
    try:
        return Finding(
            schema_version="1.1" if len(paths) > 1 else "1.0",
            id=fingerprint,
            tool=tool,
            rule_id=rule_id,
            category=CATEGORY,
            title=_title(name, summary),
            message=_clip(f"{name} {version} is affected by {rule_id}; {fix_text}.", MAX_MESSAGE),
            severity=severity,
            severity_source=severity_source,
            cwe=sorted(cwes, key=lambda cwe: int(cwe.removeprefix("CWE-"))) or None,
            cve=sorted(cves) or None,
            aliases=sorted(aliases) or None,
            location=Location(path=paths[0]) if paths else None,
            other_locations=[Location(path=path) for path in paths[1:]] or None,
            package=Package(
                purl=first.purl,
                name=name,
                version=version,
                ecosystem=first.ecosystem,
                fixed_versions=fixed or None,
            ),
            run=run,
        )
    except ValidationError as exc:
        raise NormalizationError(f"{where} does not fit Finding v1: {exc.errors()[0]['msg']}") from exc
