"""Build an enrichment snapshot from the live feeds (SPEC section 6.1): OSV, FIRST EPSS and CISA KEV.

The only part of enrichment that uses the network. Its output, the snapshot, is what `sentinel enrich` applies
offline and what decisions record by digest, so replay never calls a feed again.

1. OSV (`GET /v1/vulns/{id}`) for every vulnerability id of the package findings (rule_id, cve, aliases), then
   once more for the aliases those records reveal: aliases, CVSS (3.x base score computed from the vector) and
   fixed versions per package. An id OSV does not know (404) is simply absent; a withdrawn record gives
   nothing.
2. The KEV catalogue, filtered to the CVE ids now known; `sources.kev.cves` records them, so "not listed" is
   known only for CVEs that were looked up. The catalogue is checked whole: every entry, its count, its size.
3. EPSS for those CVE ids, 100 per request, only when KEV was read: EPSS alone would lower the risk of a
   vulnerability KEV lists (E = 1.0 for a listed one).

Each feed is all or nothing: if any of its requests fails, or any answer is not what the API documents, that
feed is left out of the snapshot (its values stay unknown, which the risk engine counts as the worst case)
and a warning names it. Responses are untrusted data: they are parsed into fixed fields, every container is
type-checked, and the whole snapshot is validated against its contract before it is written.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any
from urllib.parse import quote

from sentinelci.enrich.apply import canonical_id
from sentinelci.enrich.cvss import base_score
from sentinelci.enrich.models import _PURL_BASE, _RFC3339, _TOKEN, _VULN_ID, load_snapshot
from sentinelci.enrich.transport import Transport, TransportError
from sentinelci.normalize.fingerprint import purl_base

OSV_URL = "https://api.osv.dev/v1/vulns"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH = 100
# The catalogue passed 1,000 entries in 2023 and only grows: fewer means a broken or substituted answer.
MIN_KEV_ENTRIES = 1000
PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DECIMAL = re.compile(r"[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
# OSV ecosystem -> purl type, for affected packages without a purl (OSV names, purl-spec types).
_PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "RubyGems": "gem", "Go": "golang",
               "NuGet": "nuget", "Packagist": "composer", "Pub": "pub", "Hex": "hex"}  # fmt: skip


class FeedError(Exception):
    """A feed answered something its API does not document."""


# What a failed feed looks like: transport errors, undocumented answers, and data of the wrong shape.
FEED_FAILURES = (FeedError, TransportError, ValueError, TypeError, KeyError, AttributeError, RecursionError)


def _json(transport: Transport, url: str) -> Any:
    """The JSON answer, or None for a 404 (an id OSV does not know; for KEV and EPSS, not an object)."""
    status, body = transport.request("GET", url)
    if status == 404:
        return None
    if status != 200:
        raise FeedError(f"HTTP {status} for {url}")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FeedError(f"{url} did not answer JSON") from exc


def _list(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise FeedError(f"{what} is not a list")
    return value


def _dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FeedError(f"{what} is not an object")
    return value


def _ids(findings: Iterable[Mapping[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for f in findings:
        if f.get("category") not in PACKAGE_CATEGORIES:
            continue
        for value in [f.get("rule_id"), *f.get("cve", []), *f.get("aliases", [])]:
            if isinstance(value, str) and _VULN_ID.fullmatch(canonical_id(value)):
                ids.add(canonical_id(value))
    return ids


def _purl_of(package: Mapping[str, Any]) -> str | None:
    purl = package.get("purl")
    if isinstance(purl, str):
        base = purl_base(purl)
    else:
        kind, name = _PURL_TYPES.get(str(package.get("ecosystem"))), package.get("name")
        if kind is None or not isinstance(name, str):
            return None
        if kind == "pypi":  # PEP 503 normalized, as the purl spec asks
            name = re.sub(r"[-_.]+", "-", name).lower()
        base = f"pkg:{kind}/{quote(name, safe='/')}"
    return base if _PURL_BASE.fullmatch(base) else None


def _fixed_versions(record: Mapping[str, Any]) -> dict[str, list[str]] | None:
    """Fixed versions per package, or None when a fix exists that cannot be tied to a package version.

    A fix on a package without a purl (Maven without one, say), or only as a commit (GIT ranges), would make
    every other package of the record look unfixed; leaving the whole map out keeps fix availability unknown.
    """
    fixed: dict[str, set[str]] = {}
    for affected in _list(record.get("affected"), "affected"):
        affected = _dict(affected, "affected entry")
        package = affected.get("package")
        purl = _purl_of(package) if isinstance(package, dict) else None
        versions: set[str] = set()
        unmapped = False
        for rng in _list(affected.get("ranges"), "ranges"):
            rng = _dict(rng, "range")
            for event in _list(rng.get("events"), "events"):
                event = _dict(event, "range event")
                if "fixed" not in event:
                    continue
                version = event["fixed"]
                if (
                    rng.get("type") in ("ECOSYSTEM", "SEMVER")
                    and isinstance(version, str)
                    and _TOKEN.fullmatch(version)
                ):
                    versions.add(version)
                else:
                    unmapped = True  # a commit, or a version this contract cannot hold
        if (versions or unmapped) and (purl is None or not versions):
            return None
        if versions and purl is not None:
            fixed.setdefault(purl, set()).update(versions)
    return {purl: sorted(versions) for purl, versions in sorted(fixed.items())}


def _osv_entry(record: Any, requested: str) -> tuple[dict[str, Any], date]:
    if not isinstance(record, dict) or record.get("id") != requested:
        raise FeedError(f"OSV answered another record for {requested}")
    try:
        modified = datetime.fromisoformat(str(record["modified"]).replace("Z", "+00:00")).date()
    except (KeyError, ValueError) as exc:
        raise FeedError(f"OSV record {requested} has no valid 'modified'") from exc
    entry: dict[str, Any] = {}
    if record.get("withdrawn"):
        return entry, modified  # withdrawn: neither its aliases, CVSS nor fixes count
    named = {canonical_id(a) for a in _list(record.get("aliases"), "aliases") if isinstance(a, str)}
    if aliases := sorted(a for a in named if _VULN_ID.fullmatch(a)):
        entry["aliases"] = aliases
    scored = []
    for severity in _list(record.get("severity"), "severity"):
        severity = _dict(severity, "severity entry")
        vector = severity.get("score")
        if (
            severity.get("type") in ("CVSS_V3", "CVSS_V3.1")
            and isinstance(vector, str)
            and (result := base_score(vector))
        ):
            scored.append((result[1], result[0], vector))
    if scored:
        score, version, vector = max(scored)
        entry["cvss"] = {"version": version, "score": score, "vector": vector}
    fixed = _fixed_versions(record)
    if fixed:
        entry["fixed_versions"] = fixed
    return entry, modified


def _osv(ids: set[str], transport: Transport) -> tuple[dict[str, dict[str, Any]], date | None]:
    entries: dict[str, dict[str, Any]] = {}
    dates: list[date] = []
    asked: set[str] = set()
    for round_ids in (ids, None):  # the finding's ids, then once more for the aliases they reveal
        wanted = sorted(round_ids if round_ids is not None else
                        {a for e in entries.values() for a in e.get("aliases", [])} - asked)  # fmt: skip
        for vuln_id in wanted:
            asked.add(vuln_id)
            record = _json(transport, f"{OSV_URL}/{quote(vuln_id, safe='')}")
            if record is None:
                continue
            entry, modified = _osv_entry(record, vuln_id)
            dates.append(modified)
            if entry:
                entries[vuln_id] = entry
    return entries, max(dates) if dates else None


def _number(value: Any, what: str) -> float:
    """A JSON number, or a plain decimal string as EPSS sends them; never a boolean, padding or '_'."""
    if (isinstance(value, int | float) and not isinstance(value, bool)) or (
        isinstance(value, str) and _DECIMAL.fullmatch(value)
    ):
        try:
            number = float(value)
        except OverflowError as exc:  # a JSON integer with hundreds of digits
            raise FeedError(f"EPSS {what} is too large: {str(value)[:20]}...") from exc
    else:
        raise FeedError(f"EPSS {what} is not a number: {value!r}"[:200])
    if not 0 <= number <= 1:  # also refuses NaN and infinity
        raise FeedError(f"EPSS {what} out of range: {number}")
    return number


def _epss(cves: list[str], transport: Transport) -> tuple[dict[str, dict[str, float]], dict[str, str]]:
    scores: dict[str, dict[str, float]] = {}
    days: set[str] = set()
    versions: set[str] = set()
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start : start + EPSS_BATCH]
        answer = _dict(_json(transport, f"{EPSS_URL}?cve={','.join(batch)}"), "EPSS answer")
        if isinstance(answer.get("model_version"), str):
            versions.add(answer["model_version"])
        for row in _list(answer.get("data"), "EPSS data"):
            if not isinstance(row, dict) or row.get("cve") not in batch:
                raise FeedError(f"EPSS answered for a CVE it was not asked about: {row!r}"[:200])
            value = {"score": _number(row.get("epss"), "score"),
                     "percentile": _number(row.get("percentile"), "percentile")}  # fmt: skip
            if scores.setdefault(row["cve"], value) != value:
                raise FeedError(f"EPSS gave two different answers for {row['cve']}")
            day = row.get("date")
            if not isinstance(day, str) or not _DATE.fullmatch(day):
                raise FeedError(f"EPSS date is not YYYY-MM-DD: {day!r}"[:200])
            days.add(date.fromisoformat(day).isoformat())
    if len(days) > 1:
        raise FeedError(f"EPSS answers mix several days: {sorted(days)}")
    source: dict[str, str] = {}
    if days:
        source["date"] = days.pop()
    if len(versions) == 1 and _TOKEN.fullmatch(next(iter(versions))):
        source["model_version"] = versions.pop()
    return scores, source


def _kev(cves: set[str], transport: Transport) -> tuple[dict[str, str], dict[str, Any]]:
    catalogue = _dict(_json(transport, KEV_URL), "KEV catalogue")
    entries = catalogue.get("vulnerabilities")
    if not isinstance(entries, list):
        raise FeedError("KEV catalogue has no vulnerabilities list")
    version = catalogue.get("catalogVersion")
    if not isinstance(version, str) or not _TOKEN.fullmatch(version):
        raise FeedError("KEV catalogue has no valid catalogVersion")
    count = catalogue.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count != len(entries):
        raise FeedError(f"KEV catalogue count {count!r} does not match its {len(entries)} entries")
    if len(entries) < MIN_KEV_ENTRIES:
        raise FeedError(
            f"KEV catalogue has only {len(entries)} entries (at least {MIN_KEV_ENTRIES} expected)"
        )
    listed: dict[str, str] = {}
    for entry in entries:  # all or nothing: one malformed entry and nothing in the catalogue is trusted
        entry = _dict(entry, "KEV entry")
        cve, added = entry.get("cveID"), entry.get("dateAdded")
        if not isinstance(cve, str) or not _CVE.fullmatch(cve):
            raise FeedError(f"KEV entry with an invalid cveID: {cve!r}"[:200])
        if not isinstance(added, str) or not _DATE.fullmatch(added):
            raise FeedError(f"KEV entry {cve} with an invalid dateAdded: {added!r}"[:200])
        added = date.fromisoformat(added).isoformat()
        if cve in cves:
            listed[cve] = added
    source: dict[str, Any] = {"catalog_version": version, "cves": sorted(cves)}  # what KEV now covers
    released = catalogue.get("dateReleased")
    if isinstance(released, str) and _RFC3339.fullmatch(released):  # optional: RFC 3339 with an offset only
        try:
            datetime.fromisoformat(re.sub(r"[Zz]$", "+00:00", released))
            source["date_released"] = released
        except ValueError:
            pass
    return listed, source


def build_snapshot(
    findings: Iterable[Mapping[str, Any]], transport: Transport
) -> tuple[dict[str, Any], list[str]]:
    """Return (snapshot document, warnings). A feed that fails is left out and named in the warnings."""
    findings = list(findings)
    ids = _ids(findings)
    vulnerabilities: dict[str, dict[str, Any]] = {}
    sources: dict[str, Any] = {}
    warnings: list[str] = []

    osv_read = False
    try:
        osv_entries, osv_date = _osv(ids, transport) if ids else ({}, None)
        vulnerabilities.update(osv_entries)
        if osv_date is not None:
            sources["osv"] = {"date": osv_date.isoformat()}
        osv_read = True
    except FEED_FAILURES as exc:
        warnings.append(f"OSV left out: {exc}")

    cves = sorted({i for i in ids | {a for e in vulnerabilities.values() for a in e.get("aliases", [])}
                   if _CVE.fullmatch(i)})  # fmt: skip
    if cves and not osv_read:
        # Without OSV the aliases are unknown: KEV could say "not listed" for a finding whose listed CVE
        # only OSV links to it, and EPSS would score the wrong CVE. Both stay unknown (the worst case).
        warnings.append(
            "KEV and EPSS left out: without OSV the findings' aliases are unknown, and a CVE only OSV "
            "links to a finding may be the one KEV lists"
        )
    elif cves:
        kev_read = False
        try:
            listed, kev_source = _kev(set(cves), transport)
            sources["kev"] = kev_source
            for cve, added in listed.items():
                vulnerabilities.setdefault(cve, {})["kev"] = {"date_added": added}
            kev_read = True
        except FEED_FAILURES as exc:
            warnings.append(f"KEV left out: {exc}")
        if not kev_read:
            warnings.append(
                "EPSS left out: without KEV, EPSS alone would lower the risk of a listed vulnerability"
            )
        else:
            try:
                scores, epss_source = _epss(cves, transport)
                if scores and "date" in epss_source:
                    sources["epss"] = epss_source
                    for cve, value in scores.items():
                        vulnerabilities.setdefault(cve, {})["epss"] = value
            except FEED_FAILURES as exc:
                warnings.append(f"EPSS left out: {exc}")

    document = {
        "schema_version": "1.0",
        "sources": dict(sorted(sources.items())),
        "vulnerabilities": {k: v for k, v in sorted(vulnerabilities.items()) if v},
    }
    load_snapshot(dumps_snapshot(document))  # the contract, before anything is written
    return document, warnings


def dumps_snapshot(document: Mapping[str, Any]) -> bytes:
    """Canonical bytes: the same feeds give the same snapshot, so the same digest."""
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
