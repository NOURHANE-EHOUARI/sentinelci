"""Build an enrichment snapshot from the live feeds (SPEC section 6.1): OSV, FIRST EPSS and CISA KEV.

The only part of enrichment that uses the network. Its output, the snapshot, is what `sentinel enrich` applies
offline and what decisions record by digest, so replay never calls a feed again.

1. OSV (`GET /v1/vulns/{id}`) for every vulnerability id of the package findings (rule_id, cve, aliases), then
   once more for the aliases those records reveal: aliases, CVSS (3.x base score computed from the vector) and
   fixed versions per package. An id OSV does not know (404) is simply absent.
2. EPSS for every CVE id now known, 100 per request.
3. The KEV catalogue, filtered to those CVE ids; `sources.kev.cves` records them, so "not listed" is known
   only for CVEs that were looked up.

Each feed is all or nothing: if any of its requests fails, or any answer is not what the API documents, that
feed is left out of the snapshot (its values stay unknown, which the risk engine counts as the worst case)
and a warning names it. Responses are untrusted data: they are parsed into fixed fields and the whole
snapshot is validated against its contract before it is written.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any
from urllib.parse import quote

from sentinelci.enrich.cvss import base_score
from sentinelci.enrich.models import _PURL_BASE, _TOKEN, _VULN_ID, load_snapshot
from sentinelci.enrich.transport import Transport, TransportError
from sentinelci.normalize.fingerprint import purl_base

OSV_URL = "https://api.osv.dev/v1/vulns"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH = 100
PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
# OSV ecosystem -> purl type, for affected packages without a purl (OSV names, purl-spec types).
_PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "RubyGems": "gem", "Go": "golang",
               "NuGet": "nuget", "Packagist": "composer", "Pub": "pub", "Hex": "hex"}  # fmt: skip


class FeedError(Exception):
    """A feed answered something its API does not document."""


def _json(transport: Transport, url: str, missing_ok: bool = False) -> Any:
    status, body = transport.request("GET", url)
    if missing_ok and status == 404:
        return None
    if status != 200:
        raise FeedError(f"HTTP {status} for {url}")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FeedError(f"{url} did not answer JSON") from exc


def _ids(findings: Iterable[Mapping[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for f in findings:
        if f.get("category") not in PACKAGE_CATEGORIES:
            continue
        for value in [f.get("rule_id"), *f.get("cve", []), *f.get("aliases", [])]:
            if isinstance(value, str) and _VULN_ID.fullmatch(value):
                ids.add(value)
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


def _osv_entry(record: Any, requested: str) -> tuple[dict[str, Any], date]:
    if not isinstance(record, dict) or record.get("id") != requested:
        raise FeedError(f"OSV answered another record for {requested}")
    try:
        modified = datetime.fromisoformat(str(record["modified"]).replace("Z", "+00:00")).date()
    except (KeyError, ValueError) as exc:
        raise FeedError(f"OSV record {requested} has no valid 'modified'") from exc
    entry: dict[str, Any] = {}
    aliases = sorted({a for a in record.get("aliases") or [] if isinstance(a, str) and _VULN_ID.fullmatch(a)})
    if aliases:
        entry["aliases"] = aliases
    scored = [
        (score, version, s["score"])
        for s in record.get("severity") or []
        if isinstance(s, dict)
        and s.get("type") in ("CVSS_V3", "CVSS_V3.1")
        and isinstance(s.get("score"), str)
        for version, score in [base_score(s["score"]) or (None, None)]
        if score is not None
    ]
    if scored:
        score, version, vector = max(scored)
        entry["cvss"] = {"version": version, "score": score, "vector": vector}
    fixed: dict[str, set[str]] = {}
    for affected in record.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        purl = _purl_of(package) if isinstance(package, dict) else None
        if purl is None:
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges name commits, not versions
            for event in rng.get("events") or []:
                version = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(version, str) and _TOKEN.fullmatch(version):
                    fixed.setdefault(purl, set()).add(version)
    if fixed:
        entry["fixed_versions"] = {purl: sorted(versions) for purl, versions in sorted(fixed.items())}
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
            record = _json(transport, f"{OSV_URL}/{quote(vuln_id, safe='')}", missing_ok=True)
            if record is None:
                continue
            entry, modified = _osv_entry(record, vuln_id)
            dates.append(modified)
            if entry:
                entries[vuln_id] = entry
    return entries, max(dates) if dates else None


def _number(value: Any, what: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise FeedError(f"EPSS {what} is not a number: {value!r}") from exc
    if not 0 <= number <= 1:
        raise FeedError(f"EPSS {what} out of range: {number}")
    return number


def _epss(cves: list[str], transport: Transport) -> tuple[dict[str, dict[str, float]], dict[str, str]]:
    scores: dict[str, dict[str, float]] = {}
    days: set[str] = set()
    versions: set[str] = set()
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start : start + EPSS_BATCH]
        answer = _json(transport, f"{EPSS_URL}?cve={','.join(batch)}")
        if not isinstance(answer, dict) or not isinstance(answer.get("data"), list):
            raise FeedError("EPSS answer has no data list")
        if isinstance(answer.get("model_version"), str):
            versions.add(answer["model_version"])
        for row in answer["data"]:
            if not isinstance(row, dict) or row.get("cve") not in batch:
                raise FeedError(f"EPSS answered for a CVE it was not asked about: {row!r}"[:200])
            scores[row["cve"]] = {"score": _number(row.get("epss"), "score"),
                                  "percentile": _number(row.get("percentile"), "percentile")}  # fmt: skip
            days.add(str(row.get("date")))
    if len(days) > 1:
        raise FeedError(f"EPSS answers mix several days: {sorted(days)}")
    source: dict[str, str] = {}
    if days:
        source["date"] = date.fromisoformat(days.pop()).isoformat()
    if len(versions) == 1 and _TOKEN.fullmatch(next(iter(versions))):
        source["model_version"] = versions.pop()
    return scores, source


def _kev(cves: set[str], transport: Transport) -> tuple[dict[str, str], dict[str, Any]]:
    catalogue = _json(transport, KEV_URL)
    if not isinstance(catalogue, dict) or not isinstance(catalogue.get("vulnerabilities"), list):
        raise FeedError("KEV catalogue has no vulnerabilities list")
    version = catalogue.get("catalogVersion")
    if not isinstance(version, str) or not _TOKEN.fullmatch(version):
        raise FeedError("KEV catalogue has no valid catalogVersion")
    source: dict[str, Any] = {"catalog_version": version, "cves": sorted(cves)}  # what KEV now covers
    released = catalogue.get("dateReleased")
    if isinstance(released, str):  # optional: kept only as an RFC 3339 time with an offset
        try:
            if datetime.fromisoformat(released.replace("Z", "+00:00")).tzinfo is not None:
                source["date_released"] = released
        except ValueError:
            pass
    listed: dict[str, str] = {}
    for entry in catalogue["vulnerabilities"]:
        cve = entry.get("cveID") if isinstance(entry, dict) else None
        if cve in cves:
            listed[cve] = date.fromisoformat(str(entry.get("dateAdded"))).isoformat()
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

    try:
        osv_entries, osv_date = _osv(ids, transport) if ids else ({}, None)
        vulnerabilities.update(osv_entries)
        if osv_date is not None:
            sources["osv"] = {"date": osv_date.isoformat()}
    except (FeedError, TransportError, ValueError) as exc:
        warnings.append(f"OSV left out: {exc}")

    cves = sorted({i for i in ids | {a for e in vulnerabilities.values() for a in e.get("aliases", [])}
                   if _CVE.fullmatch(i)})  # fmt: skip
    if cves:
        try:
            scores, epss_source = _epss(cves, transport)
            if scores and "date" in epss_source:
                sources["epss"] = epss_source
                for cve, value in scores.items():
                    vulnerabilities.setdefault(cve, {})["epss"] = value
        except (FeedError, TransportError, ValueError) as exc:
            warnings.append(f"EPSS left out: {exc}")
        try:
            listed, kev_source = _kev(set(cves), transport)
            sources["kev"] = kev_source
            for cve, added in listed.items():
                vulnerabilities.setdefault(cve, {})["kev"] = {"date_added": added}
        except (FeedError, TransportError, ValueError) as exc:
            warnings.append(f"KEV left out: {exc}")

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
