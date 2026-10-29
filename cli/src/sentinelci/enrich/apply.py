"""Apply an enrichment snapshot and the service context to a finding (SPEC section 6.1), offline.

Only what a source actually said is written; anything unknown stays absent, and the risk engine (B3)
treats absent as the worst case. Package findings (SCA, CONTAINER) get CVSS, EPSS, KEV and fix availability
from the snapshot entries of their ids (rule_id, cve, aliases, and the aliases of those entries); every
finding gets the exposure of its component from `sentinel.yaml`.

- matched entries: the finding's ids and every alias reachable from them in the snapshot (the alias closure).
- cvss / epss: the highest score / percentile among the matched entries (ties: the smallest id), so the result
  never depends on dictionary order.
- kev: listed if any matched id is in the catalogue; `listed: false` only when the KEV source was read and
  covered every CVE id of the finding (sources.kev.cves). A finding with no CVE id, or a CVE the KEV lookup
  never covered, keeps an unknown KEV status, which the risk engine counts as the worst case.
- fix_available: true if the finding lists fixed versions or a matched OSV entry fixes its package; false only
  when a matched OSV entry exists and fixes none of it; absent otherwise. Package URLs are compared in their
  canonical form (PyPI names normalized as PEP 503 says), so a spelling difference never reads as "no fix".
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from typing import Any

from sentinelci.enrich.models import ServiceContext, Snapshot, Vulnerability
from sentinelci.normalize.fingerprint import purl_base

PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
MANAGED = ("cvss", "epss", "kev", "fix_available", "exposure")


def finding_ids(finding: Mapping[str, Any]) -> set[str]:
    """The finding's vulnerability ids (rule_id, cve, aliases), CVE ids in their canonical upper case."""
    ids = {finding.get("rule_id"), *finding.get("cve", []), *finding.get("aliases", [])}
    return {i.upper() if _CVE.fullmatch(i.upper()) else i for i in ids if isinstance(i, str)}


def _matched(finding: Mapping[str, Any], snapshot: Snapshot) -> dict[str, Vulnerability]:
    """Snapshot entries for the finding's ids and every alias reachable from them (PYSEC -> GHSA -> CVE)."""
    entries = {i: snapshot.vulnerabilities[i] for i in finding_ids(finding) if i in snapshot.vulnerabilities}
    pending = list(entries.values())
    while pending:  # the alias closure: the fetchers follow aliases more than one level deep
        for alias in pending.pop().aliases or []:
            if alias in snapshot.vulnerabilities and alias not in entries:
                entries[alias] = snapshot.vulnerabilities[alias]
                pending.append(entries[alias])
    return dict(sorted(entries.items()))


def canonical_purl(base: str) -> str:
    """A purl base in canonical form: the purl spec lowercases PyPI names and folds runs of -_. into one -."""
    kind, _, name = base.partition("/")
    if kind == "pkg:pypi":
        return f"{kind}/{re.sub(r'[-_.]+', '-', name).lower()}"
    return base


def _cve_ids(finding: Mapping[str, Any], entries: Mapping[str, Vulnerability]) -> set[str]:
    ids = finding_ids(finding) | set(entries)
    ids.update(alias for entry in entries.values() for alias in entry.aliases or [])
    return {i for i in ids if isinstance(i, str) and _CVE.fullmatch(i)}


def _package_enrichment(finding: Mapping[str, Any], snapshot: Snapshot) -> dict[str, Any]:
    entries = _matched(finding, snapshot)
    out: dict[str, Any] = {}
    cvss = [(-e.cvss.score, i, e.cvss) for i, e in entries.items() if e.cvss]
    if cvss:
        out["cvss"] = min(cvss, key=lambda c: (c[0], c[1]))[2].model_dump(exclude_none=True)
    epss = [(-e.epss.percentile, i, e.epss) for i, e in entries.items() if e.epss]
    if epss and snapshot.sources.epss is not None:
        best = min(epss, key=lambda c: (c[0], c[1]))[2]
        out["epss"] = {
            "score": best.score,
            "percentile": best.percentile,
            "date": snapshot.sources.epss.date.isoformat(),
        }
    if snapshot.sources.kev is not None:
        added = sorted(e.kev.date_added for e in entries.values() if e.kev)
        cves = _cve_ids(finding, entries)
        if added:
            out["kev"] = {"listed": True, "date_added": added[0].isoformat()}
        elif cves and cves <= set(snapshot.sources.kev.cves):  # "not listed" only for what KEV covered
            out["kev"] = {"listed": False}
    raw_package = finding.get("package")
    package: Mapping[str, Any] = raw_package if isinstance(raw_package, Mapping) else {}
    purl = package.get("purl")
    base = canonical_purl(purl_base(purl)) if isinstance(purl, str) else None
    osv_entries = [e for e in entries.values() if e.fixed_versions is not None]
    fixed = [
        versions
        for e in osv_entries
        for key, versions in (e.fixed_versions or {}).items()
        if canonical_purl(key) == base
    ]
    if package.get("fixed_versions") or any(fixed):
        out["fix_available"] = True
    elif osv_entries and snapshot.sources.osv is not None:
        out["fix_available"] = False
    return out


def _within(path: str, component: str) -> bool:
    return path == component or path.startswith(component.rstrip("/") + "/")


def _exposure(finding: Mapping[str, Any], context: ServiceContext) -> str:
    location = finding.get("location")
    path = location.get("path") if isinstance(location, Mapping) else None
    exposure: str = context.exposure
    if isinstance(path, str):
        matches = [c for c in context.components or [] if c.exposure is not None and _within(path, c.path)]
        if matches:
            best = max(matches, key=lambda c: len(c.path.rstrip("/")))
            exposure = best.exposure or exposure
    return exposure


def enrich_finding(
    finding: Mapping[str, Any], snapshot: Snapshot, context: ServiceContext | None
) -> dict[str, Any]:
    """Return a copy of the finding with the enrichment this snapshot and context support (idempotent)."""
    result = copy.deepcopy(dict(finding))
    enrichment = {k: v for k, v in (result.get("enrichment") or {}).items() if k not in MANAGED}
    if result.get("category") in PACKAGE_CATEGORIES:
        enrichment.update(_package_enrichment(result, snapshot))
    if context is not None:
        enrichment["exposure"] = _exposure(result, context)
    if enrichment:
        result["enrichment"] = dict(sorted(enrichment.items()))
    else:
        result.pop("enrichment", None)
    return result
