"""Apply an enrichment snapshot and the service context to a finding (SPEC section 6.1), offline.

Only what a source actually said is written; anything unknown stays absent, and the risk engine (B3)
treats absent as the worst case. Package findings (SCA, CONTAINER) get CVSS, EPSS, KEV and fix availability
from the snapshot entries of their ids (rule_id, cve, aliases, and the aliases of those entries); every
finding gets the exposure of its component from `sentinel.yaml`.

- cvss / epss: the highest score / percentile among the matched entries (ties: the smallest id), so the result
  never depends on dictionary order.
- kev: listed if any matched id is in the catalogue; `listed: false` only when the KEV source was read.
- fix_available: true if the finding lists fixed versions or a matched OSV entry fixes its package; false only
  when a matched OSV entry exists and fixes none of it; absent otherwise.
- reachability: from the static import analysis of the source trees (enrich/reachability.py), when given.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from sentinelci.enrich.models import ServiceContext, Snapshot, Vulnerability
from sentinelci.enrich.reachability import Reachability
from sentinelci.normalize.fingerprint import purl_base

PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
MANAGED = ("cvss", "epss", "kev", "fix_available", "exposure", "reachability")


def _matched(finding: Mapping[str, Any], snapshot: Snapshot) -> dict[str, Vulnerability]:
    """Snapshot entries for the finding's ids, following one level of aliases (GHSA -> CVE for EPSS)."""
    ids = {finding.get("rule_id"), *finding.get("cve", []), *finding.get("aliases", [])}
    entries = {
        i: snapshot.vulnerabilities[i] for i in ids if isinstance(i, str) and i in snapshot.vulnerabilities
    }
    for entry in list(entries.values()):
        for alias in entry.aliases or []:
            if alias in snapshot.vulnerabilities:
                entries.setdefault(alias, snapshot.vulnerabilities[alias])
    return dict(sorted(entries.items()))


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
        out["kev"] = {"listed": True, "date_added": added[0].isoformat()} if added else {"listed": False}
    raw_package = finding.get("package")
    package: Mapping[str, Any] = raw_package if isinstance(raw_package, Mapping) else {}
    purl = package.get("purl")
    base = purl_base(purl) if isinstance(purl, str) else None
    osv_entries = [e for e in entries.values() if e.fixed_versions is not None]
    if package.get("fixed_versions") or any((e.fixed_versions or {}).get(base or "") for e in osv_entries):
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
    finding: Mapping[str, Any],
    snapshot: Snapshot,
    context: ServiceContext | None,
    reachability: Reachability | None = None,
) -> dict[str, Any]:
    """Return a copy of the finding with the enrichment these sources support (idempotent)."""
    result = copy.deepcopy(dict(finding))
    enrichment = {k: v for k, v in (result.get("enrichment") or {}).items() if k not in MANAGED}
    if result.get("category") in PACKAGE_CATEGORIES:
        enrichment.update(_package_enrichment(result, snapshot))
    if context is not None:
        enrichment["exposure"] = _exposure(result, context)
    reached = reachability.classify(result) if reachability is not None else None
    if reached is not None:
        enrichment["reachability"] = reached
    if enrichment:
        result["enrichment"] = dict(sorted(enrichment.items()))
    else:
        result.pop("enrichment", None)
    return result
