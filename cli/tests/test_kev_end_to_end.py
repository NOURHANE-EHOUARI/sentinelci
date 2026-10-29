"""End to end, fetchers (B2) -> enrich (B2) -> score (B3): a KEV problem never lowers a risk score.

Found by Nourhane in the reviews of #16, #17 and #18: with the KEV feed down but EPSS up, a KEV-listed
CRITICAL finding went from 100 P0 to 46 P2. Each module now has its own guard (score: E < 1 only when KEV says
"not listed"; apply: "not listed" only for covered CVEs; fetchers: no EPSS without KEV). This checks the whole
chain, so no future change to one guard can quietly rely on another.
"""

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from sentinelci.enrich import enrich_finding, load_service_context, load_snapshot
from sentinelci.enrich.fetch import (
    EPSS_URL,
    KEV_URL,
    MIN_KEV_ENTRIES,
    OSV_URL,
    build_snapshot,
    dumps_snapshot,
)
from sentinelci.risk.model import RiskModel, score_finding

ROOT = Path(__file__).resolve().parents[2]
MODEL = RiskModel.load(ROOT / "policies" / "risk-model.yaml")
FIXTURES = ROOT / "schemas" / "fixtures"
SNAPSHOTS = sorted((FIXTURES / "enrichment-snapshot" / "valid").glob("*.json"))
PACKAGE_FINDINGS = [
    {k: v for k, v in json.loads(p.read_text(encoding="utf-8")).items() if k not in ("enrichment", "risk")}
    for p in sorted((FIXTURES / "finding" / "valid").glob("*.json"))
    if json.loads(p.read_text(encoding="utf-8"))["category"] in ("SCA", "CONTAINER")
]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
EXPOSURES = ["internet-facing", "internal", "offline"]


def score(finding: dict[str, Any], snapshot: bytes, exposure: str) -> float:
    context = load_service_context(f"version: 1\nservice: demo\nexposure: {exposure}\n".encode())
    enriched = enrich_finding(finding, load_snapshot(snapshot), context)
    return float(score_finding(enriched, MODEL)["risk"]["score"])


def uncovered(snapshot: bytes) -> bytes:
    """KEV was read, but for other CVEs: the finding's KEV status is unknown, not "not listed"."""
    document = json.loads(snapshot)
    if "kev" not in document["sources"]:
        return snapshot
    document["sources"]["kev"]["cves"] = []
    for entry in document["vulnerabilities"].values():
        entry.pop("kev", None)
    document["vulnerabilities"] = {k: v for k, v in document["vulnerabilities"].items() if v}
    return json.dumps(document).encode("utf-8")


def without(snapshot: bytes, *sources: str) -> bytes:
    """The same snapshot as if these feeds had been down: no source, and none of their values."""
    document = json.loads(snapshot)
    for source in sources:
        document["sources"].pop(source, None)
        for entry in document["vulnerabilities"].values():
            entry.pop(source, None)
    document["vulnerabilities"] = {k: v for k, v in document["vulnerabilities"].items() if v}
    return json.dumps(document).encode("utf-8")


@pytest.mark.parametrize("path", SNAPSHOTS, ids=lambda p: p.stem)
@pytest.mark.parametrize(
    ("finding", "severity", "exposure"),
    list(itertools.product(PACKAGE_FINDINGS, SEVERITIES, EXPOSURES)),
    ids=lambda v: v["id"][:8] if isinstance(v, dict) else str(v),
)
def test_a_kev_outage_never_lowers_a_score(
    path: Path, finding: dict[str, Any], severity: str, exposure: str
) -> None:
    finding = {**finding, "severity": severity}
    read = score(finding, path.read_bytes(), exposure)
    kev_down = score(finding, without(path.read_bytes(), "kev"), exposure)  # EPSS still there (#16's guard)
    both_down = score(finding, without(path.read_bytes(), "kev", "epss"), exposure)  # what #18 writes
    not_covered = score(finding, uncovered(path.read_bytes()), exposure)  # #17's guard
    assert kev_down >= read
    assert both_down >= read
    assert not_covered >= read
    assert kev_down == both_down == not_covered, "with KEV unknown, EPSS must not matter"


# ---------------------------------------------------------------- through the real fetchers


CVE = "CVE-2099-1001"
FINDING = {
    **PACKAGE_FINDINGS[0],
    "category": "SCA",
    "severity": "CRITICAL",
    "rule_id": "GHSA-aaaa-bbbb-cccc",
    "cve": [],
    "aliases": [],
    "package": {
        "purl": "pkg:pypi/example-lib@1.2.0",
        "name": "example-lib",
        "version": "1.2.0",
        "ecosystem": "pypi",
    },
}
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
OSV = {"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-11-09T12:00:00Z", "aliases": [CVE],
       "severity": [{"type": "CVSS_V3", "score": VECTOR}]}  # fmt: skip
EPSS = {"status": "OK", "data": [{"cve": CVE, "epss": "0.001", "percentile": "0.10", "date": "2026-11-10"}]}
FILLER = [{"cveID": f"CVE-2000-{n:05d}", "dateAdded": "2020-01-01"} for n in range(MIN_KEV_ENTRIES)]


def kev(*listed: str) -> dict[str, Any]:
    entries = [*FILLER, *({"cveID": c, "dateAdded": "2026-10-01"} for c in listed)]
    return {"catalogVersion": "2026.11.09", "count": len(entries), "vulnerabilities": entries}


class Feeds:
    def __init__(self, kev_answer: tuple[int, Any]) -> None:
        self.answers = {
            f"{OSV_URL}/GHSA-aaaa-bbbb-cccc": (200, OSV),
            f"{EPSS_URL}?cve={CVE}": (200, EPSS),
            KEV_URL: kev_answer,
        }

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        status, payload = self.answers.get(url, (404, {}))
        return status, payload if isinstance(payload, bytes) else json.dumps(payload).encode()


def fetched_score(kev_answer: tuple[int, Any]) -> float:
    document, _ = build_snapshot([FINDING], Feeds(kev_answer))
    return score(FINDING, dumps_snapshot(document), "internet-facing")


def test_nourhanes_table_end_to_end() -> None:
    # CRITICAL SCA, internet-facing, EPSS percentile 0.10, R not analysed (1.0).
    worst = 100.0
    assert fetched_score((200, kev(CVE))) == worst, "KEV-listed: E = 1.0"
    assert fetched_score((403, b"Forbidden")) == worst, "KEV down"
    renamed = {**kev(CVE), "vulnerabilities": [{"cveId": CVE, "dateAdded": "2026-10-01"}, *FILLER]}
    assert fetched_score((200, renamed)) == worst, "KEV field renamed"
    assert fetched_score((200, {**kev(), "vulnerabilities": [], "count": 0})) == worst, "KEV empty"
    assert fetched_score((200, kev())) == pytest.approx(46.0), (
        "the one allowed decrease: KEV read, not listed"
    )
