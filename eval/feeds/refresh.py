"""Offline feed fixtures (SPEC section 6.1): recorded OSV, FIRST EPSS and CISA KEV answers for fixed findings.

`sentinel snapshot --offline eval/feeds/recordings` rebuilds `eval/feeds/snapshot.json` byte for byte, with
no network: demos, the evaluation (B8) and tests use real feed data without depending on the feeds being up,
and every run of them reads the same answers. The findings are real, well-known vulnerable packages chosen for
what they exercise, and each case states it, so a refresh that silently stops covering, say, a KEV-listed CVE
or an alias chain fails here instead of passing with weaker fixtures.

Refresh (needs the network; review the diff like any other evidence input):
    uv run python eval/feeds/refresh.py
Check (offline, also run by the tests):
    uv run python eval/feeds/refresh.py --check

Owner: Track B (B2, B8).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.contracts.finding import Finding
from sentinelci.enrich import enrich_finding, load_snapshot
from sentinelci.enrich.fetch import build_snapshot, dumps_snapshot
from sentinelci.enrich.transport import HttpTransport, RecordingTransport, ReplayTransport, Transport
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.normalize.ndjson import dumps_ndjson

HERE = Path(__file__).resolve().parent
FINDINGS = HERE / "findings.ndjson"
RECORDINGS = HERE / "recordings"
SNAPSHOT = HERE / "snapshot.json"
REPO = "NOURHANE-EHOUARI/sentinelci"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@dataclass(frozen=True)
class Case:
    rule_id: str
    purl: str
    severity: str
    manifest: str
    covers: str
    kev: bool  # listed in CISA KEV
    epss: bool = True  # EPSS knows the CVE
    cve: tuple[str, ...] = ()


CASES = (
    Case("GHSA-jfh8-c2jp-5v3q", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "CRITICAL", "pom.xml",
         "KEV-listed, CVSS 10.0 reached from a GHSA id through its CVE alias (Log4Shell)", kev=True),
    Case("GHSA-36p3-wjmg-h94x", "pkg:maven/org.springframework/spring-beans@5.3.17", "CRITICAL", "pom.xml",
         "KEV-listed, a second ecosystem path (Spring4Shell)", kev=True),
    Case("PYSEC-2021-19", "pkg:pypi/lxml@4.6.2", "MEDIUM", "requirements.txt",
         "a PYSEC id whose CVSS and EPSS come only through its aliases", kev=False),
    Case("GHSA-8q59-q68h-6hv4", "pkg:pypi/pyyaml@5.3.1", "CRITICAL", "requirements.txt",
         "a CRITICAL PyPI vulnerability that KEV does not list (KEV covered, not listed)", kev=False),
    Case("GHSA-j8r2-6x86-q33q", "pkg:pypi/requests@2.30.0", "MEDIUM", "requirements.txt",
         "a medium PyPI vulnerability with a known fix", kev=False),
    Case("GHSA-35jh-r3h4-6jhm", "pkg:npm/lodash@4.17.20", "HIGH", "package-lock.json",
         "an npm vulnerability (lodash command injection)", kev=False),
    Case("GHSA-xvch-5gv4-984h", "pkg:npm/minimist@1.2.5", "CRITICAL", "package-lock.json",
         "a CRITICAL npm vulnerability that KEV does not list", kev=False),
)  # fmt: skip


def finding(case: Case) -> dict[str, Any]:
    kind, _, rest = case.purl.partition(":")[2].partition("/")
    name, _, version = rest.rpartition("@")
    return {
        "schema_version": "1.0",
        "id": package_fingerprint("SCA", case.rule_id, case.purl),
        "tool": {"name": "grype", "version": "0.92.0"},
        "rule_id": case.rule_id,
        "category": "SCA",
        "title": f"{name.rsplit('/', 1)[-1]} {version}: {case.rule_id}",
        "severity": case.severity,
        "cve": list(case.cve),
        "aliases": [],
        "location": {"path": case.manifest},
        "package": {"purl": case.purl, "name": name, "version": version, "ecosystem": kind},
        "run": {"repo": REPO, "commit": COMMIT, "context": "release"},
    }


def findings() -> list[dict[str, Any]]:
    return sorted((finding(c) for c in CASES), key=lambda f: f["id"])


def check_coverage(snapshot: bytes) -> list[str]:
    """What the fixtures exist to cover, checked on the enriched findings: [] when everything holds."""
    loaded = load_snapshot(snapshot)
    problems = [f"source {s} missing" for s in ("osv", "epss", "kev") if getattr(loaded.sources, s) is None]
    for case in CASES:
        enrichment = enrich_finding(finding(case), loaded, None).get("enrichment", {})
        listed = enrichment.get("kev", {}).get("listed")
        if listed is not case.kev:
            problems.append(f"{case.rule_id}: KEV listed is {listed}, expected {case.kev} ({case.covers})")
        if case.epss and "epss" not in enrichment:
            problems.append(f"{case.rule_id}: no EPSS ({case.covers})")
        if "cvss" not in enrichment:
            problems.append(f"{case.rule_id}: no CVSS ({case.covers})")
    return problems


def replay() -> bytes:
    document, warnings = build_snapshot(findings(), ReplayTransport(RECORDINGS))
    if warnings:
        raise SystemExit("offline replay is incomplete:\n  " + "\n  ".join(warnings))
    return dumps_snapshot(document)


def refresh(transport: Transport | None = None, here: Path = HERE) -> None:
    """Re-record every feed answer, then swap the new set in. Nothing changes unless every feed answered:
    the recordings go to a staging directory first, so a failed refresh never leaves a partial set."""
    recordings, staging, old = here / "recordings", here / "recordings.new", here / "recordings.old"
    shutil.rmtree(staging, ignore_errors=True)
    document, warnings = build_snapshot(findings(), RecordingTransport(transport or HttpTransport(), staging))
    if warnings:
        shutil.rmtree(staging, ignore_errors=True)
        raise SystemExit("a feed failed, fixtures not refreshed:\n  " + "\n  ".join(warnings))
    shutil.rmtree(old, ignore_errors=True)
    if recordings.exists():
        recordings.rename(old)
    staging.rename(recordings)  # no stale recording survives a refresh
    shutil.rmtree(old, ignore_errors=True)
    (here / "findings.ndjson").write_text(
        dumps_ndjson(Finding.model_validate(f) for f in findings()), encoding="utf-8"
    )
    (here / "snapshot.json").write_bytes(dumps_snapshot(document))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="offline: replay and compare, no network")
    args = parser.parse_args()
    if not args.check:
        refresh()
    replayed = replay()
    problems = [] if replayed == SNAPSHOT.read_bytes() else ["offline replay differs from snapshot.json"]
    problems += check_coverage(replayed)
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        size = sum(p.stat().st_size for p in RECORDINGS.glob("*.json"))
        print(f"{len(CASES)} findings, {len(list(RECORDINGS.glob('*.json')))} recordings ({size} bytes): ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
