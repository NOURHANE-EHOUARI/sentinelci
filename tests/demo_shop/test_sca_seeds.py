"""The SCA seeds of demo-shop (A9): eight known-vulnerable dependencies whose advisories the offline feed
fixtures (eval/feeds) cover, so enrichment, scoring and the gate run on them with no network.

Always (no network, no vulnerability database):
- each seed's manifest declares exactly its package and version, at its line (and the npm lockfile pins it);
- the eval/feeds snapshot covers each seed, and the recorded OSV advisory of its id lists its version;
- enrichment gives each seed its CVSS and the KEV status the ground truth states;
- a dependency the ground truth says is never imported is never classified `imported` (B2's reachability);
- with OPA: each seed's gate rule is the one the engine gives with the feed fixtures.

With the pinned tools (SENTINEL_TOOLS_DIR): Syft catalogs each seed's purl from its service. With a Grype
database as well (SENTINEL_GRYPE_DB_DIR, a GRYPE_DB_CACHE_DIR filled by `grype db update`): Grype, on that
SBOM, reports each seed's id, as the pipeline runs it (SPEC section 5, stage 3).
"""

import base64
import gzip
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.enrich import enrich_finding, load_snapshot
from sentinelci.enrich.reachability import Reachability
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.decision import Subject, evaluate
from sentinelci.policy.opa import OpaError, OpaRunner
from sentinelci.risk.model import RiskModel, score_finding
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-shop"
FEEDS = ROOT / "eval" / "feeds"
TRUTH: dict[str, Any] = yaml.safe_load((DEMO / "ground-truth" / "findings.yaml").read_text(encoding="utf-8"))
SEEDS = [seed for seed in TRUTH["seeds"] if seed["category"] == "SCA"]
SNAPSHOT = (FEEDS / "snapshot.json").read_bytes()
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
PURL = re.compile(
    r"^pkg:(?P<type>pypi|npm|maven)/(?:(?P<namespace>[^/@]+)/)?(?P<name>[^/@]+)@(?P<version>[^@?#]+)$"
)
OSV_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm", "maven": "Maven"}
FEED_FINDINGS = [json.loads(line) for line in (FEEDS / "findings.ndjson").read_text().splitlines()]
SNAPSHOT_VULNERABILITIES: dict[str, Any] = json.loads(SNAPSHOT)["vulnerabilities"]


def _cve(vuln_id: str) -> str | None:
    """The CVE of the snapshot that is `vuln_id` or has it as an alias."""
    for cve, entry in SNAPSHOT_VULNERABILITIES.items():
        if vuln_id == cve or vuln_id in entry.get("aliases", []):
            return cve
    return None


# Grype's severity of each CVE, as the feed fixtures record it.
SEVERITIES = {_cve(f["rule_id"]): f["severity"] for f in FEED_FINDINGS}


def _purl(seed: dict[str, Any]) -> dict[str, str]:
    match = PURL.match(seed["package"])
    assert match, f"{seed['id']}: {seed['package']} is not a pypi, npm or maven purl with a version"
    return {k: v or "" for k, v in match.groupdict().items()}


def _finding(seed: dict[str, Any]) -> dict[str, Any]:
    """The finding Grype's normalizer gives for a seed (A1): its id, its CVE alias, its package."""
    purl = _purl(seed)
    name = f"{purl['namespace']}/{purl['name']}" if purl["namespace"] else purl["name"]
    return {
        "schema_version": "1.0",
        "id": package_fingerprint("SCA", seed["vulnerability"], seed["package"]),
        "tool": {"name": "grype", "version": "0.121.0"},
        "rule_id": seed["vulnerability"],
        "category": "SCA",
        "title": f"{purl['name']} {purl['version']}: {seed['vulnerability']}",
        "severity": SEVERITIES[seed["cve"]],
        "cve": [seed["cve"]],
        "aliases": [],
        "location": {"path": f"demo-shop/{seed['location']['path']}"},
        "package": {
            "purl": seed["package"],
            "name": name,
            "version": purl["version"],
            "ecosystem": purl["type"],
        },
        "run": {"repo": "NOURHANE-EHOUARI/sentinelci", "commit": "0" * 40, "context": "release"},
    }


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_manifest_declares_the_seeded_version_at_its_line(seed: dict[str, Any]) -> None:
    purl = _purl(seed)
    path = DEMO / seed["location"]["path"]
    lines = path.read_text(encoding="utf-8").splitlines()
    line = lines[seed["location"]["line"] - 1].strip()
    if purl["type"] == "pypi":
        assert path.name == "requirements.txt"
        assert line == f"{purl['name']}=={purl['version']}"
    elif purl["type"] == "npm":
        assert path.name == "package.json"
        assert line.rstrip(",") == f'"{purl["name"]}": "{purl["version"]}"'
        lock = json.loads((path.parent / "package-lock.json").read_text(encoding="utf-8"))
        assert lock["packages"][f"node_modules/{purl['name']}"]["version"] == purl["version"]
        assert lock["packages"][""]["dependencies"][purl["name"]] == purl["version"]
    else:
        assert path.name == "pom.xml"
        assert lines[seed["location"]["line"] - 2].strip() == f"<groupId>{purl['namespace']}</groupId>"
        assert line == f"<artifactId>{purl['name']}</artifactId>"
        assert lines[seed["location"]["line"]].strip() == f"<version>{purl['version']}</version>"


def test_every_feed_case_is_a_seed_and_every_seed_is_enriched_offline() -> None:
    """The seeds are the seven packages of the feed fixtures (and lodash-es, under lodash's advisory): the
    snapshot covers every seed's CVE and knows its id as an alias, so enrichment needs no network."""
    assert {f["package"]["purl"] for f in FEED_FINDINGS} <= {seed["package"] for seed in SEEDS}
    assert len({seed["package"] for seed in SEEDS}) == len(SEEDS)
    for seed in SEEDS:
        assert _cve(seed["vulnerability"]) == seed["cve"], seed["id"]


def test_the_benchmark_has_what_the_spec_asks_for() -> None:
    """SPEC section 17: SCA 8, at least 2 KEV-listed with a fix, at least 3 never imported."""
    assert len(SEEDS) == 8
    assert sum(seed["kev"] for seed in SEEDS) >= 2
    assert sum(seed.get("imported") is False for seed in SEEDS) >= 3


def _recorded(vuln_id: str) -> dict[str, Any]:
    for path in sorted((FEEDS / "recordings").glob("*.json")):
        recording = json.loads(path.read_text(encoding="utf-8"))
        if recording["url"] == f"https://api.osv.dev/v1/vulns/{vuln_id}":
            body = gzip.decompress(base64.b64decode(recording["response_gzip_base64"]))
            assert hashlib.sha256(body).hexdigest() == recording["response_sha256"], path.name
            record: dict[str, Any] = json.loads(body)
            return record
    raise AssertionError(f"no OSV record of {vuln_id} in eval/feeds/recordings")


def _semver(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _affected(entry: dict[str, Any], version: str) -> bool:
    if version in entry.get("versions", []):
        return True
    for span in entry.get("ranges", []):
        if span["type"] != "SEMVER":
            continue  # ECOSYSTEM ranges come with the `versions` list checked above
        events = {key: value for event in span["events"] for key, value in event.items()}
        introduced, fixed = events.get("introduced", "0"), events.get("fixed")
        if introduced != "0" and _semver(version) < _semver(introduced):
            continue
        if fixed is not None and _semver(version) < _semver(fixed):
            return True
        if "last_affected" in events and _semver(version) <= _semver(events["last_affected"]):
            return True
    return False


@pytest.mark.parametrize(
    ("version", "affected"),
    [("1.1.9", False), ("1.2.0", True), ("1.2.5", True), ("1.2.6", False), ("1.10.0", False),
     ("2.0.0", True), ("2.0.1", True), ("2.0.2", False), ("3.0.0", True), ("3.1.0", False)],
)  # fmt: skip
def test_the_range_check_follows_osv(version: str, affected: bool) -> None:
    entry = {
        "versions": ["3.0.0"],
        "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "1.2.6"}]},
            {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.0.1"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]},
        ],
    }
    assert _affected(entry, version) is affected


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_recorded_advisory_lists_the_seeded_version_as_affected(seed: dict[str, Any]) -> None:
    purl = _purl(seed)
    record = _recorded(seed["vulnerability"])
    assert seed["cve"] in record.get("aliases", []), (
        f"{seed['vulnerability']} is not an alias of {seed['cve']}"
    )
    name = f"{purl['namespace']}:{purl['name']}" if purl["type"] == "maven" else purl["name"]
    entries = [
        entry
        for entry in record["affected"]
        if entry["package"]["ecosystem"] == OSV_ECOSYSTEMS[purl["type"]]
        and entry["package"]["name"].lower() == name.lower()
    ]
    assert entries, f"{seed['vulnerability']} names no {purl['type']} package {name}"
    assert any(_affected(entry, purl["version"]) for entry in entries), purl["version"]


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_enrichment_gives_the_seed_its_kev_status_offline(seed: dict[str, Any]) -> None:
    enrichment = enrich_finding(_finding(seed), load_snapshot(SNAPSHOT), None)["enrichment"]
    assert "cvss" in enrichment and "epss" in enrichment, seed["id"]
    assert enrichment["kev"]["listed"] is seed["kev"]


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_reachability_analysis_agrees_with_the_ground_truth(seed: dict[str, Any]) -> None:
    """`imported: false` is a dependency the service declares and never imports (B9's code must not either):
    the analysis never claims it is imported. `imported: true` must be found once the code exists."""
    classified = Reachability.of_trees([DEMO]).classify(_finding(seed))
    if "imported" in seed:
        assert isinstance(seed["imported"], bool), seed["id"]
        assert classified == ("imported" if seed["imported"] else None)


@pytest.fixture
def opa_binary() -> Path:
    """The real OPA binary. Skips when absent, unless SENTINEL_REQUIRE_OPA is set (CI)."""
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")


def test_each_seeds_gate_rule_is_the_engines(opa_binary: Path) -> None:
    """Enrich (feed fixtures, reachability of demo-shop), score and evaluate the seeds in release context: the
    rule that names each seed is its `expected.gate`, none for a seed without one."""
    snapshot = load_snapshot(SNAPSHOT)
    model = RiskModel.load(ROOT / "policies" / "risk-model.yaml")
    reachability = Reachability.of_trees([DEMO])
    scored = [score_finding(enrich_finding(_finding(s), snapshot, None, reachability), model) for s in SEEDS]
    decision = evaluate(
        findings_data="".join(json.dumps(f, sort_keys=True) + "\n" for f in scored).encode(),
        subject=Subject(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release"),
        evaluated_at="2026-11-01T00:00:00Z",
        bundle=PolicyBundle.load(ROOT / "policies"),
        opa=OpaRunner.locate(opa_binary),
        enrichment_snapshot=SNAPSHOT,
    )
    rules: dict[str, set[str]] = {}
    for violation in decision["violations"]:
        for finding_id in violation["finding_ids"]:
            rules.setdefault(finding_id, set()).add(violation["rule"])
    for seed, finding in zip(SEEDS, scored, strict=True):
        expected = {seed["expected"]["gate"]} if "gate" in seed["expected"] else set()
        assert rules.get(finding["id"], set()) == expected, (seed["id"], finding["risk"]["priority"])


# ---------------------------------------------------------------- real scanners (integration)

real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


def _sbom(work: Path) -> Path:
    """The pinned Syft's SBOM of demo-shop (syft-json), as the pipeline makes it before Grype."""
    sbom = work / "sbom.json"
    run = run_verified_tool(
        "syft",
        ["scan", "dir:.", "--output", f"syft-json={sbom}", "--quiet"],
        lock=load_lock(ROOT / "tools.lock.toml"),
        tools_dir=Path(str(TOOLS_DIR)),
        cwd=DEMO,
        extra_env={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
    )
    assert run.returncode == 0
    return sbom


@real
@pytest.mark.integration
def test_syft_catalogs_every_seed_from_its_service() -> None:
    with tempfile.TemporaryDirectory(prefix="sentinel-syft-") as work:
        artifacts = json.loads(_sbom(Path(work)).read_text(encoding="utf-8"))["artifacts"]
    found = {
        (a["purl"], str(Path(location["path"]).parent)) for a in artifacts for location in a["locations"]
    }
    for seed in SEEDS:
        service = "/" + str(Path(seed["location"]["path"]).parent)
        assert (seed["package"], service) in found, seed["id"]


@real
@pytest.mark.integration
@pytest.mark.skipif(not GRYPE_DB, reason="set SENTINEL_GRYPE_DB_DIR to a Grype database cache directory")
def test_grype_reports_every_seed_on_syfts_sbom() -> None:
    with tempfile.TemporaryDirectory(prefix="sentinel-grype-") as work:
        sbom = _sbom(Path(work))
        report = Path(work) / "grype.json"
        run_verified_tool(
            "grype",
            [f"sbom:{sbom}", "--output", f"json={report}", "--quiet"],
            lock=load_lock(ROOT / "tools.lock.toml"),
            tools_dir=Path(str(TOOLS_DIR)),
            cwd=Path(work),
            extra_env={
                "GRYPE_DB_CACHE_DIR": str(GRYPE_DB),
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            },
        )
        matches = json.loads(report.read_text(encoding="utf-8"))["matches"]
    found = {(m["artifact"]["purl"], m["vulnerability"]["id"]) for m in matches}
    expected = {
        (seed["package"], detection["rule"])
        for seed in SEEDS
        for detection in seed["expected"]["detections"]
        if detection["tool"] == "grype"
    }
    assert expected <= found, sorted(expected - found)
