"""Grype JSON report -> Finding v1, category SCA (task A1).

The golden input is a real report: Grype 0.121.0 (database v6.1.10, built 2026-11-01T06:20:12Z) on the Syft
1.55.0 SBOM of demo-shop's dependency seeds, made by track B and kept byte for byte, with its SBOM.
Regenerate the expected findings with UPDATE_GOLDEN=1 after a deliberate change, and review the diff.
"""

import copy
import hashlib
import json
import os
import random
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Location, Run
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.normalize.grype import (
    BUILTIN_IGNORE_RULES,
    MAX_TITLE,
    GrypeDatabase,
    check_grype_report,
    load_grype_report,
    normalize_grype,
)
from sentinelci.normalize.ndjson import dumps_ndjson

FIXTURES = Path(__file__).parent / "fixtures" / "grype"
REPORT = FIXTURES / "grype-demo-shop.json"
# The sha256 the producer stated when sending the files: the golden inputs are never edited by hand.
INPUTS = {
    "grype-demo-shop.json": "a3355d4967c7ee504f31d1f429940abc701dbd1bc28ebf400b981c1b99fd6ae3",
    "demo-shop.syft.json": "4f2f4ced8125eacbb9a47ec6cc65798b044a27c4720f027758ed397ec3c653f3",
}
RUN = Run(
    repo="NOURHANE-EHOUARI/sentinelci",
    commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    ref="refs/pull/51/merge",
    context="pr",
    run_id="2001",
)
LOG4SHELL = "GHSA-jfh8-c2jp-5v3q"


def _report() -> dict[str, Any]:
    return load_grype_report(REPORT)


def _normalize(report: dict[str, Any], scan_root: str = "demo-shop") -> str:
    return dumps_ndjson(normalize_grype(report, run=RUN, scan_root=scan_root))


def _match(**changes: Any) -> dict[str, Any]:
    """The Log4Shell match of the golden report, with top-level parts replaced."""
    match = next(m for m in _report()["matches"] if m["vulnerability"]["id"] == LOG4SHELL)
    return {**copy.deepcopy(match), **changes}


def _with(report: dict[str, Any], *matches: dict[str, Any]) -> dict[str, Any]:
    return {**report, "matches": list(matches)}


@pytest.mark.parametrize(("name", "sha256"), sorted(INPUTS.items()))
def test_the_golden_inputs_are_the_files_received(name: str, sha256: str) -> None:
    assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == sha256


def test_matches_golden_file() -> None:
    output = _normalize(_report())
    golden = FIXTURES / "grype-demo-shop.findings.ndjson"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.write_text(output, encoding="utf-8")
    assert output == golden.read_text(encoding="utf-8")


def test_every_finding_satisfies_the_contract(finding_validator: Draft202012Validator) -> None:
    lines = _normalize(_report()).splitlines()
    assert len(lines) == len(_report()["matches"]) == 36  # no two matches share a fingerprint here
    for line in lines:
        errors = [e.message for e in finding_validator.iter_errors(json.loads(line))]
        assert not errors, errors


def test_log4shell_is_one_sca_finding_with_its_ids_and_fix() -> None:
    finding = next(
        f for f in normalize_grype(_report(), run=RUN, scan_root="demo-shop") if f.rule_id == LOG4SHELL
    )
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert finding.id == package_fingerprint("SCA", LOG4SHELL, purl)
    assert (finding.category, finding.severity, finding.severity_source) == ("SCA", "CRITICAL", "Critical")
    assert (finding.cve, finding.aliases) == (["CVE-2021-44228"], None)
    assert finding.cwe == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]
    assert finding.location == Location(path="demo-shop/services/reports/pom.xml")
    assert finding.package is not None
    assert (finding.package.purl, finding.package.ecosystem, finding.package.fixed_versions) == (
        purl,
        "maven",
        ["2.15.0"],
    )
    assert finding.title == "log4j-core: Remote code injection in Log4j"
    assert finding.message == "log4j-core 2.14.1 is affected by GHSA-jfh8-c2jp-5v3q; fixed in 2.15.0."
    # The report's CVSS, EPSS and KEV are not copied: enrichment comes from the dated snapshot (B2) only.
    assert (finding.enrichment, finding.risk) == (None, None)
    assert finding.tool.name == "grype" and finding.tool.version == "0.121.0"


def test_the_order_of_matches_does_not_matter() -> None:
    report = _report()
    expected = _normalize(report)
    for seed in range(3):
        shuffled = report["matches"][:]
        random.Random(seed).shuffle(shuffled)
        assert _normalize(_with(report, *shuffled)) == expected


def test_paths_start_at_the_scanned_directory() -> None:
    match = _match()
    assert [f.location for f in normalize_grype(_with(_report(), match), run=RUN)] == [
        Location(path="services/reports/pom.xml")
    ]
    assert [f.location for f in normalize_grype(_with(_report(), match), run=RUN, scan_root="a/b/")] == [
        Location(path="a/b/services/reports/pom.xml")
    ]


@pytest.mark.parametrize("scan_root", ["/abs", "../up", "a/../../b"])
def test_a_scan_root_outside_the_repository_is_refused(scan_root: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_grype(_with(_report(), _match()), run=RUN, scan_root=scan_root)


@pytest.mark.parametrize("path", ["/../etc/passwd", "/services/../../x", "/services/../pom.xml", "", "/a\nb"])
def test_a_location_outside_the_scanned_directory_or_malformed_is_refused(path: str) -> None:
    match = _match()
    match["artifact"]["locations"] = [{"path": path}]
    with pytest.raises(NormalizationError):
        normalize_grype(_with(_report(), match), run=RUN)


def test_the_same_package_in_two_places_is_one_finding_listing_every_place() -> None:
    first, second = _match(), _match()
    second["artifact"]["locations"] = [{"path": "/services/batch/pom.xml"}]
    second["artifact"]["version"] = "2.14.0"
    second["artifact"]["purl"] = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
    (finding,) = normalize_grype(_with(_report(), first, second), run=RUN)
    assert finding.schema_version == "1.1"
    assert finding.location == Location(path="services/batch/pom.xml")
    assert finding.other_locations == [Location(path="services/reports/pom.xml")]
    assert finding.package is not None and finding.package.version == "2.14.0"  # the first place's package


def test_a_match_reported_twice_is_one_finding_in_one_place() -> None:
    (finding,) = normalize_grype(_with(_report(), _match(), _match()), run=RUN)
    assert (finding.schema_version, finding.other_locations) == ("1.0", None)


def test_a_package_found_through_several_files_lists_them_all() -> None:
    match = _match()
    match["artifact"]["locations"] = [{"path": "/b/pom.xml"}, {"path": "/a/pom.xml"}, {"path": "/a/pom.xml"}]
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert finding.location == Location(path="a/pom.xml")
    assert finding.other_locations == [Location(path="b/pom.xml")]


def test_a_package_without_location_is_still_a_finding() -> None:
    match = _match()
    match["artifact"]["locations"] = []
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert (finding.location, finding.package is not None) == (None, True)


@pytest.mark.parametrize(
    ("raw", "severity", "source"),
    [
        ("Critical", "CRITICAL", "Critical"),
        ("High", "HIGH", "High"),
        ("Medium", "MEDIUM", "Medium"),
        ("Low", "LOW", "Low"),
        ("Negligible", "LOW", "Negligible"),  # a known vulnerability is never INFO
        ("Unknown", "HIGH", "Unknown"),  # missing data never lowers risk
        ("", "HIGH", "Unknown"),
        (None, "HIGH", "Unknown"),
    ],
)
def test_grype_severities_are_mapped_without_lowering_risk(
    raw: str | None, severity: str, source: str
) -> None:
    match = _match()
    match["vulnerability"]["severity"] = raw
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert (finding.severity, finding.severity_source) == (severity, source)


@pytest.mark.parametrize("raw", ["Severe", "critical", "CRITICAL", 9.8])
def test_a_severity_nobody_mapped_fails_closed(raw: object) -> None:
    match = _match()
    match["vulnerability"]["severity"] = raw
    with pytest.raises(NormalizationError, match="severity SentinelCI does not map"):
        normalize_grype(_with(_report(), match), run=RUN)


def test_a_cve_match_keeps_its_ghsa_as_an_alias() -> None:
    match = _match()
    match["vulnerability"]["id"] = "CVE-2021-44228"
    match["relatedVulnerabilities"] = [{"id": "GHSA-jfh8-c2jp-5v3q"}, {"id": "CVE-2021-44228"}]
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert (finding.rule_id, finding.cve, finding.aliases) == (
        "CVE-2021-44228",
        ["CVE-2021-44228"],
        ["GHSA-jfh8-c2jp-5v3q"],
    )


def test_a_cve_match_with_no_related_cve_still_lists_its_cve() -> None:
    match = _match()
    match["vulnerability"]["id"] = "CVE-2021-44228"
    match["relatedVulnerabilities"] = []
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert (finding.cve, finding.aliases) == (["CVE-2021-44228"], None)


def test_cve_ids_are_kept_in_their_canonical_upper_case() -> None:
    match = _match()
    match["relatedVulnerabilities"] = [{"id": "cve-2021-44228"}, {"id": "CVE-2021-45046"}]
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert (finding.cve, finding.aliases) == (["CVE-2021-44228", "CVE-2021-45046"], None)


def test_a_related_record_with_the_matched_id_is_not_an_alias() -> None:
    match = _match()
    match["relatedVulnerabilities"] = [{"id": LOG4SHELL}, {"id": "PYSEC-2021-1"}]
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert finding.aliases == ["PYSEC-2021-1"]


@pytest.mark.parametrize("vuln_id", ["GHSA x", "GHSA-1\nCVE-2", "", "GHSA-é"])
def test_a_malformed_vulnerability_id_fails_closed(vuln_id: str) -> None:
    match = _match()
    match["relatedVulnerabilities"] = [{"id": vuln_id}]
    with pytest.raises(NormalizationError):
        normalize_grype(_with(_report(), match), run=RUN)


@pytest.mark.parametrize(
    "purl",
    [None, "", "log4j-core@2.14.1", "pkg:maven/a/b@1\npkg:npm/x@1", "pkg:maven/a/b@1\u2028", "pkg:npm/a b@1",
     "pkg:Maven/a@1"],
)  # fmt: skip
def test_a_package_without_a_usable_purl_fails_closed(purl: str | None) -> None:
    match = _match()
    match["artifact"]["purl"] = purl
    with pytest.raises(NormalizationError):
        normalize_grype(_with(_report(), match), run=RUN)


def test_fixed_versions_are_listed_once_in_grypes_order() -> None:
    match = _match()
    match["vulnerability"]["fix"] = {"versions": ["2.15.0", "2.12.2", "2.15.0"], "state": "fixed"}
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert finding.package is not None and finding.package.fixed_versions == ["2.15.0", "2.12.2"]
    assert finding.message is not None and finding.message.endswith("fixed in 2.15.0, 2.12.2.")


@pytest.mark.parametrize("versions", [[""], [" "], [2.15], [None], "2.15.0", {"v": 1}])
def test_a_malformed_fixed_version_fails_closed(versions: object) -> None:
    match = _match()
    match["vulnerability"]["fix"] = {"versions": versions, "state": "fixed"}
    with pytest.raises(NormalizationError):
        normalize_grype(_with(_report(), match), run=RUN)


def test_a_vulnerability_without_fix_says_so() -> None:
    match = _match()
    match["vulnerability"]["fix"] = {"versions": [], "state": "not-fixed"}
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert finding.package is not None and finding.package.fixed_versions is None
    assert finding.message == (
        "log4j-core 2.14.1 is affected by GHSA-jfh8-c2jp-5v3q; "
        "no fixed version is known (fix state: not-fixed)."
    )


@pytest.mark.parametrize(
    ("description", "title"),
    [
        ("log4j-core: remote code injection", "log4j-core: remote code injection"),
        ("urllib3: TLS settings ignored", "log4j-core: urllib3: TLS settings ignored"),
        ("Log4j-core vulnerable to RCE", "Log4j-core vulnerable to RCE"),
        ("log4j-core-extra is unrelated", "log4j-core: log4j-core-extra is unrelated"),
        ("\n\n  First   line \nsecond line", "log4j-core: First line"),
        (None, "log4j-core: GHSA-jfh8-c2jp-5v3q"),
        ("x" * 400, "log4j-core: " + "x" * (MAX_TITLE - len("log4j-core: ") - 1) + "…"),
    ],
)
def test_the_title_is_one_short_line_naming_the_package(description: str | None, title: str) -> None:
    match = _match()
    match["vulnerability"]["description"] = description
    (finding,) = normalize_grype(_with(_report(), match), run=RUN)
    assert finding.title == title and len(finding.title) <= MAX_TITLE


def test_the_report_and_its_database_are_checked() -> None:
    tool, database = check_grype_report(_report())
    assert (tool.name, tool.version) == ("grype", "0.121.0")
    assert database == GrypeDatabase(
        schema_version="v6.1.10",
        built="2026-11-01T06:20:12Z",
        checksum="sha256:d0e1af9e6491440e1a671d0a0aafc32c5c7cb5cda787dcec3482799ef298f31c",
    )


def _configured(**changes: object) -> dict[str, Any]:
    report = _report()
    report["descriptor"]["configuration"].update(changes)
    return report


SILENCING = [
    ("only-fixed", True),
    ("only-notfixed", True),
    ("ignore-wontfix", "fixed"),
    ("by-cve", True),
    ("exclude", ["./services/reports/**"]),
    ("vex-documents", ["vex.json"]),
    ("vex-add", ["fixed"]),
    ("distro", "debian:12"),
]


@pytest.mark.parametrize(("key", "value"), SILENCING)
def test_a_report_made_with_a_silencing_setting_fails_closed(key: str, value: object) -> None:
    with pytest.raises(NormalizationError, match=f"made with {key} = .*exceptions are waivers"):
        normalize_grype(_configured(**{key: value}), run=RUN)


@pytest.mark.parametrize(("key", "_value"), SILENCING)
def test_a_report_that_does_not_show_a_setting_fails_closed(key: str, _value: object) -> None:
    report = _report()
    del report["descriptor"]["configuration"][key]
    with pytest.raises(NormalizationError, match=f"{key} = '\\(absent\\)'"):
        normalize_grype(report, run=RUN)


def test_an_ignore_rule_of_the_repository_fails_closed() -> None:
    rule = {**BUILTIN_IGNORE_RULES[0], "vulnerability": LOG4SHELL, "package": {"name": "log4j-core"}}
    with pytest.raises(NormalizationError, match="not one of Grype's built-in kernel-header rules"):
        normalize_grype(_configured(ignore=[*BUILTIN_IGNORE_RULES, rule]), run=RUN)


def test_a_changed_built_in_rule_fails_closed() -> None:
    widened = {
        **BUILTIN_IGNORE_RULES[2],
        "match-type": "",
    }  # every match of linux-libc-dev, not just indirect
    with pytest.raises(NormalizationError, match="not one of Grype's built-in"):
        normalize_grype(_configured(ignore=[widened]), run=RUN)


@pytest.mark.parametrize("rules", [[], list(BUILTIN_IGNORE_RULES[1:3])])
def test_fewer_built_in_rules_hide_nothing(rules: list[object]) -> None:
    assert len(normalize_grype(_configured(ignore=rules), run=RUN)) == 36


@pytest.mark.parametrize("rules", [None, {}, "x"])
def test_a_report_without_its_ignore_list_fails_closed(rules: object) -> None:
    with pytest.raises(NormalizationError, match="cannot show that nothing was hidden"):
        normalize_grype(_configured(ignore=rules), run=RUN)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda r: r["descriptor"].update(name="syft"), "not a Grype report"),
        (lambda r: r["descriptor"].update(version=""), "has no version"),
        (lambda r: r["descriptor"].pop("configuration"), "configuration is not an object"),
        (lambda r: r["descriptor"]["db"]["status"].update(valid=False), "database was not valid"),
        (lambda r: r["descriptor"]["db"]["status"].pop("valid"), "database was not valid"),
        (lambda r: r["descriptor"].pop("db"), "descriptor.db is not an object"),
        (lambda r: r.pop("descriptor"), "descriptor is not an object"),
        (lambda r: r.update(source={"type": "image", "target": {}}), "needs the image adapter"),
        (lambda r: r.pop("source"), "source is not an object"),
        (lambda r: r.pop("matches"), "has no matches list"),
        (lambda r: r.update(matches={}), "matches is not a list"),
        (lambda r: r.update(matches=["x"]), "is not an object"),
    ],
)
def test_a_report_that_is_not_a_trusted_grype_directory_report_fails_closed(
    change: Any, message: str
) -> None:
    report = _report()
    change(report)
    with pytest.raises(NormalizationError, match=message):
        normalize_grype(report, run=RUN)


def test_a_database_without_a_checksum_is_still_recorded() -> None:
    report = _report()
    report["descriptor"]["db"]["status"]["from"] = "file:///imported.tar.zst"
    assert check_grype_report(report)[1].checksum is None


def test_an_empty_report_has_no_findings() -> None:
    assert normalize_grype(_with(_report()), run=RUN) == []
    assert normalize_grype({**_report(), "matches": None}, run=RUN) == []


def test_cli_writes_the_golden_findings(tmp_path: Path) -> None:
    out = tmp_path / "findings.ndjson"
    result = CliRunner().invoke(
        app,
        [
            "normalize", "grype", str(REPORT), "--out", str(out), "--repo", RUN.repo, "--commit", RUN.commit,
            "--context", "pr", "--ref", "refs/pull/51/merge", "--run-id", "2001", "--scan-root", "demo-shop",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "36 finding(s)" in result.output
    assert out.read_text() == (FIXTURES / "grype-demo-shop.findings.ndjson").read_text()


def test_cli_fails_closed_and_leaves_no_findings_file(tmp_path: Path) -> None:
    report = tmp_path / "grype.json"
    report.write_text(json.dumps(_configured(**{"only-fixed": True})))
    out = tmp_path / "findings.ndjson"
    out.write_text("stale\n")
    result = CliRunner().invoke(
        app,
        ["normalize", "grype", str(report), "--out", str(out), "--repo", RUN.repo, "--commit", RUN.commit,
         "--context", "pr"],
    )  # fmt: skip
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output
    assert not out.exists()
