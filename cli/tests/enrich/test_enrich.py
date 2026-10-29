"""Offline enrichment (task B2, SPEC 6.1): a snapshot and `sentinel.yaml` applied to findings, no network."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.enrich import (
    EnrichmentError,
    ServiceContext,
    Snapshot,
    enrich_finding,
    load_service_context,
    load_snapshot,
)

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_FIXTURES = ROOT / "schemas" / "fixtures"
SNAPSHOTS = SCHEMA_FIXTURES / "enrichment-snapshot"
CONFIGS = SCHEMA_FIXTURES / "sentinel-config"
FULL = (SNAPSHOTS / "valid" / "all-sources.json").read_bytes()
NO_KEV = (SNAPSHOTS / "valid" / "kev-feed-unreachable.json").read_bytes()
EMPTY = (SNAPSHOTS / "valid" / "no-source-reachable.json").read_bytes()
SCORED_SCA = json.loads(
    (SCHEMA_FIXTURES / "finding" / "valid" / "sca-enriched-and-scored.json").read_text("utf-8")
)
SECRET = json.loads((SCHEMA_FIXTURES / "finding" / "valid" / "secret-in-config.json").read_text("utf-8"))


def config(**fields: Any) -> ServiceContext:
    document = {"version": 1, "service": "demo-shop", "exposure": "internet-facing", **fields}
    return load_service_context(yaml.safe_dump(document).encode("utf-8"))


SITE = config()
SCA = {k: v for k, v in SCORED_SCA.items() if k not in ("enrichment", "risk")}


def enrichment(finding: dict[str, Any], snapshot: bytes = FULL, context: ServiceContext | None = SITE) -> Any:
    return enrich_finding(finding, load_snapshot(snapshot), context).get("enrichment")


# ---------------------------------------------------------------- the models agree with the schemas


@pytest.mark.parametrize("path", sorted((SNAPSHOTS / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_valid_snapshots_load(path: Path) -> None:
    assert isinstance(load_snapshot(path.read_bytes()), Snapshot)


@pytest.mark.parametrize("path", sorted((SNAPSHOTS / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_invalid_snapshots_are_refused(path: Path) -> None:
    with pytest.raises(EnrichmentError):
        load_snapshot(path.read_bytes())


@pytest.mark.parametrize("path", sorted((CONFIGS / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_valid_service_contexts_load_from_yaml(path: Path) -> None:
    as_yaml = yaml.safe_dump(json.loads(path.read_text(encoding="utf-8"))).encode("utf-8")
    assert isinstance(load_service_context(as_yaml), ServiceContext)


@pytest.mark.parametrize("path", sorted((CONFIGS / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_invalid_service_contexts_are_refused(path: Path) -> None:
    as_yaml = yaml.safe_dump(json.loads(path.read_text(encoding="utf-8"))).encode("utf-8")
    with pytest.raises(EnrichmentError):
        load_service_context(as_yaml)


@pytest.mark.parametrize(
    "data", [b"", b"{not json", b"\xff", b"[]"], ids=["empty", "not-json", "not-utf8", "list"]
)
def test_unreadable_snapshots_are_refused(data: bytes) -> None:
    with pytest.raises(EnrichmentError):
        load_snapshot(data)


# ---------------------------------------------------------------- what a finding gets


def test_the_contract_fixture_enrichment_is_rebuilt_from_the_snapshot() -> None:
    expected = {
        k: v for k, v in SCORED_SCA["enrichment"].items() if k != "reachability"
    }  # reachability: next slice
    assert enrichment(SCA) == expected


def test_epss_reaches_a_finding_known_only_by_an_alias() -> None:
    ghsa = {**SCA, "rule_id": "GHSA-xxxx-yyyy-zzzz", "cve": [], "aliases": []}
    assert enrichment(ghsa)["epss"] == {"score": 0.41, "percentile": 0.95, "date": "2026-11-10"}


def test_a_kev_listed_vulnerability_says_so() -> None:
    kev = {**SCA, "rule_id": "CVE-2099-0002", "cve": ["CVE-2099-0002"], "aliases": []}
    assert enrichment(kev)["kev"] == {"listed": True, "date_added": "2026-10-01"}


def test_without_the_kev_feed_kev_status_stays_unknown() -> None:
    assert "kev" not in enrichment(SCA, NO_KEV)


def test_with_no_source_only_the_service_context_and_known_fixes_remain() -> None:
    assert enrichment(SCA, EMPTY) == {"exposure": "internet-facing", "fix_available": True}


def test_fix_availability_comes_from_osv_when_the_finding_has_none() -> None:
    no_fix_listed = {**SCA, "package": {k: v for k, v in SCA["package"].items() if k != "fixed_versions"}}
    assert enrichment(no_fix_listed)["fix_available"] is True
    other_package = {
        **no_fix_listed,
        "package": {**no_fix_listed["package"], "purl": "pkg:pypi/other-lib@1.0"},
    }
    assert enrichment(other_package)["fix_available"] is False
    assert "fix_available" not in enrichment(no_fix_listed, EMPTY)  # nobody said: unknown, not "no fix"


def test_the_highest_cvss_and_epss_of_matched_ids_win() -> None:
    both = {**SCA, "cve": ["CVE-2099-0001", "CVE-2099-0002"]}
    result = enrichment(both)
    assert (result["cvss"]["score"], result["epss"]["percentile"]) == (9.8, 0.99)


def test_a_secret_gets_only_its_exposure() -> None:
    assert enrichment(SECRET) == {"exposure": "internet-facing"}


def test_without_a_service_context_no_exposure_is_invented() -> None:
    assert "exposure" not in enrichment(SCA, context=None)
    assert enrich_finding(SECRET, load_snapshot(EMPTY), None) == SECRET
    # An exposure left by an earlier run is not this run's to keep: without a context it is unknown again.
    stale = {**SECRET, "enrichment": {"exposure": "offline"}}
    assert enrich_finding(stale, load_snapshot(EMPTY), None) == SECRET


@pytest.mark.parametrize(
    ("path", "exposure"),
    [
        ("services/shop-api/app/config.py", "internal"),
        ("services/shop-api", "internal"),
        ("services/shop-api-v2/main.py", "internet-facing"),  # a prefix of the name is not the component
        ("services/shop-api/admin/x.py", "offline"),  # the longest component wins
        ("services/web/app.py", "internet-facing"),
    ],
)
def test_components_override_the_exposure_by_path(path: str, exposure: str) -> None:
    context = config(
        components=[
            {"path": "services/shop-api", "exposure": "internal"},
            {"path": "services/shop-api/admin", "exposure": "offline"},
        ]
    )
    finding = {**SECRET, "location": {**SECRET["location"], "path": path}}
    assert enrichment(finding, context=context)["exposure"] == exposure


def test_earlier_enrichment_is_replaced_and_enriching_twice_changes_nothing() -> None:
    finding = {**SCA, "enrichment": {"reachability": "not_imported", "exposure": "offline"}}
    once = enrich_finding(finding, load_snapshot(FULL), SITE)
    assert "reachability" not in once["enrichment"]  # no source tree given: a stale value is never kept
    assert once["enrichment"]["exposure"] == "internet-facing"  # the service context wins
    assert enrich_finding(once, load_snapshot(FULL), SITE) == once
    assert {k: v for k, v in once.items() if k != "enrichment"} == {
        k: v for k, v in finding.items() if k != "enrichment"
    }


def test_enriched_findings_satisfy_the_contract(finding_validator: Draft202012Validator) -> None:
    for snapshot in (FULL, NO_KEV, EMPTY):
        for finding in (SCA, SECRET):
            assert not list(
                finding_validator.iter_errors(enrich_finding(finding, load_snapshot(snapshot), SITE))
            )


def test_the_input_finding_is_not_modified() -> None:
    finding = copy.deepcopy(SCA)
    enrich_finding(finding, load_snapshot(FULL), SITE)
    assert finding == SCA


# ---------------------------------------------------------------- sentinel enrich


def run_enrich(tmp_path: Path, findings: list[dict[str, Any]], *extra: str) -> tuple[int, str, Path]:
    (tmp_path / "in.ndjson").write_text("".join(json.dumps(f) + "\n" for f in findings), encoding="utf-8")
    out = tmp_path / "out.ndjson"
    result = CliRunner().invoke(
        app, ["enrich", "--findings", str(tmp_path / "in.ndjson"), "--out", str(out), *extra]
    )
    return result.exit_code, result.output, out


def write(tmp_path: Path, name: str, data: bytes) -> str:
    (tmp_path / name).write_bytes(data)
    return str(tmp_path / name)


def test_cli_enriches_every_finding(tmp_path: Path) -> None:
    sentinel_yaml = write(tmp_path, "sentinel.yaml", b"version: 1\nservice: demo-shop\nexposure: internal\n")
    code, out, path = run_enrich(
        tmp_path,
        [SCA, SECRET],
        "--snapshot",
        write(tmp_path, "snapshot.json", FULL),
        "--config",
        sentinel_yaml,
    )
    assert code == 0, out
    enriched = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [f["id"] for f in enriched] == sorted(f["id"] for f in (SCA, SECRET))
    assert {f["enrichment"]["exposure"] for f in enriched} == {"internal"}
    assert "2 finding(s) enriched" in out


def test_cli_without_snapshot_or_config_still_writes_findings(tmp_path: Path) -> None:
    code, out, path = run_enrich(tmp_path, [SECRET])
    assert code == 0, out
    assert json.loads(path.read_text(encoding="utf-8")) == SECRET


@pytest.mark.parametrize(
    ("option", "name", "data"),
    [
        (
            "--snapshot",
            "snapshot.json",
            (SNAPSHOTS / "invalid" / "epss-without-epss-source.json").read_bytes(),
        ),
        ("--config", "sentinel.yaml", b"version: 1\nservice: demo-shop\nexposure: dmz\n"),
        ("--config", "sentinel.yaml", b"version: 1\nservice: [unclosed\n"),
    ],
    ids=["invalid-snapshot", "invalid-config", "config-not-yaml"],
)
def test_cli_fails_closed_on_unreadable_inputs(tmp_path: Path, option: str, name: str, data: bytes) -> None:
    (tmp_path / "out.ndjson").write_text("stale\n", encoding="utf-8")
    code, _, path = run_enrich(tmp_path, [SECRET], option, write(tmp_path, name, data))
    assert code == 3
    assert not path.exists()
