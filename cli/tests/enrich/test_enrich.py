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


@pytest.mark.parametrize(
    ("top", "components", "exposure"),
    [
        ("internal", [{"path": "web", "exposure": "internet-facing"}], "internet-facing"),
        (
            "offline",
            [{"path": "a", "exposure": "internal"}, {"path": "b", "exposure": "offline"}],
            "internal",
        ),
        ("internet-facing", [{"path": "a", "exposure": "offline"}], "internet-facing"),
        ("internal", [{"path": "a", "data_classification": "confidential"}], "internal"),
    ],
)
def test_a_finding_without_a_path_gets_the_highest_exposure_of_the_service(
    top: str, components: list[dict[str, str]], exposure: str
) -> None:
    """A container image finding may belong to any component: never assume the least exposed (#17 nit)."""
    image = {k: v for k, v in SCA.items() if k != "location"}
    assert enrichment(image, context=config(exposure=top, components=components))["exposure"] == exposure


def test_a_null_enrichment_field_is_dropped_not_kept_as_an_empty_object(tmp_path: Path) -> None:
    """#17 nit: `{"reachability": null}` must not come out as `"enrichment": {}`."""
    code, out, path = run_enrich(tmp_path, [{**SECRET, "enrichment": {"reachability": None}}])
    assert code == 0, out
    assert "enrichment" not in json.loads(path.read_text(encoding="utf-8"))


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


# ---------------------------------------------------------------- "known no" only for what was checked (#17)


def snapshot_with(**changes: Any) -> bytes:
    document = json.loads(FULL)
    for key, value in changes.items():
        if key == "kev_cves":
            document["sources"]["kev"]["cves"] = value
        else:
            document[key] = value
    return json.dumps(document).encode("utf-8")


def test_kev_says_not_listed_only_for_cves_the_kev_lookup_covered() -> None:
    assert enrichment(SCA)["kev"] == {"listed": False}  # CVE-2099-0001 covered, not listed
    assert "kev" not in enrichment(SCA, snapshot_with(kev_cves=["CVE-2099-0002"]))


def test_a_finding_without_a_cve_never_gets_a_known_kev_status() -> None:
    only_kev = json.dumps(
        {
            "schema_version": "1.0",
            "sources": {"kev": {"catalog_version": "2026.11.09", "cves": ["CVE-2099-0001"]}},
            "vulnerabilities": {},
        }
    ).encode("utf-8")
    ghsa = {**SCA, "rule_id": "GHSA-aaaa-bbbb-cccc", "cve": [], "aliases": []}
    assert "kev" not in enrichment(ghsa, only_kev)  # OSV down: no alias leads to a CVE
    assert enrichment({**ghsa, "cve": ["CVE-2099-0001"]}, only_kev)["kev"] == {"listed": False}


def test_one_uncovered_cve_keeps_kev_unknown() -> None:
    two = {**SCA, "cve": ["CVE-2099-0001", "CVE-2099-0999"]}
    assert "kev" not in enrichment(two)


def chain(last_alias: str = "CVE-2099-0102") -> bytes:
    """GHSA -> CVE-2099-0101 -> CVE-2099-0102 (listed): the shape two OSV rounds produce (#18)."""
    return json.dumps(
        {
            "schema_version": "1.0",
            "sources": {
                "kev": {"catalog_version": "2026.11.09", "cves": ["CVE-2099-0101", "CVE-2099-0102"]},
                "epss": {"date": "2026-11-10"},
            },
            "vulnerabilities": {
                "GHSA-aaaa-bbbb-cccc": {"aliases": ["CVE-2099-0101"]},
                "CVE-2099-0101": {"aliases": [last_alias], "epss": {"score": 0.01, "percentile": 0.10}},
                "CVE-2099-0102": {
                    "epss": {"score": 0.90, "percentile": 0.99},
                    "kev": {"date_added": "2026-10-01"},
                },
            },
        }
    ).encode("utf-8")


GHSA_ONLY = {**SCA, "rule_id": "GHSA-aaaa-bbbb-cccc", "cve": [], "aliases": []}


@pytest.mark.parametrize("last_alias", ["CVE-2099-0102", "cve-2099-0102"])
def test_aliases_are_followed_to_the_end_of_the_chain(last_alias: str) -> None:
    """Two hops away is still the same vulnerability: its KEV listing and EPSS apply (#17 N1)."""
    result = enrichment(GHSA_ONLY, chain(last_alias))
    assert result["kev"] == {"listed": True, "date_added": "2026-10-01"}
    assert result["epss"]["percentile"] == 0.99


def test_a_lowercase_cve_alias_on_the_finding_counts() -> None:
    """finding.v1 allows `cve-...` in aliases: it must neither be ignored nor read as "not listed"."""
    listed_by_alias = {**SCA, "aliases": ["cve-2099-0002"]}  # 0001 covered, not listed; 0002 listed
    assert enrichment(listed_by_alias)["kev"] == {"listed": True, "date_added": "2026-10-01"}
    uncovered = {**SCA, "aliases": ["cve-2099-0999"]}
    assert "kev" not in enrichment(uncovered)


@pytest.mark.parametrize("alias", ["CVE-2099-0999", "cve-2099-0999"])
def test_an_uncovered_alias_without_an_entry_keeps_kev_unknown(alias: str) -> None:
    """The entry names a CVE the snapshot has no record of and KEV never covered: it may be listed."""
    document = json.loads(FULL)
    document["vulnerabilities"]["CVE-2099-0001"]["aliases"].append(alias)
    assert "kev" not in enrichment(SCA, json.dumps(document).encode("utf-8"))


def kev_released(value: str) -> bytes:
    document = json.loads(FULL)
    document["sources"]["kev"]["date_released"] = value
    return json.dumps(document).encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-09 18:00:00Z",
        "2026-11-09T18:00Z",
        "2026-11-09T18:00:00",
        "2026-13-09T18:00:00Z",
        "2026-11-09",
    ],
    ids=["space", "no-seconds", "no-offset", "month-13", "date-only"],
)
def test_kev_date_released_is_what_the_schema_calls_a_date_time(
    value: str, snapshot_validator: Draft202012Validator
) -> None:
    """The model refuses exactly what the schema refuses (#17 nit)."""
    assert list(snapshot_validator.iter_errors(json.loads(kev_released(value))))
    with pytest.raises(EnrichmentError):
        load_snapshot(kev_released(value))


@pytest.mark.parametrize("value", ["2026-11-09T18:00:00Z", "2026-11-09t18:00:00.5+01:00"])
def test_rfc3339_date_released_forms_load(value: str) -> None:
    assert load_snapshot(kev_released(value)).sources.kev is not None


def test_a_kev_entry_outside_the_covered_cves_is_refused() -> None:
    with pytest.raises(EnrichmentError, match="did not cover"):
        load_snapshot(snapshot_with(kev_cves=["CVE-2099-0001"]))


def test_package_names_are_compared_in_canonical_form() -> None:
    package = {**SCA["package"], "purl": "pkg:pypi/Example_Lib@1.2.3"}
    package.pop("fixed_versions", None)
    assert enrichment({**SCA, "package": package})["fix_available"] is True


def with_fixes(fixed_versions: dict[str, list[str]]) -> bytes:
    document = json.loads(FULL)
    for vuln_id in ("CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"):
        document["vulnerabilities"][vuln_id]["fixed_versions"] = fixed_versions
    return json.dumps(document).encode("utf-8")


NO_FIX_ON_FINDING = {**SCA, "package": {k: v for k, v in SCA["package"].items() if k != "fixed_versions"}}


def test_an_empty_fixed_versions_list_is_no_fix() -> None:
    """OSV knows the package and fixes none of its versions (#17 N4)."""
    assert enrichment(NO_FIX_ON_FINDING, with_fixes({"pkg:pypi/example-lib": []}))["fix_available"] is False


@pytest.mark.parametrize("key", ["pkg:pypi/Example.Lib", "pkg:pypi/example__lib", "pkg:pypi/EXAMPLE-LIB"])
def test_snapshot_package_names_are_compared_in_canonical_form(key: str) -> None:
    """The snapshot side is canonicalized too, dots folded like - and _ (#17 N4)."""
    assert enrichment(NO_FIX_ON_FINDING, with_fixes({key: ["1.2.4"]}))["fix_available"] is True


def test_without_a_snapshot_no_source_is_claimed(tmp_path: Path) -> None:
    code, out, path = run_enrich(tmp_path, [SCA])
    assert code == 0, out
    assert set(json.loads(path.read_text(encoding="utf-8")).get("enrichment", {})) <= {"fix_available"}


# ---------------------------------------------------------------- sentinel.yaml is a trust boundary (#17)


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("version: 1\nservice: demo\nexposure: internet-facing\nexposure: offline\n", "duplicate key"),
        ("version: 1\nservice: &s demo\nexposure: internet-facing\nowners: [*s]\n", "anchor and alias"),
        ("a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n", "alias bomb"),
        ("version: 1\nservice: 2026-01-01\nexposure: internal\n", "unquoted date"),
        ("version: 1\nservice: !!binary aGVsbG8=\nexposure: internal\n", "binary tag"),
        ("version: 1\nservice: !!set {a}\nexposure: internal\n", "set tag"),
        ("version: yes\nservice: demo\nexposure: internal\n", "YAML 1.1 boolean for the version"),
        ("version: 1\nservice: demo\nexposure: internal\nowners: " + "[" * 5000 + "]" * 5000, "deep nesting"),
        ("version: 1\nservice: demo\nexposure: internal\n# " + "x" * 70_000 + "\n", "larger than 64 KiB"),
    ],
)  # fmt: skip
def test_sentinel_yaml_means_what_it_says_or_is_refused(text: str, why: str) -> None:
    with pytest.raises(EnrichmentError):
        load_service_context(text.encode("utf-8"))


def test_component_paths_are_unique() -> None:
    with pytest.raises(EnrichmentError, match="unique"):
        config(
            components=[{"path": "infra", "exposure": "offline"}, {"path": "infra", "exposure": "internal"}]
        )


# ---------------------------------------------------------------- the CLI fails closed (#17)


def test_out_may_not_be_the_findings_file(tmp_path: Path) -> None:
    findings = tmp_path / "in.ndjson"
    findings.write_text(json.dumps(SECRET) + "\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["enrich", "--findings", str(findings), "--out", str(findings)])
    assert result.exit_code == 3
    assert json.loads(findings.read_text(encoding="utf-8")) == SECRET, "the input is never deleted"


@pytest.mark.parametrize("option", ["--snapshot", "--config"])
def test_out_may_not_be_any_other_input(tmp_path: Path, option: str) -> None:
    """#17 N3: --out naming the snapshot or sentinel.yaml would delete it before reading it."""
    data = FULL if option == "--snapshot" else b"version: 1\nservice: demo-shop\nexposure: internal\n"
    target = tmp_path / "out.ndjson"
    target.write_bytes(data)
    code, out, _ = run_enrich(tmp_path, [SECRET], option, str(target))
    assert code == 3, out
    assert target.read_bytes() == data, "the input is never deleted"


def test_merge_keys_are_refused_by_name() -> None:
    """`<<:` lets one mapping fill another: refused on purpose, not by a missing constructor (#17 nit)."""
    with pytest.raises(EnrichmentError, match=r"merge keys \(<<\)"):
        load_service_context(b"version: 1\nservice: s\nexposure: internal\n<<: {owners: ['@a']}\n")
    with pytest.raises(EnrichmentError, match="Extra inputs"):  # a quoted "<<" is just an unknown key
        load_service_context(b"version: 1\nservice: s\nexposure: internal\n'<<': x\n")


def test_a_null_inside_a_list_item_is_refused() -> None:
    """`exposure: null` would read as "no override"; the guard looks inside list items too (#17 N4)."""
    text = b"version: 1\nservice: s\nexposure: internal\ncomponents:\n  - {path: web, exposure: null}\n"
    with pytest.raises(EnrichmentError, match=r"components\[0\]\.exposure"):
        load_service_context(text)


@pytest.mark.parametrize("depth", [2_000, 30_000])
def test_a_deeply_nested_sentinel_yaml_fails_closed(depth: int) -> None:
    text = b"version: 1\nservice: s\nexposure: internal\nx: " + b"[" * depth + b"]" * depth + b"\n"
    with pytest.raises(EnrichmentError):
        load_service_context(text)


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_sentinel_yaml_is_never_read_past_the_size_limit(tmp_path: Path) -> None:
    """An endless input is refused after 64 KiB + 1 bytes instead of being read whole (#17 nit)."""
    code, out, _ = run_enrich(tmp_path, [SECRET], "--config", "/dev/zero")
    assert code == 3
    assert "larger than" in out


def test_out_may_not_be_a_directory(tmp_path: Path) -> None:
    (tmp_path / "out.ndjson").mkdir()
    code, out, _ = run_enrich(tmp_path, [SECRET])
    assert code == 3, out


@pytest.mark.parametrize(
    "extra", [{"reachability": "maybe"}, {"ai_says": "safe"}, {"kev": {"listed": "yes"}}], ids=str
)
def test_enrichment_outside_the_contract_is_refused(tmp_path: Path, extra: dict[str, Any]) -> None:
    code, _, path = run_enrich(tmp_path, [{**SECRET, "enrichment": extra}])
    assert code == 3
    assert not path.exists()


def test_anchors_and_aliases_are_refused_even_when_the_result_would_be_valid() -> None:
    text = b"version: 1\nservice: demo\nexposure: &e internal\ncomponents:\n  - {path: infra, exposure: *e}\n"
    with pytest.raises(EnrichmentError, match="anchors and aliases"):
        load_service_context(text)


@pytest.mark.parametrize(
    "value", ["2026-01-01", "!!binary aGVsbG8=", "!!set {a}"], ids=["date", "binary", "set"]
)
def test_typed_yaml_values_are_refused_by_name(value: str) -> None:
    with pytest.raises(EnrichmentError, match=r"not allowed in sentinel\.yaml"):
        load_service_context(f"version: 1\nservice: {value}\nexposure: internal\n".encode())


def test_a_document_that_is_not_json_shaped_fails_closed() -> None:
    from sentinelci.enrich.models import ServiceContext as Context
    from sentinelci.enrich.models import _validate

    with pytest.raises(EnrichmentError):
        _validate(Context, {"version": 1, "service": {"a", "b"}, "exposure": "internal"}, "sentinel.yaml")


@pytest.mark.parametrize("depth", [2_000, 10_000, 200_000])
def test_a_deeply_nested_snapshot_fails_closed(depth: int) -> None:
    """Deep enough for Python's recursion limit, still within json.loads' own (#17 N2)."""
    nested = b'{"schema_version": "1.0", "sources": {}, "vulnerabilities": {}, "x": ' + b"[" * depth
    with pytest.raises(EnrichmentError):
        load_snapshot(nested + b"]" * depth + b"}")


@pytest.mark.parametrize("depth", [2_000, 10_000])
def test_enrich_exits_3_on_a_deeply_nested_snapshot(tmp_path: Path, depth: int) -> None:
    snapshot = write(tmp_path, "deep.json", b'{"x": ' + b"[" * depth + b"]" * depth + b"}")
    code, out, path = run_enrich(tmp_path, [SECRET], "--snapshot", snapshot)
    assert (code, path.exists()) == (3, False), out
