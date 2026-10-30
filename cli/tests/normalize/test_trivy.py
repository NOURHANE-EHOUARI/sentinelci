"""Trivy `config` report -> Finding v1, category IAC (tasks A1c, A2)."""

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import config_fingerprint
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.normalize.trivy import normalize_trivy_config

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"
RUN = Run(
    repo="NOURHANE-EHOUARI/sentinelci",
    commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    ref="refs/pull/7/merge",
    context="pr",
    run_id="1001",
)
TOOL = Tool(name="trivy", version="0.76.1")


def _results() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))[
        "Results"
    ]
    return results


def _normalize(results: list[dict[str, Any]], scan_root: str = "demo-shop") -> list[dict[str, Any]]:
    findings = normalize_trivy_config(results, run=RUN, tool=TOOL, scan_root=scan_root)
    return [finding.to_json_dict() for finding in findings]


def test_matches_golden_file() -> None:
    output = dumps_ndjson(normalize_trivy_config(_results(), run=RUN, tool=TOOL, scan_root="demo-shop"))
    golden = FIXTURES / "expected.ndjson"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.write_text(output, encoding="utf-8")
    assert output == golden.read_text(encoding="utf-8")


def test_every_finding_satisfies_the_contract(finding_validator: Draft202012Validator) -> None:
    for finding in _normalize(_results()):
        assert not list(finding_validator.iter_errors(finding))


def test_passes_are_dropped_and_exceptions_are_reported_like_failures() -> None:
    rules = sorted(f["rule_id"] for f in _normalize(_results()))
    assert rules == ["AWS-0080", "AWS-0177", "DS-0002", "KSV-0009", "KSV-0017"]  # AWS-0077 passed


def test_paths_are_repository_relative_and_fingerprints_use_the_resource() -> None:
    by_rule = {f["rule_id"]: f for f in _normalize(_results())}
    rds = by_rule["AWS-0080"]
    assert rds["location"] == {
        "path": "demo-shop/infra/terraform/database.tf",
        "start_line": 2,
        "end_line": 13,
    }
    assert rds["id"] == config_fingerprint(
        "AWS-0080", "demo-shop/infra/terraform/database.tf", "aws_db_instance.orders"
    )
    dockerfile = by_rule["DS-0002"]
    assert dockerfile["location"] == {"path": "demo-shop/services/shop-api/Dockerfile"}
    assert dockerfile["id"] == config_fingerprint("DS-0002", "demo-shop/services/shop-api/Dockerfile", "")


def test_the_same_check_on_the_same_resource_is_one_finding_with_every_place() -> None:
    # Two containers named shop-api (whitespace differs): one fingerprint, both places kept.
    privileged = next(f for f in _normalize(_results()) if f["rule_id"] == "KSV-0017")
    assert privileged["schema_version"] == "1.1"
    assert privileged["location"]["start_line"] == 20
    assert privileged["other_locations"] == [
        {"path": "demo-shop/infra/k8s/shop-api.yaml", "start_line": 52, "end_line": 61}
    ]
    assert privileged["id"] == config_fingerprint(
        "KSV-0017", "demo-shop/infra/k8s/shop-api.yaml", "- name: shop-api"
    )


def test_fingerprints_survive_line_shifts() -> None:
    shifted = copy.deepcopy(_results())
    for result in shifted:
        for item in result.get("Misconfigurations", []):
            cause = item.get("CauseMetadata", {})
            for key in ("StartLine", "EndLine"):
                if key in cause:
                    cause[key] += 40
    assert {f["id"] for f in _normalize(shifted)} == {f["id"] for f in _normalize(_results())}


def test_no_code_from_the_scanned_files_is_kept() -> None:
    # Trivy quotes the cause lines, which may hold credentials.
    output = dumps_ndjson(normalize_trivy_config(_results(), run=RUN, tool=TOOL, scan_root="demo-shop"))
    assert "fake-db-password-0003-not-real" not in output
    assert all("evidence" not in f for f in _normalize(_results()))


def test_unknown_severity_counts_as_high_and_keeps_the_raw_value() -> None:
    deletion = next(f for f in _normalize(_results()) if f["rule_id"] == "AWS-0177")
    assert (deletion["severity"], deletion["severity_source"]) == ("HIGH", "UNKNOWN")
    rds = next(f for f in _normalize(_results()) if f["rule_id"] == "AWS-0080")
    assert (rds["severity"], rds["severity_source"]) == ("HIGH", "HIGH")


def test_output_is_deterministic_whatever_the_report_order() -> None:
    reversed_results = [
        {**result, "Misconfigurations": list(reversed(result.get("Misconfigurations", [])))}
        for result in reversed(_results())
    ]
    assert dumps_ndjson(
        normalize_trivy_config(reversed_results, run=RUN, tool=TOOL, scan_root="demo-shop")
    ) == (dumps_ndjson(normalize_trivy_config(_results(), run=RUN, tool=TOOL, scan_root="demo-shop")))


def test_a_scan_of_the_repository_root_keeps_trivy_paths() -> None:
    paths = {f["location"]["path"] for f in _normalize(_results(), scan_root=".")}
    assert "infra/terraform/database.tf" in paths


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r[1].pop("Target"), "has no Target"),
        (lambda r: r[1]["Misconfigurations"][0].pop("ID"), "has no ID"),
        (lambda r: r[1]["Misconfigurations"][0].pop("Status"), "has no Status"),
        (lambda r: r[1]["Misconfigurations"][0].update(Title=" "), "has no Title"),
        (lambda r: r[1].update(Misconfigurations={"a": 1}), "invalid Misconfigurations"),
        (lambda r: r[1].update(Misconfigurations={}), "invalid Misconfigurations"),
        (lambda r: r[1]["Misconfigurations"].append("FAIL"), "is not an object"),
        (lambda r: r[1]["Misconfigurations"][0].update(CauseMetadata=[]), "invalid CauseMetadata"),
        (lambda r: r[1].update(Target="../../etc/passwd"), "escapes the repository"),
        (lambda r: r[1].update(Target="/etc/passwd"), "absolute path"),
    ],
    ids=[
        "no-target",
        "no-id",
        "no-status",
        "blank-title",
        "bad-list",
        "empty-dict",
        "bad-item",
        "bad-cause",
        "dotdot",
        "abs",
    ],
)
def test_malformed_reports_fail_closed(mutate: Any, message: str) -> None:
    results = copy.deepcopy(_results())
    mutate(results)
    with pytest.raises(NormalizationError, match=message):
        normalize_trivy_config(results, run=RUN, tool=TOOL, scan_root="demo-shop")


def test_a_local_module_outside_the_scan_path_keeps_its_repository_path() -> None:
    results = copy.deepcopy(_results())
    results[1]["Target"] = "../modules/db/main.tf"
    paths = {f["location"]["path"] for f in _normalize(results)}
    assert "modules/db/main.tf" in paths
