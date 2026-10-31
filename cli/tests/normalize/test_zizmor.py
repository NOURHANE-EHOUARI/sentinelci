"""zizmor JSON v1 -> Finding v1, category PIPELINE (task A2).

The fixture is zizmor 1.31.1's real output on the three demo workflow seeds (GT-PIPELINE-001 to 003), audited
from the repository root of a copy, so its paths are `examples/...`.
"""

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sentinelci.contracts.finding import Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import config_fingerprint
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.normalize.zizmor import normalize_zizmor

FIXTURES = Path(__file__).parent / "fixtures" / "zizmor"
RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")
TOOL = Tool(name="zizmor", version="1.31.1")


def _report() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))
    return data


def _normalize(report: list[dict[str, Any]], scan_root: str = ".") -> str:
    return dumps_ndjson(normalize_zizmor(report, run=RUN, tool=TOOL, scan_root=scan_root))


def test_matches_golden_file() -> None:
    output = _normalize(_report())
    golden = FIXTURES / "expected.ndjson"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.write_text(output, encoding="utf-8")
    assert output == golden.read_text(encoding="utf-8")


def test_every_finding_satisfies_the_contract(finding_validator: Draft202012Validator) -> None:
    for line in _normalize(_report()).splitlines():
        errors = [e.message for e in finding_validator.iter_errors(json.loads(line))]
        assert not errors, errors


def test_the_seeds_ground_truth_is_found() -> None:
    found = {
        (f.rule_id, f.location.path, f.location.start_line)
        for f in normalize_zizmor(_report(), run=RUN, tool=TOOL)
        if f.location
    }
    assert ("dangerous-triggers", "examples/pwn-request.yml", 7) in found  # GT-PIPELINE-001
    assert ("template-injection", "examples/issue-title-injection.yml", 18) in found  # GT-PIPELINE-002
    assert ("excessive-permissions", "examples/overprivileged-unpinned.yml", 10) in found  # GT-PIPELINE-003
    assert ("unpinned-uses", "examples/overprivileged-unpinned.yml", 16) in found


def test_no_workflow_code_is_kept() -> None:
    output = _normalize(_report())
    for code in ("github.event.issue.title", "actions/checkout", "secrets: inherit", "run: |"):
        assert code not in output


def test_one_finding_per_rule_file_and_job() -> None:
    findings = normalize_zizmor(_report(), run=RUN, tool=TOOL)
    assert len(_report()) == 11 and len(findings) == 10
    merged = [f for f in findings if f.other_locations]
    assert len(merged) == 1
    (unpinned,) = merged
    assert (unpinned.rule_id, unpinned.schema_version) == ("unpinned-uses", "1.1")
    assert unpinned.location == Location(
        path="examples/overprivileged-unpinned.yml", start_line=16, end_line=16
    )
    assert unpinned.other_locations == [
        Location(path="examples/overprivileged-unpinned.yml", start_line=17, end_line=17)
    ]
    assert unpinned.id == config_fingerprint(
        "unpinned-uses", "examples/overprivileged-unpinned.yml", "jobs.build"
    )


def test_paths_are_repository_relative() -> None:
    findings = normalize_zizmor(_report(), run=RUN, tool=TOOL, scan_root="demo-shop")
    assert {f.location.path for f in findings if f.location} == {
        "demo-shop/examples/issue-title-injection.yml",
        "demo-shop/examples/overprivileged-unpinned.yml",
        "demo-shop/examples/pwn-request.yml",
    }


def _first(**changes: Any) -> list[dict[str, Any]]:
    item = copy.deepcopy(_report()[0])  # template-injection, in job `label`
    item.update(changes)
    return [item]


def _primary(item: dict[str, Any]) -> dict[str, Any]:
    location: dict[str, Any] = next(loc for loc in item["locations"] if loc["symbolic"]["kind"] == "Primary")
    return location


def test_adding_a_step_keeps_the_fingerprint() -> None:
    """The step index and the line are not in the fingerprint: a new step must not make old findings new."""
    before = normalize_zizmor(_first(), run=RUN, tool=TOOL)[0]
    item = _first()[0]
    primary = _primary(item)
    primary["symbolic"]["route"]["route"][3] = {"Index": 4}
    primary["concrete"]["location"]["start_point"]["row"] += 9
    primary["concrete"]["location"]["end_point"]["row"] += 9
    after = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert after.id == before.id
    assert after.location is not None and before.location is not None
    assert after.location.start_line == before.location.start_line + 9


def test_a_finding_zizmor_marks_ignored_is_kept_and_says_so() -> None:
    item = _first()[0]
    item["ignored"] = True
    (finding,) = normalize_zizmor([item], run=RUN, tool=TOOL)
    assert finding.rule_id == "template-injection" and finding.severity == "HIGH"
    assert finding.message is not None and "does not honour" in finding.message


def test_a_malformed_occurrence_merged_into_a_finding_is_refused() -> None:
    first, second = copy.deepcopy(_report()[0]), copy.deepcopy(_report()[0])
    second["determinations"] = {"severity": "Severe", "confidence": "High"}
    with pytest.raises(NormalizationError, match="finding 1 determinations"):
        normalize_zizmor([first, second], run=RUN, tool=TOOL)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW"), ("Informational", "INFO"), ("Unknown", "HIGH")],
)
def test_severities(severity: str, expected: str) -> None:
    item = _first()[0]
    item["determinations"]["severity"] = severity
    finding = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert finding.severity == expected
    assert finding.severity_source == f"{severity} (confidence High)"


def test_the_highest_severity_of_a_merged_finding_wins() -> None:
    first, second = copy.deepcopy(_report()[0]), copy.deepcopy(_report()[0])
    first["determinations"]["severity"] = "Low"
    for location in second["locations"]:
        for point in ("start_point", "end_point"):
            location["concrete"]["location"][point]["row"] += 3
    second["determinations"]["severity"] = "High"
    (finding,) = normalize_zizmor([first, second], run=RUN, tool=TOOL)
    assert finding.severity == "HIGH" and finding.other_locations


REMOTE = {"Remote": {"slug": "x/y"}}


def _broken(edit: Any) -> list[dict[str, Any]]:
    items = _first()
    edit(items[0])
    return items


@pytest.mark.parametrize(
    ("items", "message"),
    [
        (_broken(lambda i: i.pop("ident")), "has no rule"),
        (_broken(lambda i: i.pop("determinations")), "has no determinations"),
        (_broken(lambda i: i.update(locations=[])), "has no location"),
        (_broken(lambda i: i["determinations"].update(severity="Severe")), "determinations"),
        (_broken(lambda i: i["determinations"].update(confidence="Certain")), "determinations"),
        (_broken(lambda i: _primary(i)["symbolic"].update(key=REMOTE)), "not about a local file"),
        (_broken(lambda i: _primary(i)["symbolic"]["key"]["Local"].update(verbatim_path="../escape.yml")),
         "escapes the repository"),
        (_broken(lambda i: _primary(i)["symbolic"]["key"]["Local"].update(verbatim_path="/etc/x.yml")),
         "absolute path"),
        (_broken(lambda i: _primary(i)["concrete"].update(location={})), "no line span"),
        (_broken(lambda i: _primary(i)["concrete"]["location"]["start_point"].update(row=-1)), "impossible"),
        (_broken(lambda i: _primary(i)["symbolic"]["route"].update(route=[{"Weird": 1}])), "neither a key"),
    ],
    ids=["no-ident", "no-determinations", "no-location", "unknown-severity", "unknown-confidence", "remote",
         "dot-dot",
         "absolute", "no-span", "negative-row", "odd-route"],
)  # fmt: skip
def test_malformed_findings_fail_closed(items: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(NormalizationError, match=message):
        normalize_zizmor(items, run=RUN, tool=TOOL)


@pytest.mark.parametrize(
    ("route", "resource"),
    [
        ([{"Key": "permissions"}], "permissions"),
        ([{"Key": "on"}, {"Key": "pull_request_target"}], "on"),
        ([{"Key": "runs"}, {"Key": "steps"}, {"Index": 0}], "runs"),
        ([], "workflow"),
        (
            [{"Key": "jobs"}, {"Key": "deploy"}, {"Key": "steps"}, {"Index": 2}, {"Key": "uses"}],
            "jobs.deploy",
        ),
    ],
)
def test_the_resource_is_the_job_or_the_top_level_key(route: list[dict[str, Any]], resource: str) -> None:
    item = _first()[0]
    _primary(item)["symbolic"]["route"]["route"] = route
    finding = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert finding.id == config_fingerprint(
        "template-injection", "examples/issue-title-injection.yml", resource
    )
