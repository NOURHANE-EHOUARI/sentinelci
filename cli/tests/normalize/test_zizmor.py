"""zizmor JSON v1 -> Finding v1, category PIPELINE (task A2).

The fixture is zizmor 1.31.1's real output on the demo workflow seeds (GT-PIPELINE-001 to 003 and the clean
control), audited from `demo-shop/` with the flags `sentinel scan pipelines` uses, so its paths are the
ground truth's (`examples/bad-workflows/...`). zizmor 1.32.0 gives the same 11 findings, ids included.
"""

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from sentinelci.contracts.finding import Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import config_fingerprint, pipeline_fingerprint
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.normalize.zizmor import normalize_zizmor

FIXTURES = Path(__file__).parent / "fixtures" / "zizmor"
GROUND_TRUTH = Path(__file__).resolve().parents[3] / "demo-shop" / "ground-truth" / "findings.yaml"
RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")
TOOL = Tool(name="zizmor", version="1.31.1")
INJECTION = "examples/bad-workflows/issue-title-injection.yml"


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
    findings = normalize_zizmor(_report(), run=RUN, tool=TOOL)
    found = {(f.rule_id, f.location.path, f.location.start_line) for f in findings if f.location}
    seeds = [s for s in yaml.safe_load(GROUND_TRUTH.read_text())["seeds"] if s["category"] == "PIPELINE"]
    assert len(seeds) == 3
    for seed in seeds:
        rules = {(f.rule_id, f.location.path) for f in findings if f.location}
        for detection in seed["expected"]["detections"]:
            assert (detection["rule"], seed["location"]["path"]) in rules, seed["id"]
        # The seed's line is where its first detection points.
        first = seed["expected"]["detections"][0]["rule"]
        assert (first, seed["location"]["path"], seed["location"]["line"]) in found, seed["id"]
    assert not any("good-workflows" in path for _, path, _ in found), "the clean control has no finding"


def test_no_workflow_code_is_kept() -> None:
    output = _normalize(_report())
    for code in ("github.event.issue.title", "actions/checkout", "secrets: inherit", "run: |"):
        assert code not in output


def test_every_occurrence_of_the_seeds_is_its_own_finding() -> None:
    findings = normalize_zizmor(_report(), run=RUN, tool=TOOL)
    assert len(_report()) == len(findings) == 11
    unpinned = sorted(
        f.location.start_line
        for f in findings
        if f.location
        and f.rule_id == "unpinned-uses"
        and f.location.path.endswith("overprivileged-unpinned.yml")
    )
    assert unpinned == [16, 17, 23], "two actions in one job are two findings: each can be fixed or waived"


def _first() -> dict[str, Any]:
    item: dict[str, Any] = copy.deepcopy(_report()[0])  # template-injection, in job `label`
    assert item["ident"] == "template-injection"
    return item


def _primary(item: dict[str, Any]) -> dict[str, Any]:
    location: dict[str, Any] = next(loc for loc in item["locations"] if loc["symbolic"]["kind"] == "Primary")
    return location


def _shift(item: dict[str, Any], rows: int) -> dict[str, Any]:
    for location in item["locations"]:
        for point in ("start_point", "end_point"):
            location["concrete"]["location"][point]["row"] += rows
    return item


def test_a_new_expression_in_a_job_that_already_has_one_is_a_new_finding() -> None:
    """Review of #37 (blocking): with the job alone as resource, a second injection in the same job shared the
    first one's id, so SC-009 saw nothing new and a waiver for the first covered it too."""
    before = normalize_zizmor([_first()], run=RUN, tool=TOOL)
    added = _shift(_first(), 3)
    _primary(added)["symbolic"]["route"]["route"][3] = {"Index": 1}
    _primary(added)["concrete"]["feature"] = '|\n  echo "${{ github.event.label.name }}"\n'
    after = normalize_zizmor([_first(), added], run=RUN, tool=TOOL)
    assert len(after) == 2
    assert before[0].id in {f.id for f in after}
    (new,) = [f for f in after if f.id != before[0].id]
    assert new.location is not None and new.location.start_line == before[0].location.start_line + 3  # type: ignore[union-attr]


def test_adding_a_step_or_reindenting_keeps_the_fingerprint() -> None:
    """The step index, the line and the indentation are not in the fingerprint: an old finding stays old."""
    before = normalize_zizmor([_first()], run=RUN, tool=TOOL)[0]
    item = _shift(_first(), 9)
    primary = _primary(item)
    primary["symbolic"]["route"]["route"][3] = {"Index": 4}
    primary["concrete"]["feature"] = "\n".join(
        "    " + line for line in primary["concrete"]["feature"].splitlines()
    )
    after = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert after.id == before.id
    assert after.location is not None and before.location is not None
    assert after.location.start_line == before.location.start_line + 9


def test_the_same_code_twice_in_a_job_is_one_finding_with_other_locations() -> None:
    first, second = _first(), _shift(_first(), 6)
    _primary(second)["symbolic"]["route"]["route"][3] = {"Index": 2}
    (finding,) = normalize_zizmor([first, second], run=RUN, tool=TOOL)
    assert finding.schema_version == "1.1" and finding.location is not None
    assert finding.other_locations == [
        Location(
            path=INJECTION, start_line=finding.location.start_line + 6, end_line=finding.location.end_line + 6
        )
    ]


def test_a_job_level_finding_does_not_depend_on_the_jobs_code() -> None:
    """excessive-permissions about a whole job: its feature is the job's text, which every edit changes."""
    item = next(
        copy.deepcopy(i)
        for i in _report()
        if i["ident"] == "excessive-permissions" and "pwn-request" in json.dumps(i["locations"])
    )
    before = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    _primary(item)["concrete"]["feature"] += "      - run: echo another step\n"
    after = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert (
        after.id
        == before.id
        == config_fingerprint(
            "excessive-permissions", "examples/bad-workflows/pwn-request.yml", "jobs.preview"
        )
    )


def test_paths_are_repository_relative() -> None:
    findings = normalize_zizmor(_report(), run=RUN, tool=TOOL, scan_root="demo-shop")
    assert {f.location.path for f in findings if f.location} == {
        "demo-shop/examples/bad-workflows/issue-title-injection.yml",
        "demo-shop/examples/bad-workflows/overprivileged-unpinned.yml",
        "demo-shop/examples/bad-workflows/pwn-request.yml",
    }


def test_a_finding_zizmor_marks_ignored_is_kept_and_says_so() -> None:
    item = _first()
    item["ignored"] = True
    (finding,) = normalize_zizmor([item], run=RUN, tool=TOOL)
    assert finding.rule_id == "template-injection" and finding.severity == "HIGH"
    assert finding.message is not None and "does not honour" in finding.message


def test_a_malformed_occurrence_merged_into_a_finding_is_refused() -> None:
    first, second = _first(), _first()
    second["determinations"] = {"severity": "Severe", "confidence": "High"}
    with pytest.raises(NormalizationError, match="finding 1 determinations"):
        normalize_zizmor([first, second], run=RUN, tool=TOOL)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW"), ("Informational", "INFO"), ("Unknown", "HIGH")],
)
def test_severities(severity: str, expected: str) -> None:
    item = _first()
    item["determinations"]["severity"] = severity
    finding = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert finding.severity == expected
    assert finding.severity_source == f"{severity} (confidence High)"


def test_the_most_severe_occurrence_gives_the_severity_and_its_source() -> None:
    """Review of #37, nit 1: the severity came from every hit but its source from the first one."""
    first, second = _first(), _shift(_first(), 3)
    first["determinations"] = {"severity": "Low", "confidence": "High"}
    second["determinations"] = {"severity": "High", "confidence": "Medium"}
    (finding,) = normalize_zizmor([first, second], run=RUN, tool=TOOL)
    assert (finding.severity, finding.severity_source) == ("HIGH", "High (confidence Medium)")
    assert finding.other_locations


REMOTE = {"Remote": {"slug": "x/y"}}


def _broken(edit: Any) -> list[dict[str, Any]]:
    item = _first()
    edit(item)
    return [item]


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
        (_broken(lambda i: _primary(i)["concrete"].pop("feature")), "no source text"),
        (_broken(lambda i: _primary(i)["concrete"].update(feature=" \n")), "no source text"),
    ],
    ids=["no-ident", "no-determinations", "no-location", "unknown-severity", "unknown-confidence", "remote",
         "dot-dot", "absolute", "no-span", "negative-row", "odd-route", "no-feature", "blank-feature"],
)  # fmt: skip
def test_malformed_findings_fail_closed(items: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(NormalizationError, match=message):
        normalize_zizmor(items, run=RUN, tool=TOOL)


CODE = '|\n  echo "New issue: ${{ github.event.issue.title }}"\n'


@pytest.mark.parametrize(
    ("route", "feature", "resource", "code"),
    [
        ([{"Key": "permissions"}], "permissions: write-all", "permissions", "write-all"),
        ([{"Key": "on"}], "on: pull_request_target", "on", "pull_request_target"),
        ([{"Key": "on"}, {"Key": "pull_request_target"}], "pull_request_target", "on", "pull_request_target"),
        ([{"Key": "on"}, {"Index": 1}], "pull_request_target", "on", "pull_request_target"),
        ([{"Key": "on"}], "on:\n  workflow_run:\n", "on", "workflow_run:"),
        ([{"Key": "on"}], "on:", "on", "on:"),
        ([{"Key": "permissions"}], "contents: write", "permissions", "contents: write"),
        ([{"Key": "runs"}, {"Key": "steps"}, {"Index": 0}], CODE, "runs", CODE),
        ([], CODE, "workflow", None),
        ([{"Key": "jobs"}], CODE, "jobs", None),
        ([{"Key": "jobs"}, {"Key": "deploy"}], CODE, "jobs.deploy", None),
        ([{"Key": "jobs"}, {"Key": "deploy"}, {"Key": "permissions"}], "permissions: write-all",
         "jobs.deploy", "permissions: write-all"),
        ([{"Key": "jobs"}, {"Key": "deploy"}, {"Key": "steps"}, {"Index": 2}, {"Key": "uses"}], CODE,
         "jobs.deploy", CODE),
    ],
    ids=["workflow-permissions", "scalar-trigger", "mapping-trigger", "list-trigger", "trigger-block",
         "key-alone", "another-key", "composite-action-step", "whole-file", "all-jobs", "whole-job",
         "job-permissions", "step"],
)  # fmt: skip
def test_only_a_whole_job_or_file_goes_without_code(
    route: list[dict[str, Any]], feature: str, resource: str, code: str | None
) -> None:
    """Review of #37 (blocking): a top-level key's own value is hashed (a scalar `on:` swapped to another
    trigger is a new finding, and its three forms are one id); only a whole job or file goes without code."""
    item = _first()
    _primary(item)["symbolic"]["route"]["route"] = route
    _primary(item)["symbolic"]["feature_kind"] = "Normal"
    _primary(item)["concrete"]["feature"] = feature
    finding = normalize_zizmor([item], run=RUN, tool=TOOL)[0]
    assert finding.id == pipeline_fingerprint("template-injection", INJECTION, resource, code)


SCRIPT = '|\n  echo start\n  echo "body ${{ github.event.issue.body }}" \\\n    >> "$GITHUB_STEP_SUMMARY"\n'


def _subfeature(feature: str, fragment: Any, after: int = 0) -> str:
    item = _first()
    _primary(item)["concrete"]["feature"] = feature
    _primary(item)["symbolic"]["feature_kind"] = {"Subfeature": {"after": after, "fragment": fragment}}
    return normalize_zizmor([item], run=RUN, tool=TOOL)[0].id


def _id(code: str) -> str:
    return pipeline_fingerprint("template-injection", INJECTION, "jobs.label", code)


def test_an_expression_is_identified_by_its_own_line_only() -> None:
    """Review of #37 (should fix 1): the whole `run:` script was hashed, so any edit to it made the injection
    new and broke its waiver. Only the line holding zizmor's fragment is hashed now."""
    line = '  echo "body ${{ github.event.issue.body }}" \\'
    fragment = {"Raw": "github.event.issue.body"}
    assert _subfeature(SCRIPT, fragment) == _id(line)
    assert _subfeature(SCRIPT.replace("echo start", "echo start now"), fragment) == _id(line)
    assert _subfeature(SCRIPT.replace("|", "|-"), fragment) == _id(line)
    assert _subfeature(
        SCRIPT.replace("${{ github", "${{github").replace("body }}", "body}}"), fragment
    ) == _id(line)


def test_the_fragment_is_searched_from_zizmors_byte_offset() -> None:
    """zizmor's offset counts bytes: a non-ASCII character before it must not skip the fragment."""
    script = '|\n  echo "é ${{ github.event.issue.body }}"\n  echo "${{ github.event.issue.body }}"\n'
    second = script.encode().index(b'  echo "${{')
    fragment = {"Raw": "github.event.issue.body"}
    assert _subfeature(script, fragment, after=second) == _id('  echo "${{ github.event.issue.body }}"')
    assert _subfeature(script, fragment, after=0) == _id('  echo "é ${{ github.event.issue.body }}"')


def test_a_fragment_over_several_lines_keeps_all_of_them() -> None:
    script = "|\n  echo start\n  echo ${{ format('{0}',\n    github.event.issue.body) }}\n  echo end\n"
    fragment = {"Raw": "format('{0}',\n    github.event.issue.body)"}
    assert _subfeature(script, fragment) == _id("  echo ${{ format('{0}',\n    github.event.issue.body) }}")


@pytest.mark.parametrize(
    ("fragment", "after"),
    [({"Raw": "github.event.issue.title"}, 0), ({"Raw": "github.event.issue.body"}, 400),
     ({"Regex": "github.event.issue.body"}, 0), ({"Raw": ""}, 0),
     ({"Raw": "github.event.issue.body"}, -1000)],
    ids=["not-in-the-text", "after-the-text", "a-pattern", "empty", "negative-offset"],
)  # fmt: skip
def test_without_a_fragment_to_find_the_whole_text_is_hashed(fragment: Any, after: int) -> None:
    assert _subfeature(SCRIPT, fragment, after) == _id(SCRIPT)


def _dependabot(route: list[dict[str, Any]], feature: str, related: list[dict[str, Any]]) -> dict[str, Any]:
    item = _first()
    item["ident"] = "dependabot-execution"
    primary = _primary(item)
    primary["symbolic"]["route"]["route"] = route
    primary["symbolic"]["feature_kind"] = "Normal"
    primary["concrete"]["feature"] = feature
    item["locations"] = [primary, *related]
    return item


def _ecosystem(entry: int, name: str) -> dict[str, Any]:
    location = copy.deepcopy(_primary(_first()))
    location["symbolic"]["kind"] = "Related"
    location["symbolic"]["route"]["route"] = [
        {"Key": "updates"},
        {"Index": entry},
        {"Key": "package-ecosystem"},
    ]
    location["concrete"]["feature"] = f"package-ecosystem: {name}"
    return location


EXECUTION = "    insecure-external-code-execution: allow"


def _entry(entry: int) -> list[dict[str, Any]]:
    return [{"Key": "updates"}, {"Index": entry}, {"Key": "insecure-external-code-execution"}]


def test_a_dependabot_entry_is_identified_by_its_ecosystem() -> None:
    """Review of #37 (blocking): the entry index was dropped and the flagged line is the same in every entry,
    so a second entry shared the first one's id. Its `package-ecosystem` (a Related location) is hashed
    too."""
    pip = normalize_zizmor([_dependabot(_entry(0), EXECUTION, [_ecosystem(0, "pip")])], run=RUN, tool=TOOL)
    both = normalize_zizmor(
        [
            _dependabot(_entry(0), EXECUTION, [_ecosystem(0, "pip")]),
            _dependabot(_entry(1), EXECUTION, [_ecosystem(0, "pip"), _ecosystem(1, "npm")]),
        ],
        run=RUN,
        tool=TOOL,
    )
    assert len(both) == 2 and pip[0].id in {f.id for f in both}
    expected = pipeline_fingerprint(
        "dependabot-execution", INJECTION, "updates", f"{EXECUTION}\npackage-ecosystem: pip"
    )
    assert pip[0].id == expected


def test_a_finding_on_the_ecosystem_line_hashes_it_once() -> None:
    route = [{"Key": "updates"}, {"Index": 0}, {"Key": "package-ecosystem"}]
    (finding,) = normalize_zizmor([_dependabot(route, "package-ecosystem: pip", [])], run=RUN, tool=TOOL)
    assert finding.id == pipeline_fingerprint(
        "dependabot-execution", INJECTION, "updates", "package-ecosystem: pip"
    )


def test_a_dependabot_entry_without_its_ecosystem_fails_closed() -> None:
    item = _dependabot(_entry(1), EXECUTION, [_ecosystem(0, "pip")])
    with pytest.raises(NormalizationError, match="which Dependabot entry"):
        normalize_zizmor([item], run=RUN, tool=TOOL)
