"""Gitleaks JSON report -> Finding v1 (task A2)."""

import json
import os
import random
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Location, Run, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import secret_fingerprint
from sentinelci.normalize.gitleaks import load_gitleaks_report, normalize_gitleaks
from sentinelci.normalize.ndjson import dumps_ndjson

FIXTURES = Path(__file__).parent / "fixtures" / "gitleaks"
FAKE_SECRETS = ("fake-secret-value-0001-not-real", "FAKE-PRIVATE-KEY-0002-not-a-real-key")

RUN = Run(
    repo="NOURHANE-EHOUARI/sentinelci",
    commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    ref="refs/pull/7/merge",
    context="pr",
    run_id="1001",
)
TOOL = Tool(name="gitleaks", version="8.30.1")


def _report() -> list[dict[str, Any]]:
    return load_gitleaks_report(FIXTURES / "report.json")


def _normalize(report: list[dict[str, Any]]) -> str:
    return dumps_ndjson(normalize_gitleaks(report, run=RUN, tool=TOOL))


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


def test_same_secret_in_two_files_is_one_finding() -> None:
    findings = normalize_gitleaks(_report(), run=RUN, tool=TOOL)
    assert len(findings) == 2
    api_key = next(f for f in findings if f.rule_id == "generic-api-key")
    assert api_key.id == secret_fingerprint("generic-api-key", FAKE_SECRETS[0])
    assert api_key.message is not None and "2 locations" in api_key.message
    # Canonical location is the first one in a stable (path, line) order.
    assert api_key.location is not None
    assert api_key.location.path == "demo-shop/services/shop-api/app/config.py"


def test_other_places_of_the_same_secret_are_listed_as_other_locations() -> None:
    findings = normalize_gitleaks(_report(), run=RUN, tool=TOOL)
    api_key = next(f for f in findings if f.rule_id == "generic-api-key")
    assert api_key.schema_version == "1.1"
    assert api_key.other_locations == [
        Location(path="demo-shop/services/web/.env.example", start_line=3, end_line=3)
    ]


def test_secret_seen_in_one_place_stays_finding_1_0() -> None:
    findings = normalize_gitleaks(_report(), run=RUN, tool=TOOL)
    key = next(f for f in findings if f.rule_id == "private-key")
    assert (key.schema_version, key.other_locations) == ("1.0", None)


def test_same_place_in_several_commits_is_one_location() -> None:
    # Git mode reports a secret once per commit that touches it; the place is still one place.
    first = _report()[0]
    report = [{**first, "Commit": c} for c in ("a" * 40, "b" * 40, "")]
    (finding,) = normalize_gitleaks(report, run=RUN, tool=TOOL)
    assert (finding.schema_version, finding.other_locations) == ("1.0", None)


def test_every_other_location_is_kept_sorted_and_unique() -> None:
    first = _report()[0]
    places = [("b.py", 9), ("a.py", 30), ("b.py", 2), ("a.py", 30), ("a.py", 4)] + [
        (f"many/{i:03}.py", 1) for i in range(200)
    ]
    report = [{**first, "File": p, "StartLine": n, "EndLine": n} for p, n in places]
    random.Random(3).shuffle(report)
    (finding,) = normalize_gitleaks(report, run=RUN, tool=TOOL)
    assert finding.location == Location(path="a.py", start_line=4, end_line=4)
    assert finding.other_locations is not None
    assert [(o.path, o.start_line) for o in finding.other_locations] == [
        ("a.py", 30),
        ("b.py", 2),
        ("b.py", 9),
        *[(f"many/{i:03}.py", 1) for i in range(200)],
    ]


def test_raw_secret_and_author_data_never_leave_the_normalizer() -> None:
    output = _normalize(_report())
    for secret in FAKE_SECRETS:
        assert secret not in output
    assert "[REDACTED]" in output
    assert "jane.developer@example.com" not in output
    assert "Jane Developer" not in output


def test_history_finding_mentions_the_commit() -> None:
    findings = normalize_gitleaks(_report(), run=RUN, tool=TOOL)
    key = next(f for f in findings if f.rule_id == "private-key")
    assert key.message is not None and "9fceb02d0ae5" in key.message


def test_output_is_independent_of_input_order() -> None:
    report = _report()
    shuffled = report[:]
    random.Random(7).shuffle(shuffled)
    assert _normalize(shuffled) == _normalize(report)


def test_line_shift_keeps_the_same_fingerprint() -> None:
    shifted = _report()
    for item in shifted:
        item["StartLine"] += 40
        item["EndLine"] += 40
    before = {f.id for f in normalize_gitleaks(_report(), run=RUN, tool=TOOL)}
    after = {f.id for f in normalize_gitleaks(shifted, run=RUN, tool=TOOL)}
    assert before == after


def test_redacted_report_fails_closed() -> None:
    # Without the raw secret we cannot compute a stable fingerprint: refuse instead of guessing.
    with pytest.raises(NormalizationError, match="redacted"):
        normalize_gitleaks(load_gitleaks_report(FIXTURES / "redacted.json"), run=RUN, tool=TOOL)


def test_missing_required_field_fails_closed() -> None:
    broken = _report()
    del broken[0]["Secret"]
    with pytest.raises(NormalizationError, match="Secret"):
        normalize_gitleaks(broken, run=RUN, tool=TOOL)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("EndLine", "x"),
        ("EndLine", 0),
        ("EndLine", True),
        ("EndLine", 11),  # before StartLine (12)
        ("StartLine", True),
        ("StartLine", "12"),
    ],
)
def test_malformed_line_numbers_fail_closed(field: str, value: object) -> None:
    broken = _report()
    broken[0][field] = value
    with pytest.raises(NormalizationError, match=f"invalid {field}"):
        normalize_gitleaks(broken, run=RUN, tool=TOOL)


def test_missing_end_line_defaults_to_start_line() -> None:
    report = _report()[:1]
    del report[0]["EndLine"]
    (finding,) = normalize_gitleaks(report, run=RUN, tool=TOOL)
    assert finding.location is not None
    assert finding.location.end_line == finding.location.start_line == 12


def test_path_outside_the_repository_fails_closed(tmp_path: Path) -> None:
    report = _report()
    report[0]["File"] = "/etc/passwd"
    with pytest.raises(NormalizationError, match="outside"):
        normalize_gitleaks(report, run=RUN, tool=TOOL, repo_root=tmp_path)


def test_absolute_path_inside_the_repository_becomes_relative(tmp_path: Path) -> None:
    report = _report()[:1]
    report[0]["File"] = str(tmp_path / "app" / "config.py")
    (finding,) = normalize_gitleaks(report, run=RUN, tool=TOOL, repo_root=tmp_path)
    assert finding.location is not None
    assert finding.location.path == "app/config.py"


def test_report_that_is_not_a_list_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"RuleID": "x"}', encoding="utf-8")
    with pytest.raises(NormalizationError, match="list"):
        load_gitleaks_report(bad)


def test_empty_report_produces_empty_output(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    assert _normalize(load_gitleaks_report(empty)) == ""


def test_cli_writes_ndjson(tmp_path: Path) -> None:
    out = tmp_path / "findings.ndjson"
    result = CliRunner().invoke(
        app,
        [
            "normalize",
            "gitleaks",
            str(FIXTURES / "report.json"),
            "--out",
            str(out),
            "--repo",
            RUN.repo,
            "--commit",
            RUN.commit,
            "--context",
            "pr",
            "--ref",
            "refs/pull/7/merge",
            "--run-id",
            "1001",
            "--tool-version",
            "8.30.1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8") == (FIXTURES / "expected.ndjson").read_text(encoding="utf-8")


def test_cli_failure_never_leaves_an_older_findings_file(tmp_path: Path) -> None:
    # A stale file from an earlier run could be read by a later step and lead to a wrong PASS.
    out = tmp_path / "findings.ndjson"
    out.write_text('{"stale": true}\n', encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "normalize", "gitleaks", str(FIXTURES / "redacted.json"),
            "--out", str(out),
            "--repo", RUN.repo, "--commit", RUN.commit, "--context", "pr",
            "--tool-version", "8.30.1",
        ],
    )  # fmt: skip
    assert result.exit_code == 3
    assert not out.exists()


def test_cli_malformed_report_exits_3_not_1(tmp_path: Path) -> None:
    report = _report()
    report[0]["EndLine"] = "x"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(report), encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "normalize", "gitleaks", str(bad), "--out", str(tmp_path / "o.ndjson"),
            "--repo", RUN.repo, "--commit", RUN.commit, "--context", "pr", "--tool-version", "8.30.1",
        ],
    )  # fmt: skip
    assert result.exit_code == 3, result.output


def test_cli_fails_closed_with_dedicated_exit_code(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "normalize",
            "gitleaks",
            str(FIXTURES / "redacted.json"),
            "--out",
            str(tmp_path / "out.ndjson"),
            "--repo",
            RUN.repo,
            "--commit",
            RUN.commit,
            "--context",
            "pr",
            "--tool-version",
            "8.30.1",
        ],
    )
    assert result.exit_code == 3
    assert not (tmp_path / "out.ndjson").exists()
