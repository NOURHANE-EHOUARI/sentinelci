"""Opengrep JSON -> Finding v1, category SAST (task A2).

The fixture is Opengrep 1.33.1's real `results` with SentinelCI's rules on four small files (scanned at a
temporary path, rewritten to /scan/target): the same command twice in one file, a SQL statement built from an
f-string, TLS verification turned off under a `# nosemgrep` comment, and HTML built from data.
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
from sentinelci.normalize.fingerprint import sast_fingerprint
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.normalize.opengrep import normalize_opengrep
from sentinelci.scanners.opengrep import rule_ids

FIXTURES = Path(__file__).parent / "fixtures" / "opengrep"
TARGET = Path("/scan/target")
RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")
TOOL = Tool(name="opengrep", version="1.33.1")
RULES = rule_ids()


def _results() -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = json.loads((FIXTURES / "results.json").read_text(encoding="utf-8"))
    return data


def _normalize(results: list[dict[str, Any]], scan_root: str = "."):  # type: ignore[no-untyped-def]
    return normalize_opengrep(
        results, run=RUN, tool=TOOL, rules=RULES, scan_target=TARGET, scan_root=scan_root
    )


def test_matches_golden_file() -> None:
    output = dumps_ndjson(_normalize(_results()))
    golden = FIXTURES / "expected.ndjson"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.write_text(output, encoding="utf-8")
    assert output == golden.read_text(encoding="utf-8")


def test_every_finding_satisfies_the_contract(finding_validator: Draft202012Validator) -> None:
    for line in dumps_ndjson(_normalize(_results())).splitlines():
        errors = [e.message for e in finding_validator.iter_errors(json.loads(line))]
        assert not errors, errors


def test_findings_say_what_and_where_and_keep_no_code() -> None:
    findings = {f.rule_id: f for f in _normalize(_results(), scan_root="demo-shop/services")}
    assert set(findings) == {
        "python-shell-command-from-data", "python-sql-built-from-strings", "python-tls-verification-disabled",
        "js-html-from-data",
    }  # fmt: skip
    sql = findings["python-sql-built-from-strings"]
    assert (sql.category, sql.severity, sql.cwe) == ("SAST", "HIGH", ["CWE-89"])
    assert sql.location == Location(path="demo-shop/services/app/sql.py", start_line=2, end_line=2)
    assert sql.title == "SQL statement built from strings"
    assert sql.severity_source == "ERROR (confidence HIGH)"
    assert findings["python-tls-verification-disabled"].severity == "MEDIUM"
    output = dumps_ndjson(list(findings.values()))
    for code in ("subprocess.run", "SELECT", "verify=False", "innerHTML", "/scan/target"):
        assert code not in output


def test_the_same_code_twice_in_a_file_is_one_finding_with_other_locations() -> None:
    (shell,) = [f for f in _normalize(_results()) if f.rule_id == "python-shell-command-from-data"]
    assert shell.schema_version == "1.1"
    assert shell.location == Location(path="app/dup.py", start_line=5, end_line=5)
    assert shell.other_locations == [Location(path="app/dup.py", start_line=9, end_line=9)]


def test_a_match_under_a_nosemgrep_comment_is_kept_and_says_so() -> None:
    (tls,) = [f for f in _normalize(_results()) if f.rule_id == "python-tls-verification-disabled"]
    assert tls.message is not None and "does not honour" in tls.message


def _sql() -> dict[str, Any]:
    result = copy.deepcopy(next(r for r in _results() if r["check_id"] == "python-sql-built-from-strings"))
    return result


def test_a_moved_or_reindented_match_keeps_its_id_and_new_code_gets_a_new_one() -> None:
    before = _normalize([_sql()])[0]
    moved = _sql()
    moved["start"]["line"] += 7
    moved["end"]["line"] += 7
    moved["extra"]["lines"] = "        " + moved["extra"]["lines"].strip()
    after = _normalize([moved])[0]
    assert (
        after.id
        == before.id
        == sast_fingerprint("python-sql-built-from-strings", "app/sql.py", _sql()["extra"]["lines"])
    )
    assert after.location is not None and after.location.start_line == 9
    changed = _sql()
    changed["extra"]["lines"] = changed["extra"]["lines"].replace("users", "orders")
    assert _normalize([_sql(), changed])[0].id != _normalize([_sql(), changed])[1].id


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "LOW"), ("CRITICAL", "CRITICAL"), ("LOW", "LOW")],
)
def test_severities(severity: str, expected: str) -> None:
    result = _sql()
    result["extra"]["severity"] = severity
    assert _normalize([result])[0].severity == expected


def test_the_most_severe_match_gives_the_severity_and_its_source() -> None:
    first, second = _sql(), _sql()
    first["extra"]["severity"] = "INFO"
    second["start"]["line"] = second["end"]["line"] = 12
    (finding,) = _normalize([first, second])
    assert (finding.severity, finding.severity_source) == ("HIGH", "ERROR (confidence HIGH)")


def _broken(edit: Any) -> list[dict[str, Any]]:
    result = _sql()
    edit(result)
    return [result]


@pytest.mark.parametrize(
    ("results", "message"),
    [
        (_broken(lambda r: r.update(check_id="their-own-rule")), "is not SentinelCI's"),
        (_broken(lambda r: r.pop("check_id")), "no usable check_id"),
        (_broken(lambda r: r["extra"].update(lines="")), "no usable lines"),
        (_broken(lambda r: r["extra"].update(severity="FATAL")), "unknown severity"),
        (_broken(lambda r: r["extra"]["metadata"].update(confidence="SURE")), "unknown confidence"),
        (_broken(lambda r: r["extra"]["metadata"].update(cwe=["CWE-89: SQL Injection"])), "malformed CWE"),
        (_broken(lambda r: r["extra"]["metadata"].pop("title")), "no usable title"),
        (_broken(lambda r: r.update(path="/elsewhere/app/sql.py")), "outside the repository"),
        (_broken(lambda r: r.update(path="/scan/target/../escape.py")), "outside the repository|escapes"),
        (_broken(lambda r: r["start"].update(line=0)), "no start line"),
        (_broken(lambda r: r["end"].update(line=True)), "no end line"),
        (_broken(lambda r: r["end"].update(line=1) or r["start"].update(line=2)), "ends before it starts"),
    ],
    ids=["foreign-rule", "no-rule", "no-snippet", "unknown-severity", "unknown-confidence", "cwe-with-text",
         "no-title", "outside-target", "dot-dot", "line-zero", "bool-line", "reversed-span"],
)  # fmt: skip
def test_malformed_results_fail_closed(results: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(NormalizationError, match=message):
        _normalize(results)
