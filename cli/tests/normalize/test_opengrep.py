"""Opengrep JSON -> Finding v1, category SAST (task A2).

The fixture is Opengrep 1.33.1's real `results` with SentinelCI's rules on four small files (scanned at a
temporary path, rewritten to /scan/target): the same command twice in one file (two findings), a SQL
statement built from an f-string, TLS verification turned off under a `# nosemgrep` comment, and HTML built
from data.
"""

import copy
import hashlib
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
from sentinelci.normalize.opengrep import NOT_ANALYSED_RULE, ParseGap, normalize_opengrep
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


def test_the_same_code_twice_in_a_file_is_one_finding_per_place_numbered_in_line_order() -> None:
    first, second = sorted(
        (f for f in _normalize(_results()) if f.rule_id == "python-shell-command-from-data"),
        key=lambda f: f.location.start_line if f.location else 0,
    )
    base = sast_fingerprint("python-shell-command-from-data", "app/dup.py", _results()[0]["extra"]["lines"])
    assert (first.id, first.location) == (base, Location(path="app/dup.py", start_line=5, end_line=5))
    assert (second.id, second.location) == (
        hashlib.sha256(f"{base}|2".encode()).hexdigest(),
        Location(path="app/dup.py", start_line=9, end_line=9),
    )
    assert first.schema_version == second.schema_version == "1.0"
    assert first.other_locations is second.other_locations is None


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


def test_one_place_reported_twice_is_one_finding_with_the_most_severe_match() -> None:
    first, second = _sql(), _sql()
    first["extra"]["severity"] = "INFO"
    (finding,) = _normalize([first, second])
    assert (finding.severity, finding.severity_source) == ("HIGH", "ERROR (confidence HIGH)")
    assert finding.id == _normalize([_sql()])[0].id


def _at(line: int, **extra: Any) -> dict[str, Any]:
    """The SQL match of the fixture, at another line of the same file."""
    result = _sql()
    result["start"]["line"] = result["end"]["line"] = line
    result["extra"].update(extra)
    return result


def _ids(results: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """(id, line) of each finding, in line order."""
    findings = _normalize(results)
    return sorted(((f.id, f.location.start_line if f.location else 0) for f in findings), key=lambda x: x[1])


def _nth(base: str, n: int) -> str:
    return hashlib.sha256(f"{base}|{n}".encode()).hexdigest()


def test_a_copy_of_a_known_match_below_it_is_a_new_finding() -> None:
    ((base, _),) = _ids([_at(2)])
    assert _ids([_at(2), _at(9)]) == [(base, 2), (_nth(base, 2), 9)]


def test_a_copy_above_takes_the_first_id_and_the_count_still_goes_up() -> None:
    """The trade-off of numbering in line order: the new id lands on the older line, but there is one."""
    ((base, _),) = _ids([_at(9)])
    assert _ids([_at(9), _at(2)]) == [(base, 2), (_nth(base, 2), 9)]


def test_three_copies_are_three_findings() -> None:
    ((base, _),) = _ids([_at(4)])
    assert _ids([_at(30), _at(4), _at(17)]) == [(base, 4), (_nth(base, 2), 17), (_nth(base, 3), 30)]


def test_each_file_numbers_its_own_copies() -> None:
    def elsewhere(line: int) -> dict[str, Any]:
        result = _at(line)
        result["path"] = "/scan/target/app/other.py"
        return result

    findings = _normalize([_at(2), elsewhere(3), _at(8), elsewhere(1)])
    by_file: dict[str, list[tuple[int, str]]] = {}
    for finding in findings:
        assert finding.location is not None
        by_file.setdefault(finding.location.path, []).append((finding.location.start_line, finding.id))
    for path, lines in (("app/sql.py", (2, 8)), ("app/other.py", (1, 3))):
        base = sast_fingerprint("python-sql-built-from-strings", path, _sql()["extra"]["lines"])
        assert sorted(by_file[path]) == [(lines[0], base), (lines[1], _nth(base, 2))]


def test_the_note_and_the_first_id_follow_line_order_not_report_order() -> None:
    """Two hits of the same code given in reverse line order, the second (the lower line) under nosemgrep."""
    findings = {f.id: f for f in _normalize([_at(12), _at(3, is_ignored=True)])}
    base = _normalize([_sql()])[0].id
    first, second = findings[base], findings[_nth(base, 2)]
    assert first.location == Location(path="app/sql.py", start_line=3, end_line=3)
    assert first.message is not None and "does not honour" in first.message
    assert second.location == Location(path="app/sql.py", start_line=12, end_line=12)
    assert second.message is not None and "does not honour" not in second.message


def test_one_place_reported_twice_keeps_the_nosemgrep_note_of_either_report() -> None:
    for results in ([_at(3), _at(3, is_ignored=True)], [_at(3, is_ignored=True), _at(3)]):
        (finding,) = _normalize(results)
        assert finding.message is not None and "does not honour" in finding.message


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


# ---------------------------------------------------------------- code Opengrep did not analyse (#40 review)

GAP_TEXT = "    def f[T](x: T) -> T:\n        return os.system(x)\n"


def _gap(path: str = "app/new.py", start: int = 12, end: int = 13, text: str = GAP_TEXT) -> ParseGap:
    return ParseGap(path=path, start=start, end=end, error="PartialParsing", text=text)


def _gaps(*gaps: ParseGap, scan_root: str = "."):  # type: ignore[no-untyped-def]
    return normalize_opengrep(
        [], run=RUN, tool=TOOL, rules=RULES, scan_target=TARGET, scan_root=scan_root, gaps=gaps
    )


def test_each_part_not_analysed_is_a_sast_high_finding_that_quotes_no_code(
    finding_validator: Draft202012Validator,
) -> None:
    (finding,) = _gaps(_gap(), scan_root="services")
    assert (finding.category, finding.severity, finding.rule_id) == ("SAST", "HIGH", NOT_ANALYSED_RULE)
    assert finding.rule_id == "sentinel-sast-not-analysed"
    assert finding.location == Location(path="services/app/new.py", start_line=12, end_line=13)
    assert finding.message.startswith(
        "Opengrep did not analyse lines 12-13 of services/app/new.py (PartialParsing)."
    )
    assert finding.id == sast_fingerprint(NOT_ANALYSED_RULE, "services/app/new.py", GAP_TEXT)
    output = dumps_ndjson([finding])
    for code in ("def f", "os.system", "return"):
        assert code not in output
    assert not [e.message for e in finding_validator.iter_errors(json.loads(output))]
    (one_line,) = _gaps(_gap(start=7, end=7))
    assert "did not analyse line 7 of app/new.py" in one_line.message


def test_a_gap_that_moves_or_is_re_indented_keeps_its_id_and_new_code_is_new() -> None:
    (first,) = _gaps(_gap())
    (moved,) = _gaps(_gap(start=40, end=41, text="\n" + GAP_TEXT.replace("    ", "  ")))
    (other,) = _gaps(_gap(text="    def g[T](x: T) -> T:\n        return x\n"))
    (elsewhere,) = _gaps(_gap(path="app/other.py"))
    assert moved.id == first.id
    assert len({first.id, other.id, elsewhere.id}) == 3


def test_the_same_gap_twice_in_a_file_is_one_finding_per_place_numbered_in_line_order() -> None:
    """A waiver for one gap never covers another, even with the same text in the same file."""
    later, earlier = _gap(start=30, end=31), _gap(start=2, end=3)
    findings = sorted(_gaps(later, earlier), key=lambda f: f.location.start_line)
    first = sast_fingerprint(NOT_ANALYSED_RULE, "app/new.py", GAP_TEXT)
    assert [f.id for f in findings] == [first, hashlib.sha256(f"{first}|2".encode()).hexdigest()]


def test_a_gap_and_a_rule_match_on_the_same_lines_are_two_findings() -> None:
    sql = next(r for r in _results() if r["check_id"] == "python-sql-built-from-strings")
    findings = normalize_opengrep(
        [sql], run=RUN, tool=TOOL, rules=RULES, scan_target=TARGET,
        gaps=[_gap(path="app/sql.py", start=2, end=2, text=sql["extra"]["lines"])],
    )  # fmt: skip
    assert sorted(f.rule_id for f in findings) == ["python-sql-built-from-strings", NOT_ANALYSED_RULE]
