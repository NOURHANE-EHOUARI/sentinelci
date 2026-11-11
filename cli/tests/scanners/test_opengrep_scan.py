"""`sentinel scan sast`: Opengrep, never configured or silenced by the scanned repository (task A1).

Unit tests use a fake `opengrep` script pinned in a test lock. Integration tests use the real binary and run
only when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners import runner
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.opengrep import OFFLINE_ENV, escaping_links, scan_sast_with_run

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
FIXTURE = Path(__file__).resolve().parents[1] / "normalize" / "fixtures" / "opengrep" / "results.json"
SHELL = 'import subprocess\n\n\ndef f(name):\n    subprocess.run("ls " + name, shell=True)\n'
JS_SHELL = 'const cp = require("child_process");\nfunction f(name) {\n  cp.exec("ls " + name);\n}\n'


def _result(target: Path) -> dict[str, Any]:
    """A real Opengrep result (from the normalizer fixture), moved under `target`."""
    result: dict[str, Any] = json.loads(FIXTURE.read_text())[2]  # python-sql-built-from-strings
    result["path"] = str(target.resolve() / "app" / "sql.py")
    return result


def fake_opengrep(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    report: dict[str, Any] | str | None = None,
    exit_code: int = 0,
) -> tuple[Path, Path]:
    """A fake opengrep that records its call and prints `report` (JSON) on stdout."""
    record = tmp_path / "record"
    record.mkdir()
    payload = tmp_path / "report.json"
    text = (
        report
        if isinstance(report, str)
        else json.dumps(report or {"version": "1.0.0", "results": [], "errors": []})
    )
    payload.write_text(text)
    script = f"""printf '%s\\n' "$@" > {record}/argv
env > {record}/env
pwd > {record}/cwd
cat {payload}
exit {exit_code}
"""
    _, dest = install_script(tmp_path, releases, write_lock, script, tool="opengrep")
    return dest, record


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "sql.py").write_text("def f(cur, uid):\n    cur.execute(f'SELECT {uid}')\n")
    return target


def _scan(tmp_path: Path, dest: Path, target: Path, repo_root: Path | None = None):  # type: ignore[no-untyped-def]
    return scan_sast_with_run(
        target,
        lock=load_lock(tmp_path / "tools.lock.toml"),
        tools_dir=dest,
        repo_root=repo_root,
        platform=PLATFORM,
    )


def test_opengrep_runs_isolated_with_sentinelcis_rules_only(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("SEMGREP_RULES", "p/default")  # a SEMGREP_* variable of the job never reaches Opengrep
    target = _target(tmp_path)
    dest, record = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [], "errors": []}
    )
    scan = _scan(tmp_path, dest, target)
    argv = (record / "argv").read_text().splitlines()
    assert argv[:2] == ["scan", "--config"] and argv[2].endswith(os.path.join("configs", "opengrep"))
    assert argv[3:] == [
        "--json", "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore",
        "--x-ignore-semgrepignore-files", "--disable-version-check", "--max-target-bytes=0", "--timeout=0",
        "--", str(target.resolve()),
    ]  # fmt: skip
    env = dict(line.split("=", 1) for line in (record / "env").read_text().splitlines() if "=" in line)
    assert "GITHUB_TOKEN" not in env and "SEMGREP_RULES" not in env
    assert all(env.get(key) == value for key, value in OFFLINE_ENV.items())
    cwd = Path((record / "cwd").read_text().strip())
    assert not cwd.is_relative_to(target) and not cwd.exists(), "a private, empty working directory"
    assert (scan.results, scan.warnings, scan.run.stdout) == ([], [], "")


@pytest.mark.parametrize(
    ("report", "exit_code", "message"),
    [
        (None, 2, "exited with code 2"),
        ("", 0, "no `results` list"),
        ("{not json", 0, "unreadable JSON"),
        ({"version": "1.0.0", "results": {}, "errors": []}, 0, "no `results` list"),
        ({"version": "1.0.0", "results": ["x"], "errors": []}, 0, "results are not objects"),
        ({"version": "9.9.9", "results": [], "errors": []}, 0, "version '9.9.9', the lock pins 1.0.0"),
        ({"version": "1.0.0", "results": []}, 0, "no `errors` list"),
        ({"version": "1.0.0", "results": [], "errors": ["x"]}, 0, "malformed error entry"),
        ({"version": "1.0.0", "results": [],
          "errors": [{"level": "error", "type": "Fatal error", "path": "a.py"}]},
         0, "could not scan everything: Fatal error in a.py"),
        ({"version": "1.0.0", "results": [], "errors": [{"type": ["Timeout", []]}]},
         0, "could not scan everything: Timeout"),
    ],
    ids=["crash", "no-output", "unreadable", "results-not-list", "result-not-object", "other-version",
         "no-errors", "error-not-object", "fatal-error", "error-without-level"],
)  # fmt: skip
def test_unusable_runs_fail_closed(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    report: dict[str, Any] | str | None,
    exit_code: int,
    message: str,
) -> None:
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report, exit_code)
    with pytest.raises(ScannerError, match=message):
        _scan(tmp_path, dest, _target(tmp_path))


def _span(start: int, end: int) -> dict[str, Any]:
    return {"start": {"line": start, "col": 1, "offset": 0}, "end": {"line": end, "col": 2, "offset": 1}}


def _parse_error(
    target: Path, name: str, *spans: tuple[int, int], kind: str = "PartialParsing"
) -> dict[str, Any]:
    """A parse error as Opengrep 1.33.1 writes it: a warning, its spans twice (in `type` and `spans`)."""
    path = str(target.resolve() / name)
    located = [{"path": path, **_span(start, end)} for start, end in spans]
    error: dict[str, Any] = {"code": 3, "level": "warn", "path": path, "message": "Syntax error at line ..."}
    if kind == "PartialParsing":
        error |= {"type": [kind, located], "spans": [{"file": path, **_span(s, e)} for s, e in spans]}
    else:
        error["type"] = kind
    return error


def _gap_scan(  # type: ignore[no-untyped-def]
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    errors: Callable[[Path], list[dict[str, Any]]],
    text: str = "x = 1\n" * 10,
):
    target = _target(tmp_path)
    (target / "app" / "w.py").write_text(text)
    report = {"version": "1.0.0", "results": [], "errors": errors(target)}
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report)
    return _scan(tmp_path, dest, target)


W, TEN = "app/w.py", "x = 1\n" * 10


@pytest.mark.parametrize(
    ("errors", "text", "skipped"),
    [
        (lambda t: [_parse_error(t, W, (3, 3))], TEN, "1 of 10"),
        (lambda t: [_parse_error(t, W, (1, 5))], TEN, "5 of 10"),  # exactly half
        (lambda t: [_parse_error(t, W, (1, 3), (3, 5))], TEN, "5 of 10"),  # spans that overlap
        (lambda t: [_parse_error(t, W, (2, 4)), _parse_error(t, W, (3, 5))], TEN, "4 of 10"),
        (lambda t: [_parse_error(t, W, (1, 4), (2, 3))], TEN, "4 of 10"),  # a span inside another
        (lambda t: [_parse_error(t, W, (8, 40))], TEN, "3 of 10"),  # past the last line
        (lambda t: [_parse_error(t, W, (2, 2))], "x = 1\nx = 2\nx = 3", "1 of 3"),  # no final newline
        (lambda t: [_parse_error(t, W, (7, 8)), _parse_error(t, W, (1, 2))], TEN, "4 of 10"),  # any order
        (lambda t: [_parse_error(t, W, (1, 4)) | {"spans": None}], TEN, "4 of 10"),  # in `type` only
        (lambda t: [_parse_error(t, W, (1, 4)) | {"type": ["PartialParsing", []]}], TEN, "4 of 10"),
    ],
    ids=["one-line", "exactly-half", "overlapping-spans", "overlapping-entries", "nested-spans",
         "past-the-end", "no-final-newline", "entries-in-reverse-order", "type-locations-only",
         "spans-only"],
)  # fmt: skip
def test_a_file_parsed_in_part_for_at_most_half_of_its_lines_is_a_warning(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    errors: Callable[[Path], list[dict[str, Any]]],
    text: str,
    skipped: str,
) -> None:
    scan = _gap_scan(tmp_path, releases, write_lock, errors, text)
    assert scan.warnings == [f"PartialParsing in app/w.py: {skipped} lines not analysed"]


def test_each_gap_is_listed_with_its_lines_and_the_text_opengrep_skipped(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    """#40 review: each smaller gap becomes a finding, so the scan says which lines and gives their text.
    Overlapping or adjacent spans are one gap; a span past the last line stops there."""
    text = "".join(f"line {n}\n" for n in range(1, 11))
    scan = _gap_scan(
        tmp_path, releases, write_lock,
        lambda t: [
            _parse_error(t, W, (2, 3), (3, 4)), _parse_error(t, W, (7, 7)), _parse_error(t, W, (8, 8)),
        ],
        text,
    )  # fmt: skip
    assert [(g.path, g.start, g.end, g.error) for g in scan.gaps] == [
        ("app/w.py", 2, 4, "PartialParsing"), ("app/w.py", 7, 8, "PartialParsing"),
    ]  # fmt: skip
    assert scan.gaps[0].text == "line 2\nline 3\nline 4\n"


def test_a_gap_past_the_last_line_stops_there(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    scan = _gap_scan(tmp_path, releases, write_lock, lambda t: [_parse_error(t, W, (9, 40))], TEN)
    assert [(g.start, g.end, g.text) for g in scan.gaps] == [(9, 10, "x = 1\nx = 1\n")]


@pytest.mark.parametrize(
    ("errors", "message"),
    [
        (lambda t: [_parse_error(t, W, (1, 6))], "PartialParsing in app/w.py: 6 of 10 lines"),
        (lambda t: [_parse_error(t, W, (1, 3)), _parse_error(t, W, (7, 9))], ": 6 of 10 lines"),
        (lambda t: [_parse_error(t, W, (1, 2), (4, 5), (9, 10))], ": 6 of 10 lines"),
        (lambda t: [_parse_error(t, W, kind="Syntax error")], "Syntax error in app/w.py: 10 of 10 lines"),
        (lambda t: [_parse_error(t, W, (1, 1)), _parse_error(t, W, kind="Lexical error")],
         "PartialParsing in app/w.py: 10 of 10 lines"),  # an entry without a span: the whole file
        (lambda t: [_parse_error(t, W, kind="Other syntax error"), _parse_error(t, W, (1, 1))],
         "Other syntax error in app/w.py: 10 of 10 lines"),  # still the whole file
        (lambda t: [_parse_error(t, "app/gone.py", (1, 1))], "in app/gone.py: the file cannot be read"),
        (lambda t: [_parse_error(t, W, (1, 1)) | {"level": "error"}], ": PartialParsing in app/w.py$"),
        (lambda t: [{"level": "warn", "type": "Too many matches", "path": str(t.resolve() / W)}],
         "could not scan everything: Too many matches in app/w.py$"),
        (lambda t: [{"level": "warn", "type": ["PartialParsing", []], "path": "/elsewhere/w.py"}],
         "could not scan everything: PartialParsing in /elsewhere/w.py$"),
        (lambda t: [{"level": "warn", "type": [["PartialParsing"]], "path": "w.py"}], "could not scan"),
    ],
    ids=["over-half", "two-entries", "three-spans", "syntax-error-without-span", "an-entry-without-span",
         "whole-file-then-a-span", "unreadable-file", "parse-error-above-warning", "too-many-matches",
         "outside-the-target", "odd-type"],
)  # fmt: skip
def test_a_file_mostly_not_analysed_or_any_other_problem_fails_closed(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    errors: Callable[[Path], list[dict[str, Any]]],
    message: str,
) -> None:
    with pytest.raises(ScannerError, match=message):
        _gap_scan(tmp_path, releases, write_lock, errors)


@pytest.mark.parametrize(
    "spans",
    [{"spans": {}}, {"spans": ["x"]}, {"spans": [{"start": {"line": 1}}]}, {"spans": [_span(3, 2)]},
     {"spans": [_span(0, 2)]}, {"spans": [{"start": {"line": True}, "end": {"line": 2}}]},
     {"type": ["PartialParsing", "x"]}],
    ids=["not-a-list", "not-an-object", "no-end", "reversed", "line-zero", "bool-line",
         "locations-not-a-list"],
)  # fmt: skip
def test_malformed_parse_error_spans_fail_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], spans: dict[str, Any]
) -> None:
    with pytest.raises(ScannerError, match="malformed error span"):
        _gap_scan(tmp_path, releases, write_lock, lambda t: [_parse_error(t, W, (1, 1)) | spans])


@pytest.mark.parametrize(
    "case", ["file-link", "directory-link", "loop", "outside-the-root", "not-a-directory"]
)
def test_bad_targets_never_run_opengrep(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], case: str
) -> None:
    dest, record = fake_opengrep(tmp_path, releases, write_lock)
    target, root = _target(tmp_path), None
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lib.py").write_text(SHELL)
    expected = "symbolic links leave the scanned tree or loop"
    if case == "file-link":
        (target / "app" / "lib.py").symlink_to(outside / "lib.py")
    elif case == "directory-link":
        (target / "vendor").symlink_to(outside)
    elif case == "loop":
        (target / "a.py").symlink_to("b.py")
        (target / "b.py").symlink_to("a.py")
    elif case == "outside-the-root":
        root, expected = target, "outside the repository root"
        target = outside
    else:
        target, expected = target / "app" / "sql.py", "is not a directory"
    with pytest.raises(ScannerError, match=expected):
        _scan(tmp_path, dest, target, root)
    assert not (record / "argv").exists(), "the scanner must not even start"


def test_links_inside_the_tree_are_fine(tmp_path: Path) -> None:
    target = _target(tmp_path)
    (target / "alias.py").symlink_to(target / "app" / "sql.py")
    (target / "lib").symlink_to(target / "app")
    assert escaping_links(target) == []


def _cli(
    tmp_path: Path, dest: Path, target: Path, out: Path, repo_root: Path, *extra: str
) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "scan", "sast", str(target), "--out", str(out), "--repo", "o/r", "--commit", "0" * 40,
            "--context", "pr", "--repo-root", str(repo_root), "--lock", str(tmp_path / "tools.lock.toml"),
            "--tools-dir", str(dest),
            "--platform", PLATFORM,
            *extra,
        ],
    )  # fmt: skip
    return result.exit_code, result.output


def test_cli_writes_repository_relative_sast_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    services = repo / "services"
    (services / "app").mkdir(parents=True)
    (services / "app" / "sql.py").write_text("def f(cur, uid):\n    cur.execute(f'SELECT {uid}')\n")
    (services / "app" / "w.js").write_text("let a = 1;\nlet b = 2;\n")
    warn = _parse_error(services, "app/w.js", (2, 2))
    report = {"version": "1.0.0", "results": [_result(services)], "errors": [warn]}
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report)
    out = tmp_path / "out" / "sast.ndjson"
    code, output = _cli(tmp_path, dest, services, out, repo)
    assert code == 0, output
    findings = {f["rule_id"]: f for f in (json.loads(line) for line in out.read_text().splitlines())}
    finding, gap = findings["python-sql-built-from-strings"], findings["sentinel-sast-not-analysed"]
    assert finding["category"] == "SAST" and finding["location"]["path"] == "services/app/sql.py"
    assert finding["tool"] == {"name": "opengrep", "version": "1.0.0"}
    assert gap["location"] == {"path": "services/app/w.js", "start_line": 2, "end_line": 2}
    assert (gap["category"], gap["severity"]) == ("SAST", "HIGH") and "let b" not in gap["message"]
    assert "2 finding(s)" in output and "PartialParsing in app/w.js: 1 of 2 lines not analysed" in output


def test_cli_failure_leaves_no_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    target = _target(tmp_path)
    dest, _ = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [{"check_id": "x"}], "errors": []}
    )
    out = tmp_path / "sast.ndjson"
    out.write_text("stale")
    code, output = _cli(tmp_path, dest, target, out, target)
    assert code == 3 and "FAIL CLOSED" in output and "is not SentinelCI's" in output
    assert not out.exists()


def test_cli_a_file_mostly_not_analysed_exits_3_even_with_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    target = _target(tmp_path)
    (target / "app" / "mid.py").write_text("x = 1\n" * 610)
    report = {
        "version": "1.0.0",
        "results": [_result(target)],
        "errors": [_parse_error(target, "app/mid.py", (1, 609))],
    }
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report)
    out = tmp_path / "sast.ndjson"
    code, output = _cli(tmp_path, dest, target, out, target)
    assert code == 3 and "FAIL CLOSED" in output
    assert "PartialParsing in app/mid.py: 609 of 610 lines not analysed" in output
    assert not out.exists()


# ---------------------------------------------------------------- tool status (the gate's SC-010, A3)


def _validator() -> Any:
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[3]
    return Draft202012Validator(json.loads((root / "schemas" / "tool-status.v1.json").read_text("utf-8")))


def test_cli_records_an_ok_status_for_the_verified_binary_after_the_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    target = _target(tmp_path)
    dest, _ = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [_result(target)], "errors": []}
    )
    out, status = tmp_path / "sast.ndjson", tmp_path / "status.json"
    code, output = _cli(tmp_path, dest, target, out, target, "--tool-status-out", str(status))
    assert code == 0, output
    document = json.loads(status.read_text())
    assert not list(_validator().iter_errors(document))
    binary = hashlib.sha256((dest / "bin" / "opengrep").read_bytes()).hexdigest()
    assert document["tools"] == {
        "opengrep": {"version": "1.0.0", "binary_sha256": binary, "artifact_sha256": binary, "status": "ok"}
    }
    lock_bytes = (tmp_path / "tools.lock.toml").read_bytes()
    assert document["lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    assert len(out.read_text().splitlines()) == 1


@pytest.mark.parametrize(
    ("how", "status_name", "detail"),
    [
        ("crash", "failed", "exited with code 2"),
        ("untrusted", "failed", "is not SentinelCI's"),
        ("timeout", "timeout", "timed out after 37 s"),
        ("tampered", "integrity_mismatch", ""),
    ],
)
def test_cli_records_a_failure_so_the_gate_blocks_it(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
    how: str,
    status_name: str,
    detail: str,
) -> None:
    target = _target(tmp_path)
    results = [{"check_id": "x"}] if how == "untrusted" else []
    report = {"version": "1.0.0", "results": results, "errors": []}
    dest, record = fake_opengrep(tmp_path, releases, write_lock, report, exit_code=2 if how == "crash" else 0)
    if how == "timeout":

        def slow(*args: Any, **kwargs: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd="opengrep", timeout=kwargs["timeout"])

        monkeypatch.setattr(runner.subprocess, "run", slow)
    if how == "tampered":
        (dest / "bin" / "opengrep").write_text(f"#!/bin/sh\ntouch {record}/tampered-ran\n")
    out, status = tmp_path / "sast.ndjson", tmp_path / "status.json"
    out.write_text("stale")
    status.write_text("stale")
    code, output = _cli(
        tmp_path, dest, target, out, target, "--tool-status-out", str(status), "--timeout", "37"
    )
    assert code == 3 and "FAIL CLOSED" in output, output
    assert not out.exists() and not (record / "tampered-ran").exists()
    document = json.loads(status.read_text())
    assert not list(_validator().iter_errors(document))
    outcome = document["tools"]["opengrep"]
    assert outcome["status"] == status_name and detail in outcome["detail"] and "binary_sha256" not in outcome
    assert outcome["version"] == "1.0.0", "the pinned version: it may never have run"


def test_cli_writes_no_status_without_a_lock(tmp_path: Path) -> None:
    # Nothing to vouch for: no status at all, which the gate reports as SC-010 "Tool status missing".
    target = _target(tmp_path)
    status = tmp_path / "status.json"
    status.write_text("stale")
    code, _ = _cli(tmp_path, tmp_path / "tools", target, tmp_path / "out.ndjson", target,
                   "--tool-status-out", str(status))  # fmt: skip
    assert code == 3 and not status.exists()


def test_cli_passes_its_time_limit_to_opengrep(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.cli as cli

    seen: dict[str, object] = {}
    real = cli.scan_sast_with_run

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "scan_sast_with_run", spy)
    target = _target(tmp_path)
    dest, _ = fake_opengrep(tmp_path, releases, write_lock)
    code, output = _cli(tmp_path, dest, target, tmp_path / "out.ndjson", target, "--timeout", "1234")
    assert code == 0, output
    assert seen["timeout_s"] == 1234


# ---------------------------------------------------------------- the real Opengrep

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
@pytest.mark.integration
def test_real_opengrep_cannot_be_silenced_by_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each file below is skipped or hidden by a plain `opengrep scan`; SentinelCI reports all of them."""
    target = tmp_path / "repo"
    files = {
        "app/plain.py": SHELL,
        "app/semgrepignored.py": SHELL,
        "app/nosem.py": SHELL.replace("shell=True)", "shell=True)  # nosemgrep"),
        "app/gitignored.py": SHELL,
        "app/big.py": SHELL + "# padding\n" * 120_000,  # over Opengrep's default 1 MB limit
        "tests/test_x.py": SHELL,
        "node_modules/pkg/x.py": SHELL,
    }
    for name, text in files.items():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(text)
    (target / ".semgrepignore").write_text("app/semgrepignored.py\n")
    (target / ".gitignore").write_text("app/gitignored.py\n")
    (target / ".semgrep.yml").write_text(  # a repository rule file: never loaded
        "rules:\n  - id: their-rule\n    languages: [python]\n    severity: ERROR\n    message: x\n"
        "    pattern: def $F(...): ...\n"
    )
    monkeypatch.setenv("SEMGREP_RULES", str(target / ".semgrep.yml"))
    monkeypatch.chdir(target)  # the repository as working directory, as in CI: still ignored
    scan = scan_sast_with_run(target, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    found = {str(Path(r["path"]).relative_to(target.resolve())): r for r in scan.results}
    assert set(found) == set(files)
    assert {r["check_id"] for r in scan.results} == {"python-shell-command-from-data"}
    assert [name for name, r in found.items() if r["extra"]["is_ignored"]] == ["app/nosem.py"]
    assert scan.run.version == "1.33.1" and scan.warnings == []


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
@pytest.mark.integration
def test_real_opengrep_too_many_matches_in_a_file_fails_closed(tmp_path: Path) -> None:
    """Over 10,000 matches in a file, Opengrep drops all of the file's results with a mere warning."""
    target = tmp_path / "repo"
    target.mkdir()
    (target / "many.py").write_text(SHELL + "def g(x):\n    return eval(x)\n" * 10_001)
    with pytest.raises(ScannerError, match=r"could not scan everything: Too many matches in many\.py$"):
        scan_sast_with_run(target, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))


# Opengrep chooses files by extension, and an executable file by its `#!` line. Nothing else is scanned.
SCANNED = {
    "a.py": SHELL, "a.pyi": SHELL, "a.js": JS_SHELL, "a.mjs": JS_SHELL, "a.cjs": JS_SHELL,
    "a.jsx": JS_SHELL, "a.ts": JS_SHELL, "a.tsx": JS_SHELL, "bin/py-exec": "#!/usr/bin/env python3\n" + SHELL,
    "bin/node-exec": "#!/usr/bin/env node\n" + JS_SHELL,
}  # fmt: skip
NOT_SCANNED = {
    "a.pyw": SHELL, "a.mts": JS_SHELL, "a.cts": JS_SHELL, "a.vue": JS_SHELL,
    "bin/py-script": "#!/usr/bin/env python3\n" + SHELL,
    "bin/node-script": "#!/usr/bin/env node\n" + JS_SHELL,
}  # fmt: skip


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
@pytest.mark.integration
def test_real_opengrep_scans_these_files_only(tmp_path: Path) -> None:
    """What the README and SPEC §5 say is scanned: a script with no extension only if it is executable."""
    target = tmp_path / "repo"
    for name, code in {**SCANNED, **NOT_SCANNED}.items():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(code)
    for name in ("bin/py-exec", "bin/node-exec"):
        (target / name).chmod(0o755)
    scan = scan_sast_with_run(target, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    assert {str(Path(r["path"]).relative_to(target.resolve())) for r in scan.results} == set(SCANNED)
