"""Build and tests of an LLM code proposal (`sentinel remediate check` for `llm:code`, ADR-0014 decision 3).

The container is recorded, not run: what matters here is what it is asked to run, with which sandbox and which
trees, and how each of pytest's and Docker's answers is read. A real `docker` stand-in checks that the named
container is removed, even after a time-out.
"""

import json
import os
import shutil
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.remediation import Model, PatchProposal
from sentinelci.remediation import code
from sentinelci.remediation.code import CodeCheckError, Ran, check_code, docker_runner, service_of, summary_of
from sentinelci.remediation.proposal import proposal_id_of, unified_diff

from .conftest import NOW

SERVICE = "demo-shop/services/shop-api"
TARGET = f"{SERVICE}/app/db.py"
OLD = "def find(cur, q):\n    return cur.execute(f\"SELECT * FROM items WHERE name = '{q}'\")\n"
NEW = 'def find(cur, q):\n    return cur.execute("SELECT * FROM items WHERE name = ?", (q,))\n'
IMAGE = "python@sha256:" + "a" * 64
FINDING = "b" * 64
RULE = "python-sql-built-from-strings"
SECURITY = f"{SERVICE}/security_tests/test_python_sql_built_from_strings.py"
# A pass: the behaviour tests pass on the patch, the security test fails on the base and passes on the patch.
# pytest -q ends with its summary line: only a run whose summary agrees with its exit code counts.
PASSING = (Ran(0, "12 passed in 0.31s\n"), Ran(1, "3 failed in 0.11s\n"), Ran(0, "3 passed in 0.09s\n"))


def proposal_of(old: str, new: str, path: str = TARGET, strategy: str = "llm:code") -> PatchProposal:
    diff = unified_diff(path, old, new)
    return PatchProposal(
        schema_version="1.0",
        proposal_id=proposal_id_of(strategy, 1, [FINDING], diff),
        finding_ids=[FINDING],
        strategy=strategy,  # type: ignore[arg-type]
        diff=diff,
        files=[path],
        rationale="Bind the parameter instead of formatting it into the SQL text.",
        attempt=1,
        model=Model(name="gemma4:12b-it-qat", prompt_version="sentinel-patch-code/1"),
        created_at=NOW,
    )


def trees(tmp_path: Path, new: str = NEW, *, tests: bool = True, security: bool = True) -> tuple[Path, Path]:
    base = tmp_path / "base"
    (base / TARGET).parent.mkdir(parents=True)
    (base / TARGET).write_text(OLD, encoding="utf-8")
    if tests:
        (base / SERVICE / "tests").mkdir()
        (base / SERVICE / "tests" / "test_db.py").write_text("def test_find():\n    pass\n", encoding="utf-8")
    if security:
        (base / SECURITY).parent.mkdir()
        (base / SECURITY).write_text("def test_no_sql_text():\n    pass\n", encoding="utf-8")
    (base / "tests").mkdir()  # SentinelCI's own tests, at the repository root: never a service's
    (base / "tests" / "test_root.py").write_text("def test_root():\n    pass\n", encoding="utf-8")
    patched = tmp_path / "patched"
    shutil.copytree(base, patched)
    (patched / TARGET).write_text(new, encoding="utf-8")
    return base, patched


class Recorder:
    def __init__(self, *answers: Ran) -> None:
        self.answers = list(answers) or list(PASSING)
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str], timeout: int) -> Ran:
        self.calls.append(list(args))
        return self.answers.pop(0)


def flag(args: list[str], name: str) -> list[str]:
    return [args[i + 1] for i, value in enumerate(args) if value == name]


# ---------------------------------------------------------------- what runs, and where


def test_the_services_tests_run_against_the_patch_in_a_sandbox(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    run = Recorder()
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])
    behaviour, on_base, on_patch = run.calls
    for args in run.calls:
        assert args[:2] == ["run", "--rm"] and flag(args, "--name")[0].startswith("sentinel-tests-")
        for name, value in [("--network", "none"), ("--cap-drop", "ALL"), ("--user", "65534:65534"),
                            ("--security-opt", "no-new-privileges:true"), ("--pids-limit", "256"),
                            ("--memory", "1g"), ("--memory-swap", "1g"), ("--cpus", "2"),
                            ("--tmpfs", SCRATCH), ("--workdir", "/srv")]:  # fmt: skip
            assert flag(args, name) == [value], name
        assert "--read-only" in args and "--privileged" not in args and "-v" not in args
        assert flag(args, "--mount")[1:] == [
            f"type=bind,source={(base / SERVICE / 'tests').resolve()},target=/srv/tests,readonly",
            f"type=bind,source={(base / SERVICE / 'security_tests').resolve()},"
            "target=/srv/security_tests,readonly",
        ], "the base commit's tests and security tests, always, over the service's own"
        image = args.index(IMAGE)
        assert args[image + 1 : -1] == [
            "timeout", "-s", "KILL", "300",
            "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header",
        ]  # fmt: skip
    service = {"patched": f"type=bind,source={(patched / SERVICE).resolve()},target=/srv,readonly",
               "base": f"type=bind,source={(base / SERVICE).resolve()},target=/srv,readonly"}  # fmt: skip
    selected = "security_tests/test_python_sql_built_from_strings.py"
    assert (flag(behaviour, "--mount")[0], behaviour[-1]) == (service["patched"], "tests")
    assert (flag(on_base, "--mount")[0], on_base[-1]) == (service["base"], selected), "the weakness is real"
    assert (flag(on_patch, "--mount")[0], on_patch[-1]) == (service["patched"], selected), "and it is gone"
    assert checked.log == (
        "$ pytest tests (behaviour tests, patched code)\n12 passed in 0.31s\n\n"
        f"$ pytest {selected} ({selected}, base code, expected to fail)\n3 failed in 0.11s\n\n"
        f"$ pytest {selected} ({selected}, patched code)\n3 passed in 0.09s\n"
    )


@pytest.mark.parametrize(
    ("ran", "problem"),
    [
        (Ran(1, "1 failed in 0.01s\n"), f"{SERVICE}/tests failed on the patched code (pytest exit 1)"),
        (Ran(2, "interrupted\n"), f"{SERVICE}/tests failed on the patched code (pytest exit 2)"),
        (Ran(5, "no tests ran\n"), f"{SERVICE}/tests failed on the patched code (pytest exit 5)"),
        (Ran(124, "x\n"), "behaviour tests, patched code: did not finish within 300 s, or ran out of memory"),
        (Ran(137, "x\n"), "behaviour tests, patched code: did not finish within 300 s, or ran out of memory"),
        (
            Ran(-1, "x\n", timed_out=True),
            "behaviour tests, patched code: did not finish within 300 s, or ran out of memory",
        ),
    ],
    ids=["failed", "interrupted", "no-tests-collected", "timeout", "killed", "client-timeout"],
)
def test_only_pytests_exit_0_is_a_pass(tmp_path: Path, ran: Ran, problem: str) -> None:
    base, patched = trees(tmp_path)
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=Recorder(ran))
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, False, [f"tests: {problem}"])
    assert checked.log.endswith(ran.output), "kept as the feedback for a retry"


@pytest.mark.parametrize("returncode", [125, 126, 127])
def test_a_container_that_could_not_run_verifies_nothing(tmp_path: Path, returncode: int) -> None:
    base, patched = trees(tmp_path)
    with pytest.raises(CodeCheckError, match=f"could not run \\(docker exit {returncode}\\)"):
        check_code(
            proposal_of(OLD, NEW),
            base,
            patched,
            rule=RULE,
            test_image=IMAGE,
            run=Recorder(Ran(returncode, "")),
        )


def test_the_log_kept_is_the_end_of_the_output(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    output = "x" * 20_000 + "FAILED tests/test_db.py::test_find\n"
    checked = check_code(
        proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=Recorder(Ran(1, output))
    )
    assert len(checked.log) == code.MAX_LOG_CHARS and checked.log.endswith("test_find\n")


# ---------------------------------------------------------------- the target's security test (review of #91)


@pytest.mark.parametrize(
    "ran",
    [
        Ran(0, "1 passed in 0.01s\n"),
        Ran(2, "interrupted\n"),
        Ran(4, "usage\n"),
        Ran(5, "no tests ran in 0.01s\n"),
    ],
    ids=["passes-on-the-base", "interrupted", "usage-error", "nothing-collected"],
)
def test_a_security_test_that_does_not_fail_on_the_base_proves_nothing(tmp_path: Path, ran: Ran) -> None:
    """Only a test that ran and failed (pytest exit 1) shows the weakness was there before the patch."""
    base, patched = trees(tmp_path)
    run = Recorder(PASSING[0], ran)
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.build_ok, checked.tests_ok, len(run.calls)) == (True, False, 2)
    assert checked.problems == [
        "tests: the security_tests/test_python_sql_built_from_strings.py of python-sql-built-from-strings "
        f"does not fail on the base code (pytest exit {ran.returncode}): it proves nothing about this fix"
    ]


@pytest.mark.parametrize(
    "ran", [Ran(1, "1 failed in 0.01s\n"), Ran(5, "no tests ran in 0.01s\n")], ids=["fails", "nothing"]
)
def test_a_fix_whose_security_test_still_fails_is_not_verified(tmp_path: Path, ran: Ran) -> None:
    """The scanner may no longer see a rewritten pattern; the security test still finds the weakness."""
    base, patched = trees(tmp_path)
    checked = check_code(
        proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=Recorder(*PASSING[:2], ran)
    )
    assert checked.problems == [
        f"tests: {SECURITY} failed on the patched code (pytest exit {ran.returncode})"
    ] and checked.log.endswith(ran.output)
    assert checked.log.startswith("$ pytest tests (behaviour tests, patched code)\n12 passed in 0.31s\n"), (
        "every run so far, in order, not only the one that failed (#100 review, C10)"
    )


SECURITY_RUN = "security_tests/test_python_sql_built_from_strings.py"
SCRATCH = "/tmp:rw,noexec,nosuid,size=64m"  # noqa: S108 (the container's tmpfs, written out: C19)


def test_each_run_is_kept_with_its_exit_and_summary_whatever_the_log_keeps(tmp_path: Path) -> None:
    """#100 review, nit 2: the log is clipped to its end, so the runs are kept apart, each with its answer."""
    base, patched = trees(tmp_path)
    long = Ran(0, "x" * code.MAX_LOG_CHARS + "\n12 passed in 0.31s\n")
    checked = check_code(
        proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=Recorder(long, *PASSING[1:])
    )
    assert checked.tests_ok and checked.log.startswith("...")
    assert checked.runs == [
        {"selection": "tests", "label": "behaviour tests, patched code", "exit": 0,
         "summary": "12 passed"},
        {"selection": SECURITY_RUN, "label": f"{SECURITY_RUN}, base code, expected to fail", "exit": 1,
         "summary": "3 failed"},
        {"selection": SECURITY_RUN, "label": f"{SECURITY_RUN}, patched code", "exit": 0,
         "summary": "3 passed"},
    ]  # fmt: skip


def test_a_failed_check_keeps_the_runs_that_ran(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    run = Recorder(PASSING[0], Ran(0, "3 passed in 0.10s\n"))
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert not checked.tests_ok
    assert [(r["exit"], r["summary"]) for r in checked.runs] == [
        (0, "12 passed"),
        (0, "3 passed"),
    ]


@pytest.mark.parametrize(
    ("ran", "at", "shown"),
    [
        (Ran(0, ""), 0, "it printed no summary"),
        (Ran(0, "9 passed, 3 skipped in 0.50s\n"), 0, "its summary says 9 passed, 3 skipped"),
        (Ran(0, "11 passed, 1 deselected in 0.40s\n"), 0, "its summary says 11 passed, 1 deselected"),
        (Ran(1, ""), 1, "it printed no summary"),
        (Ran(1, "1 error in 0.20s\n"), 1, "its summary says 1 error"),
        (Ran(0, ""), 2, "it printed no summary"),
        (Ran(0, "2 passed, 1 xfailed in 0.10s\n"), 2, "its summary says 2 passed, 1 xfailed"),
        # #100 review: a second summary, printed at exit by the code under test, and one inside another line.
        (Ran(0, "9 passed, 3 skipped in 0.50s\n12 passed in 0.50s\n"), 0, "it printed 2 summary lines"),
        (Ran(0, "E   assert '12 passed in 0.31s'\n"), 0, "it printed no summary"),
    ],
    ids=[
        "early-exit",
        "skipped",
        "deselected",
        "base-early-exit",
        "base-error",
        "patched-early-exit",
        "xfailed",
        "two-summaries",
        "summary-inside-a-line",
    ],
)
def test_a_run_counts_only_when_pytests_summary_agrees(tmp_path: Path, ran: Ran, at: int, shown: str) -> None:
    """#100 review, should-fix 1: the patched code runs inside pytest, so it can end the process with the
    expected exit code before any test ran (`os._exit(0)`), or skip a test."""
    base, patched = trees(tmp_path)
    run = Recorder(*PASSING[:at], ran)
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    label = (
        "behaviour tests, patched code",
        f"{SECURITY_RUN}, base code, expected to fail",
        f"{SECURITY_RUN}, patched code",
    )[at]
    assert (checked.build_ok, checked.tests_ok, len(run.calls)) == (True, False, at + 1)
    assert checked.problems == [
        f"tests: {label}: pytest's summary does not show that (exit {ran.returncode}, {shown}): an early "
        "exit, a skip or a deselection proves nothing"
    ]


@pytest.mark.parametrize(
    ("output", "said", "counts"),
    [
        ("3 passed in 0.04s\n", "3 passed", {"passed": 3}),
        (
            "F..\n1 failed, 2 passed, 1 warning in 0.31s (0:00:01)\n",
            "1 failed, 2 passed, 1 warning",
            {"failed": 1, "passed": 2, "warning": 1},
        ),
        ("== 12 passed, 2 warnings in 1.20s ==\n", "12 passed, 2 warnings", {"passed": 12, "warnings": 2}),
        ("1 passed in 0.01s\nprinted after the summary\n", "1 passed", {"passed": 1}),
        ("no tests ran in 0.01s\n", "", {}),
        ("passed\n", "", {}),
    ],
)
def test_the_summary_is_pytests_last_summary_line(output: str, said: str, counts: dict[str, int]) -> None:
    assert summary_of(output) == (said, counts)


def test_warnings_do_not_stop_a_run_from_counting(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    run = Recorder(Ran(0, "12 passed, 1 warning in 0.31s\n"), PASSING[1], PASSING[2])
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])


def test_a_rule_without_a_security_test_is_never_verified(tmp_path: Path) -> None:
    base, patched = trees(tmp_path, security=False)
    run = Recorder()
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.tests_ok, run.calls) == (False, [])
    assert checked.problems == [
        f"tests: no security test {SECURITY} for {RULE}: a fix is never verified without one"
    ]
    (base / SECURITY).parent.mkdir()
    (base / SECURITY).symlink_to(base / SERVICE / "tests" / "test_db.py")
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert checked.problems[0].startswith("tests: no security test") and run.calls == [], "not a link"


def test_a_patch_to_the_security_tests_is_not_verified_by_them(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    old = (base / SECURITY).read_text(encoding="utf-8")
    new = "def test_no_sql_text():\n    assert True\n"
    (patched / SECURITY).write_text(new, encoding="utf-8")
    run = Recorder()
    checked = check_code(proposal_of(old, new, SECURITY), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert checked.problems == [
        "tests: the patch edits its service's security_tests, which then prove nothing"
    ]
    assert run.calls == []


@pytest.mark.parametrize("rule", ["", "Python-SQL", "../../etc", "a/b", "x" * 200, "rule with space"])
def test_a_rule_a_test_cannot_be_named_after_is_refused(tmp_path: Path, rule: str) -> None:
    base, patched = trees(tmp_path)
    with pytest.raises(CodeCheckError, match="is not a rule id a security test can be named after"):
        check_code(proposal_of(OLD, NEW), base, patched, rule=rule, test_image=IMAGE, run=Recorder())


# ---------------------------------------------------------------- build, and what is never run


def test_a_patch_that_does_not_parse_fails_the_build_and_runs_nothing(tmp_path: Path) -> None:
    broken = NEW.replace("(q,))", "(q,)")
    base, patched = trees(tmp_path, broken)
    run = Recorder()
    checked = check_code(proposal_of(OLD, broken), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.build_ok, checked.tests_ok) == (False, False) and run.calls == []
    assert checked.problems == [
        f"build: {TARGET}: not valid Python any more (line 2)", "tests: not run, the build failed",
    ]  # fmt: skip


def test_a_patched_file_that_is_not_utf8_fails_the_build(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    (patched / TARGET).write_bytes(b"\xff\xfe")
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=Recorder())
    assert checked.problems[0] == f"build: {TARGET}: not UTF-8 any more"


def test_without_tests_next_to_the_code_it_is_never_verified(tmp_path: Path) -> None:
    """The repository root's tests/ are SentinelCI's own, never a service's."""
    base, patched = trees(tmp_path, tests=False)
    run = Recorder()
    checked = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert (checked.build_ok, checked.tests_ok, run.calls) == (True, False, [])
    assert checked.problems == [
        f"tests: no tests next to {TARGET}: a code patch is never verified without them"
    ]
    (base / SERVICE / "tests").mkdir()
    (base / SERVICE / "tests" / "conftest.py").write_text("", encoding="utf-8")
    assert service_of(base, TARGET) is None, "a tests/ directory without a test_*.py file is not tests"


def test_a_patch_to_the_tests_is_not_verified_by_them(tmp_path: Path) -> None:
    path = f"{SERVICE}/tests/test_db.py"
    base, patched = trees(tmp_path)
    old = (base / path).read_text(encoding="utf-8")
    new = "def test_find():\n    assert True\n"
    (patched / path).write_text(new, encoding="utf-8")
    run = Recorder()
    checked = check_code(proposal_of(old, new, path), base, patched, rule=RULE, test_image=IMAGE, run=run)
    assert checked.problems == ["tests: the patch edits its service's tests, which then prove nothing"]
    assert run.calls == []


@pytest.mark.parametrize(
    "image",
    ["python:3.12", "python", "python@sha256:abc", "python@sha512:" + "a" * 128, "sha256:" + "A" * 64],
)
def test_the_test_image_must_be_pinned_by_digest(tmp_path: Path, image: str) -> None:
    base, patched = trees(tmp_path)
    with pytest.raises(CodeCheckError, match="pinned by digest"):
        check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=image, run=Recorder())


def test_a_local_image_id_is_pinned_too(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    run = Recorder()
    check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image="sha256:" + "c" * 64, run=run)
    assert "sha256:" + "c" * 64 in run.calls[0]


def test_what_cannot_be_checked_honestly_is_refused(tmp_path: Path) -> None:
    base, patched = trees(tmp_path)
    proposal = proposal_of(OLD, NEW)
    with pytest.raises(CodeCheckError, match="deterministic:kubernetes is not a code strategy"):
        check_code(proposal.model_copy(update={"strategy": "deterministic:kubernetes"}), base, patched,
                   rule=RULE, test_image=IMAGE, run=Recorder())  # fmt: skip
    yaml_file = proposal.model_copy(update={"files": [f"{SERVICE}/config.yaml"]})
    with pytest.raises(CodeCheckError, match="only Python is checked"):
        check_code(yaml_file, base, patched, rule=RULE, test_image=IMAGE, run=Recorder())
    (patched / TARGET).unlink()
    with pytest.raises(CodeCheckError, match="not a regular file of the patched tree"):
        check_code(proposal, base, patched, rule=RULE, test_image=IMAGE, run=Recorder())
    shutil.move(base / SERVICE / "app", tmp_path / "elsewhere")
    (base / SERVICE / "app").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    with pytest.raises(CodeCheckError, match="through a symbolic link in the base tree"):
        check_code(proposal, base, patched, rule=RULE, test_image=IMAGE, run=Recorder())


# ---------------------------------------------------------------- the docker runner


def fake_docker(tmp_path: Path, script: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path}/calls"\n{script}\n', encoding="utf-8")
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def test_the_runner_removes_the_named_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(fake_docker(tmp_path, 'echo "3 passed"; exit 0')))
    ran = docker_runner(["run", "--rm", "--name", "sentinel-tests-x", IMAGE], 300)
    assert (ran.returncode, ran.output, ran.timed_out) == (0, "3 passed\n", False)
    assert (tmp_path / "calls").read_text().splitlines()[-1] == "rm -f sentinel-tests-x"


def test_output_that_is_not_utf8_is_read_not_a_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#100 review, should-fix 2: a byte that is not UTF-8 (the patched code can write any) is replaced."""
    monkeypatch.setenv("PATH", str(fake_docker(tmp_path, "printf '3 passed\\377\\376 in 0.01s\\n'; exit 0")))
    ran = docker_runner(["run", "--rm", "--name", "sentinel-tests-z", IMAGE], 300)
    assert (ran.returncode, ran.output) == (0, "3 passed\ufffd\ufffd in 0.01s\n")


def test_the_runner_removes_the_container_after_a_time_out_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = f'case "$1" in run) {shutil.which("sleep")} 5;; esac'
    monkeypatch.setenv("PATH", str(fake_docker(tmp_path, script)))
    monkeypatch.setattr(code, "GRACE_S", 0)
    ran = docker_runner(["run", "--rm", "--name", "sentinel-tests-y", IMAGE], 1)
    assert ran.timed_out
    assert (tmp_path / "calls").read_text().splitlines()[-1] == "rm -f sentinel-tests-y"


def test_without_docker_nothing_is_verified(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(CodeCheckError, match="docker is not on PATH"):
        docker_runner(["run", "--name", "n"], 1)


# ---------------------------------------------------------------- the command


def sast_findings(tmp_path: Path, *, rule: str = RULE, category: str = "SAST") -> Path:
    """The base commit's findings, with the proposal's target."""
    path = tmp_path / "before.ndjson"
    path.write_text(json.dumps({
        "schema_version": "1.0", "id": FINDING, "tool": {"name": "opengrep", "version": "1.33.1"},
        "rule_id": rule, "category": category, "title": "SQL built from strings", "severity": "HIGH",
        "location": {"path": TARGET, "start_line": 2, "end_line": 2},
        "run": {"repo": "NOURHANE-EHOUARI/sentinelci", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                "context": "pr"},
    }) + "\n", encoding="utf-8")  # fmt: skip
    return path


def test_the_command_checks_a_code_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base, patched = trees(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(proposal_of(OLD, NEW).model_dump_json(), encoding="utf-8")
    run = Recorder(
        *PASSING, Ran(0, "1 passed in 0.01s\n"), Ran(1, "1 failed in 0.01s\n"), Ran(1, "1 failed in 0.02s\n")
    )
    monkeypatch.setattr(code, "docker_runner", run)
    command = ["remediate", "check", "--proposal", str(path), "--base-root", str(base),
               "--patched-root", str(patched)]  # fmt: skip
    findings = ["--findings", str(sast_findings(tmp_path))]
    done = CliRunner().invoke(app, [*command, *findings])
    assert done.exit_code == 3 and "needs --test-image" in done.stderr and done.stdout == ""
    done = CliRunner().invoke(app, [*command, "--test-image", IMAGE])
    assert done.exit_code == 3 and "needs --findings" in done.stderr and run.calls == []
    done = CliRunner().invoke(app, [*command, *findings, "--test-image", IMAGE])
    assert done.exit_code == 0, done.output
    result = json.loads(done.stdout)
    assert result.pop("log").endswith("3 passed in 0.09s\n")
    assert [(r["exit"], r["summary"]) for r in result.pop("runs")] == [
        (0, "12 passed"), (1, "3 failed"), (0, "3 passed"),
    ]  # fmt: skip
    assert result == {
        "proposal_id": proposal_of(OLD, NEW).proposal_id, "strategy": "llm:code", "build_ok": True,
        "tests_ok": True, "problems": [],
    }  # fmt: skip
    assert run.calls[1][-1] == "security_tests/test_python_sql_built_from_strings.py", "the target's rule"
    done = CliRunner().invoke(app, [*command, *findings, "--test-image", IMAGE])
    assert done.exit_code == 1 and json.loads(done.stdout)["log"].endswith("1 failed in 0.02s\n")
    done = CliRunner().invoke(app, [*command, *findings, "--test-image", "python:3.12"])
    assert done.exit_code == 3 and "FAIL CLOSED" in done.stderr


@pytest.mark.parametrize(
    ("findings", "message"),
    [
        (lambda tmp: sast_findings(tmp, category="SCA"), "is not a SAST finding of the base commit's scan"),
        (
            lambda tmp: (tmp / "empty.ndjson", (tmp / "empty.ndjson").write_text(""))[0],
            "is not a SAST finding",
        ),
    ],
    ids=["not-sast", "not-found"],
)
def test_the_target_must_be_a_sast_finding_of_the_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, findings: Any, message: str
) -> None:
    base, patched = trees(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(proposal_of(OLD, NEW).model_dump_json(), encoding="utf-8")
    run = Recorder()
    monkeypatch.setattr(code, "docker_runner", run)
    done = CliRunner().invoke(app, ["remediate", "check", "--proposal", str(path), "--base-root", str(base),
                                    "--patched-root", str(patched), "--findings", str(findings(tmp_path)),
                                    "--test-image", IMAGE])  # fmt: skip
    assert done.exit_code == 3 and message in done.stderr and run.calls == []


def test_an_iac_proposal_still_needs_its_findings(tmp_path: Path) -> None:
    proposal = proposal_of(OLD, NEW, strategy="deterministic:dockerfile").model_copy(update={"model": None})
    path = tmp_path / "proposal.json"
    path.write_text(proposal.model_dump_json(), encoding="utf-8")
    done = CliRunner().invoke(app, ["remediate", "check", "--proposal", str(path), "--base-root",
                                    str(tmp_path), "--patched-root", str(tmp_path)])  # fmt: skip
    assert done.exit_code == 3 and "need --findings" in done.stderr


@pytest.mark.skipif(
    shutil.which("docker") is None or not os.environ.get("SENTINEL_TEST_IMAGE"),
    reason="set SENTINEL_TEST_IMAGE to a pinned image with Python and pytest, with a Docker daemon",
)
def test_a_real_container_runs_the_tests(tmp_path: Path) -> None:
    """On the laptop: the real sandbox passes a fix whose security test fails on the base and passes on the
    patch, and fails a patch that leaves the weakness."""
    image = os.environ["SENTINEL_TEST_IMAGE"]
    base, patched = trees(tmp_path)
    (base / SECURITY).write_text(
        "import pathlib\n\n\ndef test_no_sql_text():\n"
        "    assert '?' in pathlib.Path('app/db.py').read_text()\n",
        encoding="utf-8",
    )
    for tree in (base, patched):
        for path in [tree, *tree.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)  # readable by nobody, never writable
    good = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=image)
    assert good.tests_ok, good.log
    (patched / TARGET).write_text(OLD, encoding="utf-8")
    bad = check_code(proposal_of(OLD, NEW), base, patched, rule=RULE, test_image=image)
    assert not bad.tests_ok and "1 failed" in bad.log and "patched code" in bad.problems[0]
    subprocess.run(["docker", "ps", "-a", "--filter", "name=sentinel-tests-", "-q"], check=True)
