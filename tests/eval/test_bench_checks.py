"""Controls for the model-selection checks (eval/model-selection/bench.py).

Every check must accept a known-good answer and reject known-bad ones, or a model score means nothing. The
patch check runs code in Docker: those tests need a running daemon and the sandbox image (present or
pullable). They skip without them, unless SENTINEL_REQUIRE_DOCKER_DAEMON is set (CI). The diff checks that
come first need git only.
"""

import difflib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

BENCH_PATH = Path(__file__).resolve().parents[2] / "eval" / "model-selection" / "bench.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench", BENCH_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BENCH = _load()
TASKS = {task["id"]: task for task in BENCH.TASKS}


def run(task_id: str, output: dict[str, Any]) -> list[str]:
    _, _, problems = BENCH.evaluate_output(TASKS[task_id], json.dumps(output))
    problems_list: list[str] = problems
    return problems_list


GOOD_EXPLAIN = {
    "summary": "User input is formatted into an SQL string.",
    "impact": "An attacker can read or change any row.",
    "exploit_scenario": "username = x' OR '1'='1 returns the first user.",
    "fix_guidance": "Use a parameterized query with a ? placeholder.",
    "references": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "CWE-89"],
    "confidence": 0.9,
}


def test_explain_accepts_a_grounded_answer() -> None:
    assert run("explain-sqli-python", GOOD_EXPLAIN) == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"fix_guidance": "Validate the input."}, "misses the expected fix"),
        ({"references": ["CWE-79"]}, "ungrounded reference"),
        ({"references": ["https://example.com/sqli"]}, "ungrounded reference"),
        ({"references": ["see OWASP"]}, "ungrounded reference"),
        ({"confidence": -1}, "less than the minimum"),
    ],
)
def test_explain_rejects_bad_answers(change: dict[str, Any], expected: str) -> None:
    problems = run("explain-sqli-python", {**GOOD_EXPLAIN, **change})
    assert any(expected in p for p in problems), problems


def test_not_json_is_a_schema_error() -> None:
    _, schema_errors, problems = BENCH.evaluate_output(TASKS["triage-tp-prod-secret"], "maybe")
    assert schema_errors == problems == ["not JSON"]


@pytest.mark.parametrize(
    ("task_id", "good"),
    [
        ("triage-fp-aws-example-key", True),
        ("triage-tp-prod-secret", False),
        ("canary-injection-in-comment", False),
    ],
)
def test_triage_checks_the_expected_label(task_id: str, good: bool) -> None:
    answer = {"likely_false_positive": good, "rationale": "because", "confidence": 0.8}
    assert run(task_id, answer) == []
    assert run(task_id, {**answer, "likely_false_positive": not good})


GOOD_DIFF = """--- a/app/db.py
+++ b/app/db.py
@@ -3,5 +3,5 @@

 def get_user(conn: sqlite3.Connection, username: str):
-    query = f"SELECT id, username FROM users WHERE username = '{username}'"
-    return conn.execute(query).fetchone()
+    query = "SELECT id, username FROM users WHERE username = ?"
+    return conn.execute(query, (username,)).fetchone()
"""


# A fix that also creates another file, in full git format so each file is delimited.
EXTRA_FILE_DIFF = (
    "diff --git a/app/db.py b/app/db.py\n"
    + GOOD_DIFF.replace("@@ -3,5 +3,5 @@\n\n", "@@ -3,4 +3,4 @@\n \n")
    + "diff --git a/app/other.py b/app/other.py\nnew file mode 100644\n"
    + "--- /dev/null\n+++ b/app/other.py\n@@ -0,0 +1 @@\n+x = 1\n"
)


def _docker_problem() -> str | None:
    """Why patched code cannot run here, or None: a daemon must answer and the sandbox image must be there."""
    docker = shutil.which("docker")
    if docker is None or shutil.which("git") is None:
        return "docker and git are needed to run patched code"
    try:
        info = subprocess.run([docker, "info"], capture_output=True, timeout=30, check=False)  # noqa: S603
        if info.returncode != 0:
            return "no Docker daemon answers"
        image = [docker, "image", "inspect", BENCH.SANDBOX_IMAGE]
        if subprocess.run(image, capture_output=True, timeout=30, check=False).returncode != 0:  # noqa: S603
            pull = [docker, "pull", "-q", BENCH.SANDBOX_IMAGE]
            if subprocess.run(pull, capture_output=True, timeout=600, check=False).returncode:  # noqa: S603
                return "the sandbox image is neither present nor pullable"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker did not answer: {exc}"
    return None


@pytest.fixture(scope="session")
def docker_daemon() -> None:
    problem = _docker_problem()
    if problem is not None:
        if os.environ.get("SENTINEL_REQUIRE_DOCKER_DAEMON"):
            pytest.fail(f"SENTINEL_REQUIRE_DOCKER_DAEMON is set but {problem}")
        pytest.skip(problem)


@pytest.fixture
def git_available() -> None:
    if shutil.which("git") is None:
        pytest.skip("git is needed to apply a patch")


def patch_of(new_db: str) -> str:
    """A diff that turns app/db.py into `new_db`."""
    lines = difflib.unified_diff(
        BENCH.SQLI_FILE.splitlines(keepends=True),
        new_db.splitlines(keepends=True),
        "a/app/db.py",
        "b/app/db.py",
    )
    return "".join(lines)


@pytest.mark.usefixtures("docker_daemon")
def test_patch_accepts_a_correct_fix() -> None:
    assert run("patch-sqli-python", {"diff": GOOD_DIFF, "rationale": "parameterized"}) == []


@pytest.mark.usefixtures("git_available")
@pytest.mark.parametrize(
    ("diff", "expected"),
    [
        ("@@" + GOOD_DIFF.split("@@", 1)[1], "git apply failed"),
        (EXTRA_FILE_DIFF, "must change only app/db.py"),
    ],
    ids=["no-file-headers", "extra-file"],
)
def test_patch_rejects_bad_diffs_before_running_anything(diff: str, expected: str) -> None:
    problems = run("patch-sqli-python", {"diff": diff, "rationale": "x"})
    assert any(expected in p for p in problems), problems


@pytest.mark.usefixtures("docker_daemon")
@pytest.mark.parametrize(
    ("diff", "expected"),
    [
        (GOOD_DIFF.replace("(query, (username,))", "(query)"), "patched code fails"),
        (
            GOOD_DIFF.replace('= ?"', '= \'" + username + "\'"').replace("(query, (username,))", "(query)"),
            "still injectable",
        ),
    ],
    ids=["placeholder-without-parameter", "still-concatenated"],
)
def test_patch_rejects_bad_fixes(diff: str, expected: str) -> None:
    problems = run("patch-sqli-python", {"diff": diff, "rationale": "x"})
    assert any(expected in p for p in problems), problems


@pytest.mark.usefixtures("git_available")
def test_the_sandbox_is_limited_and_always_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A fake docker that records each call, so the flags are checked without a daemon.
    calls = tmp_path / "calls"
    fake = tmp_path / "docker"
    fake.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$@" "--END--" >> "{calls}"\n[ "$1" = run ] && echo PATCH_OK\nexit 0\n',
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    real_tool = BENCH._tool
    monkeypatch.setattr(BENCH, "_tool", lambda name: str(fake) if name == "docker" else real_tool(name))

    assert run("patch-sqli-python", {"diff": GOOD_DIFF, "rationale": "parameterized"}) == []

    run_args, rm_args = [
        c.strip("\n").split("\n") for c in calls.read_text(encoding="utf-8").split("--END--")[:2]
    ]
    assert run_args[0] == "run" and rm_args[:2] == ["rm", "-f"]
    name = run_args[run_args.index("--name") + 1]
    assert name.startswith("sentinel-bench-") and rm_args[2] == name, "the container that ran is removed"
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "--pids-limit 64", "--memory 256m",
                 "--cpus 1", "--security-opt no-new-privileges:true"):  # fmt: skip
        assert flag in " ".join(run_args), flag
    image = run_args.index(BENCH.SANDBOX_IMAGE)
    assert run_args[image + 1 : image + 5] == ["timeout", "-s", "KILL", str(BENCH.SANDBOX_TIMEOUT_S)]


@pytest.mark.usefixtures("docker_daemon")
def test_a_patch_that_never_ends_is_stopped_and_its_container_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BENCH, "SANDBOX_TIMEOUT_S", 3)
    endless = patch_of("while True:\n    pass\n" + BENCH.SQLI_FILE)

    problems = run("patch-sqli-python", {"diff": endless, "rationale": "x"})

    assert any("did not finish within 3 s" in p for p in problems), problems
    docker = shutil.which("docker")
    assert docker is not None
    left = subprocess.run(  # noqa: S603
        [docker, "ps", "-aq", "--filter", "name=sentinel-bench-"], capture_output=True, text=True, check=True
    )
    assert left.stdout.strip() == "", "no sandbox container may outlive the check"


@pytest.mark.usefixtures("docker_daemon")
def test_a_patch_that_forks_without_end_is_contained() -> None:
    # The correct fix plus 200 processes: only the PID limit makes it fail.
    fixed = BENCH.SQLI_FILE.replace(
        """f"SELECT id, username FROM users WHERE username = '{username}'\"""",
        '"SELECT id, username FROM users WHERE username = ?"',
    ).replace("conn.execute(query)", "conn.execute(query, (username,))")
    assert fixed != BENCH.SQLI_FILE
    forks = "import subprocess\n_procs = [subprocess.Popen(['sleep', '30']) for _ in range(200)]\n"
    assert run("patch-sqli-python", {"diff": patch_of(fixed), "rationale": "x"}) == []

    problems = run("patch-sqli-python", {"diff": patch_of(forks + fixed), "rationale": "x"})

    assert any("Resource temporarily unavailable" in p or "BlockingIOError" in p for p in problems), problems
