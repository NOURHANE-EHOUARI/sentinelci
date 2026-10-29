"""Controls for the model-selection checks (eval/model-selection/bench.py).

Every check must accept a known-good answer and reject known-bad ones, or a model score means nothing. The
patch check runs code in Docker: it skips without Docker, unless SENTINEL_REQUIRE_DOCKER is set (CI).
"""

import importlib.util
import json
import os
import shutil
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


@pytest.fixture
def docker_available() -> None:
    if shutil.which("docker") is None or shutil.which("git") is None:
        if os.environ.get("SENTINEL_REQUIRE_DOCKER"):
            pytest.fail("SENTINEL_REQUIRE_DOCKER is set but docker or git is missing")
        pytest.skip("docker and git are needed to run patched code")


@pytest.mark.usefixtures("docker_available")
def test_patch_accepts_a_correct_fix() -> None:
    assert run("patch-sqli-python", {"diff": GOOD_DIFF, "rationale": "parameterized"}) == []


@pytest.mark.usefixtures("docker_available")
@pytest.mark.parametrize(
    ("diff", "expected"),
    [
        ("@@" + GOOD_DIFF.split("@@", 1)[1], "git apply failed"),
        (GOOD_DIFF.replace("(query, (username,))", "(query)"), "patched code fails"),
        (
            GOOD_DIFF.replace('= ?"', '= \'" + username + "\'"').replace("(query, (username,))", "(query)"),
            "still injectable",
        ),
        (EXTRA_FILE_DIFF, "must change only app/db.py"),
    ],
    ids=["no-file-headers", "placeholder-without-parameter", "still-concatenated", "extra-file"],
)
def test_patch_rejects_bad_fixes(diff: str, expected: str) -> None:
    problems = run("patch-sqli-python", {"diff": diff, "rationale": "x"})
    assert any(expected in p for p in problems), problems
