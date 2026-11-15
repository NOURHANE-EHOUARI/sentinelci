"""PIPELINE fingerprints on the real zizmor's output, base against head (A1, SPEC §13.1).

SC-009 compares the ids of a pull request's head with those of its base, and a waiver matches an id. So a new
risk must get a new id (else it passes as old, and an old waiver covers it), and an edit that adds no risk
must keep every id (else every edit near a known finding blocks, and its waiver silently stops matching).
These are the reviewer's repros of #37, run through the zizmor the CLI installs.
"""

from collections import defaultdict
from pathlib import Path

import pytest

from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.zizmor import normalize_zizmor
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.zizmor import scan_pipelines_with_run

ROOT = Path(__file__).resolve().parents[3]
LOCK = load_lock(ROOT / "tools.lock.toml")
RUN = Run(repo="o/r", commit="0" * 40, context="pr")

WORKFLOW = """name: w
on: {trigger}
permissions: {{}}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
SCRIPT = """name: w
on:
  issues:
    types: [opened]
permissions: {{}}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: {run}
      - run: |
          echo other step
"""
BODY = '|\n          echo start\n          echo "body ${{ github.event.issue.body }}"\n          echo end'
PIP = """  - package-ecosystem: pip
    directory: /
    schedule: {interval: weekly}
    insecure-external-code-execution: allow
"""
NPM = PIP.replace("pip", "npm").replace("directory: /", "directory: /web")


def _ids(tmp_path: Path, path: str, text: str) -> dict[str, set[str]]:
    """rule id -> the ids of its findings, for one file in a fresh repository."""
    repo = tmp_path / f"repo-{sum(1 for _ in tmp_path.iterdir())}"
    (repo / path).parent.mkdir(parents=True)
    (repo / path).write_text(text)
    scan = scan_pipelines_with_run(repo, lock=LOCK)
    ids: dict[str, set[str]] = defaultdict(set)
    tool = Tool(name="zizmor", version=LOCK.python_tools["zizmor"].version)
    for finding in normalize_zizmor(scan.results, run=RUN, tool=tool):
        ids[finding.rule_id].add(finding.id)
    return ids


def _workflow(tmp_path: Path, text: str) -> dict[str, set[str]]:
    return _ids(tmp_path, ".github/workflows/w.yml", text)


def test_a_scalar_trigger_swapped_for_another_is_a_new_finding(tmp_path: Path) -> None:
    """Review of #37, blocking 1 (repro A): `on: workflow_run` -> `on: pull_request_target` kept the id."""
    base = _workflow(tmp_path, WORKFLOW.format(trigger="workflow_run"))["dangerous-triggers"]
    head = _workflow(tmp_path, WORKFLOW.format(trigger="pull_request_target"))["dangerous-triggers"]
    assert len(base) == len(head) == 1 and not base & head


def test_the_three_forms_of_one_trigger_are_one_id(tmp_path: Path) -> None:
    """Review of #37, nit 2: a scalar, a list and a mapping naming the same trigger are the same risk."""
    forms = ["pull_request_target", "[pull_request_target]", "\n  pull_request_target:\n    branches: [main]"]
    ids = [_workflow(tmp_path, WORKFLOW.format(trigger=form))["dangerous-triggers"] for form in forms]
    assert len(ids[0]) == 1 and ids[0] == ids[1] == ids[2]


def test_a_second_dependabot_entry_is_a_new_finding(tmp_path: Path) -> None:
    """Review of #37, blocking 1 (repro B): an npm entry with the same setting took the pip entry's id."""
    base = _ids(tmp_path, ".github/dependabot.yml", f"version: 2\nupdates:\n{PIP}")["dependabot-execution"]
    head = _ids(tmp_path, ".github/dependabot.yml", f"version: 2\nupdates:\n{PIP}{NPM}")[
        "dependabot-execution"
    ]
    assert len(base) == 1 and len(head) == 2 and base < head
    moved = _ids(tmp_path, ".github/dependabot.yml", f"version: 2\nupdates:\n{NPM}{PIP}")[
        "dependabot-execution"
    ]
    assert moved == head, "the entry's position is not part of the id"


@pytest.mark.parametrize(
    "head",
    [
        BODY.replace("echo start", "echo start now"),
        BODY.replace("echo end", "# a shell comment\n          echo end"),
        BODY.replace("|", "|-"),
        BODY.replace("${{ github.event.issue.body }}", "${{github.event.issue.body}}"),
        "        " + BODY.replace("\n", "\n    "),
    ],
    ids=["another-line-edited", "comment-added", "chomping-indicator", "spaces-in-braces", "re-indented"],
)
def test_an_edit_that_adds_no_risk_keeps_the_injections_id(tmp_path: Path, head: str) -> None:
    """Review of #37, should fix 1: the whole script was hashed, so any edit near an injection blocked and
    broke its waiver."""
    base = _workflow(tmp_path, SCRIPT.format(run=BODY))["template-injection"]
    assert len(base) == 1
    assert _workflow(tmp_path, SCRIPT.format(run=head))["template-injection"] == base


def test_a_one_line_run_and_its_block_form_are_one_id(tmp_path: Path) -> None:
    one_line = _workflow(tmp_path, SCRIPT.format(run='echo "body ${{ github.event.issue.body }}"'))
    block = _workflow(tmp_path, SCRIPT.format(run='|\n          echo "body ${{ github.event.issue.body }}"'))
    assert len(one_line["template-injection"]) == 1
    assert one_line["template-injection"] == block["template-injection"]


def test_a_changed_or_added_expression_is_new_and_the_unchanged_one_keeps_its_id(tmp_path: Path) -> None:
    base = _workflow(tmp_path, SCRIPT.format(run=BODY))["template-injection"]
    changed = _workflow(tmp_path, SCRIPT.format(run=BODY.replace("issue.body", "comment.body")))
    assert len(changed["template-injection"]) == 1 and not changed["template-injection"] & base
    added = BODY.replace("echo end", 'echo "title ${{ github.event.issue.title }}"\n          echo end')
    head = _workflow(tmp_path, SCRIPT.format(run=added))["template-injection"]
    assert len(head) == 2 and base < head


COOLDOWN = """version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule: {interval: weekly}
    cooldown:
      default-days: 1
"""
SECRETS = """name: w
on: push
permissions: {{}}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo {run}
"""


@pytest.mark.parametrize("cooldown", ["default-days: 1", "semver-major-days: 30"])
def test_an_insufficient_dependabot_cooldown_is_a_finding_not_a_scan_failure(
    tmp_path: Path, cooldown: str
) -> None:
    """Review 3 of #37: zizmor gives no `package-ecosystem` location for a short cooldown."""
    ids = _ids(tmp_path, ".github/dependabot.yml", COOLDOWN.replace("default-days: 1", cooldown))
    assert list(ids) == ["dependabot-cooldown"] and len(ids["dependabot-cooldown"]) == 1


def test_a_different_secrets_expression_in_the_same_file_is_a_new_finding(tmp_path: Path) -> None:
    """Review 3 of #37: overprovisioned-secrets has route [] (no job), so it is not a whole-file finding."""
    base = _workflow(tmp_path, SECRETS.format(run='"${{ toJSON(secrets) }}"'))["overprovisioned-secrets"]
    head = _workflow(
        tmp_path,
        SECRETS.format(
            run="\"${{ toJSON(secrets) }} ${{ secrets[format('X{0}', github.event.issue.title)] }}\""
        ),
    )["overprovisioned-secrets"]
    assert len(base) == 1 and len(head) == 2 and base < head


def test_the_whole_file_excessive_permissions_survives_edits(tmp_path: Path) -> None:
    two_jobs = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo {x}\n" + (
        "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo b\n"
    )
    before = _ids(tmp_path, ".github/workflows/w.yml", two_jobs.format(x="a"))["excessive-permissions"]
    after = _ids(tmp_path, ".github/workflows/w.yml", "# c\n" + two_jobs.format(x="changed"))[
        "excessive-permissions"
    ]
    assert len(before) == 3 and before == after


@pytest.mark.parametrize("key", ['"on"', "'on'"])
def test_a_quoted_on_key_is_the_same_trigger(tmp_path: Path, key: str) -> None:
    """Review 3 of #37, nit 2: `"on":` avoids YAML 1.1's on -> true, and is the same trigger."""
    plain = _workflow(tmp_path, WORKFLOW.format(trigger="pull_request_target"))["dangerous-triggers"]
    quoted = WORKFLOW.format(trigger="pull_request_target").replace("\non:", f"\n{key}:")
    assert _workflow(tmp_path, quoted)["dangerous-triggers"] == plain and len(plain) == 1
