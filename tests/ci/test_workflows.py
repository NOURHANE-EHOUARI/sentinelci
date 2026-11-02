"""Supply-chain rules every GitHub workflow must follow (CLAUDE.md golden rule 7, ADR-0008).

Checked on the raw text, so the `# vX.Y.Z` comment of a pinned action is seen and no YAML library is needed.
zizmor audits the workflows too, but it does not check that a same-repository reference exists: a broken
path is only caught when GitHub refuses the workflow. Same-repository references use GitHub's
self-repository syntax `$/<path>` (July 2026), which resolves to the running commit; zizmor's
`self-repository` audit flags the older `./<path>`. Reference:
https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*(?:- )?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")
VERSION_COMMENT = re.compile(r"\s+# v\d+\.\d+\.\d+\b.*")
SAME_REPOSITORY = ("$/", "./")
STEP_START = re.compile(r"^\s*- ")


def reference_problem(ref: str, rest: str, *, root: Path = ROOT) -> str | None:
    """Why a `uses:` value breaks the rules, or None."""
    if ref.startswith(SAME_REPOSITORY):
        relative = ref[2:]
        if not relative or ".." in Path(relative).parts or not (root / relative).exists():
            return "does not exist in this repository"
        return None
    if not PINNED.fullmatch(ref):
        return "must be $/<path> or owner/repo@<full commit SHA>"
    if not VERSION_COMMENT.fullmatch(rest):
        return "needs a `# vX.Y.Z` comment naming the pinned release"
    return None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _step(lines: list[str], index: int) -> list[str]:
    """The lines of the list item (workflow step) that contains line `index`."""
    start = next(i for i in range(index, -1, -1) if STEP_START.match(lines[i]))
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or _indent(lines[end]) > _indent(lines[start])):
        end += 1
    return lines[start:end]


def test_there_are_workflows_to_check() -> None:
    assert WORKFLOWS


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_reference_exists_or_is_pinned_by_commit_sha(workflow: Path) -> None:
    for lineno, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
        match = USES.match(line)
        if match:
            problem = reference_problem(match["ref"], match["rest"])
            assert problem is None, f"{workflow.name}:{lineno}: {match['ref']} {problem}"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_never_keep_the_token(workflow: Path) -> None:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        match = USES.match(line)
        if match and match["ref"].startswith("actions/checkout@"):
            step = _step(lines, index)
            assert any(re.fullmatch(r"\s*persist-credentials:\s*false\s*", s) for s in step), (
                f"{workflow.name}:{index + 1}: actions/checkout needs `persist-credentials: false`"
            )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_permissions_are_explicit_and_pull_request_target_is_never_used(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    assert re.search(r"^permissions:", text, re.MULTILINE), f"{workflow.name} needs top-level permissions"
    assert "pull_request_target" not in text, f"{workflow.name} must not use pull_request_target"


SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


@pytest.mark.parametrize(
    ("ref", "rest", "problem"),
    [
        ("$/.github/workflows/sentinel-scan.yml", "", None),
        ("$/.github/workflows/missing.yml", "", "does not exist"),
        ("./.github/workflows/sentinel-scan.yml", "", None),  # older form: zizmor reports it
        ("$/../outside.yml", "", "does not exist"),
        ("$/", "", "does not exist"),
        (f"actions/checkout@{SHA}", " # v7.0.1", None),
        (f"actions/checkout@{SHA}", "", "needs a `# vX.Y.Z` comment"),
        ("actions/checkout@v7", " # v7.0.1", "full commit SHA"),
        (f"actions/checkout@{SHA[:12]}", " # v7.0.1", "full commit SHA"),
        ("docker://alpine:3.22", "", "full commit SHA"),
    ],
)
def test_reference_rules(ref: str, rest: str, problem: str | None) -> None:
    found = reference_problem(ref, rest)
    assert (found is None) if problem is None else (found is not None and problem in found)


def test_the_pipeline_change_warning_covers_every_input_read_from_the_base_commit() -> None:
    # ADR-0008: these are taken from the base commit, so a pull request that edits them must be told.
    text = (ROOT / ".github" / "workflows" / "sentinel-scan.yml").read_text(encoding="utf-8")
    step = text[text.index("- name: List pipeline files changed by the pull request") :]
    step = step[: step.index("- name:", 10)]
    for pathspec in (
        "tools.lock.toml",
        "policies",
        "cli",
        ".sentinel",
        "uv.lock",
        "eval/feeds",
        "':(glob)**/sentinel.yaml'",
    ):
        assert f" {pathspec} " in step.replace("\\\n", " ").replace("\n", " "), pathspec


SCAN_WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-scan.yml"
SETUP_MARGIN_S = 300  # checkouts, uv sync, tool installation, upload
TRIVY_BACKSTOP_S = 60  # the runner's own limit on top of Trivy's --timeout (scanners/trivy.py)


def _job(text: str, name: str, following: str) -> str:
    return text[text.index(f"\n  {name}:\n") : text.index(f"\n  {following}:\n")]


def _steps(job: str) -> list[str]:
    return job.split("\n      - name: ")[1:]


def test_the_scan_job_outlives_every_scanner_run() -> None:
    # A scanner killed with its job leaves no tool status; one that hits its own limit is a recorded timeout.
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    per_run = int(re.search(r'^  SCANNER_TIMEOUT_S: "(\d+)"$', text, re.MULTILINE)[1])  # type: ignore[index]
    job = _job(text, "scan", "gate")
    minutes = int(re.search(r"^    timeout-minutes: (\d+)$", job, re.MULTILINE)[1])  # type: ignore[index]
    worst = SETUP_MARGIN_S
    for step in _steps(job):
        if "scan secrets" in step or "scan iac" in step:
            assert '--timeout "$SCANNER_TIMEOUT_S"' in step, f"step without a scanner time limit: {step[:60]}"
        if "scan secrets" in step:
            worst += per_run * (2 if "--mode git" in step else 1)  # git mode: remerge pass + octopus pass
        worst += step.count("scan iac") * (per_run + TRIVY_BACKSTOP_S)
    assert worst <= minutes * 60, f"the scan job needs {worst} s, its timeout-minutes allow {minutes * 60} s"


def test_the_gate_scores_with_the_base_model_then_evaluates_the_scored_findings() -> None:
    text = SCAN_WORKFLOW.read_text(encoding="utf-8")
    (step,) = [s for s in _steps(_job(text, "gate", "report")) if s.startswith("Evaluate the release gate")]
    scored = '"$RUNNER_TEMP/decision/findings.ndjson"'
    base, score, evaluate = (
        step.index("cd pipeline"),
        step.index("score --findings"),
        step.index("evaluate \\"),
    )
    assert base < score < evaluate, "score, then evaluate, both from the base checkout"
    score_call, evaluate_call = step[score:evaluate], step[evaluate:]
    assert "--policy-dir policies" in score_call and "--policy-dir policies" in evaluate_call
    assert f"--out {scored}" in score_call and f"--findings {scored}" in evaluate_call
    failure = score_call[: score_call.index("fi\n")]
    assert step[score - len('if ! "$SENTINEL" ') : score].startswith("if ! ")
    assert 'echo "status=3"' in failure and "exit 0" in failure, "a scoring failure is no decision"
    assert '--findings "$in/sentinel-decision/findings.ndjson"' in text, (
        "the report shows the scored findings"
    )
