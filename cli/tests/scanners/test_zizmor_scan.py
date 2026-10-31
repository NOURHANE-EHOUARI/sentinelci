"""`sentinel scan pipelines`: zizmor, verified, never configured or silenced by the scanned repository (A1).

zizmor is installed by `make setup` (uv.lock), so these tests run the real one; failure modes are simulated by
replacing the process call or the installed distribution.
"""

import json
import subprocess
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import sentinelci.scanners.zizmor as zizmor
from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.zizmor import collect_workflows, scan_pipelines_with_run, verified_zizmor

INJECTION = """name: label
on:
  issues:
    types: [opened]
permissions: {}
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      # zizmor: ignore[template-injection]
      - run: echo "${{ github.event.issue.title }}"  # zizmor: ignore[template-injection]
"""
CLEAN = """name: clean
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "label.yml").write_text(INJECTION)
    return repo


def _rules(results: list[dict[str, Any]]) -> set[str]:
    return {str(item["ident"]) for item in results}


def test_collection_follows_what_github_runs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for name, text in {
        ".github/workflows/ci.yml": CLEAN,
        ".github/workflows/odd.yaml": "not a workflow at all\n",  # under workflows/: always audited
        "examples/bad.yml": CLEAN,  # a workflow kept elsewhere: has `jobs:`
        "deploy/values.yaml": "replicas: 2\n",  # not a workflow
        "actions/setup/action.yml": "runs:\n  using: composite\n  steps: []\n",
        ".git/hooks/ci.yml": CLEAN,
        "README.md": "jobs: not yaml\n",
    }.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    (repo / "linked.yml").symlink_to(repo / "examples" / "bad.yml")
    assert collect_workflows(repo) == [
        ".github/workflows/ci.yml",
        ".github/workflows/odd.yaml",
        "actions/setup/action.yml",
        "examples/bad.yml",
    ]


def test_ignore_comments_and_repository_config_are_not_honoured(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for config in (repo / "zizmor.yml", repo / ".github" / "zizmor.yml"):
        config.write_text("rules:\n  template-injection:\n    disable: true\n")
    (repo / ".gitignore").write_text(".github/workflows/label.yml\n")  # listed, yet still audited
    results, run, audited = scan_pipelines_with_run(repo)
    assert audited == [".github/workflows/label.yml"]
    assert "template-injection" in _rules(results)
    # Still reported, flagged `ignored` because of the comments: the normalizer keeps it (tested there).
    assert all(item.get("ignored") for item in results if item["ident"] == "template-injection")
    assert run is not None and run.returncode in zizmor.FINDINGS_EXIT_CODES and run.stdout == ""
    for flag in ("--offline", "--no-config", "--no-ignores", "--collect=all", "--format=json"):
        assert flag in run.args


def test_zizmor_gets_a_minimal_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("ZIZMOR_CONFIG", str(tmp_path / "evil.yml"))
    seen: dict[str, Any] = {}
    real_run = subprocess.run

    def spy(args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real_run(args, **kwargs)

    monkeypatch.setattr(zizmor.subprocess, "run", spy)
    repo = _repo(tmp_path)
    scan_pipelines_with_run(repo)
    assert "GITHUB_TOKEN" not in seen["env"] and "ZIZMOR_CONFIG" not in seen["env"]
    assert Path(seen["cwd"]) == repo, "relative paths: the findings point into the audited tree"


def test_nothing_to_audit_runs_nothing_but_still_checks_the_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    assert scan_pipelines_with_run(repo) == ([], None, [])

    def missing(name: str) -> Any:
        raise PackageNotFoundError(name)

    monkeypatch.setattr(zizmor, "distribution", missing)
    with pytest.raises(ToolIntegrityError, match="not installed"):
        scan_pipelines_with_run(repo)


def test_a_binary_that_does_not_match_its_record_never_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy of the environment whose zizmor was replaced after installation."""
    real = verified_zizmor()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "zizmor"
    fake.write_text("#!/bin/sh\necho '[]'\n")
    fake.chmod(0o755)

    class Entry:
        name = "zizmor"
        hash = type("Hash", (), {"mode": "sha256", "value": "wrong"})()

    class Dist:
        version = real.version
        files = (Entry(),)

        def locate_file(self, entry: object) -> Path:
            return fake

    monkeypatch.setattr(zizmor, "distribution", lambda name: Dist())
    monkeypatch.setattr(zizmor.sys, "executable", str(bin_dir / "python"))
    with pytest.raises(ToolIntegrityError, match=r"does not match zizmor .*RECORD"):
        scan_pipelines_with_run(_repo(tmp_path))


def test_the_binary_must_be_the_one_of_this_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(zizmor.sys, "executable", str(tmp_path / "elsewhere" / "python"))
    with pytest.raises(ToolIntegrityError, match="RECORD does not list"):
        verified_zizmor()


class _Completed:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, "zizmor said no"


@pytest.mark.parametrize(
    ("returncode", "stdout", "message"),
    [
        (1, "", "exited with code 1"),
        (2, "", "exited with code 2"),
        (3, "", "exited with code 3"),
        (15, "[]", "exited with code 15"),
        (14, "[]", "exited with 14 but reported 0"),
        (0, json.dumps([{"ident": "x"}]), "exited with 0 but reported 1"),
        (14, "{not json", "unreadable JSON"),
        (14, json.dumps({"ident": "x"}), "not a list"),
    ],
)
def test_failures_are_scanner_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, message: str
) -> None:
    monkeypatch.setattr(zizmor.subprocess, "run", lambda *a, **k: _Completed(returncode, stdout))
    with pytest.raises(ScannerError, match=message):
        scan_pipelines_with_run(_repo(tmp_path))


def test_a_timeout_is_a_scanner_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="zizmor", timeout=1)

    monkeypatch.setattr(zizmor.subprocess, "run", slow)
    with pytest.raises(ScannerError, match="timed out"):
        scan_pipelines_with_run(_repo(tmp_path), timeout_s=1)


def _cli(target: Path, out: Path, repo_root: Path | None = None) -> tuple[int, str]:
    args = ["scan", "pipelines", str(target), "--out", str(out), "--repo", "o/r", "--commit", "0" * 40,
            "--context", "pr"]  # fmt: skip
    if repo_root is not None:
        args += ["--repo-root", str(repo_root)]
    result = CliRunner().invoke(app, args)
    return result.exit_code, result.output


def test_cli_writes_repository_relative_pipeline_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "demo-shop" / "examples").mkdir(parents=True)
    (repo / "demo-shop" / "examples" / "label.yml").write_text(INJECTION)
    out = tmp_path / "out" / "pipelines.ndjson"
    code, output = _cli(repo / "demo-shop", out, repo)
    assert code == 0, output
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    assert {f["category"] for f in findings} == {"PIPELINE"}
    assert {f["location"]["path"] for f in findings} == {"demo-shop/examples/label.yml"}
    assert "template-injection" in {f["rule_id"] for f in findings}
    assert "1 workflow(s)" in output


def test_cli_failure_leaves_no_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zizmor.subprocess, "run", lambda *a, **k: _Completed(1, ""))
    out = tmp_path / "pipelines.ndjson"
    out.write_text("stale")
    code, output = _cli(_repo(tmp_path), out)
    assert code == 3 and "FAIL CLOSED" in output
    assert not out.exists()


@pytest.mark.parametrize("case", ["outside-the-root", "not-a-directory"])
def test_cli_refuses_a_bad_target(tmp_path: Path, case: str) -> None:
    repo = _repo(tmp_path)
    if case == "outside-the-root":
        target = tmp_path / "elsewhere"
        target.mkdir()
    else:
        target = repo / ".github" / "workflows" / "label.yml"
    code, output = _cli(target, tmp_path / "out.ndjson", repo)
    assert code == 3 and "FAIL CLOSED" in output
