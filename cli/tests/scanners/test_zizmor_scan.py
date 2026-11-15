"""`sentinel scan pipelines`: zizmor, verified, never configured or silenced by the scanned repository (A1).

zizmor is a runtime dependency of the CLI (uv.lock), so these tests run the real one; failure modes are
simulated by replacing the process call, the installed distribution or the environment's binary.
"""

import dataclasses
import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import sentinelci.cli as cli_module
import sentinelci.scanners.zizmor as zizmor
from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.lock import ToolLock, load_lock
from sentinelci.scanners.zizmor import (
    Inputs,
    PipelineScan,
    collect_inputs,
    scan_pipelines_with_run,
    verified_zizmor,
)

ROOT = Path(__file__).resolve().parents[3]
REPO_LOCK = ROOT / "tools.lock.toml"
LOCK = load_lock(REPO_LOCK)
PINNED = LOCK.python_tools["zizmor"].version  # the version every real run must report
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
CIRCLECI = """version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
"""
DEPENDABOT = """version: 2
updates:
  - package-ecosystem: pip
    directory: /
    schedule: {interval: weekly}
    insecure-external-code-execution: allow
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
        ".github/dependabot.yml": DEPENDABOT,  # review of #37, should fix 3
        "examples/bad.yml": CLEAN,  # a workflow kept elsewhere: has `jobs:`
        "ci/config.yml": CIRCLECI,  # another CI's file with `jobs:`: tried, may be skipped
        "deploy/values.yaml": "replicas: 2\n",  # not a workflow
        "deploy/dependabot.yml": DEPENDABOT,  # GitHub only reads .github/dependabot.yml
        "actions/setup/action.yml": "runs:\n  using: composite\n  steps: []\n",
        ".git/hooks/ci.yml": CLEAN,
        "README.md": "jobs: not yaml\n",
    }.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    (repo / "linked.yml").symlink_to(repo / "examples" / "bad.yml")
    assert collect_inputs(repo) == Inputs(
        strict=[".github/dependabot.yml", ".github/workflows/ci.yml", ".github/workflows/odd.yaml",
                "actions/setup/action.yml"],
        lenient=["ci/config.yml", "examples/bad.yml"],
    )  # fmt: skip


def test_ignore_comments_and_repository_config_are_not_honoured(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for config in (repo / "zizmor.yml", repo / ".github" / "zizmor.yml"):
        config.write_text("rules:\n  template-injection:\n    disable: true\n")
    (repo / ".gitignore").write_text(".github/workflows/label.yml\n")  # listed, yet still audited
    scan = scan_pipelines_with_run(repo, lock=LOCK)
    assert (scan.audited, scan.skipped) == ([".github/workflows/label.yml"], [])
    assert "template-injection" in _rules(scan.results)
    # Still reported, flagged `ignored` because of the comments: the normalizer keeps it (tested there).
    assert all(item.get("ignored") for item in scan.results if item["ident"] == "template-injection")
    run = scan.run
    assert run is not None and run.returncode in zizmor.FINDINGS_EXIT_CODES and run.stdout == ""
    for flag in (
        "--offline",
        "--no-config",
        "--no-ignores",
        "--ignore-lockfile",
        "--collect=all",
        "--strict-collection",
        "--format=json",
    ):
        assert flag in run.args


UNPINNED = """name: build
on: push
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
"""


def test_a_workflow_lockfile_of_the_scanned_repository_silences_nothing(tmp_path: Path) -> None:
    """zizmor 1.32 drops unpinned-uses for every workflow listed in `.github/workflows/actions.lock` at the
    Git root, whatever it pins. That file belongs to the scanned repository, which never configures the
    scanner: `--ignore-lockfile` (Hiba, review of #119)."""
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".git").mkdir()  # zizmor reads the lockfile at the Git root only
    (repo / ".github" / "workflows" / "build.yml").write_text(UNPINNED, encoding="utf-8")
    (repo / ".github" / "workflows" / "actions.lock").write_text(
        "version: v0.0.3\nworkflows:\n  .github/workflows/build.yml: []\ndependencies: {}\n", encoding="utf-8"
    )
    scan = scan_pipelines_with_run(repo, lock=LOCK)
    assert scan.audited == [".github/workflows/build.yml"]
    assert "unpinned-uses" in _rules(scan.results)


def test_dependabot_is_audited(tmp_path: Path) -> None:
    # Review of #37, should fix 3: a repository with only a Dependabot file reported "zizmor not run".
    repo = tmp_path / "repo"
    (repo / ".github").mkdir(parents=True)
    (repo / ".github" / "dependabot.yml").write_text(DEPENDABOT)
    scan = scan_pipelines_with_run(repo, lock=LOCK)
    assert scan.audited == [".github/dependabot.yml"]
    assert "dependabot-execution" in _rules(scan.results)


def test_a_workflow_github_runs_that_zizmor_cannot_load_fails_closed(tmp_path: Path) -> None:
    # Review of #37, should fix 4: without --strict-collection it was skipped and still counted as audited.
    repo = _repo(tmp_path)
    (repo / ".github" / "workflows" / "ok.yml").write_text(CLEAN)
    (repo / ".github" / "workflows" / "w.yml").write_text(
        INJECTION.replace("  # zizmor", "\n        shell: 42  # z")
    )
    with pytest.raises(ScannerError, match=r"cannot load \.github/workflows/w\.yml, which GitHub runs"):
        scan_pipelines_with_run(repo, lock=LOCK)


def test_another_cis_file_is_skipped_and_reported_never_counted_as_audited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for name, text in {
        "ci/config.yml": CIRCLECI,
        "ci/other.yml": CIRCLECI,
        "examples/label.yml": INJECTION,
    }.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    scan = scan_pipelines_with_run(repo, lock=LOCK)
    assert scan.skipped == ["ci/config.yml", "ci/other.yml"]
    assert scan.audited == ["examples/label.yml"]
    assert "template-injection" in _rules(scan.results)
    assert scan.run is not None and "ci/config.yml" not in scan.run.args
    (repo / "examples" / "label.yml").unlink()
    assert scan_pipelines_with_run(repo, lock=LOCK) == PipelineScan(
        results=[], run=None, audited=[], skipped=["ci/config.yml", "ci/other.yml"], version=PINNED,
        binary_sha256=verified_zizmor(LOCK).sha256,
    )  # fmt: skip


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
    scan_pipelines_with_run(repo, lock=LOCK)
    assert "GITHUB_TOKEN" not in seen["env"] and "ZIZMOR_CONFIG" not in seen["env"]
    assert Path(seen["cwd"]) == repo, "relative paths: the findings point into the audited tree"


def test_nothing_to_audit_runs_nothing_but_still_checks_the_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    assert scan_pipelines_with_run(repo, lock=LOCK) == PipelineScan(
        results=[], run=None, audited=[], skipped=[], version=PINNED,
        binary_sha256=verified_zizmor(LOCK).sha256,
    )  # fmt: skip

    def missing(name: str) -> Any:
        raise PackageNotFoundError(name)

    monkeypatch.setattr(zizmor, "distribution", missing)
    with pytest.raises(ToolIntegrityError, match="not installed"):
        scan_pipelines_with_run(repo, lock=LOCK)


def _environment_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, binary: bytes | None) -> Path:
    """A bin directory standing for the environment, with this `zizmor` in it (the real one if None)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    target = bin_dir / "zizmor"
    if binary is None:
        shutil.copy2(verified_zizmor(LOCK).path, target)
    else:
        target.write_bytes(binary)
        target.chmod(0o755)
    monkeypatch.setattr(zizmor.sys, "executable", str(bin_dir / "python"))
    return target


def test_a_replaced_binary_never_runs_even_with_its_record_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #37, should fix 1: RECORD sits in the installed tree, so it vouched for itself. The binary is
    now checked against tools.lock.toml, whose hashes come from the wheels uv.lock pins."""
    _environment_with(tmp_path, monkeypatch, b"#!/bin/sh\necho '[]'\n")
    with pytest.raises(
        ToolIntegrityError, match=rf"is not a zizmor {re.escape(PINNED)} binary pinned in tools\.lock\.toml"
    ):
        scan_pipelines_with_run(_repo(tmp_path), lock=LOCK)


def test_the_genuine_binary_is_accepted_wherever_the_environment_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _environment_with(tmp_path, monkeypatch, None)
    assert "template-injection" in _rules(scan_pipelines_with_run(_repo(tmp_path), lock=LOCK).results)


def test_another_installed_version_never_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    class Dist:
        version = "1.30.0"

    monkeypatch.setattr(zizmor, "distribution", lambda name: Dist())
    pins = rf"zizmor 1\.30\.0 is installed, but tools\.lock\.toml pins {re.escape(PINNED)}"
    with pytest.raises(ToolIntegrityError, match=pins):
        verified_zizmor(LOCK)


def test_the_binary_must_be_a_regular_file_of_this_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(zizmor.sys, "executable", str(tmp_path / "elsewhere" / "python"))
    with pytest.raises(ToolIntegrityError, match="is not the zizmor binary of this environment"):
        verified_zizmor(LOCK)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "zizmor").symlink_to(Path(zizmor.__file__))  # a link is never followed
    with pytest.raises(ToolIntegrityError, match="is not the zizmor binary of this environment"):
        verified_zizmor(LOCK)


def test_a_lock_without_zizmor_refuses_to_run() -> None:
    lock = ToolLock.model_validate({**LOCK.model_dump(), "python_tools": {}})
    with pytest.raises(ToolIntegrityError, match=r"pins no zizmor \(\[python_tools\.zizmor\]\)"):
        verified_zizmor(lock)


def test_the_lock_pins_the_wheels_uv_lock_installs() -> None:
    """tools.lock.toml and uv.lock name the same zizmor: same version, and every wheel pinned here has the
    hash uv.lock checks at install time (so its binary_sha256, read from that wheel, is vouched for by
    uv.lock)."""
    uv_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    (package,) = [p for p in uv_lock["package"] if p["name"] == "zizmor"]
    uv_wheels = {w["url"].rsplit("/", 1)[-1]: w["hash"].removeprefix("sha256:") for w in package["wheels"]}
    pinned = LOCK.python_tools["zizmor"]
    assert pinned.version == package["version"]
    assert {wheel.file: wheel.sha256 for wheel in pinned.wheels}.items() <= uv_wheels.items()
    platforms = {
        "manylinux_2_28_x86_64",
        "manylinux_2_24_aarch64",
        "macosx_10_12_x86_64",
        "macosx_11_0_arm64",
    }
    assert all(any(tag in wheel.file for wheel in pinned.wheels) for tag in platforms)
    cli = tomllib.loads((ROOT / "cli" / "pyproject.toml").read_text(encoding="utf-8"))
    assert f"zizmor=={pinned.version}" in cli["project"]["dependencies"], (
        "the CLI installs exactly this version"
    )


class _Completed:
    def __init__(self, returncode: int, stdout: str, stderr: str = "zizmor said no") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


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
        scan_pipelines_with_run(_repo(tmp_path), lock=LOCK)


def test_an_unloadable_file_that_was_not_an_input_is_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stderr = "fatal: no audit was performed\nfailed to load file://somewhere/else.yml as workflow\n"
    monkeypatch.setattr(zizmor.subprocess, "run", lambda *a, **k: _Completed(1, "", stderr))
    with pytest.raises(ScannerError, match="exited with code 1"):
        scan_pipelines_with_run(_repo(tmp_path), lock=LOCK)


def test_a_timeout_is_a_scanner_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="zizmor", timeout=1)

    monkeypatch.setattr(zizmor.subprocess, "run", slow)
    with pytest.raises(ScannerError, match="timed out"):
        scan_pipelines_with_run(_repo(tmp_path), lock=LOCK, timeout_s=1)


def _cli(target: Path, out: Path, repo_root: Path | None = None, *extra: str) -> tuple[int, str]:
    args = ["scan", "pipelines", str(target), "--out", str(out), "--repo", "o/r", "--commit", "0" * 40,
            "--context", "pr", "--lock", str(REPO_LOCK), *extra]  # fmt: skip
    if repo_root is not None:
        args += ["--repo-root", str(repo_root)]
    result = CliRunner().invoke(app, args)
    return result.exit_code, result.output


def test_cli_writes_repository_relative_pipeline_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "demo-shop" / "examples").mkdir(parents=True)
    (repo / "demo-shop" / "examples" / "label.yml").write_text(INJECTION)
    (repo / "demo-shop" / "ci").mkdir()
    (repo / "demo-shop" / "ci" / "config.yml").write_text(CIRCLECI)
    out = tmp_path / "out" / "pipelines.ndjson"
    code, output = _cli(repo / "demo-shop", out, repo)
    assert code == 0, output
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    assert {f["category"] for f in findings} == {"PIPELINE"}
    assert {f["location"]["path"] for f in findings} == {"demo-shop/examples/label.yml"}
    assert "template-injection" in {f["rule_id"] for f in findings}
    assert "1 file(s) audited" in output
    assert "not audited: ci/config.yml" in output


def test_cli_summary_names_the_verified_version_even_when_every_file_is_skipped(tmp_path: Path) -> None:
    """Review of #37, nit 3: "zizmor not run: 0 file(s) audited", although the binary was verified and ran."""
    repo = tmp_path / "repo"
    (repo / "ci").mkdir(parents=True)
    (repo / "ci" / "config.yml").write_text(CIRCLECI)
    code, output = _cli(repo, tmp_path / "out.ndjson")
    assert code == 0, output
    assert f"zizmor {PINNED}: 0 file(s) audited, 1 skipped, 0 finding(s)" in output
    (repo / "ci" / "config.yml").unlink()
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "clean.yml").write_text(CLEAN)
    code, output = _cli(repo, tmp_path / "out.ndjson")
    assert code == 0 and f"zizmor {PINNED}: 1 file(s) audited, 0 finding(s)" in output, output


def test_cli_findings_carry_the_version_that_ran(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = cli_module.scan_pipelines_with_run
    monkeypatch.setattr(
        cli_module,
        "scan_pipelines_with_run",
        lambda *a, **k: dataclasses.replace(real(*a, **k), version="1.31.1+probe"),
    )
    out = tmp_path / "out.ndjson"
    code, output = _cli(_repo(tmp_path), out)
    assert code == 0 and "zizmor 1.31.1+probe: 1 file(s) audited" in output, output
    assert {json.loads(line)["tool"]["version"] for line in out.read_text().splitlines()} == {"1.31.1+probe"}


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


# ---------------------------------------------------------------- tool status (the gate's SC-010, A3)


def _status_validator() -> Any:
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "schemas" / "tool-status.v1.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


@pytest.mark.parametrize("files", ["a-workflow", "nothing-to-audit"])
def test_cli_records_an_ok_tool_status_with_the_verified_binary_and_its_wheel(
    tmp_path: Path, files: str
) -> None:
    repo = _repo(tmp_path) if files == "a-workflow" else tmp_path / "empty"
    repo.mkdir(exist_ok=True)
    status = tmp_path / "status.json"
    code, output = _cli(repo, tmp_path / "out.ndjson", None, "--tool-status-out", str(status))
    assert code == 0, output
    document = json.loads(status.read_text())
    assert not list(_status_validator().iter_errors(document))
    binary = verified_zizmor(LOCK)
    wheels = {wheel.sha256: wheel.binary_sha256 for wheel in LOCK.python_tools["zizmor"].wheels}
    (tool,) = document["tools"].values()
    assert list(document["tools"]) == ["zizmor"] and tool["status"] == "ok" and tool["version"] == PINNED
    assert tool["binary_sha256"] == binary.sha256 and wheels[tool["artifact_sha256"]] == binary.sha256
    assert document["lock_sha256"] == hashlib.sha256(REPO_LOCK.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("how", "status_name"),
    [("crash", "failed"), ("timeout", "timeout"), ("tampered", "integrity_mismatch")],
)
def test_cli_records_a_failure_so_the_gate_blocks_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str, status_name: str
) -> None:
    if how == "crash":
        monkeypatch.setattr(zizmor.subprocess, "run", lambda *a, **k: _Completed(2, ""))
    elif how == "timeout":

        def slow(*args: Any, **kwargs: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd="zizmor", timeout=kwargs["timeout"])

        monkeypatch.setattr(zizmor.subprocess, "run", slow)
    status = tmp_path / "status.json"
    lock = REPO_LOCK
    if how == "tampered":  # the installed binary is not one a pinned wheel carries
        lock = tmp_path / "tools.lock.toml"
        lock.write_text(re.sub(r'binary_sha256 = "[0-9a-f]{64}"', 'binary_sha256 = "' + "0" * 64 + '"',
                               REPO_LOCK.read_text()))  # fmt: skip
    status.write_text("stale")
    code, output = _cli(_repo(tmp_path), tmp_path / "out.ndjson", None, "--tool-status-out", str(status),
                        "--timeout", "37", "--lock", str(lock))  # fmt: skip
    assert code == 3 and "FAIL CLOSED" in output, output
    document = json.loads(status.read_text())
    assert not list(_status_validator().iter_errors(document))
    assert document["tools"]["zizmor"]["status"] == status_name
    assert document["tools"]["zizmor"]["version"] == PINNED, "the pinned version: it may never have run"
    if how == "timeout":
        assert "37 s" in document["tools"]["zizmor"]["detail"]
