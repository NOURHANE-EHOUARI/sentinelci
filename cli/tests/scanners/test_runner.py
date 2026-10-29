"""Running a verified tool: verify before exec, minimal environment, timeouts, exit codes (task A1b)."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.installer import install_tools
from sentinelci.scanners.lock import ToolLock, load_lock
from sentinelci.scanners.runner import run_verified_tool

from .conftest import BASE, FakeReleases, raw_tool_lock, sha256

PLATFORM = "linux-amd64"


def install_script(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    script: str,
    tool: str = "rawtool",
) -> tuple[ToolLock, Path]:
    """Pin and install a shell script as if it were an official release binary."""
    content = ("#!/bin/sh\n" + script).encode()
    releases.files[BASE.format(tool=tool) + f"/{tool}-linux-amd64"] = content
    lock = load_lock(write_lock(raw_tool_lock(sha256(content), tool=tool)))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)
    return lock, dest


def test_successful_run_returns_output(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, 'echo "hello $1"\n')
    run = run_verified_tool("rawtool", ["world"], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)
    assert run.stdout.strip() == "hello world"
    assert run.version == "1.0.0"
    assert run.returncode == 0


def test_tampered_tool_is_never_executed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, "exit 0\n")
    marker = tmp_path / "executed"
    (dest / "bin" / "rawtool").write_text(f"#!/bin/sh\ntouch {marker}\n")

    with pytest.raises(ToolIntegrityError, match="installed binary was modified"):
        run_verified_tool("rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)
    assert not marker.exists(), "verification must happen before execution"


def test_unexpected_exit_code_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, 'echo "boom" >&2\nexit 7\n')
    with pytest.raises(ScannerError, match=r"rawtool exited with code 7: boom"):
        run_verified_tool("rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)


def test_allowed_exit_codes_are_accepted(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, "exit 1\n")
    run = run_verified_tool(
        "rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path, allowed_exit_codes=(0, 1)
    )
    assert run.returncode == 1


def test_timeout_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, "sleep 5\n")
    with pytest.raises(ScannerError, match="rawtool timed out after 1 s"):
        run_verified_tool(
            "rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path, timeout_s=1
        )


def test_child_gets_a_minimal_environment(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # CI secrets in the parent environment must never reach a scanner (lesson of the 2026 Trivy compromise).
    monkeypatch.setenv("GITHUB_TOKEN", "parent-secret")
    monkeypatch.setenv("COSIGN_PASSWORD", "parent-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "parent-secret")
    lock, dest = install_script(tmp_path, releases, write_lock, "env\n")

    run = run_verified_tool("rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)

    child_env = dict(line.split("=", 1) for line in run.stdout.splitlines() if "=" in line)
    assert "parent-secret" not in run.stdout
    assert set(child_env) <= {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PWD", "SHLVL", "_"}


def test_stderr_in_errors_is_truncated(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, "yes x | head -c 20000 >&2\nexit 2\n")
    with pytest.raises(ScannerError) as excinfo:
        run_verified_tool("rawtool", [], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)
    assert len(str(excinfo.value)) < 3000


def test_run_metadata_is_serializable(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest = install_script(tmp_path, releases, write_lock, "exit 0\n")
    run = run_verified_tool("rawtool", ["--flag"], lock=lock, tools_dir=dest, platform=PLATFORM, cwd=tmp_path)
    data = json.loads(json.dumps(run.metadata()))
    assert data["tool"] == "rawtool"
    assert data["binary_sha256"] == sha256(b"#!/bin/sh\nexit 0\n")
    assert data["args"] == ["--flag"]
