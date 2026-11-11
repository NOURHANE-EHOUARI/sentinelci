"""Tool status v1 produced by the scanners (schemas/tool-status.v1.json, read by `sentinel evaluate`)."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.normalize.errors import NormalizationError
from sentinelci.policy.tool_status import ToolStatus
from sentinelci.scanners.errors import ScannerError, ScannerTimeout, ToolIntegrityError
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import ToolRun
from sentinelci.scanners.status import MAX_DETAIL, outcome_from_error, outcome_from_run, tool_status_document

from .conftest import FakeReleases
from .test_gitleaks_scan import fake_gitleaks

LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
PLATFORM = "linux-amd64"


def _run() -> ToolRun:
    return ToolRun(
        tool="gitleaks",
        version="8.30.1",
        binary_sha256="8" * 64,
        args=("dir", "."),
        returncode=0,
        duration_s=1.0,
        stdout="",
        stderr="",
    )


def _document(outcome: dict[str, object]) -> dict[str, object]:
    return tool_status_document(LOCK.read_bytes(), PLATFORM, {"gitleaks": outcome})


def test_a_successful_run_is_ok_with_its_verified_binary() -> None:
    lock = load_lock(LOCK)
    document = _document(outcome_from_run(_run(), lock=lock, platform=PLATFORM))
    ToolStatus.model_validate(document)  # the B4 model of schemas/tool-status.v1.json
    gitleaks = document["tools"]["gitleaks"]  # type: ignore[index]
    assert gitleaks == {
        "version": "8.30.1",
        "artifact_sha256": lock.tools["gitleaks"].artifacts[PLATFORM].sha256,
        "binary_sha256": "8" * 64,
        "status": "ok",
    }
    assert document["lock_sha256"] == hashlib.sha256(LOCK.read_bytes()).hexdigest()
    assert document["platform"] == PLATFORM


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (ToolIntegrityError("installed binary was modified"), "integrity_mismatch"),
        (ScannerTimeout("gitleaks timed out after 900 s"), "timeout"),
        (ScannerError("gitleaks exited with code 1: FTL"), "failed"),
        (NormalizationError("redacted report"), "failed"),
    ],
)
def test_every_failure_kind_is_recorded_with_a_reason(error: Exception, status: str) -> None:
    lock = load_lock(LOCK)
    document = _document(outcome_from_error("gitleaks", error, lock=lock))
    ToolStatus.model_validate(document)
    gitleaks = document["tools"]["gitleaks"]  # type: ignore[index]
    assert gitleaks["status"] == status
    assert gitleaks["version"] == "8.30.1"  # the pinned version: the tool may never have run
    assert gitleaks["detail"] == str(error)
    assert "binary_sha256" not in gitleaks


def test_a_long_or_multiline_reason_is_bounded_and_kept_on_one_line() -> None:
    lock = load_lock(LOCK)
    error = ScannerError("line one\nline two\t" + "x" * 2000)
    gitleaks = _document(outcome_from_error("gitleaks", error, lock=lock))["tools"]["gitleaks"]  # type: ignore[index]
    assert len(gitleaks["detail"]) == MAX_DETAIL
    assert "\n" not in gitleaks["detail"] and gitleaks["detail"].startswith("line one line two")


def test_the_document_is_deterministic_json() -> None:
    lock = load_lock(LOCK)
    first = json.dumps(_document(outcome_from_run(_run(), lock=lock, platform=PLATFORM)), sort_keys=True)
    second = json.dumps(_document(outcome_from_run(_run(), lock=lock, platform=PLATFORM)), sort_keys=True)
    assert first == second


def test_a_status_without_a_known_platform_omits_it() -> None:
    lock = load_lock(LOCK)
    outcome = outcome_from_error("gitleaks", ToolIntegrityError("unsupported platform"), lock=lock)
    document = tool_status_document(LOCK.read_bytes(), None, {"gitleaks": outcome})
    ToolStatus.model_validate(document)
    assert "platform" not in document
    assert "platform" not in tool_status_document(LOCK.read_bytes(), "windows-x86", {"gitleaks": outcome})


def test_an_empty_status_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one tool"):
        tool_status_document(LOCK.read_bytes(), PLATFORM, {})


# ------------------------------------------------------------------ sentinel scan secrets --tool-status-out

COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _scan(tmp_path: Path, dest: Path, *, lock: Path | None = None) -> tuple[Result, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    out, status = tmp_path / "out" / "secrets.ndjson", tmp_path / "out" / "tool-status.json"
    result = CliRunner().invoke(
        app,
        [
            "scan", "secrets", str(repo), "--out", str(out),
            "--repo", "NOURHANE-EHOUARI/sentinelci", "--commit", COMMIT, "--context", "pr",
            "--lock", str(lock or tmp_path / "tools.lock.toml"), "--tools-dir", str(dest),
            "--platform", PLATFORM, "--tool-status-out", str(status),
        ],
    )  # fmt: skip
    return result, out, status


def _stale_status(tmp_path: Path) -> None:
    """An `ok` status left by an earlier run: it must never vouch for this one."""
    stale = tmp_path / "out" / "tool-status.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    tools = {"gitleaks": {"version": "1.0.0", "binary_sha256": "0" * 64, "status": "ok"}}
    stale.write_text(json.dumps({"schema_version": 1, "lock_sha256": "0" * 64, "tools": tools}))


def _status(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    ToolStatus.model_validate(document)
    gitleaks: dict[str, object] = document["tools"]["gitleaks"]
    assert set(document["tools"]) == {"gitleaks"}
    return gitleaks


def test_cli_records_an_ok_status_after_the_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    result, out, status = _scan(tmp_path, dest)

    assert result.exit_code == 0, result.output
    assert out.is_file()
    binary = hashlib.sha256((dest / "bin" / "gitleaks").read_bytes()).hexdigest()
    assert _status(status) == {
        "version": "1.0.0",
        "artifact_sha256": binary,  # a raw binary release: the artifact is the binary
        "binary_sha256": binary,
        "status": "ok",
    }
    document = json.loads(status.read_text(encoding="utf-8"))
    lock_bytes = (tmp_path / "tools.lock.toml").read_bytes()
    assert document["lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    assert document["platform"] == PLATFORM


def test_cli_records_a_failed_scanner_and_still_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    body = 'echo "FTL unable to load config" >&2\nexit 1\n'
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock, body=body)
    _stale_status(tmp_path)
    result, out, status = _scan(tmp_path, dest)

    assert result.exit_code == 3 and "SC-010" in result.output
    assert not out.exists()
    gitleaks = _status(status)
    assert gitleaks["status"] == "failed"
    assert "FTL unable to load config" in str(gitleaks["detail"])


def test_cli_records_a_tampered_binary_that_never_ran(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    marker = tmp_path / "executed"
    (dest / "bin" / "gitleaks").write_text(f"#!/bin/sh\ntouch {marker}\n")
    result, out, status = _scan(tmp_path, dest)

    assert result.exit_code == 3
    assert not marker.exists() and not out.exists()
    gitleaks = _status(status)
    assert gitleaks["status"] == "integrity_mismatch"
    assert "binary_sha256" not in gitleaks


def test_cli_writes_no_status_without_a_lock(tmp_path: Path) -> None:
    # Nothing to vouch for: no status at all, which the gate reports as SC-010 "Tool status missing".
    _stale_status(tmp_path)
    result, out, status = _scan(tmp_path, tmp_path / "tools", lock=tmp_path / "missing.lock.toml")

    assert result.exit_code == 3
    assert not status.exists() and not out.exists()


def test_cli_passes_its_time_limit_to_the_scanner(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.cli as cli

    seen: dict[str, object] = {}
    real = cli.scan_secrets_with_run

    def spy(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        seen.update(kwargs)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "scan_secrets_with_run", spy)
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    _scan(tmp_path, dest)
    assert seen["timeout_s"] == 900, "default: the runner's DEFAULT_TIMEOUT_S"
    repo = tmp_path / "repo"
    result = CliRunner().invoke(
        app,
        [
            "scan", "secrets", str(repo), "--out", str(tmp_path / "o.ndjson"),
            "--repo", "o/r", "--commit", COMMIT, "--context", "pr",
            "--lock", str(tmp_path / "tools.lock.toml"), "--tools-dir", str(dest),
            "--platform", PLATFORM, "--timeout", "300",
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert seen["timeout_s"] == 300


@pytest.mark.parametrize("value", ["10", "0", "99999"])
def test_cli_refuses_a_time_limit_out_of_range(value: str) -> None:
    result = CliRunner().invoke(
        app,
        ["scan", "secrets", ".", "--out", "o", "--repo", "o/r", "--commit", COMMIT, "--context", "pr",
         "--timeout", value],
    )  # fmt: skip
    assert result.exit_code == 2


def _timeout_defaults() -> dict[str, object]:
    import typer.main

    root = typer.main.get_command(app)
    found: dict[str, object] = {}

    def walk(command: object, path: str) -> None:
        for name, sub in getattr(command, "commands", {}).items():
            walk(sub, f"{path} {name}".strip())
        for param in getattr(command, "params", []):
            if param.name == "timeout":
                found[path] = param.default

    walk(root, "")
    return found


def test_every_scan_command_defaults_to_the_scanner_time_limit() -> None:
    """Two modules export a DEFAULT_TIMEOUT_S (scanner runs, enrichment requests); a scan command must not
    pick up the enrichment one (30 s per HTTP request) by a shadowed import, and the reverse."""
    from sentinelci.enrich.transport import DEFAULT_TIMEOUT_S as FETCH_DEFAULT
    from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S as SCAN_DEFAULT

    defaults = _timeout_defaults()
    # `tools grype-db` runs Grype like a scan does: its limit is a scanner run's.
    runs_a_scanner = {path for path in defaults if path.startswith("scan ") or path == "tools grype-db"}
    scans = {path: value for path, value in defaults.items() if path in runs_a_scanner}
    assert {"scan secrets", "scan sast", "scan sca", "tools grype-db"} <= set(scans)
    assert scans == dict.fromkeys(scans, SCAN_DEFAULT)
    others = {path: value for path, value in defaults.items() if path not in runs_a_scanner}
    assert others and all(value == FETCH_DEFAULT for value in others.values()), others
