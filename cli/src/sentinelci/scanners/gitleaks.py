"""Secret scanning with Gitleaks, hardened against author-controlled suppressions (task A1b).

Gitleaks honours three suppression mechanisms that live inside the scanned repository. In a pull
request they are written by the person whose change is being checked, so each one is neutralized:

- `.gitleaks.toml` in the target       -> we always pass `--config` with SentinelCI's own configuration;
- `gitleaks:allow` inline comments     -> `--ignore-gitleaks-allow`;
- `.gitleaksignore`                    -> `--gitleaks-ignore-path` points to an empty private directory, and
  because Gitleaks *always* also loads `<source>/.gitleaksignore` (cmd/root.go), a scan target containing that
  file is refused (fail closed). Exceptions must go through SentinelCI waivers.

The raw report contains real secret values: it is written to a private temporary directory and deleted as soon
as it has been read. Only the normalized, hashed findings leave this module.
"""

import shutil
import tempfile
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, Literal

from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.gitleaks import load_gitleaks_report
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, is_within, run_verified_tool

GitleaksMode = Literal["dir", "git"]
IGNORE_FILE = ".gitleaksignore"


def _relative_target(target: Path, repo_root: Path) -> str:
    if not is_within(target, repo_root):
        raise ScannerError(f"scan target {target} is outside the repository root {repo_root}")
    relative = target.resolve().relative_to(repo_root.resolve())
    return relative.as_posix() or "."


def scan_secrets(
    target: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    repo_root: Path | None = None,
    platform: str | None = None,
    mode: GitleaksMode = "dir",
    log_opts: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> list[dict[str, Any]]:
    """Run Gitleaks on `target` and return the raw findings (to be normalized immediately)."""
    findings, _ = scan_secrets_with_run(
        target,
        lock=lock,
        tools_dir=tools_dir,
        repo_root=repo_root,
        platform=platform,
        mode=mode,
        log_opts=log_opts,
        timeout_s=timeout_s,
    )
    return findings


def scan_secrets_with_run(
    target: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    repo_root: Path | None = None,
    platform: str | None = None,
    mode: GitleaksMode = "dir",
    log_opts: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> tuple[list[dict[str, Any]], ToolRun]:
    """Same as `scan_secrets`, also returning the run metadata for the evidence bundle."""
    repo_root = repo_root or target
    source = _relative_target(target, repo_root)
    if (repo_root / source / IGNORE_FILE).exists():
        raise ScannerError(
            f"{IGNORE_FILE} found at the root of the scanned tree ({source}). Gitleaks would let it silence "
            "findings, and it is controlled by the author of the change: remove it and use SentinelCI waivers"
        )

    with tempfile.TemporaryDirectory(prefix="sentinel-gitleaks-") as private:
        work = Path(private)
        empty_ignore_dir = work / "ignore"
        empty_ignore_dir.mkdir()
        report = work / "report.json"
        with as_file(files("sentinelci.scanners.configs").joinpath("gitleaks.toml")) as packaged:
            config = work / "gitleaks.toml"
            shutil.copyfile(packaged, config)

        args = [
            mode,
            source,
            "--config", str(config),
            "--gitleaks-ignore-path", str(empty_ignore_dir),
            "--ignore-gitleaks-allow",
            "--report-format", "json",
            "--report-path", str(report),
            "--exit-code", "0",
            "--no-banner",
            "--no-color",
            "--log-level", "error",
        ]  # fmt: skip
        if mode == "git" and log_opts:
            args += ["--log-opts", log_opts]

        run = run_verified_tool(
            "gitleaks",
            args,
            lock=lock,
            tools_dir=tools_dir,
            cwd=repo_root,
            platform=platform,
            timeout_s=timeout_s,
        )
        if not report.is_file():
            raise ScannerError("gitleaks produced no report")
        try:
            findings = load_gitleaks_report(report)
        except NormalizationError as exc:
            raise ScannerError(f"gitleaks produced an unreadable report: {exc}") from exc
    return findings, run
