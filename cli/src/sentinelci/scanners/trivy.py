"""Infrastructure-as-code scanning with `trivy config`, hardened like Gitleaks (task A1c).

Trivy offers several ways for the scanned repository to configure or silence it. In a pull request they are
written by the author of the change, so each one is neutralized:

- `trivy.yaml` in the working directory          -> `--config ""` (no configuration file is loaded);
- `.trivyignore` / `.trivyignore.yaml`             -> `--ignorefile ""`;
- inline `trivy:ignore:<id>` and legacy `tfsec:ignore:<id>` comments (Terraform, Dockerfile, ...) -> Trivy
  0.76 has no flag to disable them, so a scan target that contains either marker is refused (fail closed),
  like `.gitleaksignore`. Exceptions go through SentinelCI waivers;
- WASM modules (`~/.trivy/modules`) and the check cache -> private, empty directories. The Rego checks are the
  ones embedded in the pinned binary (`--skip-check-update`), so the result depends on the lock only;
- check data -> SentinelCI's own `--config-data` (for example the trusted image registries).

Trivy also downloads the remote Terraform modules that the scanned code names (`git::https://...`, registry
sources): network access chosen by the change author, and a result that depends on the network. The run gets
proxy variables pointing at a closed local port and `GIT_ALLOW_PROTOCOL=none`, so every download fails at once
and the scan stays offline. Resources built inside a remote module are not evaluated: scanning third-party
modules is not the job of this stage. Version checks and telemetry are disabled.

Trivy does not follow symbolic links, so the marker check does not either. The raw report holds code lines
of the scanned files (which may contain credentials): it stays in a private temporary directory, and only
normalized findings, without code, leave this module.
"""

import json
import os
import re
import stat
import tempfile
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from sentinelci.scanners.errors import ScannerError, ScannerTimeout
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, is_within, run_verified_tool

# Matched case-insensitively and with optional spaces: wider than what Trivy honours, never narrower.
INLINE_IGNORE = re.compile(rb"(?:trivy|tfsec)\s*:\s*ignore", re.IGNORECASE)
_CHUNK = 1 << 20
_OVERLAP = 64
MAX_REPORTED_FILES = 5
# A closed port on the loopback interface: every proxied request fails immediately.
_NO_NETWORK_PROXY = "http://127.0.0.1:9"
OFFLINE_ENV = {
    "HTTPS_PROXY": _NO_NETWORK_PROXY,
    "HTTP_PROXY": _NO_NETWORK_PROXY,
    "ALL_PROXY": _NO_NETWORK_PROXY,
    "https_proxy": _NO_NETWORK_PROXY,
    "http_proxy": _NO_NETWORK_PROXY,
    "all_proxy": _NO_NETWORK_PROXY,
    "NO_PROXY": "",
    "no_proxy": "",
    "GIT_ALLOW_PROTOCOL": "none",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _relative_target(target: Path, repo_root: Path) -> str:
    if not is_within(target, repo_root):
        raise ScannerError(f"scan target {target} is outside the repository root {repo_root}")
    relative = target.resolve().relative_to(repo_root.resolve())
    return relative.as_posix() or "."


def _has_marker(path: Path) -> bool:
    tail = b""
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            if INLINE_IGNORE.search(tail + chunk):
                return True
            tail = chunk[-_OVERLAP:]
    return False


def inline_ignores(root: Path) -> list[str]:
    """Regular files under `root` (symlinks not followed, `.git` skipped) that contain an inline ignore."""
    found: list[str] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        for name in sorted(names):
            path = Path(directory, name)
            if stat.S_ISREG(path.lstat().st_mode) and _has_marker(path):
                found.append(path.relative_to(root).as_posix())
    return found


def scan_iac_with_run(
    target: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    repo_root: Path | None = None,
    platform: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> tuple[list[dict[str, Any]], ToolRun]:
    """Run `trivy config` on `target`; return the Trivy results (paths relative to `target`) and the run."""
    repo_root = repo_root or target
    source = _relative_target(target, repo_root)
    marked = inline_ignores(repo_root / source)
    if marked:
        shown = ", ".join(marked[:MAX_REPORTED_FILES])
        more = f" and {len(marked) - MAX_REPORTED_FILES} more" if len(marked) > MAX_REPORTED_FILES else ""
        raise ScannerError(
            f"inline trivy:ignore / tfsec:ignore comments found in the scanned tree ({shown}{more}). Trivy "
            "would let them silence findings, and they are controlled by the author of the change: remove "
            "them and use SentinelCI waivers"
        )

    with tempfile.TemporaryDirectory(prefix="sentinel-trivy-") as private:
        work = Path(private)
        for name in ("cache", "modules"):
            (work / name).mkdir()
        report = work / "report.json"
        with as_file(files("sentinelci.scanners.configs").joinpath("trivy-data")) as config_data:
            args = [
                "config",
                "--config", "",
                "--ignorefile", "",
                "--cache-dir", str(work / "cache"),
                "--module-dir", str(work / "modules"),
                "--config-data", str(config_data),
                "--skip-check-update",
                "--skip-version-check",
                "--disable-telemetry",
                "--timeout", f"{timeout_s}s",
                "--exit-code", "0",
                "--quiet",
                "--format", "json",
                "--output", str(report),
                source,
            ]  # fmt: skip
            # Trivy's own time limit comes first (reported as a timeout); the runner's is the backstop.
            try:
                run = run_verified_tool(
                    "trivy",
                    args,
                    lock=lock,
                    tools_dir=tools_dir,
                    cwd=repo_root,
                    platform=platform,
                    timeout_s=timeout_s + 60,
                    extra_env=OFFLINE_ENV,
                )
            except ScannerTimeout:
                raise
            except ScannerError as exc:
                if "context deadline exceeded" in str(exc):
                    raise ScannerTimeout(f"trivy timed out after {timeout_s} s") from exc
                raise
        if not report.is_file():
            raise ScannerError("trivy produced no report")
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScannerError(f"trivy produced an unreadable report: {exc}") from exc
    if not isinstance(data, dict) or data.get("SchemaVersion") != 2:
        raise ScannerError("trivy report is not a JSON object with SchemaVersion 2")
    results = data.get("Results", [])
    if not isinstance(results, list) or not all(isinstance(result, dict) for result in results):
        raise ScannerError("trivy report `Results` must be a list of objects")
    return results, run
