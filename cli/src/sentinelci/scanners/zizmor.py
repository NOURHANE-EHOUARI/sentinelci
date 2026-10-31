"""CI workflow analysis with zizmor, hardened like the other scanners (task A1, SPEC §5 stage 4).

zizmor is pinned in uv.lock: `uv sync --locked` installs its PyPI wheel after checking the wheel's hash
(zizmor publishes no checksum file for its release binaries, so like Opengrep it is not in tools.lock.toml).
Right before every run, the binary of the CLI's own environment is checked against that wheel's RECORD, so a
binary replaced after installation never runs, and a `zizmor` found on PATH is never used.

The scanned repository cannot configure or silence it: `--no-config` (no zizmor.yml), `--no-ignores`
(no `# zizmor: ignore[...]` comment is honoured), `--collect=all` (a workflow listed in .gitignore is still
read).
`--offline` and a minimal environment (no GitHub token) keep it from reaching the network.

SentinelCI collects the workflows, not zizmor, which only looks in `.github/workflows/` when given a
directory: every `*.yml` / `*.yaml` under `.github/workflows/`, every `action.yml` / `action.yaml`, and any
other YAML file with a top-level `jobs:` key (the demo's example workflows, reusable workflows kept
elsewhere).
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any

from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, minimal_env

# 0: no finding; 11 to 14: findings, by highest severity. 1, 2 and 3 (no input) are failures.
FINDINGS_EXIT_CODES = (0, 11, 12, 13, 14)
_WORKFLOW_SUFFIXES = (".yml", ".yaml")
_ACTION_NAMES = ("action.yml", "action.yaml")
_JOBS = re.compile(rb"^jobs[ \t]*:", re.MULTILINE)
MAX_WORKFLOW_BYTES = 4 << 20


@dataclass(frozen=True)
class VerifiedBinary:
    path: Path
    version: str
    sha256: str


def verified_zizmor() -> VerifiedBinary:
    """The zizmor binary installed with this environment, checked against its wheel's RECORD."""
    try:
        dist = distribution("zizmor")
    except PackageNotFoundError as exc:
        raise ToolIntegrityError("zizmor is not installed in this environment (uv sync --locked)") from exc
    expected = Path(sys.executable).parent / "zizmor"
    for entry in dist.files or []:
        path = Path(str(dist.locate_file(entry)))
        if entry.name != "zizmor" or path.resolve() != expected.resolve():
            continue
        if entry.hash is None or entry.hash.mode != "sha256":
            raise ToolIntegrityError("zizmor's RECORD has no sha256 for its binary")
        data = path.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest != entry.hash.value:
            raise ToolIntegrityError(
                f"{path} does not match zizmor {dist.version}'s RECORD: refusing to run it"
            )
        return VerifiedBinary(path=path, version=dist.version, sha256=hashlib.sha256(data).hexdigest())
    raise ToolIntegrityError(f"zizmor {dist.version}'s RECORD does not list {expected}")


def _is_workflow(path: Path, relative: Path) -> bool:
    if relative.name in _ACTION_NAMES:
        return True
    if relative.suffix not in _WORKFLOW_SUFFIXES:
        return False
    if relative.parts[:2] == (".github", "workflows"):
        return True
    if path.stat().st_size > MAX_WORKFLOW_BYTES:
        return True  # too large to sniff: let zizmor decide, never skip it silently
    return _JOBS.search(path.read_bytes()) is not None


def collect_workflows(root: Path) -> list[str]:
    """GitHub workflows and actions under `root`, as POSIX paths relative to it (links and .git skipped)."""
    found: list[str] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        for name in sorted(names):
            path = Path(directory, name)
            relative = path.relative_to(root)
            if not path.is_symlink() and path.is_file() and _is_workflow(path, relative):
                found.append(relative.as_posix())
    return found


def scan_pipelines_with_run(
    root: Path, *, timeout_s: int = DEFAULT_TIMEOUT_S
) -> tuple[list[dict[str, Any]], ToolRun | None, list[str]]:
    """Run zizmor on the workflows under `root`. Returns its findings (JSON v1), the run (None when there is
    no workflow to audit), and the files audited."""
    workflows = collect_workflows(root)
    binary = verified_zizmor()  # checked even when there is nothing to scan: a broken install still fails
    if not workflows:
        return [], None, []
    args = [
        "--offline", "--no-config", "--no-ignores", "--collect=all",
        "--format=json", "--no-progress", "--color=never", "--persona=regular",
        "--", *workflows,
    ]  # fmt: skip
    with tempfile.TemporaryDirectory(prefix="sentinel-zizmor-home-") as home:
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 (verified binary, argument list, no shell)
                [str(binary.path), *args],
                cwd=root,
                env=minimal_env(Path(home)),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(f"zizmor timed out after {timeout_s} s") from exc
        except OSError as exc:
            raise ScannerError(f"zizmor could not be started: {exc}") from exc
        duration = time.monotonic() - started
    if completed.returncode not in FINDINGS_EXIT_CODES:
        tail = completed.stderr.strip()[-2000:]
        raise ScannerError(f"zizmor exited with code {completed.returncode}: {tail}")
    try:
        results = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"zizmor produced unreadable JSON: {exc}") from exc
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise ScannerError("zizmor's JSON output is not a list of findings")
    if (completed.returncode == 0) != (not results):
        raise ScannerError(
            f"zizmor exited with {completed.returncode} but reported {len(results)} finding(s)"
        )
    run = ToolRun(
        tool="zizmor",
        version=binary.version,
        binary_sha256=binary.sha256,
        args=tuple(args),
        returncode=completed.returncode,
        stdout="",  # the report holds workflow code: it never leaves this module raw
        stderr=completed.stderr,
        duration_s=duration,
    )
    return results, run, workflows
