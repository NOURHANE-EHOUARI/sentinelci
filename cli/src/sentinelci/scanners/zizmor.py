"""CI workflow analysis with zizmor, hardened like the other scanners (task A1, SPEC §5 stage 4).

zizmor is a runtime dependency of the CLI, installed by `uv sync --locked` from its PyPI wheel (zizmor
publishes no checksum file for its release binaries, so it is not a `[tools]` entry). Right before every run,
the binary of the CLI's own environment is hashed and must be one that a wheel pinned in tools.lock.toml
(`[python_tools.zizmor]`) carries, at the pinned version: a binary replaced or reinstalled after installation
never runs, and a `zizmor` found on PATH is never used.

The scanned repository cannot configure or silence it: `--no-config` (no zizmor.yml), `--no-ignores`
(no `# zizmor: ignore[...]` comment is honoured), `--collect=all` (a workflow listed in .gitignore is still
read). `--offline` and a minimal environment (no GitHub token) keep it from reaching the network.
`--persona=regular` is zizmor's default set of audits: the pedantic and auditor personas add findings meant
for manual review, too noisy for a blocking gate.

SentinelCI collects the inputs, not zizmor (which only looks in `.github/workflows/` when given a
directory):
- what GitHub runs: every `*.yml` / `*.yaml` under `.github/workflows/`, every `action.yml` /
  `action.yaml`, and `.github/dependabot.yml` / `.yaml`. These must load (`--strict-collection`): one that
  zizmor cannot load is a scan error (SC-010), never a silent skip;
- any other YAML file with a top-level `jobs:` key (the demo's example workflows, reusable workflows kept
  elsewhere). Other CI systems use that key too, so such a file that zizmor cannot load as a GitHub workflow
  is skipped and reported, never counted as audited.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any

from sentinelci.scanners.errors import ScannerError, ScannerTimeout, ToolIntegrityError
from sentinelci.scanners.lock import LOCK_FILE_NAME, ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, minimal_env

# 0: no finding; 11 to 14: findings, by highest severity. 1, 2 and 3 (no input) are failures.
FINDINGS_EXIT_CODES = (0, 11, 12, 13, 14)
_WORKFLOW_SUFFIXES = (".yml", ".yaml")
_ACTION_NAMES = ("action.yml", "action.yaml")
_DEPENDABOT = frozenset({(".github", "dependabot.yml"), (".github", "dependabot.yaml")})
_JOBS = re.compile(rb"^jobs[ \t]*:", re.MULTILINE)
MAX_WORKFLOW_BYTES = 4 << 20
_FLAGS = (
    "--offline", "--no-config", "--no-ignores", "--collect=all", "--strict-collection",
    "--format=json", "--no-progress", "--color=never", "--persona=regular",
)  # fmt: skip


@dataclass(frozen=True)
class VerifiedBinary:
    path: Path
    version: str
    sha256: str


@dataclass(frozen=True)
class Inputs:
    """What to audit, as POSIX paths relative to the scan root."""

    strict: list[str] = field(default_factory=list)  # GitHub runs them: they must load
    lenient: list[str] = field(default_factory=list)  # found by their `jobs:` key: may be another CI's file

    @property
    def all(self) -> list[str]:
        return sorted([*self.strict, *self.lenient])


@dataclass(frozen=True)
class PipelineScan:
    results: list[dict[str, Any]]
    run: ToolRun | None  # None when there was nothing to audit
    audited: list[str]
    skipped: list[str]  # found by their `jobs:` key, but zizmor cannot load them as GitHub workflows
    version: str  # of the verified binary, checked even when nothing was audited
    binary_sha256: str  # of the verified binary, for the tool status


def verified_zizmor(lock: ToolLock) -> VerifiedBinary:
    """The zizmor binary of this environment, checked against tools.lock.toml (version and binary hash)."""
    pinned = lock.python_tools.get("zizmor")
    if pinned is None:
        raise ToolIntegrityError(f"{LOCK_FILE_NAME} pins no zizmor ([python_tools.zizmor])")
    try:
        installed = distribution("zizmor").version
    except PackageNotFoundError as exc:
        raise ToolIntegrityError("zizmor is not installed in this environment (uv sync --locked)") from exc
    if installed != pinned.version:
        raise ToolIntegrityError(
            f"zizmor {installed} is installed, but {LOCK_FILE_NAME} pins {pinned.version}"
        )
    path = Path(sys.executable).parent / pinned.binary
    if path.is_symlink() or not path.is_file():
        raise ToolIntegrityError(f"{path} is not the zizmor binary of this environment")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest not in {wheel.binary_sha256 for wheel in pinned.wheels}:
        raise ToolIntegrityError(
            f"{path} (sha256 {digest}) is not a zizmor {pinned.version} binary pinned in {LOCK_FILE_NAME}: "
            "refusing to run it"
        )
    return VerifiedBinary(path=path, version=installed, sha256=digest)


def _kind(path: Path, relative: Path) -> str | None:
    """ "strict", "lenient", or None (not audited)."""
    if relative.name in _ACTION_NAMES:
        return "strict"
    if relative.suffix not in _WORKFLOW_SUFFIXES:
        return None
    if relative.parts[:2] == (".github", "workflows") or relative.parts in _DEPENDABOT:
        return "strict"
    if path.stat().st_size > MAX_WORKFLOW_BYTES:
        return "lenient"  # too large to sniff: let zizmor decide, never skip it silently
    return "lenient" if _JOBS.search(path.read_bytes()) is not None else None


def collect_inputs(root: Path) -> Inputs:
    """GitHub workflows, actions and Dependabot files under `root` (links and .git skipped)."""
    inputs = Inputs()
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        for name in sorted(names):
            path = Path(directory, name)
            relative = path.relative_to(root)
            if path.is_symlink() or not path.is_file():
                continue
            kind = _kind(path, relative)
            if kind is not None:
                (inputs.strict if kind == "strict" else inputs.lenient).append(relative.as_posix())
    return inputs


def _not_loadable(stderr: str, candidates: list[str]) -> str | None:
    """The input zizmor stopped on because it could not load it (--strict-collection), among `candidates`."""
    for name in candidates:
        if f"failed to load file://{name} as " in stderr:
            return name
    return None


def _run(
    binary: VerifiedBinary, root: Path, files: list[str], timeout_s: float
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="sentinel-zizmor-home-") as home:
        try:
            return subprocess.run(  # noqa: S603 (verified binary, argument list, no shell)
                [str(binary.path), *_FLAGS, "--", *files],
                cwd=root,
                env=minimal_env(Path(home)),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeout(f"zizmor timed out after {timeout_s:g} s") from exc
        except OSError as exc:
            raise ScannerError(f"zizmor could not be started: {exc}") from exc


def scan_pipelines_with_run(
    root: Path, *, lock: ToolLock, timeout_s: int = DEFAULT_TIMEOUT_S
) -> PipelineScan:
    """Run zizmor on the workflows under `root`: its findings (JSON v1), the run, and what was audited."""
    inputs = collect_inputs(root)
    binary = verified_zizmor(lock)  # checked even when there is nothing to scan: a broken install still fails
    files, skipped = inputs.all, []
    started = time.monotonic()
    while files:
        remaining = timeout_s - (time.monotonic() - started)
        if remaining <= 0:
            raise ScannerTimeout(f"zizmor timed out after {timeout_s} s")
        completed = _run(binary, root, files, remaining)
        if completed.returncode != 1:
            break
        unloadable = _not_loadable(completed.stderr, files)
        if unloadable is None:
            break  # a real failure: reported below
        if unloadable in inputs.strict:
            raise ScannerError(
                f"zizmor cannot load {unloadable}, which GitHub runs, so it cannot be audited: "
                + completed.stderr.strip()[-1500:]
            )
        files.remove(unloadable)  # another CI's file with a `jobs:` key: not a GitHub workflow
        skipped.append(unloadable)
    if not files:
        return PipelineScan(
            results=[], run=None, audited=[], skipped=sorted(skipped), version=binary.version,
            binary_sha256=binary.sha256,
        )  # fmt: skip
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
        args=(*_FLAGS, "--", *files),
        returncode=completed.returncode,
        stdout="",  # the report holds workflow code: it never leaves this module raw
        stderr=completed.stderr,
        duration_s=time.monotonic() - started,
    )
    return PipelineScan(
        results=results, run=run, audited=files, skipped=sorted(skipped), version=binary.version,
        binary_sha256=binary.sha256,
    )  # fmt: skip
