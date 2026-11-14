"""Run a pinned tool safely (SPEC §5.2, job isolation — task A1b).

- The binary is verified against tools.lock.toml immediately before it is executed.
- The child process gets a minimal environment: CI secrets in the parent environment never reach a scanner.
- No shell is involved; arguments are passed as a list.
- Timeouts and unexpected exit codes raise ScannerError (fail closed, SC-010).
"""

import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.scanners.errors import ScannerError, ScannerTimeout
from sentinelci.scanners.installer import verify_tools
from sentinelci.scanners.lock import ToolLock

DEFAULT_TIMEOUT_S = 900
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
_STDERR_TAIL = 2000


@dataclass(frozen=True)
class ToolRun:
    tool: str
    version: str
    binary_sha256: str
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float

    def metadata(self) -> dict[str, Any]:
        """What the evidence bundle records about this run (never the output itself)."""
        return {
            "tool": self.tool,
            "version": self.version,
            "binary_sha256": self.binary_sha256,
            "args": list(self.args),
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 3),
        }


def minimal_env(home: Path) -> dict[str, str]:
    """A clean environment: no tokens, keys or proxy settings from the CI job are inherited."""
    return {
        "PATH": SAFE_PATH,
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": str(home),
    }


def _tail(text: str) -> str:
    text = text.strip()
    return text if len(text) <= _STDERR_TAIL else "…" + text[-_STDERR_TAIL:]


def run_verified_tool(
    name: str,
    args: Sequence[str],
    *,
    lock: ToolLock,
    tools_dir: Path,
    cwd: Path,
    platform: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    allowed_exit_codes: Sequence[int] = (0,),
    extra_env: dict[str, str] | None = None,
) -> ToolRun:
    """Verify `name` against the lock, then run it. Raises ToolIntegrityError or ScannerError on any doubt."""
    (verified,) = verify_tools(lock, tools_dir, platform=platform, only=[name]).entries
    # The file just verified, by an absolute path: the tool runs in `cwd`, often an empty directory of its
    # own, where a relative --tools-dir (`.sentinel/tools`, the default) names nothing.
    binary = verified.path.absolute()
    with tempfile.TemporaryDirectory(prefix=f"sentinel-{name}-home-") as home:
        env = minimal_env(Path(home)) | (extra_env or {})
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 (verified binary, argument list, no shell)
                [str(binary), *args],
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeout(f"{name} timed out after {timeout_s} s") from exc
        except OSError as exc:
            raise ScannerError(f"{name} could not be started: {exc}") from exc
        duration = time.monotonic() - started
    if completed.returncode not in allowed_exit_codes:
        raise ScannerError(f"{name} exited with code {completed.returncode}: {_tail(completed.stderr)}")
    return ToolRun(
        tool=name,
        version=verified.version,
        binary_sha256=verified.binary_sha256,
        args=tuple(args),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_s=duration,
    )


def is_within(path: Path, root: Path) -> bool:
    """Whether `path`, links resolved, is inside `root`. A path that cannot be resolved is not inside: on
    Python 3.12 a link loop raises RuntimeError here (3.13 returns the path unresolved), so callers refuse
    what they cannot place instead of crashing without a reason."""
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, RuntimeError, OSError):
        return False
    return True
