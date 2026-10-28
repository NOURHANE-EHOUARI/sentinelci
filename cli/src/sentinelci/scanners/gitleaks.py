"""Secret scanning with Gitleaks, hardened against author-controlled suppressions (task A1b).

Gitleaks honours three suppression mechanisms that live inside the scanned repository. In a pull
request they are written by the person whose change is being checked, so each one is neutralized:

- `.gitleaks.toml` in the target       -> we always pass `--config` with SentinelCI's own configuration;
- `gitleaks:allow` inline comments     -> `--ignore-gitleaks-allow`;
- `.gitleaksignore`                    -> `--gitleaks-ignore-path` points to an empty private directory, and
  because Gitleaks *always* also loads `<source>/.gitleaksignore` (cmd/root.go), a scan target containing that
  file is refused (fail closed). Exceptions must go through SentinelCI waivers.

In git mode, Gitleaks reads `git log -p`, and git applies the scanned repository's `.gitattributes` to
that output: a `-diff` or `binary` attribute added by the author turns a file's patch into "Binary files
differ", so its secrets are never seen. Patches are therefore forced to text (`--text`, no textconv, no
external diff), and caller-supplied `--log-opts` are limited to revisions, pathspecs and a few harmless
options, so they cannot turn that back off or make git write files (`--output`).

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

# Always passed to `git log` in git mode (see the module docstring).
GIT_LOG_HARDENING = ("--text", "--no-textconv", "--no-ext-diff")
# Gitleaks' own default when no --log-opts is given (sources/git.go): every ref, deleted files excluded.
GIT_LOG_DEFAULT = ("--full-history", "--all", "--diff-filter=tuxdb")
_SAFE_LOG_FLAGS = frozenset({"--all", "--full-history", "--first-parent", "--no-merges"})
_SAFE_LOG_PREFIXES = ("--since=", "--until=", "--max-count=")


def git_log_opts(log_opts: str | None) -> str:
    """The `--log-opts` value for Gitleaks: hardening flags first, then a validated range and pathspecs."""
    if not log_opts:
        return " ".join((*GIT_LOG_HARDENING, *GIT_LOG_DEFAULT))
    tokens = log_opts.split()  # Gitleaks itself splits on spaces, so no token can contain one
    separator = tokens.index("--") if "--" in tokens else len(tokens)
    for token in tokens[:separator]:
        allowed = token in _SAFE_LOG_FLAGS or token.startswith(_SAFE_LOG_PREFIXES)
        if token.startswith("-") and not allowed:
            raise ScannerError(
                f"git log option {token!r} is not allowed in --log-opts: only revisions, pathspecs and "
                f"{', '.join(sorted(_SAFE_LOG_FLAGS))}, --since=, --until=, --max-count= are accepted"
            )
    return " ".join((*GIT_LOG_HARDENING, "--diff-filter=tuxdb", *tokens))


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
    if mode != "git" and log_opts:
        raise ScannerError("--log-opts only applies to git mode")
    hardened_log_opts = git_log_opts(log_opts) if mode == "git" else None
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
        if hardened_log_opts is not None:
            args += ["--log-opts", hardened_log_opts]

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
