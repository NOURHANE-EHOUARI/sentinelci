"""SAST with Opengrep, hardened like the other scanners (task A1, SPEC §5 stage 2).

The binary is the one pinned in tools.lock.toml, verified right before it runs (Opengrep publishes no checksum
file: its pin was taken after checking each asset's keyless signature, see the lock). It runs SentinelCI's own
rules only (`configs/opengrep/*.yaml`, passed with `--config`), from a private working directory, with a
minimal environment and a private home, and offline (the proxy variables point at a closed local port).

Opengrep offers several ways for the scanned repository to silence it. In a pull request they are written by
the author of the change, so each one is neutralized:

- `# nosemgrep` / `# nosem` comments      -> `--disable-nosem`: the finding is reported, flagged `is_ignored`;
- `.semgrepignore` files                  -> `--x-ignore-semgrepignore-files` (internal flag, pinned version);
- `.gitignore`                            -> `--no-git-ignore` (git is not even called);
- a large file (1 MB by default)          -> `--max-target-bytes=0`: never skipped for its size;
- a slow file (5 s per rule by default)   -> `--timeout=0`: no per-file time-out that silently drops a rule;
  the whole run keeps the scanner time limit, which fails closed (SC-010);
- repository rule files (`.semgrep.yml`)  -> never loaded: `--config` names SentinelCI's rules only;
- a link out of the scan target           -> Opengrep does not follow it while the code it points to may be
  built and run, so the target is refused when it has one (a link loop too).

`--no-rewrite-rule-ids` keeps the rule ids as written (no prefix from where the rules are installed)."""

import errno
import json
import os
import tempfile
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

import yaml

from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, is_within, run_verified_tool

RULES_PACKAGE = "sentinelci.scanners.configs"
RULES_DIR = "opengrep"
FLAGS = (
    "--json", "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore", "--x-ignore-semgrepignore-files",
    "--disable-version-check", "--max-target-bytes=0", "--timeout=0",
)  # fmt: skip
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
}
MAX_REPORTED = 5


@dataclass(frozen=True)
class SastScan:
    results: list[dict[str, Any]]
    run: ToolRun
    target: Path  # resolved: result paths are absolute, under it
    warnings: list[str]  # non-fatal problems Opengrep reported (a file parsed only partly, ...)


def rule_ids() -> frozenset[str]:
    """The ids of SentinelCI's rules: a result naming any other rule is refused (fail closed)."""
    ids: set[str] = set()
    for entry in files(RULES_PACKAGE).joinpath(RULES_DIR).iterdir():
        if entry.name.endswith((".yaml", ".yml")):
            document = yaml.safe_load(entry.read_text(encoding="utf-8"))
            ids.update(str(rule["id"]) for rule in document["rules"])
    return frozenset(ids)


def _loops(path: Path) -> bool:
    try:
        os.path.realpath(path, strict=True)
    except OSError as exc:
        return exc.errno == errno.ELOOP
    return False


def escaping_links(root: Path) -> list[str]:
    """Symbolic links under `root` (files or directories) that leave it, or loop; `.git` is skipped."""
    found: list[str] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        for name in sorted([*subdirs, *names]):
            path = Path(directory, name)
            if path.is_symlink() and (_loops(path) or not is_within(path, root)):
                found.append(path.relative_to(root).as_posix())
    return found


def _listed(items: list[str]) -> str:
    more = f" and {len(items) - MAX_REPORTED} more" if len(items) > MAX_REPORTED else ""
    return ", ".join(items[:MAX_REPORTED]) + more


def _problems(report: dict[str, Any], target: Path) -> tuple[list[str], list[str]]:
    """(fatal, warnings) from Opengrep's `errors`: anything but a warning means part of the scan did not
    run."""
    fatal: list[str] = []
    warnings: list[str] = []
    errors = report.get("errors")
    if not isinstance(errors, list):
        raise ScannerError("opengrep's JSON report has no `errors` list")
    for error in errors:
        if not isinstance(error, dict):
            raise ScannerError("opengrep's JSON report has a malformed error entry")
        kind = error.get("type")
        name = kind[0] if isinstance(kind, list) and kind else kind
        where = error.get("path")
        if isinstance(where, str) and Path(where).is_absolute() and is_within(Path(where), target):
            where = Path(where).resolve().relative_to(target).as_posix()
        text = f"{name or 'error'}{f' in {where}' if isinstance(where, str) and where else ''}"
        (warnings if error.get("level") == "warn" else fatal).append(text)
    return fatal, warnings


def scan_sast_with_run(
    target: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    repo_root: Path | None = None,
    platform: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> SastScan:
    """Run `opengrep scan` with SentinelCI's rules on the directory `target` and return its results."""
    root = repo_root or target
    if not target.is_dir():
        raise ScannerError(f"{target} is not a directory")
    if not is_within(target, root):
        raise ScannerError(f"scan target {target} is outside the repository root {root}")
    links = escaping_links(target)
    if links:
        raise ScannerError(
            f"symbolic links leave the scanned tree or loop ({_listed(links)}). Opengrep does not follow "
            "them while the code they point to may be built and run: commit the files themselves"
        )
    source = target.resolve()
    with (
        tempfile.TemporaryDirectory(prefix="sentinel-opengrep-") as private,
        as_file(files(RULES_PACKAGE).joinpath(RULES_DIR)) as rules,
    ):
        run = run_verified_tool(
            "opengrep",
            ["scan", "--config", str(rules), *FLAGS, "--", str(source)],
            lock=lock,
            tools_dir=tools_dir,
            cwd=Path(private),  # empty: no repository file is read as configuration
            platform=platform,
            timeout_s=timeout_s,
            extra_env=OFFLINE_ENV,
        )
    try:
        report = json.loads(run.stdout) if run.stdout.strip() else None
    except json.JSONDecodeError as exc:
        raise ScannerError(f"opengrep produced unreadable JSON: {exc}") from exc
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ScannerError("opengrep's JSON report has no `results` list")
    if report.get("version") != run.version:
        raise ScannerError(f"opengrep reports version {report.get('version')!r}, the lock pins {run.version}")
    fatal, warnings = _problems(report, source)
    if fatal:
        raise ScannerError(f"opengrep could not scan everything: {_listed(fatal)}")
    results = report["results"]
    if not all(isinstance(result, dict) for result in results):
        raise ScannerError("opengrep's JSON results are not objects")
    kept = ToolRun(
        tool=run.tool,
        version=run.version,
        binary_sha256=run.binary_sha256,
        args=run.args,
        returncode=run.returncode,
        stdout="",  # the report holds code: it never leaves this module raw
        stderr=run.stderr,
        duration_s=run.duration_s,
    )
    return SastScan(results=results, run=kept, target=source, warnings=warnings)
