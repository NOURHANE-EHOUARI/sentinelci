"""Infrastructure-as-code scanning with `trivy config`, hardened like Gitleaks (task A1c).

Trivy offers several ways for the scanned repository to configure or silence it. In a pull request they are
written by the author of the change, so each one is neutralized:

- `trivy.yaml` in the working directory          -> `--config ""` (no configuration file is loaded);
- `.trivyignore` / `.trivyignore.yaml`             -> `--ignorefile ""`;
- inline `trivy:ignore:<id>` and legacy `tfsec:ignore:<id>` comments (Terraform, Dockerfile, ...) -> Trivy
  0.76 has no flag to disable them, so a scan target that contains either marker is refused (fail closed),
  like `.gitleaksignore`. Exceptions go through SentinelCI waivers;
- WASM modules (`~/.trivy/modules`) and the check cache -> private, empty directories. The Rego checks are the
  ones embedded in the pinned binary (`--skip-check-update`), so the result depends on the lock only, plus
  SentinelCI's own checks (`configs/trivy-checks`, namespace `sentinelci`, ids `SENTINEL-*`) for gaps in
  Trivy's (ADR-0012), which ship with the CLI like the rest of its scanner configuration. A check that does
  not compile stops the scan (`--rego-error-limit 0`): Trivy would otherwise drop it and exit 0;
- check data -> SentinelCI's own `--config-data` (for example the trusted image registries).

Trivy also downloads the remote Terraform modules that the scanned code names (`git::https://...`, registry
sources): network access chosen by the change author, and a result that depends on the network. The run gets
proxy variables pointing at a closed local port and `GIT_ALLOW_PROTOCOL=none`, so every download fails at once
and the scan stays offline. Remote modules are therefore not fetched and not evaluated; `remote_modules` lists
them, following local modules transitively, so the CLI can say so. Version checks and telemetry are disabled.

What Trivy reads beyond the scan target is checked too:
- local Terraform modules outside the scan path (`source = "../mod"`) are loaded by Trivy, transitively,
  and their inline ignores are honoured, including an ignore above a `module` block, which silences every
  resource of the called module while the calling module is never reported. Which directories Trivy loads
  depends on its own evaluation of the sources (HCL escapes, expressions), so it is over-approximated: when
  the scan tree declares any module, every Terraform and OpenTofu file (`.tf`, `.tf.json`, `.tofu`,
  `.tofu.json`) of the repository outside the scan tree gets the marker check before the run, and a
  directory or Terraform file link in the repository that leaves it is refused. After the run, the
  directory of every file Trivy reports outside the scan path gets the check too, and a file outside the
  repository is refused;
- Trivy does not follow symbolic links, but Terraform and kubectl do: a link that leaves the scan target would
  hide its content, so the target is refused when it has one.

The marker check skips files Trivy never parses as configuration (source code, documentation, images), so a
tree whose code merely mentions the markers can still be scanned; every other file is checked, and so is any
name Trivy reads as a Dockerfile whatever its extension (`Dockerfile.txt`, `Containerfile.md`). The raw report
holds code lines of the scanned files (which may contain credentials): it stays in a private temporary
directory, and only normalized findings, without code, leave this module.
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
# Files Trivy's misconfiguration scanners never read (they select by name and extension). Unknown types are
# checked: the list only names what is certainly not configuration.
NOT_CONFIGURATION = frozenset(
    {
        ".py", ".pyc", ".pyi", ".md", ".rst", ".txt", ".adoc", ".go", ".rs", ".java", ".kt", ".c", ".h",
        ".cpp", ".cs", ".rb", ".php", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1",
        ".html", ".css", ".scss", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock", ".sql",
        ".csv", ".ipynb",
    }
)  # fmt: skip
# Trivy reads these as Dockerfiles by name, whatever the extension: never skipped by NOT_CONFIGURATION.
_DOCKERFILE_PREFIXES = ("dockerfile", "containerfile")
_DOCKERFILE_SUFFIXES = (".dockerfile", ".containerfile")
# Trivy 0.76 loads OpenTofu files as Terraform, in the scan tree and in local modules.
_TERRAFORM_SUFFIXES = (".tf", ".tf.json", ".tofu", ".tofu.json")
# Best effort, for the remote-module warning only (no security check relies on it): a `module` block header
# and a quoted literal source inside the block, also on one line such as `module "a" { source = "../a" }`.
_MODULE_BLOCK = re.compile(r'(?<![\w.-])module\s*(?:"[^"\n]*"|[A-Za-z_][\w-]*)\s*\{')
_MODULE_SOURCE = re.compile(r'(?<![\w.-])source\s*=\s*"([^"]+)"')
# Any `module` word in an HCL file: a block keyword cannot be escaped, so this over-approximates the blocks.
_MODULE_WORD = re.compile(rb"(?<![\w.-])module(?![\w-])")
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


# The Rego package prefix of SentinelCI's own Trivy checks (configs/trivy-checks).
CHECK_NAMESPACE = "sentinelci"


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


def _may_be_configuration(name: str) -> bool:
    lower = name.lower()
    if lower.startswith(_DOCKERFILE_PREFIXES) or lower.endswith(_DOCKERFILE_SUFFIXES):
        return True
    return Path(lower).suffix not in NOT_CONFIGURATION


def _is_terraform(name: str) -> bool:
    return name.lower().endswith(_TERRAFORM_SUFFIXES)


def _is_json(path: Path) -> bool:
    return path.name.lower().endswith(".json")


def _declares_modules(path: Path) -> bool:
    """Whether a Terraform file may declare a module. A link or anything but a regular file counts as yes and
    is never read (a link to /dev/zero would never end); so do unreadable and unparsable files."""
    if path.is_symlink() or not path.is_file():
        return True
    try:
        data = path.read_bytes()
    except OSError:
        return True
    if not _is_json(path):
        return _MODULE_WORD.search(data) is not None
    try:
        document = json.loads(data)  # decodes escaped keys such as "\u006dodule"
    except (ValueError, RecursionError):
        return True
    return not isinstance(document, dict) or "module" in document


def inline_ignores(root: Path, *, recursive: bool = True) -> list[str]:
    """Files under `root` Trivy may read (no symlink followed, `.git` skipped) that hold an inline ignore."""
    found: list[str] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git") if recursive else []
        for name in sorted(names):
            path = Path(directory, name)
            if _may_be_configuration(name) and stat.S_ISREG(path.lstat().st_mode) and _has_marker(path):
                found.append(path.relative_to(root).as_posix())
    return found


def escaping_links(root: Path, *, terraform_only: bool = False) -> list[str]:
    """Symbolic links under `root` (directories, and files: only Terraform ones with `terraform_only`) whose
    target is outside `root`."""
    found: list[str] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        files = [name for name in names if _is_terraform(name)] if terraform_only else names
        for name in sorted([*subdirs, *files]):
            path = Path(directory, name)
            if path.is_symlink() and not is_within(path, root):
                found.append(path.relative_to(root).as_posix())
    return found


def _terraform_files(root: Path, *, recursive: bool = True, skip: Path | None = None) -> list[Path]:
    """Terraform files under `root` (`.git` and `skip` excluded, no directory link followed)."""
    found: list[Path] = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        here = Path(directory)
        kept = [d for d in subdirs if d != ".git" and (skip is None or (here / d).resolve() != skip)]
        subdirs[:] = sorted(kept) if recursive else []
        found.extend(here / name for name in sorted(names) if _is_terraform(name))
    return found


def outside_terraform_ignores(scan_root: Path, repo_root: Path) -> list[str]:
    """Repository Terraform files outside `scan_root` holding an inline ignore, when the scan tree declares a
    module: Trivy may load any of them as a local module. A linked file is checked through its target, and a
    directory or Terraform file link that leaves the repository is refused: what it points to cannot be
    checked. Other links (a virtual environment's `bin/python`) are not loaded as modules."""
    scan, repo = scan_root.resolve(), repo_root.resolve()
    if scan == repo or not any(_declares_modules(path) for path in _terraform_files(scan)):
        return []
    leaving = escaping_links(repo, terraform_only=True)
    if leaving:
        raise ScannerError(
            f"symbolic links leave the repository ({_listed(leaving)}), and a local module of the scanned "
            "tree may load what they point to: commit the files themselves"
        )
    found: list[str] = []
    for path in _terraform_files(repo, skip=scan):
        resolved = path.resolve()
        if resolved.is_file() and _has_marker(resolved):
            found.append(path.relative_to(repo).as_posix())
    return found


def _block_end(text: str, start: int) -> int:
    """Index just past the `}` closing the block opened right before `start` (strings and comments skipped;
    best effort: the remote-module warning only)."""
    depth, i = 1, start
    while i < len(text) and depth:
        if text[i] == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif text[i] == "#" or text.startswith("//", i):
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = len(text) if close < 0 else close + 1
        elif text[i] in "{}":
            depth += 1 if text[i] == "{" else -1
        i += 1
    return i


def _sources(path: Path) -> list[str]:
    """Literal sources of the `module` blocks of a Terraform file (not provider sources). Links and special
    files are not read: a link that leaves the tree is refused by the scan, one inside it is read there."""
    if path.is_symlink() or not path.is_file():
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if not _is_json(path):
        text = data.decode("utf-8", errors="replace")
        return [
            source
            for block in _MODULE_BLOCK.finditer(text)
            for source in _MODULE_SOURCE.findall(text, block.end(), _block_end(text, block.end()))
        ]
    try:
        document = json.loads(data)
    except (ValueError, RecursionError):
        return []
    documents = document if isinstance(document, list) else [document]  # Trivy also loads a top-level array
    sources: list[str] = []
    pending: list[Any] = [item.get("module") for item in documents if isinstance(item, dict)]
    while pending:  # iterative: deep documents cannot exhaust the stack
        node = pending.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "source" and isinstance(value, str):
                    sources.append(value)
                else:
                    pending.append(value)
        elif isinstance(node, list):
            pending.extend(node)
    return sources


def remote_modules(root: Path, repo_root: Path | None = None) -> list[str]:
    """Module sources that are not local paths, under `root` and in the local modules it reaches
    (transitively, inside `repo_root`): not fetched, so not evaluated. Best effort, for the job log: literal
    sources only."""
    repo = (repo_root or root).resolve()
    remote: set[str] = set()
    seen: set[Path] = set()
    pending = _terraform_files(root)
    while pending:
        path = pending.pop()
        for source in _sources(path):
            if not source.startswith(("./", "../")):
                remote.add(source)
                continue
            module = (path.parent / source).resolve()
            outside_scan = is_within(module, repo) and not is_within(module, root)
            if module in seen or not module.is_dir() or not outside_scan:
                continue
            seen.add(module)
            pending.extend(_terraform_files(module, recursive=False))
    return sorted(remote)


def _listed(items: list[str]) -> str:
    more = f" and {len(items) - MAX_REPORTED_FILES} more" if len(items) > MAX_REPORTED_FILES else ""
    return ", ".join(items[:MAX_REPORTED_FILES]) + more


def _refuse_markers(marked: list[str], where: str) -> None:
    if marked:
        raise ScannerError(
            f"inline trivy:ignore / tfsec:ignore comments found {where} ({_listed(marked)}). Trivy would let "
            "them silence findings, and they are controlled by the author of the change: remove them and use "
            "SentinelCI waivers"
        )


def check_outside_reads(results: list[dict[str, Any]], repo_root: Path, source: str) -> None:
    """Fail closed on what Trivy read outside the scan path: a file outside the repository, or an ignore."""
    scan_root, repo = (repo_root / source).resolve(), repo_root.resolve()
    directories: set[Path] = set()
    for result in results:
        target = result.get("Target")
        if not isinstance(target, str):
            continue  # the normalizer refuses it
        path = (scan_root / target).resolve()
        if not is_within(path, repo):
            raise ScannerError(f"trivy read {target!r}, outside the repository (a local module?)")
        if not is_within(path, scan_root):
            directories.add(path if path.is_dir() else path.parent)
    marked = [
        f"{directory.relative_to(repo).as_posix()}/{name}".removeprefix("./")
        for directory in sorted(directories)
        for name in inline_ignores(directory, recursive=False)
    ]
    _refuse_markers(marked, "in a module outside the scan path")


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
    _refuse_markers(inline_ignores(repo_root / source), "in the scanned tree")
    links = escaping_links(repo_root / source)
    if links:
        raise ScannerError(
            f"symbolic links leave the scanned tree ({_listed(links)}). Trivy does not follow them while "
            "Terraform and kubectl do, so their content would go unscanned: commit the files themselves"
        )
    _refuse_markers(
        outside_terraform_ignores(repo_root / source, repo_root),
        "outside the scan path, in Terraform files a local module of the scanned tree may load",
    )

    with tempfile.TemporaryDirectory(prefix="sentinel-trivy-") as private:
        work = Path(private)
        for name in ("cache", "modules"):
            (work / name).mkdir()
        report = work / "report.json"
        configs = files("sentinelci.scanners.configs")
        with (
            as_file(configs.joinpath("trivy-data")) as config_data,
            as_file(configs.joinpath("trivy-checks")) as checks,
        ):
            args = [
                "config",
                "--config", "",
                "--ignorefile", "",
                "--cache-dir", str(work / "cache"),
                "--module-dir", str(work / "modules"),
                "--config-data", str(config_data),
                "--config-check", str(checks),
                "--check-namespaces", CHECK_NAMESPACE,
                # Stop on any check that does not compile: Trivy would otherwise log a type error, drop the
                # check and exit 0, so a SentinelCI check could silently stop reporting.
                "--rego-error-limit", "0",
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
    check_outside_reads(results, repo_root, source)
    return results, run
