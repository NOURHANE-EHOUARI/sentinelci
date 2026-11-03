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
  built and run, so the target is refused when it has one (a link loop too);
- a file Opengrep cannot parse in full   -> Opengrep skips the code it could not parse and only warns: when
  that is more than half of the file's lines (one line of modern syntax can hide a whole file), the scan
  fails closed; each smaller gap (overlapping or adjacent spans merged) is returned with its lines and text,
  and becomes a SAST HIGH finding of its own (`sentinel-sast-not-analysed`), so blank lines or a long
  docstring around unparsable code cannot hide it;
- any other problem, even a warning      -> fails closed: Opengrep drops the file's results (too many matches
  in one file, out of memory, ...).

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

from sentinelci.normalize.opengrep import ParseGap
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
# Opengrep's error types for a file it could not parse in full. Their spans are the code it skipped; without a
# span, it skipped the whole file. Any other error type means results were lost: it is always fatal.
PARSE_ERRORS = frozenset(
    {"PartialParsing", "Syntax error", "Lexical error", "Other syntax error", "AST builder error"}
)


@dataclass(frozen=True)
class SastScan:
    results: list[dict[str, Any]]
    run: ToolRun
    target: Path  # resolved: result paths are absolute, under it
    warnings: list[str]  # files Opengrep parsed in part, for at most half of their lines
    gaps: list[ParseGap]  # the code it skipped in those files, one entry per contiguous range of lines


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


def _span_line(position: Any) -> int:
    line = position.get("line") if isinstance(position, dict) else None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise ScannerError("opengrep's JSON report has a malformed error span")
    return line


def _spans(error: dict[str, Any]) -> list[tuple[int, int]]:
    """The (start, end) lines Opengrep skipped, from `spans` and the PartialParsing locations."""
    kind = error.get("type")
    found: list[Any] = []
    for spans in (error.get("spans"), kind[1] if isinstance(kind, list) and len(kind) > 1 else None):
        if spans is not None and not isinstance(spans, list):
            raise ScannerError("opengrep's JSON report has a malformed error span")
        found += spans or []
    lines: list[tuple[int, int]] = []
    for span in found:
        if not isinstance(span, dict):
            raise ScannerError("opengrep's JSON report has a malformed error span")
        start, end = _span_line(span.get("start")), _span_line(span.get("end"))
        if end < start:
            raise ScannerError("opengrep's JSON report has a malformed error span")
        lines.append((start, end))
    return lines


def line_count(data: bytes) -> int:
    """Lines as Opengrep numbers them: a last line without a newline still counts."""
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def merged_ranges(spans: list[tuple[int, int]], total: int) -> list[tuple[int, int]]:
    """The (start, end) spans within lines 1..total, overlapping or adjacent ones merged, in line order."""
    ranges: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        end = min(end, total)
        if end < start:
            continue
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))
    return ranges


def _lines(data: bytes, start: int, end: int) -> str:
    """Lines start..end as Opengrep numbers them ("\n" only), each with its newline when it has one."""
    segments = data.split(b"\n")
    chunk = b"\n".join(segments[start - 1 : end]) + (b"\n" if end < len(segments) else b"")
    return chunk.decode("utf-8", errors="replace")


def lines_covered(spans: list[tuple[int, int]], total: int) -> int:
    """How many of lines 1..total the (start, end) spans cover, overlaps counted once."""
    covered, reached = 0, 0
    for start, end in sorted(spans):
        start, end = max(start, reached + 1), min(end, total)
        if end >= start:
            covered += end - start + 1
            reached = end
    return covered


def _relative(where: Any, target: Path) -> str | None:
    if isinstance(where, str) and Path(where).is_absolute() and is_within(Path(where), target):
        return Path(where).resolve().relative_to(target).as_posix()
    return None


def _parse_gap(
    name: str, where: str, spans: list[tuple[int, int]] | None, target: Path
) -> tuple[bool, str, list[ParseGap]]:
    """(fatal, text, gaps) for a file Opengrep parsed only in part (`spans` None: not at all)."""
    try:
        data = (target / where).read_bytes()
    except OSError:
        return True, f"{name} in {where}: the file cannot be read to count what was not analysed", []
    total = line_count(data)
    skipped = total if spans is None else lines_covered(spans, total)
    gaps = [
        ParseGap(path=where, start=start, end=end, error=name, text=_lines(data, start, end))
        for start, end in merged_ranges(spans or [], total)
    ]
    return 2 * skipped > total, f"{name} in {where}: {skipped} of {total} lines not analysed", gaps


def _problems(report: dict[str, Any], target: Path) -> tuple[list[str], list[str], list[ParseGap]]:
    """(fatal, warnings, gaps) from Opengrep's `errors`. Only a file parsed in part, for at most half of its
    lines, is a warning, with its gaps: anything else means part of the scan did not run."""
    fatal: list[str] = []
    warnings: list[str] = []
    found: list[ParseGap] = []
    errors = report.get("errors")
    if not isinstance(errors, list):
        raise ScannerError("opengrep's JSON report has no `errors` list")
    gaps: dict[str, tuple[str, list[tuple[int, int]] | None]] = {}  # file -> (first error, spans; None: all)
    for error in errors:
        if not isinstance(error, dict):
            raise ScannerError("opengrep's JSON report has a malformed error entry")
        kind = error.get("type")
        name = kind[0] if isinstance(kind, list) and kind else kind
        where = _relative(error.get("path"), target)
        if (
            error.get("level") == "warn"
            and isinstance(name, str)
            and name in PARSE_ERRORS
            and where is not None
        ):
            first, known = gaps.get(where, (name, []))
            spans = _spans(error)
            gaps[where] = (first, None if known is None or not spans else known + spans)
            continue
        where = where or error.get("path")
        fatal.append(f"{name or 'error'}{f' in {where}' if isinstance(where, str) and where else ''}")
    for path, (first, skipped) in sorted(gaps.items()):
        is_fatal, text, ranges = _parse_gap(first, path, skipped, target)
        (fatal if is_fatal else warnings).append(text)
        if not is_fatal:
            found += ranges
    return fatal, warnings, found


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
    fatal, warnings, gaps = _problems(report, source)
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
    return SastScan(results=results, run=kept, target=source, warnings=warnings, gaps=gaps)
