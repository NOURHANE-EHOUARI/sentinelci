"""Command-line entry point (`sentinel`).

Sub-commands are added task by task (see docs/spec/SPEC.md, section 15).

Exit codes:
    0  success
    2  usage error (Typer)
    3  untrusted input or toolchain (scanner output unreadable, tool missing or tampered)
       -> callers must fail closed (rule SC-010)
"""

import hashlib
import json
from pathlib import Path
from typing import Annotated

import typer

from sentinelci import __version__
from sentinelci.contracts.finding import Run, RunContext, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.gitleaks import load_gitleaks_report, normalize_gitleaks
from sentinelci.normalize.ndjson import write_ndjson
from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.gitleaks import GitleaksMode, scan_secrets_with_run
from sentinelci.scanners.installer import VerificationReport, install_tools, verify_tools
from sentinelci.scanners.lock import LOCK_FILE_NAME, load_lock

EXIT_UNTRUSTED_INPUT = 3
DEFAULT_TOOLS_DIR = Path(".sentinel/tools")

app = typer.Typer(
    name="sentinel",
    help="SentinelCI: scan, decide, attest and verify software changes.",
    no_args_is_help=True,
)
normalize_app = typer.Typer(help="Convert raw scanner output into Finding v1 NDJSON.", no_args_is_help=True)
tools_app = typer.Typer(
    help="Install and verify the pinned security tools (tools.lock.toml).", no_args_is_help=True
)
scan_app = typer.Typer(
    help="Run a verified scanner and write normalized Finding v1 NDJSON.", no_args_is_help=True
)
app.add_typer(normalize_app, name="normalize")
app.add_typer(tools_app, name="tools")
app.add_typer(scan_app, name="scan")

LockOption = Annotated[Path, typer.Option("--lock", help="Path to the tool lock file.")]
DestOption = Annotated[Path, typer.Option("--dest", help="Installation directory (bin/ and cache/).")]
PlatformOption = Annotated[
    str | None, typer.Option("--platform", help="Override platform detection, e.g. linux-amd64.")
]
ToolsArgument = Annotated[
    list[str] | None, typer.Argument(help="Tools to process (default: all pinned tools).")
]


def _fail_closed(exc: Exception) -> typer.Exit:
    typer.echo(
        f"error: {exc}\nFAIL CLOSED: the toolchain or its output cannot be trusted (rule SC-010).", err=True
    )
    return typer.Exit(EXIT_UNTRUSTED_INPUT)


@app.callback()
def main() -> None:
    """SentinelCI command-line interface."""


@app.command()
def version() -> None:
    """Print the SentinelCI engine version."""
    typer.echo(__version__)


# ---------------------------------------------------------------- normalize


@normalize_app.command("gitleaks")
def normalize_gitleaks_cmd(
    report: Annotated[Path, typer.Argument(help="Gitleaks JSON report (generated without --redact).")],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    tool_version: Annotated[str, typer.Option(help=f"Gitleaks version from {LOCK_FILE_NAME}.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[Path, typer.Option(help="Repository root used to relativize paths.")] = Path("."),
) -> None:
    """Normalize a Gitleaks report. Secrets are hashed and redacted; nothing raw is written."""
    out.unlink(missing_ok=True)  # a failed run must never leave an older findings file behind
    try:
        run = Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id)
        findings = normalize_gitleaks(
            load_gitleaks_report(report),
            run=run,
            tool=Tool(name="gitleaks", version=tool_version),
            repo_root=repo_root,
        )
    except NormalizationError as exc:
        raise _fail_closed(exc) from exc
    write_ndjson(findings, out)
    typer.echo(f"{len(findings)} finding(s) written to {out}")


# ---------------------------------------------------------------- tools


def _write_manifest(report: VerificationReport, lock_path: Path, destination: Path) -> None:
    """Evidence of the exact toolchain used (feeds `inputs.tool_versions` of the decision record)."""
    manifest = {
        "schema_version": 1,
        "platform": report.platform,
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "tools": {
            entry.name: {
                "version": entry.version,
                "artifact_sha256": entry.artifact_sha256,
                "binary_sha256": entry.binary_sha256,
            }
            for entry in report.entries
        },
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(destination)


@tools_app.command("list")
def tools_list(lock: LockOption = Path(LOCK_FILE_NAME)) -> None:
    """Show the pinned tools and versions."""
    try:
        tool_lock = load_lock(lock)
    except ToolIntegrityError as exc:
        raise _fail_closed(exc) from exc
    for name, tool in sorted(tool_lock.tools.items()):
        typer.echo(f"{name:<10} {tool.version:<10} {', '.join(sorted(tool.artifacts))}")


@tools_app.command("install")
def tools_install(
    tools: ToolsArgument = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    dest: DestOption = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
) -> None:
    """Download the pinned artifacts, check their SHA-256 against the lock, and install the binaries."""
    try:
        report = install_tools(load_lock(lock), dest, platform=platform, only=tools)
    except ToolIntegrityError as exc:
        raise _fail_closed(exc) from exc
    for entry in report.entries:
        typer.echo(f"installed {entry.name} {entry.version} ({entry.binary_sha256[:12]}) -> {entry.path}")


@tools_app.command("verify")
def tools_verify(
    tools: ToolsArgument = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    dest: DestOption = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
    report: Annotated[
        Path | None, typer.Option("--report", help="Write the verified tool manifest (JSON) here.")
    ] = None,
) -> None:
    """Fail closed unless every installed binary is exactly the one pinned in the lock."""
    if report is not None:
        report.unlink(missing_ok=True)  # an older manifest must never vouch for a failing toolchain
    try:
        result = verify_tools(load_lock(lock), dest, platform=platform, only=tools)
    except ToolIntegrityError as exc:
        raise _fail_closed(exc) from exc
    if report is not None:
        _write_manifest(result, lock, report)
    for entry in result.entries:
        typer.echo(f"verified {entry.name} {entry.version} sha256={entry.binary_sha256}")


# ---------------------------------------------------------------- scan


@scan_app.command("secrets")
def scan_secrets_cmd(
    target: Annotated[Path, typer.Argument(help="Directory (or git repository with --mode git) to scan.")],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[
        Path | None, typer.Option(help="Repository root (default: the target itself).")
    ] = None,
    mode: Annotated[str, typer.Option(help="dir (working tree) or git (history).")] = "dir",
    log_opts: Annotated[
        str | None, typer.Option(help="git mode only: commit range, e.g. origin/main..HEAD.")
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
) -> None:
    """Scan for secrets with the verified Gitleaks binary; raw secrets never leave memory."""
    if mode not in ("dir", "git"):
        raise typer.BadParameter("mode must be 'dir' or 'git'")
    scan_mode: GitleaksMode = "git" if mode == "git" else "dir"
    root = repo_root or target
    try:
        tool_lock = load_lock(lock)
        raw, tool_run = scan_secrets_with_run(
            target,
            lock=tool_lock,
            tools_dir=tools_dir,
            repo_root=root,
            platform=platform,
            mode=scan_mode,
            log_opts=log_opts,
        )
        findings = normalize_gitleaks(
            raw,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            tool=Tool(name="gitleaks", version=tool_run.version),
            repo_root=root,
        )
    except (ToolIntegrityError, ScannerError, NormalizationError) as exc:
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(findings, out)
    typer.echo(f"gitleaks {tool_run.version}: {len(findings)} finding(s) written to {out}")


if __name__ == "__main__":
    app()
