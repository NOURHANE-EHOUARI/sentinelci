"""Command-line entry point (`sentinel`).

Sub-commands are added task by task (see docs/spec/SPEC.md, section 15).
"""

import os
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from sentinelci import __version__
from sentinelci.policy.bundle import BundleError, PolicyBundle
from sentinelci.policy.decision import (
    CONTEXTS,
    EvaluationError,
    Subject,
    dumps_decision,
    evaluate,
    now_utc,
)
from sentinelci.policy.opa import OpaError, OpaRunner
from sentinelci.policy.waivers import DEFAULT_WAIVERS_PATH, load_waivers

app = typer.Typer(
    name="sentinel",
    help="SentinelCI: scan, decide, attest and verify software changes.",
    no_args_is_help=True,
)

EXIT_BLOCK = 1
EXIT_ERROR = 2


@app.callback()
def main() -> None:
    """SentinelCI command-line interface."""


@app.command()
def version() -> None:
    """Print the SentinelCI engine version."""
    typer.echo(__version__)


def _parse_tool_versions(values: list[str]) -> dict[str, str]:
    pairs = {}
    for value in values:
        name, sep, ver = value.partition("=")
        if not sep or not name or not ver:
            raise EvaluationError(f"--tool-version expects name=version, got {value!r}")
        pairs[name] = ver
    return pairs


def _write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@app.command("evaluate")
def evaluate_command(
    findings: Annotated[Path, typer.Option(help="Findings NDJSON (Finding v1, one per line).")],
    repo: Annotated[str, typer.Option(help="Repository, owner/name.")],
    commit: Annotated[str, typer.Option(help="Full 40-character commit SHA.")],
    context: Annotated[str, typer.Option(help=f"One of: {', '.join(CONTEXTS)}.")] = "local",
    ref: Annotated[str | None, typer.Option(help="Git ref, e.g. refs/pull/12/merge.")] = None,
    image_digest: Annotated[str | None, typer.Option(help="Release image digest, sha256:<hex>.")] = None,
    evaluated_at: Annotated[
        str | None, typer.Option(help="RFC 3339 evaluation time given to the policy. Default: now (UTC).")
    ] = None,
    policy_dir: Annotated[Path, typer.Option(help="Policy bundle directory.")] = Path("policies"),
    output: Annotated[Path, typer.Option("--output", "-o", help="Decision file to write.")] = Path(
        "out/decision.v1.json"
    ),
    tool_version: Annotated[
        list[str] | None,
        typer.Option(help="Scanner version as name=version (repeatable); recorded as evidence."),
    ] = None,
    waivers: Annotated[
        Path | None,
        typer.Option(
            help=f"Waivers file (schemas/waivers.v1.json). Default: {DEFAULT_WAIVERS_PATH} if present."
        ),
    ] = None,
    enrichment_snapshot: Annotated[Path | None, typer.Option(help="Enrichment snapshot file.")] = None,
    sbom: Annotated[Path | None, typer.Option(help="SBOM file to record by digest.")] = None,
    opa: Annotated[
        Path | None, typer.Option(help="OPA binary. Default: $SENTINEL_OPA, then opa on PATH.")
    ] = None,
) -> None:
    """Run the release gate and write a Decision v1 record.

    Exit code 0 for PASS or WARN, 1 for BLOCK, 2 when no decision could be made (fail closed).
    """
    # A stale decision from an earlier run must never be mistaken for this run's result.
    output.unlink(missing_ok=True)
    if waivers is None and Path(DEFAULT_WAIVERS_PATH).is_file():
        waivers = Path(DEFAULT_WAIVERS_PATH)
    try:
        decision = evaluate(
            findings_data=findings.read_bytes(),
            subject=Subject(repo=repo, commit=commit, context=context, ref=ref, image_digest=image_digest),
            evaluated_at=evaluated_at or now_utc(),
            bundle=PolicyBundle.load(policy_dir),
            opa=OpaRunner.locate(opa),
            tool_versions=_parse_tool_versions(tool_version or []),
            waivers=load_waivers(waivers.read_bytes()) if waivers else [],
            enrichment_snapshot=enrichment_snapshot.read_bytes() if enrichment_snapshot else None,
            sbom=sbom.read_bytes() if sbom else None,
        )
    except (BundleError, EvaluationError, OpaError, OSError) as exc:
        typer.echo(f"sentinel evaluate: {exc}", err=True)
        typer.echo("sentinel evaluate: no decision was made; treat this change as blocked.", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    _write_atomically(output, dumps_decision(decision))

    typer.echo(f"SentinelCI verdict: {decision['verdict']}  decision {decision['decision_id']}")
    for violation in decision["violations"]:
        count = len(violation["finding_ids"])
        noun = "finding" if count == 1 else "findings"
        rule, effect, message = violation["rule"], violation["effect"], violation["message"]
        typer.echo(f"  {rule}  {effect:<5}  {message}  ({count} {noun})")
    if decision["waivers_applied"]:
        typer.echo(f"Waivers applied: {', '.join(decision['waivers_applied'])}")
    typer.echo(f"Decision written to {output}")
    if decision["verdict"] == "BLOCK":
        raise typer.Exit(EXIT_BLOCK)


if __name__ == "__main__":
    app()
