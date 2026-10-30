"""Command-line entry point (`sentinel`).

Sub-commands are added task by task (see docs/spec/SPEC.md, section 15).

Exit codes:
    0  success (`evaluate`: PASS or WARN; `replay`: identical)
    1  `evaluate`: BLOCK; `replay`: the replayed decision differs from the record
    2  usage error (Typer)
    3  untrusted input, untrusted toolchain (tool missing or tampered), or no decision could be made
       (`replay`: missing, malformed or tampered evidence)
       -> callers must fail closed (rule SC-010)
"""

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer

from sentinelci import __version__
from sentinelci.contracts.finding import Finding, Run, RunContext, Tool
from sentinelci.enrich import (
    EMPTY_SNAPSHOT,
    EnrichmentError,
    Reachability,
    enrich_finding,
    load_snapshot,
    read_service_context,
)
from sentinelci.enrich.fetch import build_snapshot, dumps_snapshot
from sentinelci.enrich.transport import (
    DEFAULT_TIMEOUT_S,
    MAX_TIMEOUT_S,
    HttpTransport,
    RecordingTransport,
    ReplayTransport,
    Transport,
    TransportError,
)
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.gitleaks import load_gitleaks_report, normalize_gitleaks
from sentinelci.normalize.ndjson import dumps_ndjson, write_ndjson
from sentinelci.policy.bundle import BundleError, PolicyBundle
from sentinelci.policy.decision import (
    CONTEXTS,
    EMPTY_ENRICHMENT_SNAPSHOT,
    Subject,
    dumps_decision,
    evaluate,
    load_findings,
    now_utc,
)
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.opa import OpaError, OpaRunner
from sentinelci.policy.replay import ReplayResult, check_identity, replay, skip_reason
from sentinelci.policy.store import EvidenceStore, StoreError
from sentinelci.policy.waivers import DEFAULT_WAIVERS_PATH
from sentinelci.risk import RiskModel, RiskModelError, score_finding
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
policy_app = typer.Typer(help="Release-gate policy tools.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
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


EXIT_BLOCK = 1
EXIT_REPLAY_DIFFERS = 1
EXIT_NO_DECISION = 3
DEFAULT_STORE = Path("out/evidence")


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


@app.command("snapshot")
def snapshot_command(
    findings: Annotated[
        Path, typer.Option(help="Findings NDJSON (Finding v1): their package findings are looked up.")
    ],
    out: Annotated[
        Path, typer.Option(help="Enrichment snapshot to write (schemas/enrichment-snapshot.v1.json).")
    ],
    offline: Annotated[
        Path | None, typer.Option(help="Answer from responses recorded with --record instead of the network.")
    ] = None,
    record: Annotated[
        Path | None, typer.Option(help="Also save every response under this directory.")
    ] = None,
    timeout: Annotated[
        float, typer.Option(help=f"Seconds per request, in (0, {MAX_TIMEOUT_S:g}].")
    ] = DEFAULT_TIMEOUT_S,
) -> None:
    """Fetch OSV, FIRST EPSS and CISA KEV data for the findings into a snapshot (SPEC section 6.1).

    The only network step of enrichment; `sentinel enrich` then applies the snapshot offline. A feed that
    fails is left out (its values stay unknown, scored as the worst case) and named on stderr; exit code 0.
    Exit code 3 when the findings cannot be read, or anything else goes wrong (nothing is written).
    `--offline` recordings are inputs like the policies: use them from the base commit or a trusted store.
    """
    if not 0 < timeout <= MAX_TIMEOUT_S:
        raise typer.BadParameter(f"--timeout must be in (0, {MAX_TIMEOUT_S:g}] seconds")
    _refuse_output(out, [findings], "sentinel snapshot")
    _clear_output(out, "sentinel snapshot")
    try:
        loaded = load_findings(findings.read_bytes())
        transport: Transport = ReplayTransport(offline) if offline else HttpTransport(timeout=timeout)
        if record is not None:
            transport = RecordingTransport(transport, record)
        document, warnings = build_snapshot(loaded, transport)
    except (EvaluationError, EnrichmentError, TransportError, OSError) as exc:
        typer.echo(f"sentinel snapshot: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    except Exception as exc:  # fail closed: no traceback, no partial snapshot, no exit 0 or 1
        typer.echo(f"sentinel snapshot: unexpected {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    for warning in warnings:
        typer.echo(f"warning: {warning}", err=True)
    data = dumps_snapshot(document)
    _write_output(out, data.decode("utf-8"), "sentinel snapshot")
    sources = ", ".join(document["sources"]) or "none"
    typer.echo(
        f"Snapshot of {len(document['vulnerabilities'])} vulnerability id(s) (sources: {sources}) -> {out}  "
        f"sha256:{hashlib.sha256(data).hexdigest()}"
    )


def _clear_output(out: Path, command: str) -> None:
    """Remove a stale --out from an earlier run; a path that cannot be cleared is exit 3, not a traceback."""
    try:
        out.unlink(missing_ok=True)
    except OSError as exc:
        typer.echo(f"{command}: cannot use --out {out}: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc


def _write_output(out: Path, text: str, command: str) -> None:
    """Write --out atomically; a write that fails (no space, a file in the way) is exit 3, nothing left."""
    try:
        _write_atomically(out, text)
    except OSError as exc:
        typer.echo(f"{command}: cannot write --out {out}: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc


def _refuse_output(out: Path, sources: list[Path | None], command: str) -> None:
    """Fail closed before anything is deleted: --out must not be any input file, nor a directory."""
    if out.is_dir():
        typer.echo(f"{command}: --out {out} is a directory; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)
    for source in sources:
        if source is not None and out.exists() and source.exists() and out.resolve() == source.resolve():
            typer.echo(f"{command}: --out {out} is the input file {source}; nothing was written", err=True)
            raise typer.Exit(EXIT_NO_DECISION)


@app.command("enrich")
def enrich_command(
    findings: Annotated[Path, typer.Option(help="Findings NDJSON (Finding v1).")],
    out: Annotated[Path, typer.Option(help="Enriched findings NDJSON to write.")],
    snapshot: Annotated[
        Path | None,
        typer.Option(
            help="Enrichment snapshot (schemas/enrichment-snapshot.v1.json). Without it: no feed data."
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            help="Service context, sentinel.yaml (schemas/sentinel-config.v1.json), from the base branch."
        ),
    ] = None,
    source: Annotated[
        list[Path] | None,
        typer.Option(
            help="Source tree for reachability (repeatable; PR mode: the base and the head checkouts). "
            "Never run, only read."
        ),
    ] = None,
) -> None:
    """Add CVSS, EPSS, KEV, fix availability and exposure to findings, offline (SPEC section 6.1).

    Only what the snapshot and sentinel.yaml say is added; unknown stays absent (the risk engine treats it as
    the worst case). Pass the same snapshot to `sentinel evaluate --enrichment-snapshot`, so the decision
    records its digest. Exit code 0 on success, 3 when an input cannot be read (nothing is written).
    """
    _refuse_output(out, [findings, snapshot, config], "sentinel enrich")
    # A stale file from an earlier run must never be read as this run's findings.
    _clear_output(out, "sentinel enrich")
    try:
        data = load_snapshot(snapshot.read_bytes()) if snapshot else load_snapshot(EMPTY_SNAPSHOT)
        context = read_service_context(config) if config else None
        reachability = Reachability.of_trees(source) if source else None
        enriched = [
            Finding.model_validate(enrich_finding(f, data, context, reachability))
            for f in load_findings(findings.read_bytes())
        ]
    except (EnrichmentError, EvaluationError, OSError, ValueError) as exc:
        typer.echo(f"sentinel enrich: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    except Exception as exc:  # fail closed: no traceback, no partial output, no exit 0 or 1
        typer.echo(f"sentinel enrich: unexpected {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    _write_output(out, dumps_ndjson(enriched), "sentinel enrich")
    sources = sorted(k for k, v in data.sources.model_dump().items() if v is not None) or ["none"]
    typer.echo(
        f"{len(enriched)} finding(s) enriched (sources: {', '.join(sources)}; "
        f"service context: {'yes' if context else 'no'}) -> {out}"
    )
    if reachability is not None:
        imported = sum(1 for f in enriched if f.enrichment and f.enrichment.reachability == "imported")
        typer.echo(f"reachability: {imported} imported (the others are left absent: the worst case)")


@app.command("score")
def score_command(
    findings: Annotated[Path, typer.Option(help="Findings NDJSON (Finding v1), enriched or not.")],
    out: Annotated[Path, typer.Option(help="Scored findings NDJSON to write.")],
    policy_dir: Annotated[Path, typer.Option(help="Policy bundle holding risk-model.yaml.")] = Path(
        "policies"
    ),
) -> None:
    """Set `risk` (score, priority P0-P4, factors, model version) on every finding (SPEC section 6.2).

    Exit code 0 on success, 3 when the findings or the risk model cannot be read (nothing is written).
    """
    # Fail closed before anything is deleted: --out must not be the findings file, nor a directory.
    if out.is_dir() or (out.exists() and findings.exists() and out.resolve() == findings.resolve()):
        typer.echo(f"sentinel score: --out {out} is the input or a directory; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)
    # A stale file from an earlier run must never be read as this run's scores.
    _clear_output(out, "sentinel score")
    try:
        model = RiskModel.load(policy_dir / "risk-model.yaml")
        scored = [
            Finding.model_validate(score_finding(f, model)) for f in load_findings(findings.read_bytes())
        ]
    except (EvaluationError, RiskModelError, OSError, ValueError) as exc:
        typer.echo(f"sentinel score: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    _write_output(out, dumps_ndjson(scored), "sentinel score")
    typer.echo(f"{len(scored)} finding(s) scored with risk model {model.version} -> {out}")


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
    baseline: Annotated[
        Path | None,
        typer.Option(
            help="Base-branch findings (Finding v1 NDJSON): in pr context only new findings can block."
        ),
    ] = None,
    tool_status: Annotated[
        Path | None,
        typer.Option(
            help="Tool status (schemas/tool-status.v1.json): any tool that is not ok blocks (SC-010)."
        ),
    ] = None,
    enrichment_snapshot: Annotated[Path | None, typer.Option(help="Enrichment snapshot file.")] = None,
    sbom: Annotated[Path | None, typer.Option(help="SBOM file to record by digest.")] = None,
    opa: Annotated[
        Path | None, typer.Option(help="OPA binary. Default: $SENTINEL_OPA, then opa on PATH.")
    ] = None,
    store: Annotated[
        Path | None,
        typer.Option(help="Evidence store: keep every input and the decision there, for `sentinel replay`."),
    ] = None,
) -> None:
    """Run the release gate and write a Decision v1 record.

    Exit code 0 for PASS or WARN, 1 for BLOCK, 3 when no decision could be made (fail closed). With
    --store, a decision whose evidence cannot be stored is not written either (exit 3).
    """
    # A stale decision from an earlier run must never be mistaken for this run's result.
    output.unlink(missing_ok=True)
    if waivers is None and Path(DEFAULT_WAIVERS_PATH).is_file():
        waivers = Path(DEFAULT_WAIVERS_PATH)
    try:
        # Each input is read once: the same bytes are evaluated, digested and stored.
        data = _Inputs(
            findings=findings.read_bytes(),
            waivers=waivers.read_bytes() if waivers else None,
            baseline=baseline.read_bytes() if baseline else None,
            tool_status=tool_status.read_bytes() if tool_status else None,
            enrichment_snapshot=enrichment_snapshot.read_bytes() if enrichment_snapshot else None,
            sbom=sbom.read_bytes() if sbom else None,
        )
        bundle = PolicyBundle.load(policy_dir)
        decision = evaluate(
            findings_data=data.findings,
            subject=Subject(repo=repo, commit=commit, context=context, ref=ref, image_digest=image_digest),
            evaluated_at=evaluated_at or now_utc(),
            bundle=bundle,
            opa=OpaRunner.locate(opa),
            tool_versions=_parse_tool_versions(tool_version or []),
            waivers_data=data.waivers,
            baseline_data=data.baseline,
            tool_status_data=data.tool_status,
            enrichment_snapshot=data.enrichment_snapshot,
            sbom=data.sbom,
        )
        if store is not None:
            _store_evidence(EvidenceStore(store), decision, bundle, data)
    except (BundleError, EvaluationError, OpaError, StoreError, OSError) as exc:
        typer.echo(f"sentinel evaluate: {exc}", err=True)
        typer.echo("sentinel evaluate: no decision was made; treat this change as blocked.", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc

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


@dataclass(frozen=True)
class _Inputs:
    findings: bytes
    waivers: bytes | None
    baseline: bytes | None
    tool_status: bytes | None
    enrichment_snapshot: bytes | None
    sbom: bytes | None


def _store_evidence(
    store: EvidenceStore, decision: dict[str, Any], bundle: PolicyBundle, data: _Inputs
) -> None:
    """Keep what `replay` needs: every input by the digest the decision recorded, then the decision."""
    inputs = decision["inputs"]
    stored = {
        "findings_digest": data.findings,
        "waivers_digest": data.waivers or b"",
        "baseline_digest": data.baseline,
        "tool_status_digest": data.tool_status,
        "enrichment_snapshot_digest": (
            EMPTY_ENRICHMENT_SNAPSHOT if data.enrichment_snapshot is None else data.enrichment_snapshot
        ),
        "sbom_digest": data.sbom,
    }
    for key, blob in stored.items():
        if blob is not None and store.put(blob) != inputs[key]:
            raise StoreError(f"stored {key} does not match the decision")
    if store.put_bundle(bundle) != inputs["policy_bundle_digest"]:
        raise StoreError("the policy bundle changed between evaluation and storage")
    store.put_decision(decision["decision_id"], dumps_decision(decision))


# ---------------------------------------------------------------- replay

_DECISION_ID_ARGUMENT = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)  # fullmatch


_REPLAY_ERRORS = (BundleError, EvaluationError, OpaError, StoreError, OSError, ValueError)


def _load_record(path: Path, decision_id: str | None = None) -> dict[str, Any]:
    recorded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(recorded, dict):
        raise EvaluationError(f"{path} is not a decision record")
    if decision_id is not None and recorded.get("decision_id") != decision_id:
        raise EvaluationError(
            f"{path.name} holds decision {recorded.get('decision_id')!r}, not {decision_id}"
        )
    return recorded


def _replay_record(recorded: dict[str, Any], evidence: EvidenceStore, runner: OpaRunner) -> ReplayResult:
    with tempfile.TemporaryDirectory(prefix="sentinel-replay-") as work:
        return replay(recorded, store=evidence, opa=runner, work_dir=Path(work))


@app.command("replay")
def replay_command(
    decision: Annotated[
        str | None, typer.Argument(help="Decision id (looked up in the store) or path to a decision file.")
    ] = None,
    all_decisions: Annotated[
        bool, typer.Option("--all", help="Replay every decision in the store (the nightly job).")
    ] = False,
    store: Annotated[
        Path, typer.Option(help="Evidence store written by `sentinel evaluate --store`.")
    ] = DEFAULT_STORE,
    opa: Annotated[
        Path | None, typer.Option(help="OPA binary. Default: $SENTINEL_OPA, then opa on PATH.")
    ] = None,
    allow_all_skipped: Annotated[
        bool,
        typer.Option(
            "--allow-all-skipped",
            help="With --all: exit 0 when every decision was skipped (e.g. after an engine version bump).",
        ),
    ] = False,
) -> None:
    """Re-evaluate a decision from the inputs it recorded and check that the result is identical.

    Every input, the policy bundle included, comes from the store by digest. Exit code 0 when identical,
    1 when the replayed decision differs, 3 when the decision cannot be replayed (missing or tampered
    evidence). With --all, decisions recorded with another engine or OPA version are skipped; the exit code
    is 3 if any decision cannot be replayed, the store holds none or none was compared (all skipped, unless
    --allow-all-skipped), else 1 if any differs.
    """
    if (decision is None) != all_decisions:
        raise typer.BadParameter("give either a decision (id or file) or --all")
    if allow_all_skipped and not all_decisions:
        raise typer.BadParameter("--allow-all-skipped only applies to --all")
    evidence = EvidenceStore(store)
    if decision is None:
        _replay_all(evidence, opa, allow_all_skipped=allow_all_skipped)
        return
    try:
        by_id = _DECISION_ID_ARGUMENT.fullmatch(decision) is not None
        path = evidence.decision_path(decision) if by_id else Path(decision)
        recorded = _load_record(path, decision if by_id else None)
        result = _replay_record(recorded, evidence, OpaRunner.locate(opa))
    except _REPLAY_ERRORS as exc:
        typer.echo(f"sentinel replay: {exc}", err=True)
        typer.echo("sentinel replay: the decision could not be replayed.", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc

    decision_id = recorded.get("decision_id")
    if result.identical:
        typer.echo(f"Replay identical: decision {decision_id} ({recorded.get('verdict')})")
        return
    typer.echo(f"Replay differs: decision {decision_id} (field: recorded -> replayed)")
    for line in result.differences:
        typer.echo(f"  {line}")
    raise typer.Exit(EXIT_REPLAY_DIFFERS)


def _replay_all(evidence: EvidenceStore, opa: Path | None, *, allow_all_skipped: bool) -> None:
    try:
        runner = OpaRunner.locate(opa)
        opa_version = runner.version()
    except OpaError as exc:
        typer.echo(f"sentinel replay: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    decisions = evidence.root / "decisions"
    paths = sorted(decisions.glob("*.json")) if decisions.is_dir() else []
    if not paths:
        # Nothing replayed must not read as "all identical".
        typer.echo(f"sentinel replay: no decision in {decisions}", err=True)
        raise typer.Exit(EXIT_NO_DECISION)

    counts = {"identical": 0, "skipped": 0, "differ": 0, "cannot replay": 0}
    for path in paths:
        decision_id = path.stem
        try:
            evidence.decision_path(decision_id)  # the file name must be a decision id
            recorded = _load_record(path, decision_id)
            check_identity(recorded)  # before skipping: a skip must not hide an edited record
            reason = skip_reason(recorded, opa_version)
            result = None if reason else _replay_record(recorded, evidence, runner)
        except _REPLAY_ERRORS as exc:
            typer.echo(f"cannot replay {decision_id}: {exc}")
            counts["cannot replay"] += 1
            continue
        if result is None:
            typer.echo(f"skipped    {decision_id} ({reason})")
            counts["skipped"] += 1
        elif result.identical:
            typer.echo(f"identical  {decision_id} ({recorded.get('verdict')})")
            counts["identical"] += 1
        else:
            typer.echo(f"differs    {decision_id} (field: recorded -> replayed)")
            for line in result.differences:
                typer.echo(f"  {line}")
            counts["differ"] += 1
    typer.echo(", ".join(f"{n} {label}" for label, n in counts.items()))
    if counts["cannot replay"]:
        raise typer.Exit(EXIT_NO_DECISION)
    if counts["differ"]:
        raise typer.Exit(EXIT_REPLAY_DIFFERS)
    if counts["identical"] == 0:  # every decision skipped: nothing was compared, which is not "all identical"
        if allow_all_skipped:
            typer.echo("nothing compared: every decision was skipped (allowed by --allow-all-skipped)")
            return
        typer.echo("sentinel replay: nothing compared, every decision was skipped", err=True)
        raise typer.Exit(EXIT_NO_DECISION)


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


@policy_app.command("capabilities")
def policy_capabilities(
    out: Annotated[Path, typer.Option("--out", "-o", help="Where to write the capabilities document.")],
    opa: Annotated[
        Path | None, typer.Option(help="OPA binary. Default: $SENTINEL_OPA, then opa on PATH.")
    ] = None,
) -> None:
    """Write OPA's capabilities minus non-deterministic built-ins (what `evaluate` runs policies with)."""
    try:
        capabilities = OpaRunner.locate(opa).restricted_capabilities()
    except OpaError as exc:
        typer.echo(f"sentinel policy capabilities: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    _write_atomically(out, json.dumps(capabilities, indent=2, sort_keys=True) + "\n")
    typer.echo(f"{len(capabilities['builtins'])} built-ins allowed; written to {out}")


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
        str | None,
        typer.Option(help="git mode only: commit range and pathspecs, e.g. 'origin/main..HEAD -- src'."),
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
) -> None:
    """Scan for secrets with the verified Gitleaks binary; raw secrets never leave memory."""
    out.unlink(missing_ok=True)  # a failed scan must never leave an older findings file behind
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
