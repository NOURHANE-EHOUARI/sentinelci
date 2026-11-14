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
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError

from sentinelci import __version__
from sentinelci.contracts.decision import Decision
from sentinelci.contracts.finding import Finding, Run, RunContext, Tool
from sentinelci.contracts.release import TrustReport as TrustReportContract
from sentinelci.contracts.remediation import PatchProposal
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
from sentinelci.normalize.grype import ImageSubject, load_grype_report, normalize_grype, normalize_grype_image
from sentinelci.normalize.ndjson import dumps_ndjson, write_ndjson
from sentinelci.normalize.opengrep import normalize_opengrep
from sentinelci.normalize.trivy import normalize_trivy_config
from sentinelci.normalize.zizmor import normalize_zizmor
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
from sentinelci.policy.tool_status import load_tool_status
from sentinelci.policy.vex import DEFAULT_VEX_PATH
from sentinelci.policy.waivers import DEFAULT_WAIVERS_PATH
from sentinelci.remediation.apply import apply_proposal
from sentinelci.remediation.check import CheckError, check_iac
from sentinelci.remediation.dockerfile import propose as propose_dockerfile
from sentinelci.remediation.gate import check_proposal, verify_proposal
from sentinelci.remediation.kubernetes import propose as propose_kubernetes
from sentinelci.remediation.proposal import RemediationError
from sentinelci.report.pr_comment import (
    ReportError,
    load_inputs,
    parse_findings,
    render_no_decision,
    render_pr_comment,
)
from sentinelci.report.release_upload import release_evidence, upload_release
from sentinelci.report.remediation_upload import remediation_attempt, upload_remediation
from sentinelci.report.upload import (
    TOKEN_VARIABLE,
    DecisionNotRecorded,
    RunInfo,
    UploadError,
    platform_from,
    upload,
)
from sentinelci.risk import RiskModel, RiskModelError, score_finding
from sentinelci.scanners.combine import CombineError, combine_findings, combine_tool_statuses
from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.gitleaks import GitleaksMode, scan_secrets_with_run
from sentinelci.scanners.grype import ImageScanFailure, scan_image, scan_sca, update_database
from sentinelci.scanners.installer import VerificationReport, detect_platform, install_tools, verify_tools
from sentinelci.scanners.lock import LOCK_FILE_NAME, ToolLock, load_lock
from sentinelci.scanners.opengrep import rule_ids, scan_sast_with_run
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S as SCAN_TIMEOUT_DEFAULT_S
from sentinelci.scanners.runner import ToolRun
from sentinelci.scanners.status import (
    outcome_from_error,
    outcome_from_run,
    tool_status_document,
    write_tool_status,
)
from sentinelci.scanners.trivy import remote_modules, scan_iac_with_run
from sentinelci.scanners.zizmor import scan_pipelines_with_run
from sentinelci.supplychain.admission import render_policy
from sentinelci.supplychain.attestations import (
    KINDS,
    AttestationError,
    contract_errors,
    parse_image,
    release_predicates,
)
from sentinelci.supplychain.cosign import (
    Signer,
    Verifier,
    check_public_key,
    refuse_another_release,
    registry_for,
)
from sentinelci.supplychain.sbom import SOURCE_KINDS, SourceKind, generate_sbom
from sentinelci.supplychain.verify import (
    ATTESTATIONS_DIR,
    public_key_sha256,
    report_document,
    verify_evidence,
    verify_registry,
)

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
report_app = typer.Typer(help="Render reports from a decision record.", no_args_is_help=True)
app.add_typer(normalize_app, name="normalize")
policy_app = typer.Typer(help="Release-gate policy tools.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
app.add_typer(tools_app, name="tools")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
remediate_app = typer.Typer(
    help="Verified remediation loop (SPEC §9): deterministic fixers propose, the gate verifies.",
    no_args_is_help=True,
)
app.add_typer(remediate_app, name="remediate")

LockOption = Annotated[Path, typer.Option("--lock", help="Path to the tool lock file.")]
DestOption = Annotated[Path, typer.Option("--dest", help="Installation directory (bin/ and cache/).")]
ScanTimeoutOption = Annotated[
    int,
    typer.Option(
        "--timeout",
        min=30,
        max=3600,
        help="Time limit of one scanner run, in seconds (Gitleaks git mode runs twice). A scanner that "
        "outlives it is recorded as `timeout` (SC-010).",
    ),
]
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
EXIT_NOT_VERIFIED = 1
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


def _refuse_output(
    out: Path,
    sources: list[Path | None],
    command: str,
    option: str = "--out",
    dirs: dict[str, Path | None] | None = None,
) -> None:
    """Fail closed before anything is deleted: the output must not be any input file, nor a directory,
    nor anywhere inside an input directory (`dirs`, by option name: the policy bundle, the evidence store).
    """
    if out.is_dir():
        typer.echo(f"{command}: {option} {out} is a directory; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)
    for source in sources:
        if source is not None and out.exists() and source.exists() and out.resolve() == source.resolve():
            typer.echo(f"{command}: {option} {out} is the input file {source}; nothing was written", err=True)
            raise typer.Exit(EXIT_NO_DECISION)
    for dir_option, directory in (dirs or {}).items():
        if directory is not None and out.resolve().is_relative_to(directory.resolve()):
            typer.echo(
                f"{command}: {option} {out} is inside {dir_option} {directory}; nothing was written", err=True
            )
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
    _refuse_output(out, [findings], "sentinel score", dirs={"--policy-dir": policy_dir})
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
    service_context: Annotated[
        Path | None,
        typer.Option(
            help="The sentinel.yaml given to `sentinel enrich --config`, from the base branch: recorded by "
            "digest (Decision 1.3)."
        ),
    ] = None,
    vex: Annotated[
        Path | None,
        typer.Option(
            help="OpenVEX statements (schemas/vex.v1.json), from the base branch. "
            f"Default: {DEFAULT_VEX_PATH} if present."
        ),
    ] = None,
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
    if waivers is None and Path(DEFAULT_WAIVERS_PATH).is_file():
        waivers = Path(DEFAULT_WAIVERS_PATH)
    if vex is None and Path(DEFAULT_VEX_PATH).is_file():
        vex = Path(DEFAULT_VEX_PATH)
    inputs = [findings, waivers, baseline, tool_status, enrichment_snapshot, service_context, sbom, vex, opa]
    dirs = {"--policy-dir": policy_dir, "--store": store}
    _refuse_output(output, inputs, "sentinel evaluate", "--output", dirs)
    # A stale decision from an earlier run must never be mistaken for this run's result.
    output.unlink(missing_ok=True)
    try:
        # Each input is read once: the same bytes are evaluated, digested and stored.
        data = _Inputs(
            findings=findings.read_bytes(),
            waivers=waivers.read_bytes() if waivers else None,
            baseline=baseline.read_bytes() if baseline else None,
            tool_status=tool_status.read_bytes() if tool_status else None,
            enrichment_snapshot=enrichment_snapshot.read_bytes() if enrichment_snapshot else None,
            sbom=sbom.read_bytes() if sbom else None,
            service_context=service_context.read_bytes() if service_context else None,
            vex=vex.read_bytes() if vex else None,
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
            service_context=data.service_context,
            vex_data=data.vex,
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
    if decision.get("vex_applied"):
        typer.echo(f"VEX not_affected: {', '.join(decision['vex_applied'])}")
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
    service_context: bytes | None
    vex: bytes | None


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
        "service_context_digest": data.service_context,
        "vex_digest": data.vex,
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


EXIT_UPLOAD_FAILED = 4  # never 1 or 3: an upload is a report, its failure says nothing about the verdict


@app.command("upload")
def upload_command(
    findings: Annotated[Path, typer.Option(help="The findings NDJSON of one run (as the scan wrote it).")],
    api_url: Annotated[
        str, typer.Option(help="The platform, https:// (or http://localhost for a local platform).")
    ],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[
        str | None,
        typer.Option(help="CI run identifier, as the findings carry it (GitHub: <run id>/<run attempt>)."),
    ] = None,
    resume: Annotated[
        str | None, typer.Option(help="Finish the upload of a run the platform already created (its id).")
    ] = None,
    decision: Annotated[
        Path | None,
        typer.Option(
            help="The Decision v1 record `sentinel evaluate` made on --findings, sent after them (then "
            "--findings must be the scored findings the gate evaluated)."
        ),
    ] = None,
) -> None:
    """Send one run's findings to the SentinelCI platform (B1 ingestion API), after the decision, and with
    --decision the decision itself.

    The token comes only from the SENTINEL_API_TOKEN environment variable. Exit code 0 when the platform
    recorded exactly these findings (with --resume, also when it already had them), and with --decision
    exactly this decision, 4 when it did not, for whatever reason: an upload never changes the verdict, which
    was decided before. With --run-id, the same command again resumes the platform's run of that CI run;
    without it, a re-run records a new run.
    """
    run = RunInfo(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id)
    what = "the findings or the decision were not recorded" if decision else "the findings were not uploaded"
    try:
        platform = platform_from(api_url)
        decision_bytes = decision.read_bytes() if decision is not None else None
        uploaded = upload(findings.read_bytes(), run, platform, resume=resume, decision=decision_bytes)
    except (OSError, UploadError) as exc:
        # The platform's own words are quoted in some messages: one that echoes the request (a gateway quoting
        # the Authorization header) must not make the CLI print the token.
        said, token = str(exc), os.environ.get(TOKEN_VARIABLE, "").strip()
        said = said.replace(token, f"<{TOKEN_VARIABLE}>") if token else said
        if isinstance(exc, DecisionNotRecorded):
            state = "may be recorded or not" if exc.unconfirmed else "was not recorded"
            what = f"the decision {state} (the findings are, in run {exc.run_id})"
        typer.echo(f"sentinel upload: {said}\n{what} (the verdict is unchanged)", err=True)
        raise typer.Exit(EXIT_UPLOAD_FAILED) from exc
    except Exception as exc:
        # Last resort: an upload never ends with 1 or a traceback. Only the type is printed: an unexpected
        # error's text could hold anything, the token included.
        typer.echo(
            f"sentinel upload: unexpected {type(exc).__name__}\n{what} (the verdict is unchanged)", err=True
        )
        raise typer.Exit(EXIT_UPLOAD_FAILED) from None
    printed: dict[str, object] = {
        "run_id": uploaded.run_id,
        "finding_count": uploaded.finding_count,
        "findings_sha256": uploaded.findings_sha256,
        "already_recorded": uploaded.already_recorded,
    }
    if decision is not None:
        printed |= {
            "decision_sha256": uploaded.decision_sha256,
            "verdict": uploaded.verdict,
            "decision_already_recorded": uploaded.decision_already_recorded,
        }
    typer.echo(json.dumps(printed))


@app.command("upload-release")
def upload_release_command(
    decision: Annotated[
        Path, typer.Option(help="The release decision (`sentinel evaluate --context release`).")
    ],
    api_url: Annotated[
        str, typer.Option(help="The platform, https:// (or http://localhost for a local platform).")
    ],
    trust_report: Annotated[
        list[Path] | None,
        typer.Option(
            "--trust-report",
            help="A `sentinel verify --report-json` report of the image (repeatable: registry, evidence). "
            "None for a BLOCK, which nothing signed.",
        ),
    ] = None,
) -> None:
    """Send one release's evidence to the SentinelCI platform (Releases & evidence page), after the release.

    The token comes only from the SENTINEL_API_TOKEN environment variable. Exit code 0 when the platform
    recorded exactly this evidence (also when it already had it), 4 when it did not: the release itself, its
    decision and its signatures are unchanged either way.
    """
    try:
        data = release_evidence(decision.read_bytes(), [path.read_bytes() for path in trust_report or []])
        uploaded = upload_release(data, platform_from(api_url))
    except (OSError, UploadError) as exc:
        said, token = str(exc), os.environ.get(TOKEN_VARIABLE, "").strip()
        said = said.replace(token, f"<{TOKEN_VARIABLE}>") if token else said
        typer.echo(f"sentinel upload-release: {said}\nthe release evidence was not uploaded", err=True)
        raise typer.Exit(EXIT_UPLOAD_FAILED) from exc
    except Exception as exc:
        # Last resort, as for `sentinel upload`: only the type, never an unexpected error's text.
        typer.echo(
            f"sentinel upload-release: unexpected {type(exc).__name__}\n"
            "the release evidence was not uploaded",
            err=True,
        )
        raise typer.Exit(EXIT_UPLOAD_FAILED) from None
    typer.echo(
        json.dumps(
            {
                "decision_id": uploaded.decision_id,
                "image_digest": uploaded.image_digest,
                "sha256": uploaded.sha256,
                "already_recorded": uploaded.already_recorded,
            }
        )
    )


@app.command("upload-remediation")
def upload_remediation_command(
    proposal: Annotated[Path, typer.Option(help="The patch proposal (Patch proposal v1) of the attempt.")],
    result: Annotated[Path, typer.Option(help="Its verification result (Verification result v1).")],
    repo: Annotated[str, typer.Option(help="The repository the proposal was made for, owner/name.")],
    api_url: Annotated[
        str, typer.Option(help="The platform, https:// (or http://localhost for a local platform).")
    ],
) -> None:
    """Send one attempt of the remediation loop to the SentinelCI platform (Remediation page).

    The token comes only from the SENTINEL_API_TOKEN environment variable. Exit code 0 when the platform
    recorded exactly this attempt (also when it already had it), 4 when it did not: the pull request and its
    verification are unchanged either way.
    """
    try:
        data = remediation_attempt(proposal.read_bytes(), result.read_bytes(), repo=repo)
        uploaded = upload_remediation(data, platform_from(api_url))
    except (OSError, UploadError) as exc:
        said, token = str(exc), os.environ.get(TOKEN_VARIABLE, "").strip()
        said = said.replace(token, f"<{TOKEN_VARIABLE}>") if token else said
        typer.echo(f"sentinel upload-remediation: {said}\nthe attempt was not uploaded", err=True)
        raise typer.Exit(EXIT_UPLOAD_FAILED) from exc
    except Exception as exc:
        # Last resort, as for `sentinel upload`: only the type, never an unexpected error's text.
        typer.echo(
            f"sentinel upload-remediation: unexpected {type(exc).__name__}\nthe attempt was not uploaded",
            err=True,
        )
        raise typer.Exit(EXIT_UPLOAD_FAILED) from None
    typer.echo(
        json.dumps(
            {
                "proposal_id": uploaded.proposal_id,
                "outcome": uploaded.outcome,
                "sha256": uploaded.sha256,
                "already_recorded": uploaded.already_recorded,
            }
        )
    )


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


@normalize_app.command("grype")
def normalize_grype_cmd(
    report: Annotated[Path, typer.Argument(help="Grype JSON report (-o json) of a source tree's SBOM.")],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    scan_root: Annotated[
        str, typer.Option(help="The scanned directory, relative to the repository root.")
    ] = ".",
) -> None:
    """Normalize a Grype report into SCA findings. A report that shows a silenced match fails closed."""
    out.unlink(missing_ok=True)  # a failed run must never leave an older findings file behind
    try:
        run = Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id)
        findings = normalize_grype(load_grype_report(report), run=run, scan_root=scan_root)
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


@tools_app.command("grype-db")
def tools_grype_db(
    db_dir: Annotated[
        Path, typer.Option("--db-dir", help="Directory to fill: what `sentinel scan sca --db-dir` reads.")
    ],
    archive: Annotated[
        str | None,
        typer.Option(
            "--archive",
            help="Import this database instead of downloading the latest: a local archive, or an https URL "
            "ending in ?checksum=sha256:<hex>.",
        ),
    ] = None,
    report: Annotated[
        Path | None, typer.Option("--report", help="Write the prepared database's evidence (JSON) here.")
    ] = None,
    allow_stale_db: Annotated[
        bool,
        typer.Option("--allow-stale-db", help="Accept a database built over 5 days ago (replays and tests)."),
    ] = False,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
) -> None:
    """Prepare Grype's vulnerability database with the verified Grype and SentinelCI's configuration.

    The only step of an SCA scan that uses the network (through the job's proxy, if any). Exit code 3, with no
    report written, unless Grype's own status check then calls the database valid.
    """
    if report is not None:
        report.unlink(missing_ok=True)  # an older report must never vouch for a failed update
    try:
        prepared = update_database(
            db_dir,
            lock=load_lock(lock),
            tools_dir=tools_dir,
            platform=platform,
            archive=archive,
            allow_stale_db=allow_stale_db,
        )
    except (ToolIntegrityError, ScannerError) as exc:
        raise _fail_closed(exc) from exc
    database = prepared.database
    if report is not None:
        evidence = {
            "schema_version": 1,
            "grype": {"version": prepared.grype.version, "binary_sha256": prepared.grype.binary_sha256},
            "database": {
                "schema_version": database.schema_version,
                "built": database.built,
                "checksum": database.checksum,
            },
            "archive_sha256": prepared.archive_sha256,
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        report.write_text(text, encoding="utf-8", newline="\n")
    typer.echo(
        f"grype {prepared.grype.version}: database {database.schema_version} built {database.built} "
        f"(checksum {database.checksum or 'not reported'}) ready in {db_dir}"
    )


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
    timeout: ScanTimeoutOption = SCAN_TIMEOUT_DEFAULT_S,
    tool_status_out: Annotated[
        Path | None,
        typer.Option(
            help="Also write a tool status (schemas/tool-status.v1.json), on success and on failure, so the "
            "gate can record a failed scan as SC-010."
        ),
    ] = None,
) -> None:
    """Scan for secrets with the verified Gitleaks binary; raw secrets never leave memory."""
    _clear(out, tool_status_out)
    if mode not in ("dir", "git"):
        raise typer.BadParameter("mode must be 'dir' or 'git'")
    scan_mode: GitleaksMode = "git" if mode == "git" else "dir"
    root = repo_root or target

    def scan(tool_lock: ToolLock) -> tuple[list[Finding], ToolRun]:
        raw, tool_run = scan_secrets_with_run(
            target,
            lock=tool_lock,
            tools_dir=tools_dir,
            repo_root=root,
            platform=platform,
            mode=scan_mode,
            log_opts=log_opts,
            timeout_s=timeout,
        )
        findings = normalize_gitleaks(
            raw,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            tool=Tool(name="gitleaks", version=tool_run.version),
            repo_root=root,
        )
        return findings, tool_run

    _scan_and_record("gitleaks", scan, out=out, tool_status_out=tool_status_out, lock=lock, platform=platform)


@scan_app.command("iac")
def scan_iac_cmd(
    target: Annotated[
        Path, typer.Argument(help="Directory to scan (Terraform, Kubernetes, Dockerfiles, ...).")
    ],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[
        Path | None, typer.Option(help="Repository root (default: the target itself).")
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
    timeout: ScanTimeoutOption = SCAN_TIMEOUT_DEFAULT_S,
    tool_status_out: Annotated[
        Path | None,
        typer.Option(
            help="Also write a tool status (schemas/tool-status.v1.json), on success and on failure, so the "
            "gate can record a failed scan as SC-010."
        ),
    ] = None,
) -> None:
    """Scan infrastructure as code with the verified Trivy binary (`trivy config`), offline."""
    _clear(out, tool_status_out)
    root = repo_root or target

    def scan(tool_lock: ToolLock) -> tuple[list[Finding], ToolRun]:
        results, tool_run = scan_iac_with_run(
            target, lock=tool_lock, tools_dir=tools_dir, repo_root=root, platform=platform, timeout_s=timeout
        )
        # Listed once the tree passed the checks (no link leaving it): not fetched, so not evaluated.
        remote = remote_modules(target, root) if target.is_dir() else []
        if remote:
            typer.echo(
                f"warning: {len(remote)} remote Terraform module(s) not fetched or evaluated: "
                + ", ".join(remote),
                err=True,
            )
        findings = normalize_trivy_config(
            results,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            tool=Tool(name="trivy", version=tool_run.version),
            scan_root=target.resolve().relative_to(root.resolve()).as_posix(),
        )
        return findings, tool_run

    _scan_and_record("trivy", scan, out=out, tool_status_out=tool_status_out, lock=lock, platform=platform)


@scan_app.command("combine")
def scan_combine_cmd(
    findings: Annotated[
        list[Path], typer.Option("--findings", help="Findings NDJSON of one scanner (repeatable).")
    ],
    out: Annotated[Path, typer.Option(help="Combined findings NDJSON for the gate.")],
    tool_status: Annotated[
        list[Path] | None,
        typer.Option(
            "--tool-status", help="Tool status of one scanner (repeatable); missing ones are skipped."
        ),
    ] = None,
    tool_status_out: Annotated[Path | None, typer.Option(help="Combined tool status for the gate.")] = None,
) -> None:
    """Merge per-scanner findings and tool statuses into the gate's inputs; refuse anything inconsistent.

    A tool status file that does not exist is left out (that scanner wrote none, so the gate reports it as
    missing, SC-010). Exit code 3 when the outputs cannot be combined; nothing is written then.
    """
    _clear(out, tool_status_out)
    statuses = [path for path in tool_status or [] if path.exists()]
    try:
        combined = combine_findings(findings)
        document = combine_tool_statuses(statuses) if tool_status_out is not None and statuses else None
    except CombineError as exc:
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(combined, out)
    message = f"{len(combined)} finding(s) from {len(findings)} file(s) written to {out}"
    if document is not None and tool_status_out is not None:
        write_tool_status(document, tool_status_out)
        message += f"; tool status for {', '.join(document['tools'])} written to {tool_status_out}"
    typer.echo(message)


def _clear(out: Path, tool_status_out: Path | None) -> None:
    out.unlink(missing_ok=True)  # a failed scan must never leave an older findings file behind
    if tool_status_out is not None:
        tool_status_out.unlink(missing_ok=True)  # nor an older status vouching for it


def _scan_and_record(
    tool: str,
    scan: Callable[[ToolLock], tuple[list[Finding], ToolRun]],
    *,
    out: Path,
    tool_status_out: Path | None,
    lock: Path,
    platform: str | None,
) -> None:
    """Run one scanner, write its findings, then its tool status; record a failure before failing closed."""
    tool_lock: ToolLock | None = None
    try:
        tool_lock = load_lock(lock)
        findings, tool_run = scan(tool_lock)
    except (ToolIntegrityError, ScannerError, NormalizationError) as exc:
        if tool_status_out is not None and tool_lock is not None:  # no lock: no status, the gate blocks
            outcome = outcome_from_error(tool, exc, lock=tool_lock)
            _write_status(tool_status_out, lock, platform or _host_platform(), {tool: outcome})
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(findings, out)
    if tool_status_out is not None:  # last: an `ok` status never vouches for a findings file not yet written
        host = platform or _host_platform()
        outcome = outcome_from_run(tool_run, lock=tool_lock, platform=host)
        _write_status(tool_status_out, lock, host, {tool: outcome})
    typer.echo(f"{tool} {tool_run.version}: {len(findings)} finding(s) written to {out}")


def _host_platform() -> str | None:
    try:
        return detect_platform()
    except ToolIntegrityError:
        return None


def _write_status(
    destination: Path, lock: Path, platform: str | None, outcomes: dict[str, dict[str, Any]]
) -> None:
    write_tool_status(tool_status_document(lock.read_bytes(), platform, outcomes), destination)
    typer.echo(f"tool status written to {destination}", err=True)


@scan_app.command("sast")
def scan_sast_cmd(
    target: Annotated[Path, typer.Argument(help="Directory to scan with SentinelCI's SAST rules.")],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[
        Path | None, typer.Option(help="Repository root (default: the target itself).")
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
) -> None:
    """Static analysis with the verified Opengrep binary and SentinelCI's own rules (offline, never configured
    or silenced by the scanned repository): findings of category SAST."""
    out.unlink(missing_ok=True)  # a failed scan must never leave an older findings file behind
    root = repo_root or target
    try:
        scan = scan_sast_with_run(
            target, lock=load_lock(lock), tools_dir=tools_dir, repo_root=root, platform=platform
        )
        findings = normalize_opengrep(
            scan.results,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            tool=Tool(name="opengrep", version=scan.run.version),
            rules=rule_ids(),
            scan_target=scan.target,
            scan_root=scan.target.relative_to(root.resolve()).as_posix(),
            gaps=scan.gaps,
        )
    except (ToolIntegrityError, ScannerError, NormalizationError) as exc:
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(findings, out)
    if scan.warnings:  # analysed only in part: say where, in the job log
        typer.echo(
            f"warning: opengrep reported {len(scan.warnings)} problem(s): {'; '.join(scan.warnings)}",
            err=True,
        )
    typer.echo(f"opengrep {scan.run.version}: {len(findings)} finding(s) written to {out}")


@scan_app.command("pipelines")
def scan_pipelines_cmd(
    target: Annotated[Path, typer.Argument(help="Directory whose GitHub workflows and actions to audit.")],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[
        Path | None, typer.Option(help="Repository root (default: the target itself).")
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    timeout: ScanTimeoutOption = SCAN_TIMEOUT_DEFAULT_S,
    tool_status_out: Annotated[
        Path | None,
        typer.Option(
            help="Also write a tool status (schemas/tool-status.v1.json), on success and on failure, so the "
            "gate can record a failed scan as SC-010."
        ),
    ] = None,
) -> None:
    """Audit CI workflows with the zizmor of this environment, checked against tools.lock.toml (offline, never
    configured by the scanned repository): findings of category PIPELINE, for rule SC-009."""
    _clear(out, tool_status_out)
    root = repo_root or target

    def scan(tool_lock: ToolLock) -> tuple[list[Finding], ToolRun]:
        if not target.is_dir():
            raise ScannerError(f"{target} is not a directory")
        try:
            scan_root = target.resolve().relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise ScannerError(f"{target} is outside the repository root {root}") from exc
        scan = scan_pipelines_with_run(target, lock=tool_lock, timeout_s=timeout)
        findings = normalize_zizmor(
            scan.results,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            tool=Tool(name="zizmor", version=scan.version),
            scan_root=scan_root,
        )
        if scan.skipped:  # never counted as audited: say which ones, in the job log
            typer.echo(
                f"warning: {len(scan.skipped)} file(s) with a `jobs:` key are not GitHub workflows zizmor "
                f"can load, not audited: {', '.join(scan.skipped)}",
                err=True,
            )
        skipped = f", {len(scan.skipped)} skipped" if scan.skipped else ""
        typer.echo(
            f"zizmor {scan.version}: {len(scan.audited)} file(s) audited{skipped}, {len(findings)} finding(s)"
        )
        # Nothing to audit: the binary was still verified, so its status is `ok` with no finding.
        tool_run = scan.run or ToolRun(
            tool="zizmor", version=scan.version, binary_sha256=scan.binary_sha256, args=(), returncode=0,
            stdout="", stderr="", duration_s=0.0,
        )  # fmt: skip
        return findings, tool_run

    _scan_and_record(
        "zizmor", scan, out=out, tool_status_out=tool_status_out, lock=lock, platform=_host_platform()
    )


@scan_app.command("sca")
def scan_sca_cmd(
    target: Annotated[
        Path, typer.Argument(help="Source tree to scan (the repository or a directory in it).")
    ],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA that was scanned.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    db_dir: Annotated[
        Path,
        typer.Option(
            "--db-dir",
            help="Grype's vulnerability database directory, prepared before the scan (never fetched).",
        ),
    ],
    ref: Annotated[str | None, typer.Option(help="Git ref that was scanned.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    repo_root: Annotated[
        Path | None, typer.Option(help="Repository root (default: the target itself).")
    ] = None,
    allow_stale_db: Annotated[
        bool,
        typer.Option(
            "--allow-stale-db",
            help="Accept a database built over 5 days ago (replays and tests: it misses new advisories).",
        ),
    ] = False,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
) -> None:
    """Vulnerable dependencies: the verified Syft's SBOM of the tree, matched by the verified Grype, offline.

    The scan never downloads: the database is the directory given in --db-dir. Exit code 3, with no findings
    file written, when a tool fails or is tampered with, the database is missing, invalid or stale, or the
    report shows a silenced match.
    """
    out.unlink(missing_ok=True)  # a failed scan must never leave an older findings file behind
    root = repo_root or target
    try:
        scan = scan_sca(
            target,
            repo_root=root,
            name=repo,
            db_dir=db_dir,
            lock=load_lock(lock),
            tools_dir=tools_dir,
            platform=platform,
            allow_stale_db=allow_stale_db,
        )
        findings = normalize_grype(
            scan.report,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            scan_root=scan.scan_root,
        )
    except (ToolIntegrityError, ScannerError, NormalizationError) as exc:
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(findings, out)
    database = scan.database
    typer.echo(
        f"grype {scan.grype.version} on the SBOM of syft {scan.sbom.run.version} ({scan.sbom.packages} "
        f"package(s)), database {database.schema_version} built {database.built} "
        f"(checksum {database.checksum or 'not reported'}): {len(findings)} finding(s) written to {out}"
    )


@scan_app.command("image")
def scan_image_cmd(
    archive: Annotated[
        Path,
        typer.Argument(
            help="The image's OCI layout archive (`docker buildx build --output type=oci,dest=...`)."
        ),
    ],
    image_digest: Annotated[
        str,
        typer.Option(
            "--image-digest",
            help="Its manifest digest (sha256:...), as the build recorded it (`docker buildx build "
            "--metadata-file`: containerimage.digest), not as the layout claims it.",
        ),
    ],
    image_ref: Annotated[
        str,
        typer.Option(
            "--image-ref",
            help="Where it is released, without tag or digest (e.g. kind-registry:5000/demo/api): "
            "a reference with either is refused.",
        ),
    ],
    out: Annotated[Path, typer.Option(help="Destination NDJSON file.")],
    repo: Annotated[str, typer.Option(help="Repository as owner/name.")],
    commit: Annotated[str, typer.Option(help="Commit SHA the image was built from.")],
    context: Annotated[RunContext, typer.Option(help="Run context.")],
    db_dir: Annotated[
        Path,
        typer.Option(
            "--db-dir",
            help="Grype's vulnerability database directory, prepared before the scan (never fetched).",
        ),
    ],
    ref: Annotated[str | None, typer.Option(help="Git ref the image was built from.")] = None,
    run_id: Annotated[str | None, typer.Option(help="CI run identifier.")] = None,
    allow_stale_db: Annotated[
        bool,
        typer.Option(
            "--allow-stale-db",
            help="Accept a database built over 5 days ago (replays and tests: it misses new advisories).",
        ),
    ] = False,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = (DEFAULT_TOOLS_DIR),
    platform: PlatformOption = None,
    timeout: ScanTimeoutOption = SCAN_TIMEOUT_DEFAULT_S,
    tool_status_out: Annotated[
        Path | None,
        typer.Option(
            help="Also write a tool status (schemas/tool-status.v1.json) for Syft and Grype, on success and "
            "on failure, so the gate can record a failed scan as SC-010."
        ),
    ] = None,
) -> None:
    """Vulnerabilities of a built image: the verified Syft's SBOM of its OCI layout, matched by the verified
    Grype, offline. CONTAINER findings, each with the image's digest, its reference and the package's layer.

    Exit code 3, with no findings file written, when a tool fails or is tampered with, the archive does not
    hold the image of --image-digest, the database is missing, invalid or stale, or the report shows a
    silenced match.
    """
    out.unlink(missing_ok=True)  # a failed scan must never leave an older findings file behind
    if tool_status_out is not None:
        tool_status_out.unlink(missing_ok=True)  # nor an older status vouching for it
    try:  # before any tool runs: a reference with its own tag or digest is never scanned
        image = ImageSubject(digest=image_digest, ref=image_ref)
    except NormalizationError as exc:
        raise _fail_closed(exc) from exc
    host = platform or _host_platform()
    tool_lock: ToolLock | None = None
    outcomes: dict[str, dict[str, Any]] = {}
    try:
        tool_lock = load_lock(lock)
        scan = scan_image(
            archive,
            image_digest=image_digest,
            name=image_ref,
            db_dir=db_dir,
            lock=tool_lock,
            tools_dir=tools_dir,
            platform=platform,
            allow_stale_db=allow_stale_db,
            timeout_s=timeout,
        )
        outcomes["syft"] = outcome_from_run(scan.sbom.run, lock=tool_lock, platform=host)
        outcomes["grype"] = outcome_from_run(scan.grype, lock=tool_lock, platform=host)
        findings = normalize_grype_image(
            scan.report,
            run=Run(repo=repo, commit=commit, context=context, ref=ref, run_id=run_id),
            image=image,
        )
    except ImageScanFailure as failure:
        if tool_status_out is not None and tool_lock is not None:
            outcomes = {failure.tool: outcome_from_error(failure.tool, failure.error, lock=tool_lock)}
            if failure.sbom is not None:
                outcomes["syft"] = outcome_from_run(failure.sbom.run, lock=tool_lock, platform=host)
            else:
                outcomes["grype"] = {
                    "version": tool_lock.tools["grype"].version, "status": "not_run",
                    "detail": "not started: Syft produced no SBOM of the image",
                }  # fmt: skip
            _write_status(tool_status_out, lock, host, outcomes)
        raise _fail_closed(failure.error) from failure
    except (ToolIntegrityError, ScannerError, NormalizationError) as exc:
        if tool_status_out is not None and tool_lock is not None:
            if "grype" in outcomes:  # the report could not be trusted: Grype's run counts as failed
                outcomes["grype"] = outcome_from_error("grype", exc, lock=tool_lock)
            _write_status(tool_status_out, lock, host, outcomes or {
                "syft": outcome_from_error("syft", exc, lock=tool_lock),
            })  # fmt: skip
        raise _fail_closed(exc) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    write_ndjson(findings, out)
    if tool_status_out is not None:  # last: an `ok` status never vouches for a findings file not yet written
        _write_status(tool_status_out, lock, host, outcomes)
    database = scan.database
    typer.echo(
        f"grype {scan.grype.version} on the SBOM of syft {scan.sbom.run.version} of {image_digest} "
        f"({scan.sbom.packages} package(s)), database {database.schema_version} built {database.built}: "
        f"{len(findings)} finding(s) written to {out}"
    )


# ---------------------------------------------------------------- report


@report_app.command("pr-comment")
def report_pr_comment(
    decision: Annotated[Path, typer.Option(help="Decision v1 record written by `sentinel evaluate`.")],
    findings: Annotated[Path, typer.Option(help="The findings NDJSON the decision was made on.")],
    out: Annotated[Path, typer.Option(help="Destination Markdown file.")],
    baseline: Annotated[
        Path | None, typer.Option(help="Findings NDJSON of the base branch, to count new findings.")
    ] = None,
    pipeline_changes: Annotated[
        Path | None,
        typer.Option(help="File listing pipeline paths changed by the pull request, one per line."),
    ] = None,
) -> None:
    """Render the deterministic PR comment.

    Without a trustworthy decision, write a fail-closed "no decision" comment instead and exit 3.
    """
    out.unlink(missing_ok=True)  # never post an older comment if this run fails
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        inputs = load_inputs(
            decision, findings, baseline_path=baseline, pipeline_changes_path=pipeline_changes
        )
    except ReportError as exc:
        out.write_text(render_no_decision(str(exc)), encoding="utf-8", newline="\n")
        typer.echo(f"no trustworthy decision: {exc}\nFAIL CLOSED: treated as BLOCK (rule SC-010).", err=True)
        raise typer.Exit(EXIT_UNTRUSTED_INPUT) from exc
    out.write_text(render_pr_comment(inputs), encoding="utf-8", newline="\n")
    typer.echo(f"verdict {inputs.decision.verdict}: comment written to {out}")


# ---------------------------------------------------------------- supply chain (A4, ADR-0010)

EXIT_UNTRUSTED = 1
RegistryHttpOption = Annotated[
    bool,
    typer.Option(
        "--registry-http",
        help="Reach the image's registry over plain HTTP: a local registry only (a loopback host, or a "
        "single-label host with a port such as kind-registry:5000); refused for any other host.",
    ),
]


@app.command("attest")
def attest_command(
    image: Annotated[str, typer.Argument(help="The release image, <name>@sha256:<digest>.")],
    decision: Annotated[Path, typer.Option(help="The release decision (Decision v1) about this image.")],
    findings: Annotated[Path, typer.Option(help="The findings NDJSON the decision was made on.")],
    sbom: Annotated[Path, typer.Option(help="The CycloneDX JSON SBOM the decision recorded.")],
    key: Annotated[str, typer.Option(help="Cosign private key: a file, or env://VAR.")],
    out: Annotated[Path, typer.Option(help="Evidence directory: the bundles go to <out>/attestations/.")],
    push: Annotated[
        bool,
        typer.Option(
            "--push",
            help="Also sign the image and attach the four attestations to it in its registry (cosign sign "
            "and cosign attest), where Kyverno and `sentinel verify` without --evidence read them.",
        ),
    ] = False,
    registry_http: RegistryHttpOption = False,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
) -> None:
    """Sign the four release attestations of an image: decision, SBOM, vulnerability scan, provenance.

    Runs in the release workflow's attest job (the GitHub Actions variables give the provenance). Exit code 3,
    with nothing signed, when the inputs don't belong together: a BLOCK or non-release decision, a decision
    about another image, findings or an SBOM the decision did not record, or a run on another repository or
    commit. With --push, the registry must not already hold a different release of this digest signed by the
    same key (a digest has one release per registry; a re-run of the same release is fine): exit code 3, with
    nothing signed. A registry failure while pushing is exit code 3 too: no bundle is kept, and the registry
    may hold part of the set, which neither `sentinel verify` nor Kyverno trusts.
    """
    directory = out / ATTESTATIONS_DIR
    bundles = [directory / f"{kind}.sigstore.json" for kind in KINDS]
    signed = pushing = False
    try:
        target = parse_image(image)
        predicates = release_predicates(
            target,
            decision_data=decision.read_bytes(),
            findings_data=findings.read_bytes(),
            sbom_data=sbom.read_bytes(),
            env=os.environ,
        )
        signer = Signer(key, load_lock(lock), tools_dir, platform)
        if push:  # checked before anything is signed
            registry = registry_for(target, allow_http=registry_http)
            statements = {kind: (KINDS[kind], predicates[kind]) for kind in KINDS}
            refuse_another_release(signer, target, statements, registry, os.environ)
        directory.mkdir(parents=True, exist_ok=True)
        for (kind, predicate_type), bundle in zip(KINDS.items(), bundles, strict=True):
            signer.attest(target, predicate_type, predicates[kind], bundle, os.environ)
        if push:
            pushing = True
            signer.sign_image(target, registry, os.environ)
            for kind, predicate_type in KINDS.items():
                signer.attest_image(target, predicate_type, predicates[kind], registry, os.environ)
        signed = True
    except (AttestationError, OSError, ToolIntegrityError, ScannerError) as exc:
        outcome = (
            "no bundle kept; the registry may hold part of the set (not trusted)"
            if pushing
            else "nothing was signed"
        )
        typer.echo(f"sentinel attest: {exc}; {outcome}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    finally:
        if not signed:  # all four or none, whatever stopped the run; an earlier run's bundles go too
            for bundle in bundles:
                bundle.unlink(missing_ok=True)
    pushed = f"; image signed and the {len(KINDS)} attached in its registry" if push else ""
    typer.echo(f"signed {len(bundles)} attestations of {target.reference} -> {directory}{pushed}")


@app.command("verify")
def verify_command(
    image: Annotated[str, typer.Argument(help="The image to check, <name>@sha256:<digest>.")],
    key: Annotated[Path, typer.Option(help="Cosign public key that must have signed every attestation.")],
    repo: Annotated[str, typer.Option(help="The repository the release must come from, owner/name.")],
    builder_id: Annotated[
        str,
        typer.Option(
            help="The workflow that must have built it, as SLSA builder id, e.g. "
            "https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/heads/main."
        ),
    ],
    evidence: Annotated[
        Path | None,
        typer.Option(
            help="Evidence directory written by `sentinel attest` (offline verification). Without it, the "
            "image's own signature and the attestations attached to it are read from its registry."
        ),
    ] = None,
    registry_http: RegistryHttpOption = False,
    report_json: Annotated[
        Path | None,
        typer.Option(
            help="Also write the trust report as JSON (schemas/trust-report.v1.json), trusted or not: what "
            "`sentinel upload-release` sends to the platform. Not written when the verification cannot run."
        ),
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
) -> None:
    """Check that an image is backed by a signed, non-BLOCK release decision, and print a trust report.

    Exit code 0 when every check passes, 1 when any fails (not trusted), 3 when the verification could not run
    (for example a Cosign binary that does not match tools.lock.toml). Both non-zero codes refuse the image.
    """
    try:
        if report_json is not None:
            # Refused before anything is removed: the key must survive a wrong option (review of #86).
            if report_json.resolve() == key.resolve():
                raise AttestationError("--report-json cannot be the public key")
            report_json.unlink(missing_ok=True)  # an older report must never stand for this verification
        target = parse_image(image)
        check_public_key(key)  # a broken setup is "could not run" (3), not "this image is bad" (1)
        key_sha256 = public_key_sha256(key)
        verifier = Verifier(key, load_lock(lock), tools_dir, platform)
        if evidence is not None:
            report = verify_evidence(target, evidence, verifier, repo=repo, builder_id=builder_id)
        else:
            registry = registry_for(target, allow_http=registry_http)
            report = verify_registry(target, verifier, registry, os.environ, repo=repo, builder_id=builder_id)
        if report_json is not None:
            document = report_document(
                report, mode="evidence" if evidence is not None else "registry", repo=repo,
                builder_id=builder_id, key_sha256=key_sha256, verified_at=datetime.now(UTC),
            )  # fmt: skip
            _write_trust_report(document, report_json)
    except (AttestationError, ToolIntegrityError, ScannerError) as exc:
        typer.echo(f"sentinel verify: {exc}\nFAIL CLOSED: the image is not trusted.", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    typer.echo(report.render(), nl=False)
    if not report.trusted:
        raise typer.Exit(EXIT_UNTRUSTED)


def _write_trust_report(document: dict[str, Any], destination: Path) -> None:
    """Write a trust report the contract accepts, or refuse (a value the report cannot carry, such as a
    repository or builder id outside the contract's shapes)."""
    try:
        parsed = TrustReportContract.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        raise AttestationError(f"the trust report is not a trust report v1: {contract_errors(exc)}") from exc
    if (problem := parsed.problem()) is not None:
        raise AttestationError(f"the trust report contradicts itself: {problem}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


@app.command("sbom")
def sbom_command(
    target: Annotated[Path, typer.Argument(help="Source tree, or the image the build wrote to a file.")],
    name: Annotated[str, typer.Option(help="Name of the SBOM's subject, e.g. demo-shop/shop-api.")],
    cyclonedx: Annotated[Path, typer.Option(help="Destination of the CycloneDX JSON SBOM.")],
    spdx: Annotated[Path, typer.Option(help="Destination of the SPDX JSON SBOM.")],
    source: Annotated[
        str, typer.Option(help=f"What the target is: {', '.join(SOURCE_KINDS)} (never a registry pull).")
    ] = "dir",
    image_digest: Annotated[
        str | None,
        typer.Option(
            help="For an image source (required there): the manifest digest the build produced, "
            "sha256:<hex>. Both SBOMs must name it."
        ),
    ] = None,
    lock: LockOption = Path(LOCK_FILE_NAME),
    tools_dir: Annotated[
        Path, typer.Option("--tools-dir", help="Where `sentinel tools install` put the tools.")
    ] = DEFAULT_TOOLS_DIR,
    platform: PlatformOption = None,
) -> None:
    """Write the CycloneDX and SPDX SBOMs of a source tree or a built image with the pinned Syft (offline).

    Exit code 3, with neither file written, when Syft fails, does not match tools.lock.toml, or writes
    something other than a CycloneDX document with a serialNumber and an SPDX document.
    """
    if source not in SOURCE_KINDS:
        raise typer.BadParameter(f"--source must be one of {', '.join(SOURCE_KINDS)}")
    for out in (cyclonedx, spdx):  # checked before anything is deleted
        if out.resolve().is_relative_to(target.resolve()) or out.is_dir():
            typer.echo(
                f"sentinel sbom: {out} is inside the target {target} or a directory; nothing was written",
                err=True,
            )
            raise typer.Exit(EXIT_NO_DECISION)
    if cyclonedx.resolve() == spdx.resolve():
        typer.echo("sentinel sbom: --cyclonedx and --spdx are the same file; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)
    for out in (cyclonedx, spdx):
        try:
            out.unlink(missing_ok=True)  # a failed run must never leave an older SBOM behind
        except OSError as exc:
            typer.echo(f"sentinel sbom: cannot use {out}: {exc}; nothing was written", err=True)
            raise typer.Exit(EXIT_NO_DECISION) from exc
    kind: SourceKind = source  # narrowed by the membership check above
    try:
        sbom = generate_sbom(
            target,
            kind=kind,
            name=name,
            lock=load_lock(lock),
            tools_dir=tools_dir,
            image_digest=image_digest,
            platform=platform,
        )
        for out, data in ((cyclonedx, sbom.cyclonedx), (spdx, sbom.spdx)):
            out.parent.mkdir(parents=True, exist_ok=True)
            _write_atomically(out, data.decode("utf-8"))
    except (ToolIntegrityError, ScannerError, OSError, UnicodeDecodeError) as exc:
        for out in (cyclonedx, spdx):
            out.unlink(missing_ok=True)
        raise _fail_closed(exc) from exc
    typer.echo(
        f"syft {sbom.run.version}: {sbom.packages} package(s), {sbom.serial_number} -> {cyclonedx}, {spdx}"
    )


@app.command("admission-policy")
def admission_policy_command(
    key: Annotated[
        Path, typer.Option(help="Cosign public key of the releases (the one `sentinel verify` uses).")
    ],
    repo: Annotated[str, typer.Option(help="The repository releases must come from, owner/name.")],
    builder_id: Annotated[
        str, typer.Option(help="The release workflow, as SLSA builder id (the one `sentinel verify` uses).")
    ],
    image_glob: Annotated[
        str, typer.Option(help="Images the policy applies to, e.g. kind-registry:5000/demo-shop/*.")
    ],
    out: Annotated[Path, typer.Option(help="Where to write the Kyverno ImageValidatingPolicy (YAML).")],
    registry_http: RegistryHttpOption = False,
) -> None:
    """Write the Kyverno admission policy of SentinelCI releases (A5): a Pod runs an image matching the glob
    only if `sentinel verify` would trust it. Exit code 3, with nothing written, for a value that is not what
    it should be."""
    if out.resolve() == key.resolve():  # checked before anything is deleted
        typer.echo("sentinel admission-policy: --out is the key file; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)
    out.unlink(missing_ok=True)
    try:
        policy = render_policy(
            public_key=key, image_glob=image_glob, repo=repo, builder_id=builder_id, allow_http=registry_http
        )
    except AttestationError as exc:
        typer.echo(f"sentinel admission-policy: {exc}; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(policy, encoding="utf-8", newline="\n")
    typer.echo(f"admission policy for {image_glob} -> {out}")


# ---------------------------------------------------------------- remediate


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _refuse_input_as_output(out: Path, inputs: list[Path], command: str) -> None:
    """Exit 3, before anything is deleted, when `out` is an input: clearing it would lose the evidence."""
    if any(out.resolve() == path.resolve() for path in inputs):
        typer.echo(f"{command}: --out is one of the inputs; nothing was written", err=True)
        raise typer.Exit(EXIT_NO_DECISION)


def _read_findings(path: Path, what: str) -> dict[str, Finding]:
    try:
        return parse_findings(path.read_bytes(), source=what)
    except (OSError, ReportError, UnicodeDecodeError) as exc:
        raise RemediationError(f"{what} {path}: {exc}") from exc


FindingsOption = Annotated[
    Path, typer.Option(help="Findings NDJSON (the scanner's IAC findings are the input).")
]
ProposalOut = Annotated[
    Path, typer.Option(help="Destination of the patch proposal (schemas/patch-proposal.v1.json).")
]
RepoRootOption = Annotated[Path, typer.Option(help="Repository root the finding paths are relative to.")]
AttemptOption = Annotated[int, typer.Option(min=1, max=3, help="Attempt number (1, then up to two retries).")]


def _propose(command: str, fixer: Any, findings: Path, out: Path, repo_root: Path, attempt: int) -> None:
    _refuse_input_as_output(out, [findings], f"sentinel remediate {command}")
    out.unlink(missing_ok=True)
    try:
        plan = fixer(
            list(_read_findings(findings, "findings").values()), repo_root, attempt=attempt, created_at=_now()
        )
    except RemediationError as exc:
        typer.echo(f"sentinel remediate {command}: {exc}", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    for path, reason in plan.skipped.items():
        typer.echo(f"warning: {path} left alone: {reason}", err=True)
    if plan.proposal is None:
        typer.echo("nothing to propose: no finding this fixer resolves")
        return
    _write_atomically(out, plan.proposal.model_dump_json(indent=2, exclude_none=True) + "\n")
    typer.echo(
        f"proposal {plan.proposal.proposal_id}: {len(plan.proposal.finding_ids)} finding(s) in "
        f"{len(plan.proposal.files)} file(s) -> {out}"
    )


@remediate_app.command("kubernetes")
def remediate_kubernetes(
    findings: FindingsOption,
    out: ProposalOut,
    repo_root: RepoRootOption = Path("."),
    attempt: AttemptOption = 1,
) -> None:
    """Propose hardening for the Kubernetes findings the deterministic fixer resolves (it never applies it).

    Exit code 0 with a proposal, or with nothing to propose (no file written); 3 when the input is unusable.
    """
    _propose("kubernetes", propose_kubernetes, findings, out, repo_root, attempt)


@remediate_app.command("dockerfile")
def remediate_dockerfile(
    findings: FindingsOption,
    out: ProposalOut,
    repo_root: RepoRootOption = Path("."),
    attempt: AttemptOption = 1,
) -> None:
    """Propose fixes for the Dockerfile findings the deterministic fixer resolves (it never applies them):
    a non-root USER, COPY instead of ADD for local files, apt-get --no-install-recommends.

    Exit code 0 with a proposal, or with nothing to propose (no file written); 3 when the input is unusable.
    """
    _propose("dockerfile", propose_dockerfile, findings, out, repo_root, attempt)


@remediate_app.command("apply")
def remediate_apply(
    proposal: Annotated[
        Path, typer.Option(help="The patch proposal to commit (schemas/patch-proposal.v1.json).")
    ],
    findings: Annotated[
        Path,
        typer.Option(help="Findings NDJSON of the base commit: the proposal may claim and edit only those."),
    ],
    repo_root: Annotated[Path, typer.Option(help="A local clone of the repository.")] = Path("."),
    base: Annotated[str, typer.Option(help="The commit the proposal was made against.")] = "HEAD",
    branch: Annotated[
        str | None, typer.Option(help="New branch name, under sentinel/fix/ (default: from the proposal id).")
    ] = None,
) -> None:
    """Commit a proposal on a new sentinel/fix/ branch of a local clone, and print it as JSON. It never
    pushes, never changes the working tree, the index or the current branch, and runs no hook, filter or
    fsmonitor the clone configures (nothing is checked out).

    Exit code 0 when committed; 3, with nothing created, when the proposal id does not match its content, it
    claims a finding the base scan does not have or edits a file none of its findings is in, or the diff does
    anything the proposal does not list (another file, a new, deleted, renamed or executable file) or does not
    apply to the base.
    """
    try:
        applied = apply_proposal(
            PatchProposal.model_validate_json(proposal.read_bytes()),
            repo_root,
            findings=list(_read_findings(findings, "base findings").values()),
            base=base,
            branch=branch,
        )
    except (OSError, ValidationError, RemediationError) as exc:
        typer.echo(f"sentinel remediate apply: {exc}\nnothing was committed", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    typer.echo(
        json.dumps({
            "branch": applied.branch, "commit": applied.commit, "base": applied.base,
            "diff_sha256": applied.diff_sha256,
        })
    )  # fmt: skip


@remediate_app.command("check")
def remediate_check(
    proposal: Annotated[Path, typer.Option(help="The patch proposal (schemas/patch-proposal.v1.json).")],
    base_root: Annotated[
        Path, typer.Option(help="The tree of the commit the proposal applies to (exported, not checked out).")
    ],
    patched_root: Annotated[
        Path, typer.Option(help="The tree of the patched commit (exported the same way).")
    ],
) -> None:
    """Build and test an infrastructure-as-code proposal for the verification gate, and print the result
    as JSON. Build: every edited file still parses into the same resources (a manifest's documents, a
    Dockerfile's stages). Tests: the patch changes only what its strategy may change. Their results are what
    `sentinel remediate verify` takes as --build-ok/--build-failed and --tests-ok/--tests-failed.

    Exit code 0 when both hold, 1 when one does not (the JSON says which file and why), 3 when they cannot
    be checked honestly (a strategy with no build or tests defined here, a file that is not a regular file
    of both trees, a base file this check cannot read): nothing is verified then.
    """
    try:
        applied = PatchProposal.model_validate_json(proposal.read_bytes())
        checked = check_iac(applied, base_root, patched_root)
    except (OSError, ValidationError, CheckError) as exc:
        typer.echo(f"sentinel remediate check: {exc}\nFAIL CLOSED: nothing is verified.", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    typer.echo(
        json.dumps({
            "proposal_id": applied.proposal_id, "strategy": applied.strategy, "build_ok": checked.build_ok,
            "tests_ok": checked.tests_ok, "problems": checked.problems,
        })
    )  # fmt: skip
    if not (checked.build_ok and checked.tests_ok):
        raise typer.Exit(EXIT_NOT_VERIFIED)


@remediate_app.command("verify")
def remediate_verify(
    proposal: Annotated[Path, typer.Option(help="The patch proposal that was applied.")],
    before: Annotated[Path, typer.Option(help="Findings NDJSON of the commit the patch applies to.")],
    after: Annotated[Path, typer.Option(help="Findings NDJSON of the patched commit (same scanners).")],
    decision: Annotated[Path, typer.Option(help="Decision v1 record of the patched commit.")],
    tool_status: Annotated[
        Path,
        typer.Option(
            "--tool-status",
            help="The tool status that decision recorded: every target's scanner must be in it, ok.",
        ),
    ],
    build: Annotated[bool, typer.Option("--build-ok/--build-failed", help="Did the patched commit build?")],
    tests: Annotated[bool, typer.Option("--tests-ok/--tests-failed", help="Did its tests pass?")],
    out: Annotated[
        Path, typer.Option(help="Destination of the result (schemas/verification-result.v1.json).")
    ],
    pull_request: Annotated[int | None, typer.Option(min=1, help="The bot's pull request number.")] = None,
) -> None:
    """Apply the verification gate: VERIFIED only if it builds, its tests pass, the target fingerprints are
    gone, no new finding of severity MEDIUM or higher appeared, and the decision is not BLOCK.

    Exit code 0 when VERIFIED, 1 when REJECTED or FAILED (the result is written either way), 3 when the inputs
    cannot be trusted (nothing is written): a proposal whose id does not match its content, that claims
    findings the base scan does not have or edits anything but where they are; a decision that was not made in
    pr context, on the patched findings, with this tool status; a tool status that does not show the scanner
    of every target ok (a scanner that never ran finds nothing, and nothing must not vouch for the patch).
    """
    _refuse_input_as_output(
        out, [proposal, before, after, decision, tool_status], "sentinel remediate verify"
    )
    out.unlink(missing_ok=True)
    try:
        applied = PatchProposal.model_validate_json(proposal.read_bytes())
        record = Decision.model_validate_json(decision.read_bytes())
        after_data = after.read_bytes()
        if record.inputs.findings_digest != "sha256:" + hashlib.sha256(after_data).hexdigest():
            raise RemediationError("the decision was not made on the patched findings (--after)")
        if record.subject.context != "pr" or record.inputs.tool_status_digest is None:
            raise RemediationError(
                "the decision must be a pr-context decision that saw the tool status (a scan that failed "
                "must not vouch for the patch)"
            )
        status_data = tool_status.read_bytes()
        if record.inputs.tool_status_digest != "sha256:" + hashlib.sha256(status_data).hexdigest():
            raise RemediationError("the tool status is not the one the decision recorded (--tool-status)")
        statuses = load_tool_status(status_data)["tools"]
        base_findings = _read_findings(before, "base findings")
        check_proposal(applied, base_findings)
        for scanner in sorted({base_findings[finding_id].tool.name for finding_id in applied.finding_ids}):
            if statuses.get(scanner, {}).get("status") != "ok":
                raise RemediationError(
                    f"the tool status does not show {scanner} ok: the patched scan's silence about its "
                    "targets proves nothing"
                )
        result = verify_proposal(
            applied,
            before=base_findings,
            after=_read_findings(after, "patched findings"),
            build_ok=build,
            tests_ok=tests,
            verdict=record.verdict,
            verified_at=_now(),
            pull_request=pull_request,
        )
    except (OSError, ValidationError, RemediationError, EvaluationError) as exc:
        typer.echo(f"sentinel remediate verify: {exc}\nFAIL CLOSED: nothing is verified.", err=True)
        raise typer.Exit(EXIT_NO_DECISION) from exc
    _write_atomically(out, result.model_dump_json(indent=2, exclude_none=True) + "\n")
    reasons = [
        name
        for name, ok in (
            ("the build failed", result.build_ok),
            ("tests failed", result.tests_ok),
            ("a target finding is still reported", result.target_resolved),
            (
                f"{len(result.new_findings)} new finding(s) of severity MEDIUM or higher",
                not result.new_findings,
            ),
            ("the decision is BLOCK", result.verdict != "BLOCK"),
        )
        if not ok
    ]
    typer.echo(
        f"{result.outcome} (attempt {result.attempt})" + (f": {'; '.join(reasons)}" if reasons else "")
    )
    if result.outcome != "VERIFIED":
        raise typer.Exit(EXIT_NOT_VERIFIED)


if __name__ == "__main__":
    app()
