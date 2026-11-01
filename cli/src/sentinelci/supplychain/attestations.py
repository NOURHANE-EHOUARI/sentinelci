"""The four release attestations of an image and the bindings between them (ADR-0010, task A4).

`release_predicates` builds the predicates `sentinel attest` signs, after checking that the decision, the
findings and the SBOM belong together and to the image. Nothing here reads the clock or the network: the same
inputs give the same predicates.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from sentinelci.contracts.decision import Decision
from sentinelci.report.pr_comment import ReportError, parse_findings

DECISION_TYPE = "https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1"
SBOM_TYPE = "https://cyclonedx.org/bom"
VULN_TYPE = "https://cosign.sigstore.dev/attestation/vuln/v1"
PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
KINDS: dict[str, str] = {
    "decision": DECISION_TYPE,
    "sbom": SBOM_TYPE,
    "vuln": VULN_TYPE,
    "provenance": PROVENANCE_TYPE,
}
GITHUB_ACTIONS_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
GITHUB = "https://github.com"
ENGINE_PURL = "pkg:github/NOURHANE-EHOUARI/sentinelci"

_IMAGE = re.compile(r"(?P<name>[a-z0-9][a-z0-9._/:-]{0,254})@sha256:(?P<hex>[a-f0-9]{64})")
_SERIAL = re.compile(r"urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_WORKFLOW_REF = re.compile(
    r"(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?P<path>\.github/workflows/[^@\s]+)@(?P<ref>\S+)"
)
_DIGITS = re.compile(r"[0-9]{1,20}")


class AttestationError(Exception):
    """The inputs cannot be attested (or verified) as one release: nothing is signed (exit 3)."""


@dataclass(frozen=True)
class Image:
    name: str
    digest_hex: str

    @property
    def digest(self) -> str:
        return f"sha256:{self.digest_hex}"


def parse_image(reference: str) -> Image:
    """`<name>@sha256:<64 hex>`: a digest, never a tag alone (SPEC section 7: sign digests, never tags)."""
    match = _IMAGE.fullmatch(reference)
    if match is None:
        raise AttestationError(f"{reference!r} is not <name>@sha256:<64 lowercase hex>")
    return Image(name=match["name"], digest_hex=match["hex"])


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SbomRef(_Strict):
    digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    serial_number: str = Field(pattern=r"^urn:uuid:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


_LINE_BREAKS = frozenset("\r\n\u2028\u2029")


def _one_line(value: str) -> str:
    if _LINE_BREAKS.intersection(value):
        raise ValueError("must be a single line")
    return value


# Each listed severity or category occurs at least once (the schema's positive_count).
PositiveCount = Annotated[int, Field(ge=1)]
ToolName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
ToolVersion = Annotated[str, Field(min_length=1), AfterValidator(_one_line)]


class Totals(_Strict):
    findings: int = Field(ge=0)
    by_severity: dict[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], PositiveCount]
    by_category: dict[
        Literal["SECRET", "SAST", "SCA", "CONTAINER", "IAC", "PIPELINE", "LICENSE"], PositiveCount
    ]


class VulnResult(_Strict):
    """`schemas/vuln-result.v1.json` as a read model. The contract fixtures pin the two together: every valid
    fixture is accepted here and every invalid one refused. The only extra rule is `problem()`, the sums JSON
    Schema cannot express. (A JSON number such as `3.0` is an integer to JSON Schema but refused here: the
    producer never writes one, and refusing errs on the safe side.)"""

    schema_version: Literal["1.0"]
    decision_id: str = Field(pattern=r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
    findings_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    sbom: SbomRef
    totals: Totals
    tools: dict[ToolName, ToolVersion] = Field(min_length=1)

    def problem(self) -> str | None:
        """Why the totals do not add up, or None: each map must sum to `totals.findings`."""
        for name, counts in (
            ("by_severity", self.totals.by_severity),
            ("by_category", self.totals.by_category),
        ):
            total = sum(counts.values())
            if total != self.totals.findings:
                return f"totals.{name} adds up to {total}, not totals.findings ({self.totals.findings})"
        return None


def contract_errors(exc: ValidationError, *, limit: int = 3) -> str:
    """The first validation errors as `field.path: message`, for a one-line reason."""
    errors = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"])
        errors.append(f"{where}: {error['msg']}" if where else error["msg"])
    more = f" (and {len(errors) - limit} more)" if len(errors) > limit else ""
    return "; ".join(errors[:limit]) + more


def load_decision(data: bytes, *, source: str = "decision") -> Decision:
    try:
        return Decision.model_validate_json(data)
    except ValidationError as exc:
        raise AttestationError(f"{source} is not a Decision v1: {exc.error_count()} error(s)") from exc


def release_decision(data: bytes, image: Image) -> Decision:
    """The decision may be attested for this image: a release decision about it, not BLOCK."""
    decision = load_decision(data)
    if decision.subject.context != "release":
        raise AttestationError(f"the decision is for context {decision.subject.context!r}, not 'release'")
    if decision.verdict == "BLOCK":
        raise AttestationError("the decision is BLOCK: a blocked image is never signed")
    if decision.subject.image_digest != image.digest:
        raise AttestationError(
            f"the decision is about image {decision.subject.image_digest}, not {image.digest}"
        )
    return decision


def sbom_serial_number(document: Any) -> str:
    """The CycloneDX serialNumber of an SBOM: it binds the signed SBOM to the vulnerability result."""
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise AttestationError("the SBOM is not a CycloneDX JSON document")
    serial = document.get("serialNumber")
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        raise AttestationError("the SBOM has no CycloneDX serialNumber (urn:uuid:...)")
    return serial


def vuln_result(decision: Decision, findings_data: bytes, sbom_data: bytes) -> dict[str, Any]:
    """The SentinelCI summary of the findings the decision evaluated, bound to the decision and the SBOM."""
    if sha256_digest(findings_data) != decision.inputs.findings_digest:
        raise AttestationError("the findings file is not the one the decision recorded (findings_digest)")
    if decision.inputs.sbom_digest is None:
        raise AttestationError("the decision records no SBOM (inputs.sbom_digest): a release needs one")
    if sha256_digest(sbom_data) != decision.inputs.sbom_digest:
        raise AttestationError("the SBOM file is not the one the decision recorded (sbom_digest)")
    try:
        findings = parse_findings(findings_data, source="findings")
        sbom = json.loads(sbom_data)
    except (ReportError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError(str(exc)) from exc
    severities = Counter(finding.severity for finding in findings.values())
    categories = Counter(finding.category for finding in findings.values())
    result = {
        "schema_version": "1.0",
        "decision_id": decision.decision_id,
        "findings_digest": decision.inputs.findings_digest,
        "sbom": {"digest": decision.inputs.sbom_digest, "serial_number": sbom_serial_number(sbom)},
        "totals": {
            "findings": len(findings),
            "by_severity": dict(sorted(severities.items())),
            "by_category": dict(sorted(categories.items())),
        },
        "tools": dict(sorted(decision.inputs.tool_versions.items())),
    }
    # The producer never signs what the contract, or `sentinel verify`, would refuse.
    try:
        problem = VulnResult.model_validate_json(json.dumps(result)).problem()
    except ValidationError as exc:
        raise AttestationError(
            f"the decision's inputs give a vulnerability result the contract refuses: {contract_errors(exc)}"
        ) from exc
    if problem is not None:
        raise AttestationError(f"the vulnerability result would be inconsistent: {problem}")
    return result


@dataclass(frozen=True)
class WorkflowRun:
    """What the provenance says about the run, from the GitHub Actions environment of the attest job."""

    repository: str
    commit: str
    ref: str
    workflow_path: str
    workflow_ref: str
    run_id: str
    run_attempt: str
    event_name: str
    repository_id: str
    repository_owner_id: str
    runner_environment: str

    @property
    def builder_id(self) -> str:
        return f"{GITHUB}/{self.repository}/{self.workflow_path}@{self.workflow_ref}"

    @property
    def invocation_id(self) -> str:
        return f"{GITHUB}/{self.repository}/actions/runs/{self.run_id}/attempts/{self.run_attempt}"


def workflow_run(env: Mapping[str, str]) -> WorkflowRun:
    """Read the run from GitHub Actions variables; anything missing or malformed refuses the provenance."""
    if env.get("GITHUB_ACTIONS") != "true":
        raise AttestationError("provenance is written in GitHub Actions only (GITHUB_ACTIONS is not 'true')")
    if env.get("GITHUB_SERVER_URL", GITHUB) != GITHUB:
        raise AttestationError("provenance is written for github.com only")
    workflow = _WORKFLOW_REF.fullmatch(env.get("GITHUB_WORKFLOW_REF", ""))
    if workflow is None:
        raise AttestationError("GITHUB_WORKFLOW_REF is not <owner>/<repo>/.github/workflows/<file>@<ref>")
    values = {
        "repository": env.get("GITHUB_REPOSITORY", ""),
        "commit": env.get("GITHUB_SHA", ""),
        "ref": env.get("GITHUB_REF", ""),
        "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "event_name": env.get("GITHUB_EVENT_NAME", ""),
        "repository_id": env.get("GITHUB_REPOSITORY_ID", ""),
        "repository_owner_id": env.get("GITHUB_REPOSITORY_OWNER_ID", ""),
        "runner_environment": env.get("RUNNER_ENVIRONMENT", ""),
    }
    checks = {
        "GITHUB_REPOSITORY": _REPO.fullmatch(values["repository"]),
        "GITHUB_SHA": re.fullmatch(r"[a-f0-9]{40}", values["commit"]),
        "GITHUB_REF": re.fullmatch(r"refs/(heads|tags)/[^\s]+", values["ref"]),
        "GITHUB_RUN_ID": _DIGITS.fullmatch(values["run_id"]),
        "GITHUB_RUN_ATTEMPT": _DIGITS.fullmatch(values["run_attempt"]),
        "GITHUB_EVENT_NAME": re.fullmatch(r"[a-z_]{1,64}", values["event_name"]),
        "GITHUB_REPOSITORY_ID": _DIGITS.fullmatch(values["repository_id"]),
        "GITHUB_REPOSITORY_OWNER_ID": _DIGITS.fullmatch(values["repository_owner_id"]),
        "RUNNER_ENVIRONMENT": re.fullmatch(r"github-hosted|self-hosted", values["runner_environment"]),
    }
    missing = sorted(name for name, ok in checks.items() if not ok)
    if missing:
        raise AttestationError(f"missing or malformed GitHub Actions variables: {', '.join(missing)}")
    return WorkflowRun(workflow_path=workflow["path"], workflow_ref=workflow["ref"], **values)


def provenance(run: WorkflowRun, decision: Decision) -> dict[str, Any]:
    """SLSA v1 provenance of a release built by this workflow run from the decision's source commit."""
    if (run.repository, run.commit) != (decision.subject.repo, decision.subject.commit):
        raise AttestationError(
            f"the workflow ran on {run.repository}@{run.commit[:12]}, but the decision is about "
            f"{decision.subject.repo}@{decision.subject.commit[:12]}"
        )
    return {
        "buildDefinition": {
            "buildType": GITHUB_ACTIONS_BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "ref": run.workflow_ref,
                    "repository": f"{GITHUB}/{run.repository}",
                    "path": run.workflow_path,
                }
            },
            "internalParameters": {
                "github": {
                    "event_name": run.event_name,
                    "repository_id": run.repository_id,
                    "repository_owner_id": run.repository_owner_id,
                    "runner_environment": run.runner_environment,
                }
            },
            "resolvedDependencies": [
                {"uri": f"git+{GITHUB}/{run.repository}@{run.ref}", "digest": {"gitCommit": run.commit}}
            ],
        },
        "runDetails": {
            "builder": {"id": run.builder_id},
            "metadata": {"invocationId": run.invocation_id},
        },
    }


def vuln_predicate(decision: Decision, result: dict[str, Any], run: WorkflowRun) -> dict[str, Any]:
    """Cosign's vulnerability predicate around the SentinelCI result. Its times are the decision's."""
    return {
        "invocation": {
            "parameters": [],
            "uri": run.invocation_id,
            "event_id": run.run_id,
            "builder.id": run.builder_id,
        },
        "scanner": {
            "uri": f"{ENGINE_PURL}@{decision.engine_version}",
            "version": decision.engine_version,
            "db": {
                "uri": "sentinelci:enrichment-snapshot",
                "version": decision.inputs.enrichment_snapshot_digest,
            },
            "result": result,
        },
        "metadata": {"scanStartedOn": decision.evaluated_at, "scanFinishedOn": decision.evaluated_at},
    }


def release_predicates(
    image: Image,
    *,
    decision_data: bytes,
    findings_data: bytes,
    sbom_data: bytes,
    env: Mapping[str, str],
) -> dict[str, Any]:
    """The four predicates to sign for `image`, keyed by kind. Raises AttestationError when they don't belong
    together: a BLOCK or non-release decision, a decision about another image, findings or an SBOM that the
    decision did not record, or a workflow run on another repository or commit."""
    decision = release_decision(decision_data, image)
    result = vuln_result(decision, findings_data, sbom_data)
    run = workflow_run(env)
    predicates = {
        "decision": json.loads(decision_data),
        "sbom": json.loads(sbom_data),
        "vuln": vuln_predicate(decision, result, run),
        "provenance": provenance(run, decision),
    }
    return predicates
