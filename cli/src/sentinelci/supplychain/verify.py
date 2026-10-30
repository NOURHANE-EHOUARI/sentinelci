"""`sentinel verify`: is this image backed by a signed, non-BLOCK release decision? (ADR-0010, task A4).

`trust_checks` turns the four verified predicates into one check per rule; the image is trusted only if every
check passes. A check that cannot be evaluated (its attestation is missing or malformed) fails: fail closed.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinelci.contracts.decision import Decision
from sentinelci.supplychain.attestations import (
    GITHUB,
    KINDS,
    AttestationError,
    Image,
    VulnResult,
    load_decision,
)
from sentinelci.supplychain.cosign import Verified, Verifier

ATTESTATIONS_DIR = "attestations"
LABELS = {
    "decision": "release decision",
    "sbom": "SBOM (CycloneDX)",
    "vuln": "vulnerability scan",
    "provenance": "provenance (SLSA v1)",
}


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class TrustReport:
    image: Image
    checks: tuple[Check, ...]

    @property
    def trusted(self) -> bool:
        return bool(self.checks) and all(check.ok for check in self.checks)

    def render(self) -> str:
        lines = [f"sentinel verify {self.image.name}@{self.image.digest}"]
        lines += [f"  [{'ok' if c.ok else 'FAIL'}] {c.name}: {c.detail}" for c in self.checks]
        verdict = "TRUSTED" if self.trusted else "NOT TRUSTED"
        failed = sum(1 for c in self.checks if not c.ok)
        lines.append(f"{verdict}: {len(self.checks) - failed}/{len(self.checks)} checks passed")
        return "\n".join(lines) + "\n"


def _decision(predicate: Any) -> tuple[Decision | None, str]:
    if predicate is None:
        return None, "no verified decision attestation"
    try:
        return load_decision(json.dumps(predicate).encode(), source="the decision attestation"), ""
    except AttestationError as exc:
        return None, str(exc)


def _vuln(predicate: Any) -> tuple[VulnResult | None, str]:
    if predicate is None:
        return None, "no verified vulnerability attestation"
    result = predicate.get("scanner", {}).get("result") if isinstance(predicate, dict) else None
    try:
        parsed = VulnResult.model_validate_json(json.dumps(result))
    except (ValidationError, TypeError) as exc:
        return None, f"scanner.result is not a vuln-result v1: {exc}"[:300]
    if not parsed.consistent():
        return None, "scanner.result totals do not add up"
    return parsed, ""


def _source(predicate: Any, repo: str) -> list[tuple[str, Any]]:
    """(uri, gitCommit) of the provenance's source dependencies in `repo`."""
    try:
        dependencies = predicate["buildDefinition"]["resolvedDependencies"]
        return [
            (dep["uri"], dep.get("digest", {}).get("gitCommit"))
            for dep in dependencies
            if isinstance(dep, dict) and str(dep.get("uri", "")).startswith(f"git+{GITHUB}/{repo}@")
        ]
    except (KeyError, TypeError):
        return []


def _builder(predicate: Any) -> Any:
    try:
        return predicate["runDetails"]["builder"]["id"]
    except (KeyError, TypeError):
        return None


DECISION_CHECKS = (
    "decision: valid Decision v1",
    "decision: release context",
    "decision: verdict is not BLOCK",
    "decision: about this image",
    "decision: from the expected repository",
)
PROVENANCE_CHECKS = (
    "provenance: built by the expected workflow",
    "provenance: built from the decision's commit",
)
VULN_CHECKS = (
    "vulnerability scan: names this decision",
    "vulnerability scan: the decision's findings",
    "vulnerability scan: the decision's SBOM",
)
SBOM_CHECK = "SBOM: the one the vulnerability scan names"


def _unavailable(names: tuple[str, ...], reason: str) -> list[Check]:
    return [Check(name, False, reason) for name in names]


def trust_checks(
    image: Image, verified: Mapping[str, Verified], *, repo: str, builder_id: str
) -> tuple[Check, ...]:
    """Every check of ADR-0010, in a fixed order. `verified` holds the outcome of each signature check; a
    check whose attestation is missing or malformed fails with the reason."""
    outcomes = {kind: verified.get(kind, Verified(None, "not checked")) for kind in KINDS}
    checks = [
        Check(f"signature: {LABELS[kind]}", outcome.problem is None, outcome.problem or "signed by the key")
        for kind, outcome in outcomes.items()
    ]
    decision, why_decision = _decision(outcomes["decision"].predicate)
    result, why_result = _vuln(outcomes["vuln"].predicate)
    provenance = outcomes["provenance"].predicate
    sbom = outcomes["sbom"].predicate

    if decision is None:
        checks += _unavailable(DECISION_CHECKS, why_decision)
    else:
        subject = decision.subject
        checks += [
            Check(DECISION_CHECKS[0], True, f"{decision.decision_id} (schema {decision.schema_version})"),
            Check(DECISION_CHECKS[1], subject.context == "release", f"context {subject.context}"),
            Check(DECISION_CHECKS[2], decision.verdict != "BLOCK", f"verdict {decision.verdict}"),
            Check(DECISION_CHECKS[3], subject.image_digest == image.digest, f"image {subject.image_digest}"),
            Check(DECISION_CHECKS[4], subject.repo == repo, f"repository {subject.repo}"),
        ]

    if provenance is None:
        checks += _unavailable(PROVENANCE_CHECKS, "no verified provenance attestation")
    else:
        builder = _builder(provenance)
        sources = _source(provenance, repo)
        commits = sorted({str(commit) for _, commit in sources})
        where = f"{', '.join(sorted(uri for uri, _ in sources)) or 'no source in ' + repo} at {commits}"
        checks += [
            Check(PROVENANCE_CHECKS[0], builder == builder_id, f"builder {builder}"),
            Check(
                PROVENANCE_CHECKS[1],
                decision is not None and commits == [decision.subject.commit],
                where if decision is not None else f"{where}; {why_decision}",
            ),
        ]

    if result is None or decision is None:
        checks += _unavailable(VULN_CHECKS, why_result if result is None else why_decision)
    else:
        checks += [
            Check(
                VULN_CHECKS[0], result.decision_id == decision.decision_id, f"decision {result.decision_id}"
            ),
            Check(
                VULN_CHECKS[1],
                result.findings_digest == decision.inputs.findings_digest,
                f"findings {result.findings_digest}",
            ),
            Check(
                VULN_CHECKS[2],
                result.sbom.digest == decision.inputs.sbom_digest,
                f"SBOM {result.sbom.digest}",
            ),
        ]

    if sbom is None or result is None:
        checks += _unavailable((SBOM_CHECK,), "no verified SBOM attestation" if sbom is None else why_result)
    else:
        serial = sbom.get("serialNumber") if isinstance(sbom, dict) else None
        cyclonedx = isinstance(sbom, dict) and sbom.get("bomFormat") == "CycloneDX"
        checks.append(
            Check(
                SBOM_CHECK,
                cyclonedx and serial == result.sbom.serial_number,
                f"CycloneDX {cyclonedx}, serialNumber {serial}",
            )
        )
    return tuple(checks)


def verify_evidence(
    image: Image, evidence: Path, verifier: Verifier, *, repo: str, builder_id: str
) -> TrustReport:
    """Verify the four Sigstore bundles under `<evidence>/attestations/` against `image`, offline."""
    directory = evidence / ATTESTATIONS_DIR
    verified = {
        kind: verifier.verify(directory / f"{kind}.sigstore.json", image, predicate_type)
        for kind, predicate_type in KINDS.items()
    }
    return TrustReport(image, trust_checks(image, verified, repo=repo, builder_id=builder_id))
