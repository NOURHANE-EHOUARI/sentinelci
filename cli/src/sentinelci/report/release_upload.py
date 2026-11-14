"""`sentinel upload-release`: send one release's evidence to the platform (tasks A4 and A8, `POST
/api/v1/releases`), for the Releases & evidence page.

A report, like `sentinel upload`: the release was decided, signed and verified before, and an upload that
fails changes none of it (exit code 4). The same rules hold: the token only from `SENTINEL_API_TOKEN`, https
or the loopback only, no redirect, nothing secret in an error (`report.upload`).

The document is Release evidence v1 (schemas/release-evidence.v1.json): the release decision as `sentinel
evaluate` wrote it, and the trust reports `sentinel verify --report-json` wrote (none for a BLOCK). It is
checked here as the platform checks it, so a document the platform would refuse is never sent, and the same
files always give the same bytes: sending them again is answered "recorded already" (409 with the same
sha256), which counts as uploaded. Other evidence for a decision the platform holds is refused: a release
never changes.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sentinelci.contracts.release import ReleaseEvidence
from sentinelci.report.upload import Platform, UploadError, _why
from sentinelci.supplychain.attestations import contract_errors


@dataclass(frozen=True)
class UploadedRelease:
    decision_id: str
    image_digest: str
    sha256: str
    already_recorded: bool = False


def _object(data: bytes, what: str) -> Any:
    try:
        return json.loads(data)
    except ValueError as exc:
        raise UploadError(f"{what} is not JSON: {exc}") from exc


def release_evidence(decision: bytes, reports: Sequence[bytes]) -> bytes:
    """The Release evidence v1 bytes of a decision and its trust reports (registry mode first), checked as the
    platform checks them."""
    trust_reports = [_object(report, "a trust report") for report in reports]
    trust_reports.sort(key=lambda report: str(report.get("mode")) if isinstance(report, dict) else "")
    trust_reports.reverse()  # "registry" before "evidence": what Kyverno checks comes first
    document = {
        "schema_version": "1.0",
        "decision": _object(decision, "the decision"),
        "trust_reports": trust_reports,
    }
    data = (json.dumps(document, indent=2) + "\n").encode()
    try:
        evidence = ReleaseEvidence.model_validate_json(data)
    except ValidationError as exc:
        raise UploadError(f"not release evidence v1: {contract_errors(exc)}") from exc
    if (problem := evidence.problem()) is not None:
        raise UploadError(f"inconsistent release evidence: {problem}")
    return data


def upload_release(data: bytes, platform: Platform) -> UploadedRelease:
    """Record `data` (from `release_evidence`) on the platform; UploadError when it was not recorded."""
    evidence = ReleaseEvidence.model_validate_json(data)
    decision_id, digest = str(evidence.decision.decision_id), hashlib.sha256(data).hexdigest()
    status, body = platform.post_release(data)
    if status == 201 and isinstance(body, dict):
        if body.get("sha256") != digest or body.get("decision_id") != decision_id:
            raise UploadError(f"release {decision_id}: the platform recorded other bytes than the ones sent")
        return UploadedRelease(decision_id, evidence.image_digest, digest)
    recorded = body.get("release") if status == 409 and isinstance(body, dict) else None
    if isinstance(recorded, dict) and recorded.get("decision_id") == decision_id:
        if recorded.get("sha256") != digest:
            raise UploadError(
                f"release {decision_id} is recorded already with other evidence: a release never changes"
            )
        return UploadedRelease(decision_id, evidence.image_digest, digest, already_recorded=True)
    raise UploadError(f"recording release {decision_id} failed: {_why(status, body)}")
