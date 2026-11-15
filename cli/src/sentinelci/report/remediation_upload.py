"""`sentinel upload-remediation`: send one attempt of the remediation loop to the platform (tasks A6 and A8,
`POST /api/v1/remediations`), for the Remediation page and `sentinel_remediation_attempts_total`.

A report, like `sentinel upload`: the attempt was proposed, verified and reported before, and an upload that
fails changes none of it (exit code 4). The same rules hold: the token only from `SENTINEL_API_TOKEN`, https
or the loopback only, no redirect, nothing secret in an error (`report.upload`).

The document is Remediation attempt v1 (schemas/remediation-attempt.v1.json): the patch proposal, its
verification result, and the repository. It is checked here as the platform checks it (the verification gate
included), so a document the platform would refuse is never sent, and the same files always give the same
bytes: sending them again is answered "recorded already" (409 with the same sha256), which counts as
uploaded. Another document for a recorded proposal is refused: an attempt never changes.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sentinelci.contracts.remediation import RemediationAttempt
from sentinelci.report.upload import Platform, UploadError, _why
from sentinelci.supplychain.attestations import contract_errors


@dataclass(frozen=True)
class UploadedAttempt:
    proposal_id: str
    outcome: str
    sha256: str
    already_recorded: bool = False


def _object(data: bytes, what: str) -> Any:
    try:
        return json.loads(data)
    except ValueError as exc:
        raise UploadError(f"{what} is not JSON: {exc}") from exc


def remediation_attempt(proposal: bytes, result: bytes, *, repo: str) -> bytes:
    """The Remediation attempt v1 bytes of a proposal and its result, checked as the platform checks them."""
    document = {
        "schema_version": "1.0",
        "repo": repo,
        "proposal": _object(proposal, "the proposal"),
        "result": _object(result, "the result"),
    }
    data = (json.dumps(document, indent=2) + "\n").encode()
    try:
        attempt = RemediationAttempt.model_validate_json(data)
    except ValidationError as exc:
        raise UploadError(f"not a remediation attempt v1: {contract_errors(exc)}") from exc
    if (problem := attempt.problem()) is not None:
        raise UploadError(f"inconsistent remediation attempt: {problem}")
    return data


def upload_remediation(data: bytes, platform: Platform) -> UploadedAttempt:
    """Record `data` (from `remediation_attempt`) on the platform; UploadError when it was not recorded."""
    attempt = RemediationAttempt.model_validate_json(data)
    proposal_id, digest = attempt.proposal.proposal_id.lower(), hashlib.sha256(data).hexdigest()
    outcome = attempt.result.outcome
    status, body = platform.post_remediation(data)
    if status == 201 and isinstance(body, dict):
        if body.get("sha256") != digest or str(body.get("proposal_id", "")).lower() != proposal_id:
            raise UploadError(f"attempt {proposal_id}: the platform recorded other bytes than the ones sent")
        return UploadedAttempt(proposal_id, outcome, digest)
    recorded = body.get("remediation") if status == 409 and isinstance(body, dict) else None
    if isinstance(recorded, dict) and str(recorded.get("proposal_id", "")).lower() == proposal_id:
        if recorded.get("sha256") != digest:
            raise UploadError(
                f"attempt {proposal_id} is recorded already with another document: it never changes"
            )
        return UploadedAttempt(proposal_id, outcome, digest, already_recorded=True)
    raise UploadError(f"recording attempt {proposal_id} failed: {_why(status, body)}")
