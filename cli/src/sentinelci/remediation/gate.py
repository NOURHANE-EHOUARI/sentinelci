"""The verification gate (SPEC §9): a patch is VERIFIED only when every condition holds.

build OK · tests pass · every target fingerprint gone · no new finding of severity MEDIUM or higher · verdict
is not BLOCK. The inputs are the findings of the base and of the patched commit (Finding v1 NDJSON, the same
scanners), and the decision of the patched commit. A patch that fails is REJECTED while a retry is left (at
most three attempts), FAILED after the last one."""

from collections.abc import Mapping
from datetime import datetime
from typing import Literal

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import MAX_ATTEMPTS, Outcome, PatchProposal, VerificationResult

_RANK = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
NEW_FINDING_FLOOR = "MEDIUM"


def verify_proposal(
    proposal: PatchProposal,
    *,
    before: Mapping[str, Finding],
    after: Mapping[str, Finding],
    build_ok: bool,
    tests_ok: bool,
    verdict: Literal["PASS", "WARN", "BLOCK"],
    verified_at: datetime,
    pull_request: int | None = None,
) -> VerificationResult:
    target_resolved = not any(finding_id in after for finding_id in proposal.finding_ids)
    floor = _RANK.index(NEW_FINDING_FLOOR)
    new_findings = sorted(
        finding_id
        for finding_id, finding in after.items()
        if finding_id not in before and _RANK.index(finding.severity) >= floor
    )
    verified = build_ok and tests_ok and target_resolved and not new_findings and verdict != "BLOCK"
    outcome: Outcome = "VERIFIED" if verified else "REJECTED" if proposal.attempt < MAX_ATTEMPTS else "FAILED"
    return VerificationResult(
        schema_version="1.0",
        proposal_id=proposal.proposal_id,
        attempt=proposal.attempt,
        build_ok=build_ok,
        tests_ok=tests_ok,
        target_resolved=target_resolved,
        new_findings=new_findings,
        verdict=verdict,
        outcome=outcome,
        pull_request=pull_request,
        verified_at=verified_at,
    )
