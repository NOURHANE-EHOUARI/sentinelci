"""The verification gate (SPEC §9): a patch is VERIFIED only when every condition holds.

build OK · tests pass · every target gone · no new finding of severity MEDIUM or higher · verdict is not
BLOCK. The inputs are the findings of the base and of the patched commit (Finding v1 NDJSON, the same
scanners), and the decision of the patched commit. A patch that fails is REJECTED while a retry is left (at
most three attempts), FAILED after the last one.

- "Gone" is not just "its fingerprint is gone": a target is still there when the patched scan reports a new
  fingerprint of the same tool and rule in one of the target's files (a renamed container, a moved line).
- "New" includes a base finding whose severity rose to MEDIUM or higher.
- `check_proposal` refuses (exit 3) a proposal that could never be verified honestly: an id that does not
  match its content, findings the base scan does not have, a file none of its findings is in, or a diff that
  does more than edit those files in place.
"""

import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import MAX_ATTEMPTS, Outcome, PatchProposal, VerificationResult
from sentinelci.remediation.proposal import RemediationError, proposal_id_of

_RANK = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
NEW_FINDING_FLOOR = "MEDIUM"
_DIFF_HEADER = re.compile(r"diff --git a/(\S+) b/(\S+)")
_HUNK = re.compile(r"@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@.*")


def paths_of(finding: Finding) -> set[str]:
    """Every file a finding was seen in: its location and other locations."""
    places = [finding.location, *(finding.other_locations or [])]
    return {place.path for place in places if place is not None}


def diff_paths(diff: str) -> list[str]:
    """The files a diff edits in place, or RemediationError when it does anything else (creates, deletes,
    renames, copies, changes a mode, holds a binary patch, or names a path outside the repository)."""
    paths: list[str] = []
    in_header = False
    for line in diff.splitlines():
        header = _DIFF_HEADER.fullmatch(line)
        if header is not None:
            if header[1] != header[2]:
                raise RemediationError(f"the diff renames or copies {header[1]}")
            paths.append(header[1])
            in_header = True
        elif in_header and _HUNK.fullmatch(line):
            in_header = False
        elif in_header:
            if line.startswith("index ") or line in (f"--- a/{paths[-1]}", f"+++ b/{paths[-1]}"):
                continue
            raise RemediationError(f"the diff does more than edit {paths[-1]} in place: {line[:80]!r}")
        elif not paths or (line[:1] not in (" ", "+", "-", "\\") and not _HUNK.fullmatch(line)):
            raise RemediationError(f"the diff is not a plain edit of its files: {line[:80]!r}")
    for path in paths:
        if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise RemediationError(f"the diff names a path outside the repository: {path}")
    if not paths or len(set(paths)) != len(paths):
        raise RemediationError("the diff must edit each of its files once")
    return paths


def check_proposal(proposal: PatchProposal, before: Mapping[str, Finding]) -> None:
    """RemediationError unless the proposal is what its id says, claims findings of the base scan, and its
    diff edits, in place, exactly its files, each a file where one of those findings was found."""
    expected = proposal_id_of(proposal.strategy, proposal.attempt, proposal.finding_ids, proposal.diff)
    if proposal.proposal_id != expected:
        raise RemediationError("the proposal id does not match its strategy, attempt, findings and diff")
    unknown = sorted(set(proposal.finding_ids) - set(before))
    if unknown:
        raise RemediationError(f"the proposal claims findings the base scan does not have: {unknown[0]}")
    edited = diff_paths(proposal.diff)
    if set(edited) != set(proposal.files):
        listed = sorted(proposal.files)
        raise RemediationError(f"the diff edits {sorted(edited)}; the proposal lists {listed}")
    places = set().union(*(paths_of(before[finding_id]) for finding_id in proposal.finding_ids))
    outside = sorted(set(proposal.files) - places)
    if outside:
        raise RemediationError(f"the proposal changes {outside[0]}, where none of its findings was found")


def _still_there(target: Finding, after: Mapping[str, Finding], before: Mapping[str, Finding]) -> bool:
    """The target's fingerprint, or a new fingerprint of the same tool and rule in one of its files."""
    if target.id in after:
        return True
    files = paths_of(target)
    return any(
        finding.id not in before
        and (finding.tool.name, finding.rule_id) == (target.tool.name, target.rule_id)
        and paths_of(finding) & files
        for finding in after.values()
    )


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
    target_resolved = not any(
        finding_id in after or (finding_id in before and _still_there(before[finding_id], after, before))
        for finding_id in proposal.finding_ids
    )
    floor = _RANK.index(NEW_FINDING_FLOOR)
    new_findings = sorted(
        finding_id
        for finding_id, finding in after.items()
        if _RANK.index(finding.severity) >= floor
        and (
            finding_id not in before
            or _RANK.index(finding.severity) > _RANK.index(before[finding_id].severity)  # it got worse
        )
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
