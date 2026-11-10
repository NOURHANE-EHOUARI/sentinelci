"""Building a `PatchProposal` (schemas/patch-proposal.v1.json): the diff, its id, and the checks the contract
asks for (every touched file is a file the findings flag; the diff applies with `git apply`)."""

import difflib
import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime

from sentinelci.contracts.remediation import PatchProposal, Strategy

# Fixed namespace: the same proposal (strategy, attempt, findings, diff) always gets the same id.
_NAMESPACE = uuid.UUID("5e1c0a2e-6a6b-4b0e-9a8d-3c2f1e0d9b7a")


class RemediationError(Exception):
    """A proposal or a verification that cannot be made (fail closed: nothing is proposed or verified)."""


def proposal_id_of(strategy: str, attempt: int, finding_ids: Sequence[str], diff: str) -> str:
    """The id of a proposal: a UUID of its strategy, attempt, findings and diff. Anyone can recompute it, so
    the id identifies the content (the gate and the apply step check it)."""
    key = json.dumps([strategy, attempt, sorted(set(finding_ids)), hashlib.sha256(diff.encode()).hexdigest()])
    return str(uuid.uuid5(_NAMESPACE, key))


def unified_diff(path: str, old: str, new: str) -> str:
    """A `git apply`-able diff of one text file, with a/ and b/ prefixes."""
    lines = difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True), f"a/{path}", f"b/{path}", n=3
    )
    return f"diff --git a/{path} b/{path}\n" + "".join(lines)


def build_proposal(
    *,
    strategy: Strategy,
    finding_ids: Sequence[str],
    changes: Mapping[str, tuple[str, str]],
    flagged_paths: set[str],
    rationale: str,
    attempt: int,
    created_at: datetime,
) -> PatchProposal:
    """`changes` maps each repository-relative path to its (old, new) text."""
    if not changes or not finding_ids:
        raise RemediationError("nothing to propose")
    unflagged = sorted(set(changes) - flagged_paths)
    if unflagged:
        raise RemediationError(f"the patch touches files no finding flags: {', '.join(unflagged)}")
    diff = "".join(unified_diff(path, old, new) for path, (old, new) in sorted(changes.items()) if old != new)
    if not diff:
        raise RemediationError("the patch changes nothing")
    ids = sorted(set(finding_ids))
    return PatchProposal(
        schema_version="1.0",
        proposal_id=proposal_id_of(strategy, attempt, ids, diff),
        finding_ids=ids,
        strategy=strategy,
        diff=diff,
        files=sorted(path for path, (old, new) in changes.items() if old != new),
        rationale=rationale,
        attempt=attempt,
        created_at=created_at,
    )
