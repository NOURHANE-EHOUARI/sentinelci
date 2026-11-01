"""Building a `PatchProposal` (schemas/patch-proposal.v1.json): the diff, its id, and the checks the contract
asks for (every touched file is a file the findings flag; the diff applies with `git apply`)."""

import difflib
import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal, Strategy
from sentinelci.scanners.runner import is_within

# Fixed namespace: the same proposal (strategy, attempt, findings, diff) always gets the same id.
_NAMESPACE = uuid.UUID("5e1c0a2e-6a6b-4b0e-9a8d-3c2f1e0d9b7a")


class RemediationError(Exception):
    """A proposal or a verification that cannot be made (fail closed: nothing is proposed or verified)."""


class NotFixable(Exception):
    """A file a fixer cannot edit minimally (unparsable, or a layout it would have to rewrite)."""


@dataclass(frozen=True)
class Fixed:
    text: str
    changes: list[str]  # what was changed, for the proposal's rationale
    # (rule id, 1-based line) of what an edit left alone; (rule id, None): the whole rule. A finding of that
    # rule on such a line is not claimed: a proposal claims only what it resolves.
    left_open: frozenset[tuple[str, int | None]] = frozenset()


@dataclass(frozen=True)
class FixContext:
    """What a fixer may need beyond the text: where the file is, and the findings on it that it was not asked
    to fix (an edit must not change their fingerprints)."""

    path: str  # repository-relative
    repo_root: Path
    others: Sequence[Finding]


@dataclass(frozen=True)
class Plan:
    proposal: PatchProposal | None  # None: nothing the fixer can resolve
    skipped: dict[str, str]  # path -> why it was left alone


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


def _left_open(finding: Finding, left_open: frozenset[tuple[str, int | None]]) -> bool:
    if (finding.rule_id, None) in left_open:
        return True
    place = finding.location
    if place is None or place.start_line is None:
        return any(rule == finding.rule_id for rule, _ in left_open)
    lines = range(place.start_line, (place.end_line or place.start_line) + 1)
    return any((finding.rule_id, line) in left_open for line in lines)


def propose_fixes(
    findings: Sequence[Finding],
    repo_root: Path,
    *,
    select: Callable[[Finding], bool],
    fix: Callable[[str, set[str], FixContext], Fixed],
    strategy: Strategy,
    rationale: Callable[[int, list[str]], str],
    attempt: int,
    created_at: datetime,
) -> Plan:
    """One proposal for every finding `select` keeps, file by file: each flagged file is read, fixed for the
    rule ids flagged in it, and left alone (with the reason) when it cannot be edited or nothing changes. Only
    the findings an edit resolves are claimed."""
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if select(finding) and finding.location is not None:
            by_path[finding.location.path].append(finding)
    on_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for place in [finding.location, *(finding.other_locations or [])]:
            if place is not None and finding not in by_path.get(place.path, []):
                on_path[place.path].append(finding)
    changes: dict[str, tuple[str, str]] = {}
    fixed_ids: list[str] = []
    labels: set[str] = set()
    skipped: dict[str, str] = {}
    for path, flagged in sorted(by_path.items()):
        file = repo_root / path
        if file.is_symlink() or not file.is_file() or not is_within(file, repo_root):
            skipped[path] = "not a regular file inside the repository"
            continue
        try:
            old = file.read_bytes().decode("utf-8")  # as stored: CRLF is not turned into LF
            if "\r" in old:
                raise NotFixable("CRLF line endings: a diff of the LF text would not apply")
            context = FixContext(path=path, repo_root=repo_root, others=on_path.get(path, []))
            fixed = fix(old, {f.rule_id for f in flagged}, context)
        except UnicodeDecodeError:
            skipped[path] = "not UTF-8 text"
            continue
        except NotFixable as exc:
            skipped[path] = str(exc)
            continue
        claimed = [f.id for f in flagged if not _left_open(f, fixed.left_open)]
        if fixed.text == old or not claimed:
            skipped[path] = "nothing this fixer can resolve"
            continue
        changes[path] = (old, fixed.text)
        fixed_ids += claimed
        labels.update(fixed.changes)
    if not changes:
        return Plan(proposal=None, skipped=skipped)
    proposal = build_proposal(
        strategy=strategy,
        finding_ids=fixed_ids,
        changes=changes,
        flagged_paths=set(by_path),
        rationale=rationale(len(changes), sorted(labels)),
        attempt=attempt,
        created_at=created_at,
    )
    return Plan(proposal=proposal, skipped=skipped)
