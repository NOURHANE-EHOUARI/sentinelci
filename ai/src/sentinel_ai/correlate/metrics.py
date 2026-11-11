"""How well the correlator groups (task A7 acceptance, SPEC sections 3 and 17): the adjusted Rand index
against ground-truth root causes, and the alert reduction (findings to groups, target at least 40%)."""

from collections import Counter
from collections.abc import Hashable, Sequence

from sentinel_ai.correlate.models import RootCauseGroup


def _pairs(count: int) -> float:
    return count * (count - 1) / 2


def adjusted_rand_index(truth: Sequence[Hashable], predicted: Sequence[Hashable]) -> float:
    """ARI (Hubert and Arabie): 1 for the same partition, about 0 for a random one, negative below chance.
    Two partitions that each put everything in one cluster, or each item alone, agree: 1."""
    if len(truth) != len(predicted):
        raise ValueError("both labelings must cover the same items")
    total = _pairs(len(truth))
    both = sum(_pairs(n) for n in Counter(zip(truth, predicted, strict=True)).values())
    rows = sum(_pairs(n) for n in Counter(truth).values())
    columns = sum(_pairs(n) for n in Counter(predicted).values())
    expected = rows * columns / total if total else 0.0
    maximum = (rows + columns) / 2
    if maximum == expected:
        return 1.0
    return (both - expected) / (maximum - expected)


def alert_reduction(findings: int, groups: int) -> float:
    """The share of alerts a reviewer no longer sees: 1 - groups / findings (0 without findings)."""
    return 1 - groups / findings if findings else 0.0


def labels_of(groups: Sequence[RootCauseGroup], finding_ids: Sequence[str]) -> list[str]:
    """The group id of each finding id, in the order given (KeyError if a finding is in no group)."""
    owner = {finding: group.group_id for group in groups for finding in group.finding_ids}
    return [owner[finding] for finding in finding_ids]
