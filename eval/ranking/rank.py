"""Ranking quality of the risk score against a CVSS-only baseline (task B8, SPEC section 17): NDCG@10.

The relevance of each seed is its `relevance` grade in demo-shop/ground-truth/findings.yaml (its README,
"Ranking relevance"), fixed before any ranking was computed. What is ranked:

- each seed once, at the best place any finding that detects it reaches (the detection rules of
  eval/detection/score.py), with the seed's grade as its gain;
- each finding that detects no seed, on its own, with gain 0;
- a seed no finding detects is not in the ranking, but it stays in the ideal one, so it lowers both orders the
  same way.

Two orders of the same items: SentinelCI's risk score (`risk.score`), and the CVSS-only baseline
(`sentinelci.risk.cvss_baseline`: CVSS on the risk scale; a finding without CVSS falls back to the lower bound
of its severity's CVSS v3.1 rating, so a scanner's severity stands for the score it does not
give).

Ties are scored as McSherry and Najork (2008) do: the items of a tie share the mean discount of the places
they span, so no arbitrary order inside a tie changes the result. Owner: Track B (B8).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# The lower bound of each CVSS v3.1 qualitative rating, on the risk scale (x10): the baseline for a finding
# that has no CVSS score.
SEVERITY_FLOOR = {"CRITICAL": 90.0, "HIGH": 70.0, "MEDIUM": 40.0, "LOW": 1.0, "INFO": 0.0}


@dataclass(frozen=True)
class Item:
    """One ranked item: a seed (gain = its grade) or a finding that detects no seed (gain 0)."""

    key: str  # the seed id, or the finding id
    gain: int
    score: float  # the item's place in this order: higher first
    findings: tuple[str, ...]  # the findings it stands for
    label: str = ""  # how the report names it: the seed id, or the finding's tool, rule and file


def _discount(place: int) -> float:
    """The discount of a 1-based place."""
    return 1.0 / math.log2(place + 1)


def dcg(items: Sequence[Item], k: int | None) -> float:
    """Tie-aware DCG of `items` ordered by score, cut at `k` places (None: all)."""
    ordered = sorted(items, key=lambda item: -item.score)
    total, place = 0.0, 1
    index = 0
    while index < len(ordered):
        end = index
        while end + 1 < len(ordered) and ordered[end + 1].score == ordered[index].score:
            end += 1
        size = end - index + 1
        places = range(place, place + size)
        mean = sum(_discount(p) for p in places if k is None or p <= k) / size
        total += mean * sum((2**item.gain - 1) for item in ordered[index : end + 1])
        place += size
        index = end + 1
    return total


def ideal_dcg(grades: Iterable[int], k: int | None) -> float:
    """DCG of the ideal order: every seed of the ground truth, highest grade first."""
    ordered = sorted(grades, reverse=True)
    if k is not None:
        ordered = ordered[:k]
    return sum((2**grade - 1) * _discount(place) for place, grade in enumerate(ordered, start=1))


def ndcg(items: Sequence[Item], grades: Sequence[int], k: int | None) -> float | None:
    """NDCG at `k`; None when no seed is relevant (the ideal DCG is 0)."""
    ideal = ideal_dcg(grades, k)
    return None if ideal == 0 else dcg(items, k) / ideal


def baseline_score(finding: Mapping[str, Any], cvss: Callable[[Mapping[str, Any]], float | None]) -> float:
    """The CVSS-only score of a finding, on the risk scale, with the severity floor when it has no CVSS."""
    score = cvss(finding)
    if score is not None:
        return score
    return SEVERITY_FLOOR.get(str(finding.get("severity", "")).upper(), 0.0)


def items(
    seeds: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    detects: Callable[[Mapping[str, Any], Mapping[str, Any]], bool],
    score: Callable[[Mapping[str, Any]], float],
    package_of: Callable[[Mapping[str, Any]], Any] | None = None,
) -> list[Item]:
    """The ranked items of one order (module docstring): a seed at its best finding's score.

    With `package_of`, a finding with the same package key as one that detects a seed also stands for that
    seed: one upgrade fixes every advisory of a package in a manifest, so a sibling advisory leads to the
    seed's fix and is not an irrelevant item. A finding can stand for one seed only (ValueError otherwise).
    """
    by_seed: dict[str, list[Mapping[str, Any]]] = {}
    matched: dict[str, str] = {}
    for seed in seeds:
        hits = [finding for finding in findings if detects(seed, finding)]
        if hits and package_of is not None:
            keys = {key for key in (package_of(finding) for finding in hits) if key is not None}
            ids = {str(finding["id"]) for finding in hits}
            hits += [f for f in findings if str(f["id"]) not in ids and package_of(f) in keys]
        if hits:
            by_seed[str(seed["id"])] = hits
            for finding in hits:
                other = matched.setdefault(str(finding["id"]), str(seed["id"]))
                if other != str(seed["id"]):
                    raise ValueError(
                        f"finding {finding['id']} stands for two seeds: {other} and {seed['id']}"
                    )
    grade = {str(seed["id"]): int(seed["relevance"]) for seed in seeds}
    ranked = [
        Item(
            seed_id,
            grade[seed_id],
            max(score(finding) for finding in hits),
            tuple(sorted(str(finding["id"]) for finding in hits)),
        )
        for seed_id, hits in by_seed.items()
    ]
    ranked += [
        Item(str(finding["id"]), 0, score(finding), (str(finding["id"]),), _label(finding))
        for finding in findings
        if str(finding["id"]) not in matched
    ]
    return sorted(ranked, key=lambda item: (-item.score, item.key))


def _label(finding: Mapping[str, Any]) -> str:
    """A finding that detects no seed, as a reader can find it: tool, rule and file (and its id's start)."""
    tool = finding.get("tool")
    name = tool.get("name") if isinstance(tool, Mapping) else tool
    location = finding.get("location")
    path = location.get("path") if isinstance(location, Mapping) else None
    return f"{name} {finding.get('rule_id')} in {path} ({str(finding.get('id'))[:12]})"


def top(ranked: Sequence[Item], k: int) -> list[dict[str, Any]]:
    """The first `k` items as the report shows them, with the places a tie spans."""
    ordered = sorted(ranked, key=lambda item: (-item.score, item.key))
    first: dict[float, int] = {}
    count: dict[float, int] = {}
    for place, item in enumerate(ordered, start=1):
        first.setdefault(item.score, place)
        count[item.score] = count.get(item.score, 0) + 1
    shown = []
    for item in ordered[:k]:
        start = first[item.score]
        end = start + count[item.score] - 1
        shown.append(
            {
                "item": item.label or item.key,
                "gain": item.gain,
                "score": item.score,
                "places": f"{start}" if start == end else f"{start}-{end}",
            }
        )
    return shown
