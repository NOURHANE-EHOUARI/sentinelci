"""CVSS v3.0 / v3.1 base score from a vector string (FIRST specification, section 7).

OSV records give CVSS as a vector, not a number. Only the eight base metrics count; temporal and environmental
metrics in the vector are ignored, as the base score defines. CVSS 2.0 and 4.0 vectors are not scored here:
`base_score` returns None and the score stays unknown.
"""

from __future__ import annotations

import math
import re

_VECTOR = re.compile(r"CVSS:(3\.[01])/([A-Za-z]+:[A-Za-z]+(?:/[A-Za-z]+:[A-Za-z]+)*)")
_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope unchanged
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup_31(value: float) -> float:
    """CVSS 3.1 Roundup: the smallest number with one decimal >= value, without float artefacts."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10) / 10


def base_score(vector: str) -> tuple[str, float] | None:
    """(version, base score) for a CVSS 3.x vector, or None when it is not a complete, valid 3.x vector."""
    match = _VECTOR.fullmatch(vector)
    if not match:
        return None
    version, body = match.groups()
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        name, value = part.split(":")
        if name in metrics:
            return None
        metrics[name] = value
    base = {name: metrics.get(name) for name in _WEIGHTS}
    if any(value is None or value not in _WEIGHTS[name] for name, value in base.items()):
        return None
    changed = base["S"] == "C"
    w = {name: _WEIGHTS[name][value] for name, value in base.items() if value is not None}
    privileges = _PR_CHANGED[str(base["PR"])] if changed else w["PR"]
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * privileges * w["UI"]
    roundup = _roundup_31 if version == "3.1" else _roundup_30
    if impact <= 0:
        return version, 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return version, roundup(min(total, 10.0))
