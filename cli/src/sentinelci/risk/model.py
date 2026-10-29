"""Risk score and priority of a finding (SPEC section 6.2): risk = 100 x S x E x X x R, clamped to [0, 100].

S  severity weight.
E  exploitability. SCA/CONTAINER: 1.0 if KEV-listed, else epss_floor + (1 - epss_floor) x EPSS percentile.
   Other categories: their `non_cve` weight (SAST counts as SAST_TAINT until findings say which kind they are;
   a category the model does not list counts as 1.0).
X  exposure of the service (`enrichment.exposure`).
R  reachability (`enrichment.reachability`), for SCA/CONTAINER only; 1.0 for every other category.

Missing enrichment never lowers a score: no EPSS/KEV data means E = 1.0, no exposure means X = 1.0 and no
reachability analysis means R = 1.0 (the model's `unknown` is for an analysis that ran and could not decide).
So until enrichment (B2) runs, a score is exactly 100 x S, the bound the gate uses for unscored findings:
adding `sentinel score` to a pipeline never relaxes the gate.

The score is rounded to 0.1 and the priority is banded from the rounded score. The weights live in
policies/risk-model.yaml, part of the policy bundle; its version is recorded in each finding's `risk`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
EXPOSURES = ("internet-facing", "internal", "offline")
REACHABILITY = ("reachable", "imported", "unknown", "not_imported")
BANDS = ("P0", "P1", "P2", "P3")  # below P3's floor: P4
PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_CATEGORY_WEIGHT = {"SAST": "SAST_TAINT"}  # Finding category -> non_cve key, where the names differ

Weight = float


class RiskModelError(Exception):
    """The risk model file is missing or malformed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Exploitability(_Strict):
    kev: Weight = Field(ge=0, le=1)
    epss_floor: Weight = Field(ge=0, le=1)
    non_cve: dict[str, Weight]


class RiskModel(_Strict):
    version: str
    severity_weight: dict[str, Weight]
    exploitability: Exploitability
    exposure: dict[str, Weight]
    reachability: dict[str, Weight]
    priority_bands: dict[str, float]

    @model_validator(mode="after")
    def _complete_and_consistent(self) -> RiskModel:
        if not _SEMVER.fullmatch(self.version):
            raise ValueError(f"version must be a semantic version, got {self.version!r}")
        for name, table, keys in [
            ("severity_weight", self.severity_weight, SEVERITIES),
            ("exposure", self.exposure, EXPOSURES),
            ("reachability", self.reachability, REACHABILITY),
            ("priority_bands", self.priority_bands, BANDS),
        ]:
            if set(table) != set(keys):
                raise ValueError(f"{name} must have exactly {', '.join(keys)}")
        weights = [
            *self.severity_weight.values(),
            *self.exposure.values(),
            *self.reachability.values(),
            *self.exploitability.non_cve.values(),
        ]
        if any(not 0 <= w <= 1 for w in weights):
            raise ValueError("every weight must be between 0 and 1")
        floors = [self.priority_bands[b] for b in BANDS]
        if (
            floors != sorted(floors, reverse=True)
            or len(set(floors)) != len(floors)
            or not all(0 < floor <= 100 for floor in floors)
        ):  # a floor above 100 would make its band, and every rule on it, unreachable
            raise ValueError("priority_bands must be strictly descending from P0 to P3, each within (0, 100]")
        return self

    @classmethod
    def load(cls, path: Path) -> RiskModel:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            return cls.model_validate(document)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise RiskModelError(f"{path}: not a valid risk model: {exc}") from exc

    def priority(self, score: float) -> str:
        return next((band for band in BANDS if score >= self.priority_bands[band]), "P4")


def _get(finding: Mapping[str, Any], *path: str) -> Any:
    node: Any = finding
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def factors(finding: Mapping[str, Any], model: RiskModel) -> dict[str, float]:
    category = finding["category"]
    severity = model.severity_weight[finding["severity"]]
    exposure = model.exposure.get(_get(finding, "enrichment", "exposure"), 1.0)
    if category in PACKAGE_CATEGORIES:
        percentile = _get(finding, "enrichment", "epss", "percentile")
        if _get(finding, "enrichment", "kev", "listed") is True:
            exploitability = model.exploitability.kev
        elif isinstance(percentile, int | float) and not isinstance(percentile, bool):
            floor = model.exploitability.epss_floor
            exploitability = floor + (1 - floor) * min(max(float(percentile), 0.0), 1.0)
        else:
            exploitability = 1.0
        # Not analysed (absent) is the worst case; `unknown` means the analysis ran and could not decide.
        reachability = model.reachability.get(_get(finding, "enrichment", "reachability"), 1.0)
    else:
        weight_key = _CATEGORY_WEIGHT.get(category, category)
        exploitability = model.exploitability.non_cve.get(weight_key, 1.0)
        reachability = 1.0
    return {
        "S": round(severity, 4),
        "E": round(exploitability, 4),
        "X": round(exposure, 4),
        "R": round(reachability, 4),
    }


def score_finding(finding: Mapping[str, Any], model: RiskModel) -> dict[str, Any]:
    """Return a copy of the finding with `risk` set (any earlier `risk` is replaced)."""
    f = factors(finding, model)
    score = round(min(max(100 * f["S"] * f["E"] * f["X"] * f["R"], 0.0), 100.0), 1)
    risk = {"score": score, "priority": model.priority(score), "factors": f, "model_version": model.version}
    return {**finding, "risk": risk}


def cvss_baseline(finding: Mapping[str, Any]) -> float | None:
    """CVSS-only score on the risk scale (0-100), the baseline the evaluation compares rankings with (B8)."""
    score = _get(finding, "enrichment", "cvss", "score")
    if isinstance(score, int | float) and not isinstance(score, bool):
        return round(10 * float(score), 1)
    return None
