"""Risk engine (task B3, SPEC section 6.2): risk = 100 x S x E x X x R, banded into P0-P4.

Properties are checked over every combination of the model's values rather than sampled: the grid is small
enough to be exhaustive, and needs no extra dependency.
"""

import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.risk import RiskModel, RiskModelError, cvss_baseline, score_finding

ROOT = Path(__file__).resolve().parents[3]
POLICIES = ROOT / "policies"
FIXTURES = ROOT / "schemas" / "fixtures" / "finding" / "valid"
MODEL = RiskModel.load(POLICIES / "risk-model.yaml")
SCA = json.loads((FIXTURES / "sca-enriched-and-scored.json").read_text(encoding="utf-8"))
SECRET = json.loads((FIXTURES / "secret-in-config.json").read_text(encoding="utf-8"))

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]  # increasing
EXPOSURES = ["offline", "internal", "internet-facing"]  # increasing
REACHABILITY = ["not_imported", "unknown", "imported", "reachable"]  # increasing
PERCENTILES = [0.0, 0.25, 0.5, 0.95, 1.0]  # increasing
PRIORITY_ORDER = {"P4": 0, "P3": 1, "P2": 2, "P1": 3, "P0": 4}


def vuln(
    severity: str = "CRITICAL",
    percentile: float | None = 0.95,
    kev: bool | None = False,
    exposure: str | None = "internet-facing",
    reachability: str | None = "imported",
) -> dict[str, Any]:
    finding = {k: v for k, v in SCA.items() if k not in ("risk", "enrichment")}
    finding["severity"] = severity
    enrichment: dict[str, Any] = {} if kev is None else {"kev": {"listed": kev}}
    if percentile is not None:
        enrichment["epss"] = {"score": 0.1, "percentile": percentile, "date": "2026-11-01"}
    if exposure is not None:
        enrichment["exposure"] = exposure
    if reachability is not None:
        enrichment["reachability"] = reachability
    finding["enrichment"] = enrichment
    return finding


def risk(finding: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = score_finding(finding, MODEL)["risk"]
    return result


# ---------------------------------------------------------------- the SPEC section 6.2 table


@pytest.mark.parametrize(
    ("exposure", "reachability", "score", "priority"),
    [
        ("internet-facing", "imported", 87.3, "P0"),
        ("internal", "imported", 61.1, "P1"),
        ("offline", "not_imported", 19.4, "P3"),
    ],
)
def test_the_spec_examples(exposure: str, reachability: str, score: float, priority: str) -> None:
    result = risk(vuln(exposure=exposure, reachability=reachability))
    assert (result["score"], result["priority"]) == (score, priority)


def test_the_factor_breakdown_and_model_version_are_recorded() -> None:
    result = risk(vuln())
    assert result["factors"] == {"S": 1.0, "E": 0.97, "X": 1.0, "R": 0.9}
    assert result["model_version"] == "1.0.0"


# ---------------------------------------------------------------- properties over the whole grid

GRID = list(list(itertools.product(SEVERITIES, PERCENTILES, [False, True], EXPOSURES, REACHABILITY)))


@pytest.mark.parametrize(("severity", "pct", "kev", "exposure", "reach"), GRID)
def test_bounds_and_bands(severity: str, pct: float, kev: bool, exposure: str, reach: str) -> None:
    result = risk(vuln(severity, pct, kev, exposure, reach))
    assert 0 <= result["score"] <= 100
    # The bound the gate relies on for unscored findings (worst-case priority): risk <= 100 x S.
    assert result["score"] <= 100 * MODEL.severity_weight[severity]
    floor = {"P0": 70, "P1": 50, "P2": 30, "P3": 10, "P4": 0}[result["priority"]]
    ceiling = {"P0": 101, "P1": 70, "P2": 50, "P3": 30, "P4": 10}[result["priority"]]
    assert floor <= result["score"] < ceiling


def _never_decreases(values: list[str] | list[float] | list[bool], make: Any) -> None:
    scores = [risk(make(v)) for v in values]
    assert [s["score"] for s in scores] == sorted(s["score"] for s in scores)
    ranks = [PRIORITY_ORDER[s["priority"]] for s in scores]
    assert ranks == sorted(ranks)


@pytest.mark.parametrize(
    ("pct", "kev", "exposure", "reach"),
    list(itertools.product(PERCENTILES, [False, True], EXPOSURES, REACHABILITY)),
)
def test_monotone_in_severity(pct: float, kev: bool, exposure: str, reach: str) -> None:
    _never_decreases(SEVERITIES, lambda s: vuln(s, pct, kev, exposure, reach))


@pytest.mark.parametrize(
    ("sev", "kev", "exposure", "reach"),
    list(itertools.product(SEVERITIES, [False, True], EXPOSURES, REACHABILITY)),
)
def test_monotone_in_epss(sev: str, kev: bool, exposure: str, reach: str) -> None:
    _never_decreases(PERCENTILES, lambda p: vuln(sev, p, kev, exposure, reach))


@pytest.mark.parametrize(
    ("sev", "pct", "exposure", "reach"),
    list(itertools.product(SEVERITIES, PERCENTILES, EXPOSURES, REACHABILITY)),
)
def test_monotone_in_kev(sev: str, pct: float, exposure: str, reach: str) -> None:
    _never_decreases([False, True], lambda k: vuln(sev, pct, k, exposure, reach))


@pytest.mark.parametrize(
    ("sev", "pct", "kev", "reach"),
    list(itertools.product(SEVERITIES, PERCENTILES, [False, True], REACHABILITY)),
)
def test_monotone_in_exposure(sev: str, pct: float, kev: bool, reach: str) -> None:
    _never_decreases(EXPOSURES, lambda x: vuln(sev, pct, kev, x, reach))


@pytest.mark.parametrize(
    ("sev", "pct", "kev", "exposure"),
    list(itertools.product(SEVERITIES, PERCENTILES, [False, True], EXPOSURES)),
)
def test_monotone_in_reachability(sev: str, pct: float, kev: bool, exposure: str) -> None:
    _never_decreases(REACHABILITY, lambda r: vuln(sev, pct, kev, exposure, r))


# ---------------------------------------------------------------- missing enrichment (B2 not run yet)


@pytest.mark.parametrize(
    ("sev", "exposure", "reach"), list(itertools.product(SEVERITIES, EXPOSURES, REACHABILITY))
)
def test_a_kev_outage_never_lowers_a_score(sev: str, exposure: str, reach: str) -> None:
    # Found by Nourhane in the review of #16: the KEV feed down while EPSS answers (#18 writes EPSS alone).
    no_data = risk(vuln(sev, None, None, exposure, reach))
    for pct in PERCENTILES:
        kev_unknown = risk(vuln(sev, pct, None, exposure, reach))
        assert kev_unknown["factors"]["E"] == 1.0
        assert kev_unknown["score"] == no_data["score"]
        assert kev_unknown["score"] >= risk(vuln(sev, pct, False, exposure, reach))["score"]


def test_kev_without_a_listed_value_is_unknown() -> None:
    finding = vuln(percentile=0.1)
    finding["enrichment"]["kev"] = {}
    assert risk(finding)["factors"]["E"] == 1.0


def test_missing_exploitability_and_exposure_count_as_the_worst() -> None:
    unknown = risk(vuln(percentile=None, exposure=None))["factors"]
    assert (unknown["E"], unknown["X"]) == (1.0, 1.0)


def test_reachability_not_analysed_counts_as_the_worst_and_unknown_as_the_model_says() -> None:
    assert risk(vuln(reachability=None))["factors"]["R"] == 1.0
    assert risk(vuln(reachability="unknown"))["factors"]["R"] == MODEL.reachability["unknown"] < 1.0


@pytest.mark.parametrize("severity", SEVERITIES)
def test_with_no_enrichment_a_package_finding_scores_the_gates_unscored_bound(severity: str) -> None:
    # The gate counts an unscored finding at 100 x S (#15): scoring must never relax it.
    bare = {k: v for k, v in SCA.items() if k not in ("risk", "enrichment")}
    result = risk({**bare, "severity": severity})
    bound = round(100 * MODEL.severity_weight[severity], 1)
    assert result["score"] == bound
    assert result["priority"] == MODEL.priority(bound)


def test_a_finding_with_no_enrichment_at_all_is_scored() -> None:
    bare = {k: v for k, v in SCA.items() if k not in ("risk", "enrichment")}
    result = risk(bare)
    assert result["factors"] == {"S": 1.0, "E": 1.0, "X": 1.0, "R": 1.0}
    assert (result["score"], result["priority"]) == (100.0, "P0")


def test_kev_wins_over_epss() -> None:
    assert risk(vuln(percentile=0.0, kev=True))["factors"]["E"] == 1.0


# ---------------------------------------------------------------- non-package categories


@pytest.mark.parametrize(
    ("category", "exploitability"),
    [("SECRET", 1.0), ("SAST", 0.8), ("IAC", 0.5), ("PIPELINE", 0.7), ("LICENSE", 1.0)],
    ids=["secret", "sast-counts-as-taint", "iac", "pipeline", "license-unlisted-is-worst"],
)
def test_non_cve_categories_use_their_weight_and_ignore_reachability(
    category: str, exploitability: float
) -> None:
    finding = {
        **SECRET,
        "category": category,
        "enrichment": {"exposure": "internal", "reachability": "not_imported"},
    }
    factors = risk(finding)["factors"]
    assert (factors["E"], factors["R"], factors["X"]) == (exploitability, 1.0, 0.7)


# ---------------------------------------------------------------- determinism and the contract


def test_scoring_the_contract_fixture_reproduces_its_recorded_risk() -> None:
    assert score_finding(SCA, MODEL) == SCA


def test_scoring_is_idempotent_and_keeps_every_other_field() -> None:
    once = score_finding(vuln(), MODEL)
    assert score_finding(once, MODEL) == once
    assert {k: v for k, v in once.items() if k != "risk"} == vuln()


def test_scored_findings_satisfy_the_contract(finding_validator: Draft202012Validator) -> None:
    for severity, pct, kev, exposure, reach in GRID[:: len(GRID) // 20]:
        assert not list(
            finding_validator.iter_errors(score_finding(vuln(severity, pct, kev, exposure, reach), MODEL))
        )
    assert not list(finding_validator.iter_errors(score_finding(SECRET, MODEL)))


def test_the_recorded_model_version_follows_the_model_file(tmp_path: Path) -> None:
    text = (POLICIES / "risk-model.yaml").read_text(encoding="utf-8")
    (tmp_path / "risk-model.yaml").write_text(
        text.replace("version: 1.0.0", "version: 2.3.4"), encoding="utf-8"
    )
    model = RiskModel.load(tmp_path / "risk-model.yaml")
    assert score_finding(SECRET, model)["risk"]["model_version"] == "2.3.4"


def test_cvss_baseline_for_the_evaluation() -> None:
    assert cvss_baseline(SCA) == 98.0  # enrichment.cvss.score 9.8, on the risk scale
    assert cvss_baseline(SECRET) is None


# ---------------------------------------------------------------- the model file


@pytest.mark.parametrize(
    "edit",
    [
        lambda m: m.update(version="1.0"),
        lambda m: m["severity_weight"].pop("INFO"),
        lambda m: m["severity_weight"].update(HIGH=1.5),
        lambda m: m["exposure"].update(dmz=0.9),
        lambda m: m["reachability"].pop("unknown"),
        lambda m: m["priority_bands"].update(P1=80),
        lambda m: m["priority_bands"].update(P0=150),
        lambda m: m["exploitability"].update(epss_floor=-0.1),
        lambda m: m.update(extra=1),
    ],
    ids=[
        "version",
        "missing-severity",
        "weight-above-1",
        "unknown-exposure",
        "missing-reachability",
        "bands-not-descending",
        "band-above-100",
        "negative-floor",
        "unknown-key",
    ],
)
def test_an_invalid_model_is_refused(tmp_path: Path, edit: Any) -> None:
    import yaml

    model = yaml.safe_load((POLICIES / "risk-model.yaml").read_text(encoding="utf-8"))
    edit(model)
    path = tmp_path / "risk-model.yaml"
    path.write_text(yaml.safe_dump(model), encoding="utf-8")
    with pytest.raises(RiskModelError):
        RiskModel.load(path)


# ---------------------------------------------------------------- sentinel score


def run_score(tmp_path: Path, data: bytes, *extra: str) -> tuple[int, str, Path]:
    (tmp_path / "in.ndjson").write_bytes(data)
    out = tmp_path / "out.ndjson"
    result = CliRunner().invoke(
        app,
        [
            "score",
            "--findings",
            str(tmp_path / "in.ndjson"),
            "--out",
            str(out),
            "--policy-dir",
            str(POLICIES),
            *extra,
        ],
    )
    return result.exit_code, result.output, out


def test_cli_scores_every_finding(tmp_path: Path) -> None:
    findings = [vuln(), SECRET]
    code, out, path = run_score(tmp_path, "".join(json.dumps(f) + "\n" for f in findings).encode())
    assert code == 0, out
    scored = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [f["id"] for f in scored] == sorted(f["id"] for f in findings)
    assert all(f["risk"]["model_version"] == "1.0.0" for f in scored)
    assert "2 finding(s) scored with risk model 1.0.0" in out


@pytest.mark.parametrize("data", [b"{broken\n", b'{"id": "x"}\n'], ids=["not-json", "not-a-finding"])
def test_cli_fails_closed_on_unreadable_findings(tmp_path: Path, data: bytes) -> None:
    (tmp_path / "out.ndjson").write_text("stale\n", encoding="utf-8")
    code, _, path = run_score(tmp_path, data)
    assert code == 3
    assert not path.exists()
