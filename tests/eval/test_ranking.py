"""The ranking report of B8 (eval/ranking): tie-aware NDCG@10 of the risk score and of the CVSS baseline."""

from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load_run() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sentinel_eval_ranking_run", ROOT / "eval/ranking/run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run = _load_run()
rank = run.rank
Item = rank.Item


def d(place: int) -> float:
    return 1 / math.log2(place + 1)


def item(key: str, gain: int, score: float) -> Any:
    return Item(key, gain, score, (key,))


# ---------------------------------------------------------------- NDCG


def test_the_ideal_order_scores_one_and_a_worse_order_less() -> None:
    grades = [3, 2, 1]
    best = [item("a", 3, 90), item("b", 2, 80), item("c", 1, 70), item("x", 0, 60)]
    worst = [item("a", 3, 10), item("b", 2, 20), item("c", 1, 30), item("x", 0, 60)]
    assert rank.ndcg(best, grades, 10) == pytest.approx(1.0)
    assert rank.ndcg(worst, grades, 10) < rank.ndcg(best, grades, 10)
    expected = (7 * d(4) + 3 * d(3) + 1 * d(2)) / (7 * d(1) + 3 * d(2) + 1 * d(3))
    assert rank.ndcg(worst, grades, 10) == pytest.approx(expected)


def test_a_tie_shares_the_mean_discount_of_its_places() -> None:
    """Two items tied at the top: whatever order a sort picks, each gets (d(1) + d(2)) / 2."""
    tied = [item("a", 3, 50), item("x", 0, 50)]
    assert rank.dcg(tied, None) == pytest.approx(7 * (d(1) + d(2)) / 2)
    assert rank.dcg(list(reversed(tied)), None) == rank.dcg(tied, None)


def test_the_cut_at_k_counts_only_the_places_inside_it() -> None:
    ranked = [item("x", 0, 90), item("a", 3, 10)]
    assert rank.dcg(ranked, 1) == 0.0
    # A tie across the cut: places 1 and 2, with k = 1, share d(1) / 2.
    assert rank.dcg([item("a", 3, 50), item("x", 0, 50)], 1) == pytest.approx(7 * d(1) / 2)
    assert rank.ideal_dcg([1, 3, 2], 2) == pytest.approx(7 * d(1) + 3 * d(2))


def test_no_relevant_seed_is_not_measured() -> None:
    assert rank.ndcg([item("x", 0, 1)], [], 10) is None


# ---------------------------------------------------------------- what is ranked


def seed(seed_id: str, relevance: int, path: str, category: str = "SAST", rule: str = "r") -> dict[str, Any]:
    return {
        "id": seed_id,
        "category": category,
        "relevance": relevance,
        "location": {"path": path},
        "expected": {"detections": [{"tool": "opengrep", "rule": rule}]},
    }


def finding(
    finding_id: str,
    path: str,
    score: float,
    *,
    cvss: float | None = None,
    severity: str = "HIGH",
    rule: str = "r",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": finding_id,
        "tool": {"name": "opengrep", "version": "1"},
        "rule_id": rule,
        "category": "SAST",
        "severity": severity,
        "location": {"path": f"demo-shop/{path}", "start_line": 1},
        "risk": {"score": score},
    }
    if cvss is not None:
        out["enrichment"] = {"cvss": {"score": cvss}}
    return out


def test_a_seed_counts_once_at_its_best_finding_and_other_findings_count_zero() -> None:
    seeds = [seed("GT-SAST-001", 3, "app/a.py"), seed("GT-SAST-002", 1, "app/b.py")]
    findings = [
        finding("f1", "app/a.py", 20),
        finding("f2", "app/a.py", 80),  # the same seed, better placed
        finding("f3", "app/c.py", 50),  # no seed
        finding("f4", "app/b.py", 10),
    ]
    items = rank.items(seeds, findings, run.detection.detects, lambda f: float(f["risk"]["score"]))
    assert [(i.key, i.gain, i.score) for i in items] == [
        ("GT-SAST-001", 3, 80.0), ("f3", 0, 50.0), ("GT-SAST-002", 1, 10.0),
    ]  # fmt: skip
    assert items[0].findings == ("f1", "f2")


def test_a_seed_nothing_detects_lowers_both_orders() -> None:
    seeds = [seed("GT-SAST-001", 3, "app/a.py"), seed("GT-SAST-002", 3, "app/missed.py")]
    data = run.measure(seeds, [finding("f1", "app/a.py", 90, cvss=9.0)])
    assert data["seeds_detected"] == 1
    assert (
        data["advisory"]["risk"]["ndcg_at_10"]
        == data["advisory"]["cvss_baseline"]["ndcg_at_10"]
        == pytest.approx(round(7 * d(1) / (7 * d(1) + 7 * d(2)), 4))
    )


def test_the_baseline_uses_cvss_then_the_severity_floor() -> None:
    assert rank.baseline_score(finding("f", "a.py", 1, cvss=9.8), run.cvss_baseline) == 98.0
    assert rank.baseline_score(finding("f", "a.py", 1, severity="MEDIUM"), run.cvss_baseline) == 40.0
    assert rank.baseline_score(finding("f", "a.py", 1, severity="unknown"), run.cvss_baseline) == 0.0


def test_the_two_orders_differ_where_the_scores_do() -> None:
    """The risk order puts the reachable seed first; CVSS puts the higher base score first."""
    seeds = [seed("GT-SAST-001", 3, "app/a.py"), seed("GT-SAST-002", 1, "app/b.py")]
    findings = [finding("f1", "app/a.py", 90, cvss=5.0), finding("f2", "app/b.py", 30, cvss=9.0)]
    data = run.measure(seeds, findings)
    advisory = data["advisory"]
    assert advisory["risk"]["ndcg_at_10"] == 1.0
    assert advisory["cvss_baseline"]["ndcg_at_10"] < 1.0
    assert [row["item"] for row in advisory["cvss_baseline"]["top"]] == ["GT-SAST-002", "GT-SAST-001"]


# ---------------------------------------------------------------- the report


def truth_of(*seeds: dict[str, Any]) -> bytes:
    return yaml.safe_dump({"version": 1, "seeds": list(seeds), "controls": []}).encode()


def test_a_seed_without_a_grade_or_a_finding_without_a_score_is_refused() -> None:
    ungraded = seed("GT-SAST-001", 3, "a.py")
    del ungraded["relevance"]
    with pytest.raises(run.EvalError, match="every seed needs a relevance grade"):
        run.report(truth_of(ungraded), [], {})
    unscored = finding("f1", "a.py", 1)
    del unscored["risk"]
    with pytest.raises(run.EvalError, match="1 finding\\(s\\) have no risk score"):
        run.report(truth_of(seed("GT-SAST-001", 3, "a.py")), [unscored], {})


def test_the_report_is_the_same_for_the_same_inputs() -> None:
    truth = truth_of(seed("GT-SAST-001", 3, "app/a.py"), seed("GT-SAST-002", 1, "app/b.py"))
    findings = [finding("f1", "app/a.py", 90, cvss=5.0), finding("f2", "app/b.py", 30, cvss=9.0)]
    first = run.report(truth, findings, {"x": "1"})
    again = run.report(truth, list(reversed(findings)), {"x": "1"})
    assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)
    assert run.markdown(first) == run.markdown(again)
    for definition in ("advisory", "package"):  # no SCA seed: not measured, never 0
        assert first["sca_only"][definition]["risk"]["ndcg_at_10"] is None
    assert "| SCA only | advisory | 0 (0) | not measured |" in run.markdown(first)


def test_a_seed_of_a_category_no_scan_measured_is_left_out_and_listed() -> None:
    """`make eval` scans no image: a CONTAINER seed could not have been found, so it is not ranked as a miss
    (it would lower both orders), and the report lists it, as the detection report says "not measured"."""
    truth = truth_of(
        seed("GT-SAST-001", 3, "app/a.py"), seed("GT-CONTAINER-001", 2, "Dockerfile", "CONTAINER")
    )
    findings = [finding("f1", "app/a.py", 90, cvss=9.0)]
    data = run.report(truth, findings, {}, frozenset({"SAST"}))
    assert data["not_measured"] == ["GT-CONTAINER-001"] and data["all"]["seeds"] == 1
    assert data["all"]["advisory"]["risk"]["ndcg_at_10"] == 1.0
    assert "Not measured (no scan of their category ran" in run.markdown(data)
    everything = run.report(truth, findings, {})
    assert everything["not_measured"] == [] and everything["all"]["advisory"]["risk"]["ndcg_at_10"] < 1.0


def test_every_ground_truth_seed_is_graded() -> None:
    truth = yaml.safe_load(run.GROUND_TRUTH.read_text(encoding="utf-8"))
    assert all(s.get("relevance") in {1, 2, 3} for s in truth["seeds"])


def test_without_findings_it_says_to_run_make_eval_first(tmp_path: Path) -> None:
    script = str(ROOT / "eval/ranking/run.py")
    done = subprocess.run(
        [sys.executable, script, "--findings", str(tmp_path), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert done.returncode == 2 and "run `make eval` first" in done.stderr


# ---------------------------------------------------------------- #121 review


def sca_seed(seed_id: str, relevance: int, purl: str, advisory: str) -> dict[str, Any]:
    return {
        "id": seed_id,
        "category": "SCA",
        "relevance": relevance,
        "location": {"path": "services/web/package.json"},
        "package": purl,
        "vulnerability": advisory,
        "expected": {"detections": [{"tool": "grype", "rule": advisory}]},
    }


def sca_finding(finding_id: str, purl: str, advisory: str, risk: float, cvss: float | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": finding_id,
        "tool": {"name": "grype", "version": "1"},
        "rule_id": advisory,
        "category": "SCA",
        "severity": "HIGH",
        "location": {"path": "demo-shop/services/web/package-lock.json"},
        "package": {"purl": purl},
        "risk": {"score": risk},
    }
    if cvss is not None:
        out["enrichment"] = {"cvss": {"score": cvss}}
    return out


def test_a_seeded_packages_other_advisories_stand_for_the_seed_in_the_package_definition() -> None:
    """One upgrade fixes every advisory of a package in a manifest: under "package", a sibling the risk order
    puts above the seed's own advisory is the seed's item, not an irrelevant one. "advisory" is kept as it
    was."""
    seeds = [sca_seed("GT-SCA-004", 3, "pkg:npm/lodash@4.17.20", "GHSA-a")]
    findings = [
        sca_finding("seed", "pkg:npm/lodash@4.17.20", "GHSA-a", risk=70, cvss=9.8),
        *(
            sca_finding(f"sib{i}", "pkg:npm/lodash@4.17.20", f"GHSA-s{i}", risk=95, cvss=None)
            for i in range(3)
        ),
        sca_finding("other", "pkg:npm/lodash-es@4.17.20", "GHSA-s0", risk=95, cvss=None),  # another package
    ]
    data = run.measure(seeds, findings)
    assert data["advisory"]["risk"]["ndcg_at_10"] < 1.0
    assert data["package"]["risk"]["ndcg_at_10"] < 1.0  # lodash-es ties with the siblings at 95
    top = data["package"]["risk"]["top"]
    assert top[0]["item"] == "GT-SCA-004" and top[0]["score"] == 95.0
    assert "lodash-es" not in str(rank.items(seeds, findings, run.detection.detects, lambda f: 0.0,
                                             run.package_of)[0].findings)  # fmt: skip


def test_a_finding_that_stands_for_two_seeds_is_refused() -> None:
    seeds = [sca_seed("GT-SCA-004", 3, "pkg:npm/lodash@4.17.20", "GHSA-a"),
             sca_seed("GT-SCA-009", 1, "pkg:npm/lodash@4.17.20", "GHSA-b")]  # fmt: skip
    findings = [
        sca_finding("f1", "pkg:npm/lodash@4.17.20", "GHSA-a", risk=70, cvss=None),
        sca_finding("f2", "pkg:npm/lodash@4.17.20", "GHSA-b", risk=70, cvss=None),
    ]
    with pytest.raises(run.EvalError, match="stands for two seeds"):
        run.measure(seeds, findings)


def test_a_grade_outside_one_to_three_is_refused() -> None:
    with pytest.raises(run.EvalError, match="GT-SAST-001: relevance 1, 2 or 3"):
        run.report(truth_of(seed("GT-SAST-001", 7, "a.py")), [finding("f1", "a.py", 1)], {})


@pytest.mark.parametrize("missing", ["grype", "opengrep"])
def test_a_make_eval_run_without_a_scanners_findings_is_refused(tmp_path: Path, missing: str) -> None:
    """A scanner that failed writes no file: ranking the others as the whole run would hide it. An empty file
    is a scanner that ran and found nothing."""
    for tool in run.TOOLS:
        if tool != missing:
            (tmp_path / f"{tool}.ndjson").write_text("", encoding="utf-8")
    with pytest.raises(run.EvalError, match=f"no {missing}.ndjson in"):
        run.scored_findings(tmp_path, tmp_path / "work")
