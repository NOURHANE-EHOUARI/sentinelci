"""The correlation measurement (eval/correlation/run.py, task A7): labels, halves, calibration, report."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load_run() -> ModuleType:
    path = ROOT / "eval" / "correlation" / "run.py"
    spec = importlib.util.spec_from_file_location("sentinel_eval_correlation_run", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run = _load_run()
SEEDS: list[dict[str, Any]] = yaml.safe_load(run.GROUND_TRUTH.read_text(encoding="utf-8"))["seeds"]
SPLIT = run.load_split(run.SPLIT.read_text(encoding="utf-8"), SEEDS)
CAUSES = run.load_root_causes(run.ROOT_CAUSES.read_text(encoding="utf-8"), SPLIT)
MODEL = run.Model("test-embedding:1", "sha256:" + "0" * 64)


def finding(tool: str, rule: str, path: str, *, line: int = 1, category: str = "IAC", **extra: Any) -> dict:
    key = f"{tool}|{rule}|{path}|{line}"
    return {
        "id": hashlib.sha256(key.encode()).hexdigest(),
        "tool": {"name": tool, "version": "1"},
        "rule_id": rule,
        "category": category,
        "title": f"{rule} title",
        "location": {"path": f"demo-shop/{path}", "start_line": line},
        **extra,
    }


K8S = "infra/k8s/shop-api.yaml"


# ---------------------------------------------------------------- the committed labels


def test_the_split_places_every_seed_once_and_the_root_causes_agree_with_it() -> None:
    assert set(SPLIT) == {seed["id"] for seed in SEEDS}
    assert set(SPLIT.values()) == {"calibration", "test"}
    for cause in CAUSES:
        for seed in cause.seeds:
            assert SPLIT[seed] == cause.half, cause.id
        for _, file, rules in cause.matchers:
            assert (ROOT / "demo-shop" / file).is_file(), (cause.id, file)
            assert rules, cause.id


def test_the_split_follows_its_own_rule() -> None:
    """split.yaml's header: in each category, the seeds sorted by id go to calibration, test, calibration, ...
    A seed placed in the other half, by mistake or to move a score, fails here (#90 review, round 4)."""
    by_category: dict[str, list[str]] = {}
    for seed in SEEDS:
        by_category.setdefault(seed["category"], []).append(seed["id"])
    expected = {
        seed: ("calibration", "test")[i % 2]
        for ids in by_category.values()
        for i, seed in enumerate(sorted(ids))
    }
    assert expected == SPLIT


def test_a_threshold_of_another_correlator_is_said() -> None:
    """Stage 2b embeds the correlator's texts: a threshold calibrated on another version's is said."""
    current = {key: "x" for key in run.HALVES_INPUTS}
    current |= {"correlator_version": run.CORRELATOR_VERSION, "findings_sha256": {}}
    older = {**current, "correlator_version": "0.0.9"}
    assert run.calibrated_on(json.dumps({"inputs": older}), current).endswith(
        f" with correlator 0.0.9, not {run.CORRELATOR_VERSION} (other embedded texts)"
    )
    assert "correlator" not in run.calibrated_on(json.dumps({"inputs": current}), current)


def test_the_root_causes_alternate_halves_in_file_order_as_their_header_says() -> None:
    free = [cause for cause in CAUSES if not cause.seeds]
    assert [(c.matchers[0][1], min(c.matchers[0][2])) for c in free] == sorted(
        (c.matchers[0][1], min(c.matchers[0][2])) for c in free
    )
    assert [c.half for c in free] == [("test", "calibration")[i % 2] for i in range(len(free))]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("calibration: [GT-SECRET-001]\ntest: []\n", "does not place"),
        ("calibration: [GT-NOPE-001]\ntest: []\n", "listed twice|does not place"),
        ("calibration: []\n", "exactly the lists"),
    ],
)
def test_a_split_that_misses_or_repeats_a_seed_is_refused(text: str, message: str) -> None:
    with pytest.raises(run.EvalError, match=message):
        run.load_split(text, SEEDS)


def test_a_seed_in_both_halves_is_refused() -> None:
    ids = sorted(SPLIT)
    text = yaml.safe_dump({"calibration": ids, "test": ids[:1]})
    with pytest.raises(run.EvalError, match="listed twice"):
        run.load_split(text, SEEDS)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"id": "RC-X", "half": "test", "seeds": ["GT-IAC-001"]}, "not in its half"),
        ({"id": "RC-X", "findings": []}, "a unique id and a half"),
        (
            {
                "id": "RC-X",
                "half": "test",
                "findings": [{"tool": "trivy", "file": K8S, "rules": ["KSV-0011"]}],
            },
            "is in RC-Y and RC-X",
        ),
    ],
)
def test_inconsistent_root_causes_are_refused(entry: dict[str, Any], message: str) -> None:
    other = {
        "id": "RC-Y",
        "half": "test",
        "findings": [{"tool": "trivy", "file": K8S, "rules": ["KSV-0011"]}],
    }
    with pytest.raises(run.EvalError, match=message):
        run.load_root_causes(yaml.safe_dump({"root_causes": [other, entry]}), SPLIT)


# ---------------------------------------------------------------- labels and halves


def test_a_seeded_finding_has_its_seeds_root_and_half() -> None:
    secret = finding(
        "gitleaks", "github-pat", "services/shop-api/config/settings.yaml", line=8, category="SECRET"
    )
    assert run.labels([secret], SEEDS, SPLIT, CAUSES) == {
        secret["id"]: run.Label("GT-SECRET-001", "calibration")
    }


def test_a_finding_that_joins_a_seed_has_the_root_cause_that_joins_it() -> None:
    hostpath_seed = finding("trivy", "KSV-0023", K8S, line=8)  # GT-IAC-005
    hostpath_volume = finding("trivy", "KSV-0121", K8S, line=8)  # RC-K8S-HOSTPATH, the same edit
    found = run.labels([hostpath_seed, hostpath_volume], SEEDS, SPLIT, CAUSES)
    assert (
        found[hostpath_seed["id"]]
        == found[hostpath_volume["id"]]
        == run.Label("RC-K8S-HOSTPATH", "calibration")
    )


def test_unlisted_findings_take_their_root_cause_and_others_stay_unlabelled() -> None:
    limits = [finding("trivy", rule, K8S, line=20) for rule in ("KSV-0011", "KSV-0018")]
    unknown = finding("trivy", "KSV-9999", K8S)
    found = run.labels([*limits, unknown], SEEDS, SPLIT, CAUSES)
    assert {found[f["id"]] for f in limits} == {run.Label("RC-K8S-002", "test")}
    assert unknown["id"] not in found


def sca(rule: str, purl: str, path: str = "services/web/package-lock.json") -> dict:
    line = 1 + len(purl)  # a distinct id per package (the id is the tool, rule, file and line here)
    return finding("grype", rule, path, line=line, category="SCA", package={"purl": purl})


def test_every_advisory_of_a_seeded_package_in_its_manifest_has_the_seeds_root_cause() -> None:
    """Review of #90: one upgrade fixes every advisory of a package, so the seed's other advisories of that
    package (in that manifest) share its root cause; lodash and lodash-es stay two upgrades."""
    seed = sca("GHSA-35jh-r3h4-6jhm", "pkg:npm/lodash@4.17.20")  # GT-SCA-004
    other_advisory = sca("GHSA-29mw-wpgm-hmr9", "pkg:npm/lodash@4.17.20")
    es_seed = sca("GHSA-35jh-r3h4-6jhm", "pkg:npm/lodash-es@4.17.20")  # GT-SCA-008
    es_other = sca("GHSA-29mw-wpgm-hmr9", "pkg:npm/lodash-es@4.17.20")
    elsewhere = sca("GHSA-29mw-wpgm-hmr9", "pkg:npm/lodash@4.17.20", "services/admin/package-lock.json")
    unseeded = sca("GHSA-0000-0000-0000", "pkg:npm/left-pad@1.0.0")
    found = run.labels([seed, other_advisory, es_seed, es_other, elsewhere, unseeded], SEEDS, SPLIT, CAUSES)
    assert found[seed["id"]] == found[other_advisory["id"]] == run.Label("GT-SCA-004", SPLIT["GT-SCA-004"])
    assert found[es_seed["id"]] == found[es_other["id"]] == run.Label("GT-SCA-008", SPLIT["GT-SCA-008"])
    assert elsewhere["id"] not in found, "another manifest is another upgrade"
    assert unseeded["id"] not in found


def test_a_finding_two_labels_disagree_on_is_refused() -> None:
    causes = [
        *CAUSES,
        run.RootCause("RC-CLASH", "calibration", (), (("gitleaks", "services/shop-api/config/settings.yaml",
                                                      frozenset({"github-pat"})),)),
    ]  # fmt: skip
    secret = finding(
        "gitleaks", "github-pat", "services/shop-api/config/settings.yaml", line=8, category="SECRET"
    )
    with pytest.raises(run.EvalError, match="more than one true root cause: GT-SECRET-001, RC-CLASH"):
        run.labels([secret], SEEDS, SPLIT, causes)


def test_each_half_is_the_run_without_the_other_halfs_labelled_findings() -> None:
    a, b, c = (finding("trivy", f"R-{i}", K8S) for i in range(3))
    label_of = {a["id"]: run.Label("X", "test"), b["id"]: run.Label("Y", "calibration")}
    assert run.half_of_run([a, b, c], label_of, "test") == [a, c]
    assert run.half_of_run([a, b, c], label_of, "calibration") == [b, c]


def test_alerts_count_every_place_a_tool_reported() -> None:
    one = finding("grype", "GHSA-x", "a/requirements.txt", other_locations=[{"path": "b"}, {"path": "c"}])
    assert run.reported_places([one, finding("trivy", "R", K8S)]) == 4


# ---------------------------------------------------------------- calibration, measurement, report

GROUPS = {"KSV-0011": 0, "KSV-0015": 0, "KSV-0016": 0, "KSV-0018": 0, "KSV-0001": 1, "KSV-0003": 1,
          "KSV-0004": 1, "KSV-0013": 2, "AWS-0077": 3}  # fmt: skip


def fake_embed(texts: list[str]) -> list[list[float]]:
    """One direction per true root cause: what a perfect model would give."""
    vectors = []
    for text in texts:
        rule = next(rule for rule in GROUPS if rule in text)
        vectors.append([1.0 if i == GROUPS[rule] else 0.0 for i in range(4)])
    return vectors


@pytest.fixture
def findings_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "findings"
    directory.mkdir()
    rows = [finding("trivy", rule, K8S, line=20) for rule in GROUPS if rule.startswith("KSV")]
    rows.append(finding("trivy", "AWS-0077", "infra/terraform/database.tf", line=2))
    (directory / "trivy.ndjson").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    for tool in ("gitleaks", "grype", "opengrep", "zizmor"):  # every scanner ran; these found nothing here
        (directory / f"{tool}.ndjson").write_text("", encoding="utf-8")
    return directory


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    threshold = tmp_path / "threshold.json"
    monkeypatch.setattr(run, "THRESHOLD", threshold)
    monkeypatch.setattr(run, "model_embedder", lambda: (fake_embed, MODEL, None))
    return threshold


def test_calibration_then_the_test_half_with_the_committed_threshold(
    findings_dir: Path, model: Path, tmp_path: Path
) -> None:
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0
    calibrated = json.loads(model.read_text(encoding="utf-8"))
    assert calibrated["embedding_model"] == {"name": MODEL.name, "digest": MODEL.digest}
    assert calibrated["threshold"] == 0.95  # every threshold gives ARI 1 here: the tie goes to the highest
    assert calibrated["at_grid_edge"] is True  # 0.95 is the grid's highest: said, never widened afterwards
    assert calibrated["calibration"]["labelled"] == 4  # RC-K8S-001 (3) and RC-K8S-003: the calibration half

    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    report = json.loads((out / "correlation.json").read_text(encoding="utf-8"))
    test = report["test"]
    assert test["labelled"] == 5  # RC-K8S-002 (4) and RC-TF-001: the test half
    assert test["configurations"]["dedup"]["ari"] == 0.0  # four findings of one root cause, kept apart
    assert test["configurations"]["dedup+embedding"]["ari"] == 1.0
    assert test["configurations"]["dedup+embedding"]["groups"] == 2
    assert test["configurations"]["dedup+embedding"]["alert_reduction"] == pytest.approx(0.6)
    assert test["without_sca"]["dedup+embedding"]["ari"] == 1.0  # stage 2b in the ablation without SCA too
    assert {s["threshold"] for s in test["sensitivity"]} == set(run.grid())
    assert report["inputs"]["threshold_sha256"] == hashlib.sha256(model.read_bytes()).hexdigest()
    assert report["threshold"] == {
        "value": 0.95,
        "source": "threshold.json, calibrated on the calibration half",
        "at_grid_edge": True,
    }
    assert "The threshold is at the edge of the grid (0.5 to 0.95)" in (out / "correlation.md").read_text(
        encoding="utf-8"
    )

    again = tmp_path / "again"
    assert run.main(["--findings", str(findings_dir), "--out", str(again)]) == 0
    assert (again / "correlation.json").read_bytes() == (out / "correlation.json").read_bytes()
    assert (again / "correlation.md").read_bytes() == (out / "correlation.md").read_bytes()


def test_a_threshold_calibrated_with_another_model_is_refused(
    findings_dir: Path, model: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = {"embedding_model": {"name": MODEL.name, "digest": "sha256:" + "1" * 64}, "threshold": 0.8}
    model.write_text(json.dumps(other), encoding="utf-8")
    assert run.main(["--findings", str(findings_dir), "--out", str(tmp_path / "out")]) == 2
    assert "calibrate again" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_without_a_model_the_stages_without_it_are_still_measured(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "none.json")
    monkeypatch.setattr(
        run, "model_embedder", lambda: (None, MODEL, "the model server did not answer /api/tags")
    )
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    configurations = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["test"][
        "configurations"
    ]
    assert configurations["dedup+structural"]["groups"] == 5
    for name in ("dedup+embedding", "dedup+structural+embedding"):
        assert configurations[name] == {
            "measured": False,
            "reason": "the model server did not answer /api/tags",
        }
    assert "not measured: the model server did not answer" in (out / "correlation.md").read_text(
        encoding="utf-8"
    )


def test_calibration_without_a_model_is_refused(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "threshold.json")
    assert run.main(["--findings", str(findings_dir), "--calibrate", "--no-embedding"]) == 2
    assert "calibration needs the embedding model" in capsys.readouterr().err
    assert not (tmp_path / "threshold.json").exists()


def test_a_model_that_fails_mid_run_leaves_the_other_stages_measured(
    findings_dir: Path, model: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0

    def broken(texts: list[str]) -> list[list[float]]:
        raise OSError("connection reset")

    monkeypatch.setattr(run, "model_embedder", lambda: (broken, MODEL, None))
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    configurations = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["test"][
        "configurations"
    ]
    assert configurations["dedup"]["groups"] == 5
    assert configurations["dedup+embedding"]["measured"] is False
    assert "the embedder failed" in configurations["dedup+embedding"]["reason"]


def test_without_a_committed_threshold_stage_2b_is_not_run_even_with_a_model(
    findings_dir: Path, model: Path, tmp_path: Path
) -> None:
    assert not model.exists()
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    test = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["test"]
    for name in ("dedup+embedding", "dedup+structural+embedding"):
        assert test["configurations"][name] == {"measured": False, "reason": "no calibrated threshold"}
    assert "sensitivity" not in test
    text = (out / "correlation.md").read_text(encoding="utf-8")
    assert "Threshold: not calibrated" in text and "not used: no calibrated threshold" in text


def test_alert_reduction_counts_the_other_locations(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "none.json")
    path = findings_dir / "trivy.ndjson"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["other_locations"] = [{"path": "demo-shop/infra/k8s/other.yaml"}] * 5
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out), "--no-embedding"]) == 0
    test = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["test"]
    assert test["reported_places"] == 10  # 5 findings of the test half, one with 5 more places
    assert test["configurations"]["dedup"]["alerts"] == 10
    assert test["configurations"]["dedup"]["alert_reduction"] == pytest.approx(0.5)
    whole = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["whole_run"]
    assert whole["configurations"]["dedup"]["alerts"] == 14  # 9 findings, one with 5 more places
    assert whole["without_sca"]["dedup"]["same_root_pairs"] == 9


def test_the_calibration_counts_the_other_locations(findings_dir: Path, model: Path) -> None:
    path = findings_dir / "trivy.ndjson"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    (row,) = [r for r in rows if r["rule_id"] == "KSV-0001"]  # RC-K8S-001: the calibration half
    row["other_locations"] = [{"path": "demo-shop/infra/k8s/other.yaml"}] * 5
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0
    calibrated = json.loads(model.read_text(encoding="utf-8"))["calibration"]
    assert calibrated["alert_reduction"] == pytest.approx(1 - 2 / 9)  # 4 findings and 5 more places, 2 groups


def test_the_report_says_how_much_each_ari_can_see_and_measures_the_whole_run(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review of #90: the labelled root causes and same-root pairs next to each ARI, the stages with no
    parameter on the whole run, and the ARI without SCA."""
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "none.json")
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out), "--no-embedding"]) == 0
    report = json.loads((out / "correlation.json").read_text(encoding="utf-8"))
    test, whole = report["test"], report["whole_run"]
    assert (test["labelled"], test["root_causes"], test["same_root_pairs"]) == (5, 2, 6)  # RC-K8S-002's 4
    assert (whole["labelled"], whole["root_causes"]) == (9, 4)  # with RC-K8S-001 (3) and RC-K8S-003
    assert whole["same_root_pairs"] == 6 + 3
    assert set(whole["configurations"]) == {"dedup", "dedup+structural"}
    assert whole["reported_places"] == whole["findings"] == 9
    assert test["without_sca"]["dedup"]["same_root_pairs"] == 6, "no SCA here: the same pairs"
    text = (out / "correlation.md").read_text(encoding="utf-8")
    assert "5 labelled with 2 root causes (6 same-root pairs)" in text
    assert "Whole run, the stages with no parameter to tune" in text and "Without SCA" in text


def test_a_threshold_calibrated_on_other_halves_is_refused(
    findings_dir: Path,
    model: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review of #90 (Hiba): a label edit between the calibration and the measurement moves findings between
    the halves, so the report's "calibrated on the calibration half" would no longer be true."""
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0
    causes = tmp_path / "root-causes.yaml"
    text = run.ROOT_CAUSES.read_text(encoding="utf-8")
    old = "  - id: RC-K8S-001\n    half: calibration"
    assert text.count(old) == 1
    causes.write_text(text.replace(old, "  - id: RC-K8S-001\n    half: test"), encoding="utf-8")
    monkeypatch.setattr(run, "ROOT_CAUSES", causes)  # RC-K8S-001's findings move to the test half
    assert run.main(["--findings", str(findings_dir), "--out", str(tmp_path / "out")]) == 2
    assert "calibrated on other halves (root_causes_sha256 changed since)" in capsys.readouterr().err


def test_a_threshold_without_its_inputs_is_refused(
    findings_dir: Path, model: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model.write_text(json.dumps({"embedding_model": vars(MODEL), "threshold": 0.8}), encoding="utf-8")
    assert run.main(["--findings", str(findings_dir), "--out", str(tmp_path / "out")]) == 2
    err = capsys.readouterr().err
    assert "(ground_truth_sha256, split_sha256, root_causes_sha256 changed since)" in err


def test_a_threshold_from_another_make_eval_run_says_so(
    findings_dir: Path, model: Path, tmp_path: Path
) -> None:
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0
    path = findings_dir / "trivy.ndjson"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")  # same findings, other bytes
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    source = json.loads((out / "correlation.json").read_text(encoding="utf-8"))["threshold"]["source"]
    assert source.endswith("of another `make eval` run (other findings)")


def test_a_threshold_inside_the_grid_is_not_called_an_edge(
    findings_dir: Path, model: Path, tmp_path: Path
) -> None:
    assert run.main(["--findings", str(findings_dir), "--calibrate"]) == 0
    calibrated = json.loads(model.read_text(encoding="utf-8"))
    model.write_text(json.dumps(calibrated | {"threshold": 0.8}), encoding="utf-8")
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out)]) == 0
    assert (
        json.loads((out / "correlation.json").read_text(encoding="utf-8"))["threshold"]["at_grid_edge"]
        is False
    )
    assert "edge of the grid" not in (out / "correlation.md").read_text(encoding="utf-8")
    assert run.at_the_grid_edge(0.5) and run.at_the_grid_edge(0.95) and not run.at_the_grid_edge(0.55)


def test_the_whole_run_sentence_counts_what_the_test_half_holds(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "none.json")
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out), "--no-embedding"]) == 0
    text = (out / "correlation.md").read_text(encoding="utf-8")
    assert "the test half holds 5 of these 9 findings and 0 of the 0 SCA ones" in text
    assert "every finding no label places" not in text
    assert (
        "Threshold: not calibrated (no threshold.json: `make eval-correlation-calibrate` writes it)" in text
    )


def test_the_sca_findings_are_counted_in_each_part() -> None:
    iac = finding("trivy", "KSV-0011", K8S)
    dep = sca("GHSA-29mw-wpgm-hmr9", "pkg:npm/lodash@4.17.20")
    assert run.sca_findings([iac, dep, dep | {"id": "other"}]) == 2
    assert run.sca_findings([iac]) == 0


def test_without_sca_leaves_out_the_sca_findings_and_their_labels() -> None:
    iac = finding("trivy", "KSV-0011", K8S)
    dep = sca("GHSA-29mw-wpgm-hmr9", "pkg:npm/lodash@4.17.20")
    kept, truth = run.without_sca([iac, dep], {iac["id"]: "A", dep["id"]: "B"})
    assert kept == [iac] and truth == {iac["id"]: "A"}


def test_the_package_key_is_an_sca_findings_and_leaves_the_version_out() -> None:
    old, new = sca("GHSA-a", "pkg:npm/lodash@4.17.20"), sca("GHSA-b", "pkg:npm/lodash@4.17.21")
    assert run._package(old) == run._package(new) is not None, "one package in two versions: one upgrade"
    assert run._package(old | {"category": "CONTAINER"}) is None, "only SCA findings have a package key"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"threshold": 0.8}', "cannot be read: KeyError"),
        ("not json", "cannot be read: JSONDecodeError"),
        ('{"embedding_model": {"name": "test-embedding:1", "digest": "sha256:' + "0" * 64 + '"}, '
         '"threshold": true}', "holds no similarity threshold"),
        ('{"embedding_model": {"name": "test-embedding:1", "digest": "sha256:' + "0" * 64 + '"}, '
         '"threshold": 1.5}', "holds no similarity threshold"),
    ],
)  # fmt: skip
def test_a_threshold_file_that_cannot_be_read_is_refused(text: str, message: str) -> None:
    with pytest.raises(run.EvalError, match=message):
        run.read_threshold(text, MODEL)


@pytest.mark.parametrize("failed", ["gitleaks", "grype", "opengrep", "trivy", "zizmor"])
def test_a_run_without_a_scanners_findings_is_refused(
    findings_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], failed: str
) -> None:
    """A scanner that failed or was skipped in `make eval` writes no file: measuring the rest would report a
    smaller run as demo-shop's (on the laptop, a relative --tools-dir once left out Grype and Opengrep)."""
    (findings_dir / f"{failed}.ndjson").unlink()
    assert run.main(["--findings", str(findings_dir), "--no-embedding", "--out", str(tmp_path / "out")]) == 2
    assert f"{failed}.ndjson missing in" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_the_scanners_required_are_those_make_eval_runs() -> None:
    """#90 review, nit 1: a scanner `make eval` runs but this measurement does not require would be left out
    quietly, the smaller-run case the guard is for."""
    path = Path(__file__).resolve().parents[2] / "eval" / "detection" / "run.py"
    spec = importlib.util.spec_from_file_location("sentinel_eval_detection_run_for_correlation", path)
    assert spec is not None and spec.loader is not None
    detection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(detection)
    assert sorted(run.SCANNERS) == sorted(detection.SCANS)


def test_the_whole_run_sentence_takes_each_sca_count_from_its_own_part(
    findings_dir: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#90 review, nit 2: the fixture has no SCA finding, so each part gets its own count, read back."""
    monkeypatch.setattr(run, "THRESHOLD", tmp_path / "none.json")
    out = tmp_path / "out"
    assert run.main(["--findings", str(findings_dir), "--out", str(out), "--no-embedding"]) == 0
    report = json.loads((out / "correlation.json").read_text(encoding="utf-8"))
    report["test"]["sca_findings"], report["whole_run"]["sca_findings"] = 3, 7
    assert "and 3 of the 7 SCA ones" in run.markdown(report)


def test_no_findings_is_an_error_that_says_what_to_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run.main(["--findings", str(tmp_path), "--no-embedding"]) == 2
    assert "run `make eval` first" in capsys.readouterr().err
