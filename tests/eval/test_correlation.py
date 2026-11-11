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
    assert {s["threshold"] for s in test["sensitivity"]} == set(run.grid())
    assert report["inputs"]["threshold_sha256"] == hashlib.sha256(model.read_bytes()).hexdigest()

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


def test_no_findings_is_an_error_that_says_what_to_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run.main(["--findings", str(tmp_path), "--no-embedding"]) == 2
    assert "run `make eval` first" in capsys.readouterr().err
