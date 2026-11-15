"""B8's explanation rubric (eval/explanations/run.py): explanations rated by people and by an LLM judge, and
their agreement as Cohen's kappa (SPEC section 17)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"


def _load_run() -> ModuleType:
    path = ROOT / "eval/explanations/run.py"
    spec = importlib.util.spec_from_file_location("sentinel_eval_explanations_run", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run = _load_run()
SCA = json.loads((VALID / "sca-enriched-and-scored.json").read_text(encoding="utf-8"))
SECRET = json.loads((VALID / "secret-in-config.json").read_text(encoding="utf-8"))
CONTAINER = json.loads((VALID / "container-os-package.json").read_text(encoding="utf-8"))
TRUTH = {
    "version": 1,
    "seeds": [
        {"id": "GT-SCA-900", "category": "SCA", "title": "example-lib runs code",
         "package": SCA["package"]["purl"],
         "expected": {"detections": [{"tool": "grype", "rule": "CVE-2099-0001"}]}},
        {"id": "GT-SECRET-900", "category": "SECRET", "title": "an API key",
         "location": {"path": "services/shop-api/app/config.py", "line": 12},
         "expected": {"detections": [{"tool": "gitleaks", "rule": "generic-api-key"}]}},
        {"id": "GT-CONTAINER-900", "category": "CONTAINER", "title": "old openssl", "package": "pkg:deb/x@1",
         "expected": {"detections": [{"tool": "trivy", "rule": "CVE-2099-0002"}]}},
    ],
}  # fmt: skip
ANSWER = {
    "summary": "example-lib 1.2.0 runs code from crafted input.",
    "impact": "An attacker who controls the input runs code as the service.",
    "exploit_scenario": "A crafted document given to the parser runs a command.",
    "fix_guidance": "Upgrade example-lib to a fixed version.",
    "references": [],
    "confidence": 0.8,
}


class Scripted:
    """A model that gives the scripted answers, in order, and records what it was asked."""

    name = "fake"

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, schema: type[Any]) -> Any:
        self.calls.append((system, user))
        return schema.model_validate(self.answers.pop(0))

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise AssertionError("never embeds")


# ---------------------------------------------------------------- Cohen's kappa


@pytest.mark.parametrize(
    ("a", "b", "kappa"),
    [
        ([True, True, False, False], [True, True, False, False], 1.0),
        ([True, False, True, False], [False, True, False, True], -1.0),
        # 20 items: 7 both yes, 2 only a, 3 only b, 8 both no. po = 0.75, pe = 0.45*0.5 + 0.55*0.5 = 0.5.
        (
            [True] * 7 + [True] * 2 + [False] * 3 + [False] * 8,
            [True] * 7 + [False] * 2 + [True] * 3 + [False] * 8,
            0.5,
        ),
    ],
    ids=["perfect", "opposite", "half"],
)
def test_cohens_kappa(a: list[bool], b: list[bool], kappa: float) -> None:
    assert run.cohens_kappa(a, b) == pytest.approx(kappa)


def test_kappa_is_undefined_when_both_raters_never_vary() -> None:
    """Every rating the same on both sides: chance agreement is 1, kappa is 0/0: said, never 0 or 1"""
    assert run.cohens_kappa([True, True, True], [True, True, True]) is None


def test_kappa_needs_the_same_items_rated() -> None:
    with pytest.raises(ValueError, match="same number"):
        run.cohens_kappa([True], [True, False])


@pytest.mark.parametrize(
    ("kappa", "label"),
    [(None, "undefined"), (-0.1, "poor"), (0.1, "slight"), (0.3, "fair"), (0.5, "moderate"),
     (0.7, "substantial"), (0.9, "almost perfect")],
)  # fmt: skip
def test_kappa_is_named_on_landis_and_kochs_scale(kappa: float | None, label: str) -> None:
    assert run.agreement(kappa) == label


# ---------------------------------------------------------------- generate


def test_one_explanation_per_seed_a_scanner_found_and_never_a_secret(tmp_path: Path) -> None:
    other_sca = SCA | {"id": "f" * 64}
    findings = [SECRET, other_sca, SCA, CONTAINER]
    chosen = run.select(TRUTH, findings)
    # The first matching finding by id, for each seed; the secret's seed is left out; a seed no finding
    # detects (the container seed, whose package differs) is listed as not found.
    assert [(seed["id"], finding["id"] if finding else None) for seed, finding in chosen] == [
        ("GT-CONTAINER-900", None),
        ("GT-SCA-900", SCA["id"]),
    ]


def test_generate_writes_the_explanations_and_a_blank_sheet(tmp_path: Path) -> None:
    provider = Scripted(ANSWER)
    run.generate(TRUTH, [SECRET, SCA, CONTAINER], provider, run.ModelInfo("fake-model"), tmp_path)
    explained = json.loads((tmp_path / "explanations.json").read_text(encoding="utf-8"))
    assert explained["items"]["GT-SCA-900"]["status"] == "explained"
    assert explained["items"]["GT-SCA-900"]["explanation"]["summary"] == ANSWER["summary"]
    assert explained["items"]["GT-CONTAINER-900"] == {"status": "not found", "finding_id": None}
    assert len(provider.calls) == 1 and SECRET["id"] not in json.dumps(provider.calls)
    sheet = yaml.safe_load((tmp_path / "sheet.yaml").read_text(encoding="utf-8"))
    assert sheet["rater"] is None
    assert [item["seed"] for item in sheet["items"]] == ["GT-SCA-900"], "only what was explained is rated"
    assert sheet["items"][0]["ratings"] == dict.fromkeys(run.RUBRIC), "no rating is ever pre-filled"
    assert sheet["items"][0]["explanation"]["fix_guidance"] == ANSWER["fix_guidance"]
    assert set(sheet["rubric"]) == set(run.RUBRIC)


# ---------------------------------------------------------------- judge


def test_the_judge_rates_every_item_with_the_rubric_and_writes_a_sheet(tmp_path: Path) -> None:
    run.generate(TRUTH, [SCA], Scripted(ANSWER), run.ModelInfo("fake-model"), tmp_path)
    judge = Scripted({"correct": True, "grounded": True, "fix": False, "clear": True})
    run.judge(tmp_path, judge, run.ModelInfo("judge-model"))
    sheet = yaml.safe_load((tmp_path / "ratings-judge.yaml").read_text(encoding="utf-8"))
    assert sheet["rater"] == "judge-model"
    assert sheet["items"][0]["ratings"] == {"correct": True, "grounded": True, "fix": False, "clear": True}
    system, user = judge.calls[0]
    for question in run.RUBRIC.values():
        assert question in system
    assert "<explanation>" in user and "<finding>" in user and "example-lib runs code" in user
    assert "untrusted" in system


# ---------------------------------------------------------------- report


def write_sheet(directory: Path, name: str, ratings: list[dict[str, Any]]) -> None:
    sheet = yaml.safe_load((directory / "sheet.yaml").read_text(encoding="utf-8"))
    sheet["rater"] = name
    for item, rated in zip(sheet["items"], ratings, strict=True):
        item["ratings"] = rated
    (directory / f"ratings-{name}.yaml").write_text(yaml.safe_dump(sheet), encoding="utf-8")


def two_item_run(tmp_path: Path) -> None:
    truth = {"version": 1, "seeds": [TRUTH["seeds"][0], TRUTH["seeds"][0] | {"id": "GT-SCA-901"}]}
    run.generate(truth, [SCA], Scripted(ANSWER, ANSWER), run.ModelInfo("fake-model"), tmp_path)


YES = dict.fromkeys(run.RUBRIC, True)
NO = dict.fromkeys(run.RUBRIC, False)


def test_the_report_gives_pass_rates_and_kappa_per_criterion_and_pooled(tmp_path: Path) -> None:
    two_item_run(tmp_path)
    second = NO | {"clear": True}  # both people say yes to `clear` for both items
    write_sheet(tmp_path, "hiba", [YES, second])
    write_sheet(tmp_path, "nourhane", [YES, second])
    write_sheet(tmp_path, "judge", [YES, YES])
    data = run.report(tmp_path, ["hiba", "nourhane"], "judge")
    assert data["items"] == 2
    assert data["pass_rate"]["hiba"]["correct"] == 0.5 and data["pass_rate"]["judge"]["correct"] == 1.0
    assert data["kappa"]["hiba vs nourhane"]["correct"] == 1.0
    assert data["kappa"]["hiba vs nourhane"]["clear"] is None  # one answer from both: 0/0
    assert (
        data["kappa"]["hiba vs judge"]["correct"] == 0.0
    )  # only the judge never varies: no better than chance
    assert data["kappa"]["hiba vs nourhane"]["pooled"] == 1.0
    text = run.markdown(data)
    assert "| hiba vs nourhane | 1.00 (almost perfect)" in text
    assert "undefined" in text


@pytest.mark.parametrize(
    ("ratings", "message"),
    [
        ([YES, NO | {"fix": None}], "GT-SCA-901: fix is not rated"),
        ([YES, NO | {"fix": "yes"}], "GT-SCA-901: fix must be true or false"),
        ([YES], "rates 1 items, the sheet has 2"),
    ],
    ids=["blank", "not-a-boolean", "an-item-missing"],
)
def test_an_incomplete_sheet_is_refused(tmp_path: Path, ratings: list[dict[str, Any]], message: str) -> None:
    two_item_run(tmp_path)
    sheet = yaml.safe_load((tmp_path / "sheet.yaml").read_text(encoding="utf-8"))
    sheet["rater"] = "hiba"
    sheet["items"] = [item | {"ratings": rated} for item, rated in zip(sheet["items"], ratings, strict=False)]
    (tmp_path / "ratings-hiba.yaml").write_text(yaml.safe_dump(sheet), encoding="utf-8")
    write_sheet(tmp_path, "nourhane", [YES, NO])
    with pytest.raises(run.EvalError, match=message):
        run.report(tmp_path, ["hiba", "nourhane"], None)


def test_a_sheet_of_other_explanations_is_refused(tmp_path: Path) -> None:
    """A rating belongs to the explanation it was given for: the sheet names each one's sha256."""
    two_item_run(tmp_path)
    write_sheet(tmp_path, "hiba", [YES, NO])
    write_sheet(tmp_path, "nourhane", [YES, NO])
    sheet = yaml.safe_load((tmp_path / "ratings-nourhane.yaml").read_text(encoding="utf-8"))
    sheet["items"][0]["explanation"]["summary"] = "something else"
    (tmp_path / "ratings-nourhane.yaml").write_text(yaml.safe_dump(sheet), encoding="utf-8")
    with pytest.raises(run.EvalError, match="GT-SCA-900: nourhane rated another explanation"):
        run.report(tmp_path, ["hiba", "nourhane"], None)


def test_two_people_are_needed(tmp_path: Path) -> None:
    two_item_run(tmp_path)
    write_sheet(tmp_path, "hiba", [YES, NO])
    with pytest.raises(run.EvalError, match="two people"):
        run.report(tmp_path, ["hiba"], "judge")


def test_without_a_judge_only_people_are_compared(tmp_path: Path) -> None:
    two_item_run(tmp_path)
    write_sheet(tmp_path, "hiba", [YES, NO])
    write_sheet(tmp_path, "nourhane", [NO, NO])
    data = run.report(tmp_path, ["hiba", "nourhane"], None)
    assert list(data["kappa"]) == ["hiba vs nourhane"]
    assert "LLM judge: not run" in run.markdown(data)


class Down:
    name = "down"

    def complete(self, system: str, user: str, schema: type[Any]) -> Any:
        raise ConnectionError("ollama is not running")

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise AssertionError("never embeds")


def test_a_seed_without_an_explanation_is_listed_and_not_rated(tmp_path: Path) -> None:
    """The model failed: the seed says why, and the sheet has nothing to rate for it (never an empty item)."""
    run.generate(TRUTH, [SCA], Down(), run.ModelInfo("fake-model"), tmp_path)
    explained = json.loads((tmp_path / "explanations.json").read_text(encoding="utf-8"))
    assert explained["items"]["GT-SCA-900"]["status"] == "unavailable"
    assert explained["items"]["GT-SCA-900"]["explanation"] is None
    assert yaml.safe_load((tmp_path / "sheet.yaml").read_text(encoding="utf-8"))["items"] == []
