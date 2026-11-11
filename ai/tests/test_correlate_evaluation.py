"""How the correlator is measured (task A7 acceptance, SPEC section 17): ablation, the ARI against the
threshold, calibration. The embedder is deterministic, so the tests say what each measure does."""

import hashlib
from typing import Any

import pytest

from sentinel_ai.correlate import CorrelationError
from sentinel_ai.correlate.evaluation import (
    CONFIGURATIONS,
    ablation,
    cached,
    calibrate,
    grid,
    score,
    sweep,
    truth_of,
)


def fid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def finding(category: str, rule: str, path: str, title: str, *, purl: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": fid(category, rule, path, purl or "", title), "tool": {"name": "t", "version": "1"},
        "rule_id": rule, "category": category, "title": title, "message": title, "severity": "HIGH",
        "location": {"path": path, "start_line": 1},
    }  # fmt: skip
    if purl is not None:
        name, _, version = purl.split("/")[-1].partition("@")
        record["package"] = {"purl": purl, "name": name, "version": version, "ecosystem": "npm"}
    return record


# Two lodash advisories (one upgrade), the same rule twice in one file, three SQL findings in three files that
# only an embedding can bring together, and a debug finding with a root cause of its own; a seed-less finding
# is left out of the ARI.
LODASH = [
    finding("SCA", f"GHSA-{n}", "package-lock.json", f"lodash advisory {n}", purl="pkg:npm/lodash@4.17.20")
    for n in ("a", "b")
]
ROOT_USER = [finding("IAC", "KSV-0014", "infra/k8s/web.yaml", f"runs as root, line {n}") for n in (1, 2)]
SQL = [
    finding("SAST", f"sql-{n}", f"app/{n}.py", "SQL built from strings") for n in ("db", "orders", "reports")
]
DEBUG = finding("SAST", "debug", "app/main.py", "debug mode enabled")
UNSEEDED = finding("IAC", "KSV-0011", "infra/k8s/api.yaml", "no CPU limits")
FINDINGS = [*LODASH, *ROOT_USER, *SQL, DEBUG, UNSEEDED]
TRUTH = (
    {f["id"]: "lodash" for f in LODASH} | {f["id"]: "root" for f in ROOT_USER} | {f["id"]: "sql" for f in SQL}
    | {DEBUG["id"]: "debug"}
)  # fmt: skip

TOPICS = {
    "sql": [1.0, 0.0, 0.0],
    "root": [0.0, 1.0, 0.0],
    "lodash": [0.0, 0.0, 1.0],
    "debug": [0.6, 0.0, 0.8],
}


class Embedder:
    """Vectors from the topics a text mentions; counts the texts it is asked for."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def __call__(self, texts: list[str]) -> list[list[float]]:
        self.asked.extend(texts)
        return [[sum(v[i] for word, v in TOPICS.items() if word in text.lower()) + 0.01 for i in range(3)]
                for text in texts]  # fmt: skip


def test_each_stage_is_measured_on_its_own() -> None:
    scores = {s.configuration: s for s in ablation(FINDINGS, TRUTH, embed=Embedder(), threshold=0.9)}
    assert list(scores) == list(CONFIGURATIONS)
    assert scores["dedup"].groups == len(FINDINGS) and scores["dedup"].alert_reduction == 0.0
    assert scores["dedup+structural"].groups == len(FINDINGS) - 2, "one upgrade, one repeated rule"
    assert scores["dedup+structural+embedding"].ari == 1.0, "the SQL findings join through their texts"
    assert scores["dedup"].ari < scores["dedup+structural"].ari < scores["dedup+structural+embedding"].ari
    assert all(s.unlabelled == (UNSEEDED["id"],) for s in scores.values()), "listed, never guessed"
    assert scores["dedup"].threshold is None and scores["dedup+embedding"].threshold == 0.9


def test_without_an_embedder_the_embedding_configurations_are_not_run() -> None:
    assert [s.configuration for s in ablation(FINDINGS, TRUTH)] == ["dedup", "dedup+structural"]
    with pytest.raises(CorrelationError, match="needs an embedder"):
        score(FINDINGS, TRUTH, configuration="dedup+embedding")
    with pytest.raises(CorrelationError, match="unknown configuration"):
        score(FINDINGS, TRUTH, configuration="llm")


def test_alert_reduction_counts_raw_tool_reports_when_given() -> None:
    """Two tools reporting each of the 9 findings: 18 raw alerts, 7 groups after stage 2a."""
    measured = score(FINDINGS, TRUTH, configuration="dedup+structural", raw_alerts=2 * len(FINDINGS))
    assert (measured.alerts, measured.groups) == (18, 7)
    assert measured.alert_reduction == round(1 - 7 / 18, 6)
    with pytest.raises(CorrelationError, match="cannot hold"):
        score(FINDINGS, TRUTH, configuration="dedup", raw_alerts=3)


def test_the_ari_needs_two_labelled_findings() -> None:
    with pytest.raises(CorrelationError, match="at least two labelled"):
        score(FINDINGS, {LODASH[0]["id"]: "lodash"}, configuration="dedup")


def test_the_sweep_embeds_each_text_once_and_merges_less_as_the_threshold_rises() -> None:
    embedder = Embedder()
    curve = sweep(FINDINGS, TRUTH, embedder, [0.99, 0.5, 0.9, 0.9])
    assert [s.threshold for s in curve] == [0.5, 0.9, 0.99], "sorted, each once"
    assert len(embedder.asked) == len(set(embedder.asked)), "every text embedded once for the whole sweep"
    assert [s.groups for s in curve] == sorted(s.groups for s in curve), "a higher threshold merges less"
    assert curve[1].ari == 1.0 and curve[0].ari < 1.0, "at 0.5 the debug finding joins the SQL ones"


def test_calibration_takes_the_best_ari_and_the_highest_threshold_on_a_tie() -> None:
    best = calibrate(FINDINGS, TRUTH, Embedder(), grid(0.5, 0.95, 0.05))
    tied = [s.threshold for s in sweep(FINDINGS, TRUTH, Embedder(), grid()) if s.ari == best.ari]
    assert best.ari == 1.0 and best.threshold == max(t for t in tied if t is not None)
    with pytest.raises(CorrelationError, match="at least one threshold"):
        calibrate(FINDINGS, TRUTH, Embedder(), [])


def test_a_grid_is_rounded_and_includes_its_ends() -> None:
    assert grid(0.7, 0.9, 0.1) == [0.7, 0.8, 0.9]
    assert grid() == [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]
    for start, stop, step in [(0.9, 0.5, 0.1), (0.5, 0.9, 0.0)]:
        with pytest.raises(CorrelationError):
            grid(start, stop, step)


def test_the_cache_refuses_an_embedder_that_does_not_answer_each_text() -> None:
    embed = cached(lambda texts: [[1.0]])
    with pytest.raises(CorrelationError, match="one vector per text"):
        embed(["a", "b"])


def test_truth_comes_from_the_labelled_set_and_must_agree_with_itself() -> None:
    seeds = {"lodash": "GT-SCA-003", "root": "GT-IAC-002"}

    def seed(record: dict[str, Any]) -> str | None:
        return next((value for word, value in seeds.items() if word in record["title"]), None)

    truth = truth_of(FINDINGS, seed)
    assert truth == {f["id"]: "GT-SCA-003" for f in LODASH} | {f["id"]: "GT-IAC-002" for f in ROOT_USER}
    twice = [LODASH[0], LODASH[0] | {"title": "runs as root"}]
    with pytest.raises(CorrelationError, match="two true root causes"):
        truth_of(twice, seed)
