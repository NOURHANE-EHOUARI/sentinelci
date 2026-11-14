"""B8's replay identity (eval/replay/run.py): every recorded decision replayed, and counted."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_run() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sentinel_eval_replay_run", ROOT / "eval/replay/run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run = _load_run()
A = "626cc3bd-75c8-587f-b463-8adc362dc469"
B = "6bdde2ea-6af6-55d7-97e0-ba9f3c6251f0"
C = "6dbb22a7-32de-5614-b80f-8d488975a605"
D = "908d5291-97de-5272-9caa-1c27df79dba0"


def test_the_replay_output_is_read_line_by_line_and_checked_against_its_summary() -> None:
    output = (
        f"identical  {A} (BLOCK)\n"
        f"differs    {B} (field: recorded -> replayed)\n"
        "  verdict: PASS -> BLOCK\n"
        f"cannot replay {C}: the record was edited\n"
        f"skipped    {D} (engine 0.1.0)\n"
        "1 identical, 1 skipped, 1 differ, 1 cannot replay\n"
    )
    parsed = run.parse(output)
    assert parsed["results"] == {A: "identical", B: "differs", C: "cannot replay", D: "skipped"}
    assert parsed["summary"] == {"identical": 1, "skipped": 1, "differ": 1, "cannot": 1}


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (f"identical  {A} (BLOCK)\n", "printed no summary line"),
        (
            f"identical  {A} (BLOCK)\n2 identical, 0 skipped, 0 differ, 0 cannot replay\n",
            "counts 2 decisions",
        ),
    ],
    ids=["no-summary", "summary-disagrees"],
)
def test_an_output_that_cannot_be_trusted_is_refused(output: str, message: str) -> None:
    with pytest.raises(run.EvalError, match=message):
        run.parse(output)


def test_a_decision_the_replay_did_not_report_is_not_counted_as_identical() -> None:
    recorded = {"one": {"decision_id": A, "verdict": "BLOCK"}, "two": {"decision_id": B, "verdict": "PASS"}}
    replayed = {
        "results": {A: "identical"},
        "summary": {"identical": 1, "skipped": 0, "differ": 0, "cannot": 0},
    }
    data = run.report(recorded, replayed)
    assert (data["identical"], data["total"], data["identity"]) == (1, 2, 0.5)
    assert data["decisions"]["two"]["replay"] == "not replayed"
    assert "**1 of 2 decisions replay identically (50.0%).**" in run.markdown(data)


def test_the_corpus_replays_identically(opa_binary: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert run.main(["--out", str(out), "--opa", str(opa_binary)]) == 0
    data = json.loads((out / "replay.json").read_text(encoding="utf-8"))
    assert data["identical"] == data["total"] == len(run.corpus.CASES)
    assert {entry["replay"] for entry in data["decisions"].values()} == {"identical"}


def test_an_edited_record_is_reported_and_fails_the_run(opa_binary: Path, tmp_path: Path) -> None:
    """A stored decision changed after it was recorded must not count as identical."""
    store, work = tmp_path / "store", tmp_path / "work"
    recorded = run.corpus.record(store, work, opa_binary)
    victim = recorded["release-secret"]["decision_id"]
    path = store / "decisions" / f"{victim}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["verdict"] == "BLOCK"
    record["verdict"] = "PASS"
    path.write_text(json.dumps(record), encoding="utf-8")
    data = run.report(recorded, run.replay(store, opa_binary))
    assert data["decisions"]["release-secret"]["replay"] != "identical"
    assert data["identical"] == data["total"] - 1


def test_without_make_evals_findings_it_says_so(tmp_path: Path) -> None:
    with pytest.raises(run.EvalError, match=r"no gitleaks\.ndjson"):
        run.record_demo_shop(tmp_path, tmp_path / "store", tmp_path / "work", None)
