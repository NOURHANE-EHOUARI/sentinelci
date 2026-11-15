"""B8's replay identity (eval/replay/run.py): every recorded decision replayed, and counted."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

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


def test_the_report_says_what_one_checkout_cannot_show() -> None:
    """Recorded and replayed with one engine: drift between versions is the nightly job's (#124 review)."""
    replayed = {
        "results": {A: "identical"},
        "summary": {"identical": 1, "skipped": 0, "differ": 0, "cannot": 0},
    }
    text = run.markdown(run.report({"one": {"decision_id": A, "verdict": "BLOCK"}}, replayed))
    assert "Same checkout, same tools" in text
    assert "replay-nightly.yml" in text


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


# ------------------------------------------------------------ recorded on one checkout, replayed on another

ONE = {"identical": 1, "skipped": 0, "differ": 0, "cannot": 0}
CHECKOUTS = {
    "recorded": {"commit": "a" * 40, "clean": True},
    "replayed": {"commit": "b" * 40, "clean": False},
}


def _files(directory: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(directory)): p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file()
    }


def test_a_store_recorded_on_one_checkout_is_replayed_on_another(opa_binary: Path, tmp_path: Path) -> None:
    """`--record-to` on one checkout (e.g. main), `--replay-from` on another (e.g. a pull request)."""
    recording, out = tmp_path / "recording", tmp_path / "out"
    assert run.main(["--record-to", str(recording), "--opa", str(opa_binary)]) == 0
    assert sorted(p.name for p in recording.iterdir()) == ["recorded.json", "store"], "recording only"
    manifest = json.loads((recording / "recorded.json").read_text(encoding="utf-8"))
    assert set(manifest["recorded"]) == {case.name for case in run.corpus.CASES}
    assert manifest["checkout"] == run.checkout()
    before = _files(recording)
    assert run.main(["--replay-from", str(recording), "--out", str(out), "--opa", str(opa_binary)]) == 0
    assert _files(recording) == before, "the recording is never changed by a replay"
    data = json.loads((out / "replay.json").read_text(encoding="utf-8"))
    assert data["mode"] == "two checkouts"
    assert data["checkouts"] == {"recorded": manifest["checkout"], "replayed": run.checkout()}
    assert data["identical"] == data["compared"] == data["total"] == len(run.corpus.CASES)


def test_record_to_refuses_a_directory_that_holds_anything(tmp_path: Path, capsys: Any) -> None:
    (tmp_path / "old.json").write_text("{}", encoding="utf-8")
    assert run.main(["--record-to", str(tmp_path)]) == 2
    assert "is not empty" in capsys.readouterr().err
    assert _files(tmp_path) == {"old.json": b"{}"}


@pytest.mark.parametrize(
    ("manifest", "message"),
    [(None, "no recorded.json"), ("[]", "not a recording"), ('{"recorded": {}}', "not a recording")],
    ids=["missing", "not-an-object", "no-checkout"],
)
def test_replay_from_something_that_is_not_a_recording_cannot_measure(
    tmp_path: Path, capsys: Any, manifest: str | None, message: str
) -> None:
    recording = tmp_path / "recording"
    (recording / "store").mkdir(parents=True)
    if manifest is not None:
        (recording / "recorded.json").write_text(manifest, encoding="utf-8")
    assert run.main(["--replay-from", str(recording), "--out", str(tmp_path / "out")]) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [["--record-to", "a", "--replay-from", "b"], ["--replay-from", "b", "--findings", "f"]],
    ids=["both-modes", "findings-on-replay"],
)
def test_one_mode_at_a_time_and_the_findings_are_recorded_not_replayed(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        run.main(argv)
    assert exited.value.code == 2


def test_across_checkouts_a_skipped_decision_is_listed_and_not_compared() -> None:
    """Another engine or OPA version on the replaying side: `sentinel replay` skips it, compares nothing."""
    recorded = {"one": {"decision_id": A, "verdict": "BLOCK"}, "two": {"decision_id": B, "verdict": "PASS"}}
    replayed = {
        "results": {A: "identical", B: "skipped"},
        "summary": {"identical": 1, "skipped": 1, "differ": 0, "cannot": 0},
    }
    data = run.report(recorded, replayed, CHECKOUTS)
    assert (data["identical"], data["compared"], data["total"], data["identity"]) == (1, 1, 2, 1.0)
    assert run.exit_code(data) == 0
    text = run.markdown(data)
    assert "**1 of 1 compared decisions replay identically (100.0%).**" in text
    assert "1 skipped" in text
    every_skipped = {
        "results": {A: "skipped"},
        "summary": {"identical": 0, "skipped": 1, "differ": 0, "cannot": 0},
    }
    nothing = run.report({"one": recorded["one"]}, every_skipped, CHECKOUTS)
    assert (nothing["compared"], nothing["identity"], run.exit_code(nothing)) == (0, None, 2)


def test_in_one_run_a_skipped_decision_is_a_failure() -> None:
    """Recorded and replayed by the same engine, nothing may be skipped: skipping would hide an edit."""
    replayed = {
        "results": {A: "skipped"},
        "summary": {"identical": 0, "skipped": 1, "differ": 0, "cannot": 0},
    }
    data = run.report({"one": {"decision_id": A, "verdict": "BLOCK"}}, replayed)
    assert (data["identical"], data["compared"], data["total"]) == (0, 1, 1)
    assert run.exit_code(data) == 1


def test_across_checkouts_a_decision_that_differs_fails_the_run() -> None:
    replayed = {
        "results": {A: "differs"},
        "summary": {"identical": 0, "skipped": 0, "differ": 1, "cannot": 0},
    }
    data = run.report({"one": {"decision_id": A, "verdict": "BLOCK"}}, replayed, CHECKOUTS)
    assert run.exit_code(data) == 1


def test_the_report_names_both_checkouts_and_what_it_compares() -> None:
    replayed = {"results": {A: "identical"}, "summary": ONE}
    text = run.markdown(run.report({"one": {"decision_id": A, "verdict": "BLOCK"}}, replayed, CHECKOUTS))
    assert f"Recorded on `{'a' * 40}`, replayed on `{'b' * 40}` (uncommitted changes)" in text
    assert "the stored policy bundle" in text
    assert "Same checkout, same tools" not in text


def test_a_checkout_with_uncommitted_changes_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    git("add", "a.txt")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "a")
    monkeypatch.setattr(run, "ROOT", tmp_path)
    clean = run.checkout()
    assert clean["clean"] is True and len(clean["commit"]) == 40
    (tmp_path / "b.txt").write_text("b\n", encoding="utf-8")
    assert run.checkout() == {"commit": clean["commit"], "clean": False}


def test_a_store_decision_the_recording_does_not_list_is_refused() -> None:
    """Replayed but not counted, a decision that differs would hide: store and recording must agree."""
    recorded = {"a": {"decision_id": A, "verdict": "BLOCK"}}
    replayed = {"results": {A: "identical", B: "differs"}, "summary": {"identical": 1, "differ": 1}}
    with pytest.raises(run.EvalError, match=f"does not list \\({B}\\)"):
        run.report(recorded, replayed)
