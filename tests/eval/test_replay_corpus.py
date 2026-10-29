"""The nightly replay corpus (eval/replay/corpus.py) records every case and replays identically."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app

ROOT = Path(__file__).resolve().parents[2]


def load_corpus() -> ModuleType:
    spec = importlib.util.spec_from_file_location("replay_corpus", ROOT / "eval" / "replay" / "corpus.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


corpus = load_corpus()


def test_the_corpus_covers_pass_and_every_implemented_block_rule() -> None:
    names = {case.name for case in corpus.CASES}
    assert {
        "release-secret",
        "release-waiver-without-owner",
        "release-scanner-timeout",
    } <= names  # SC-001/5/10
    assert {case.expected for case in corpus.CASES} == {"PASS", "BLOCK"}
    assert len(names) == len(corpus.CASES)


def test_recording_then_replaying_the_corpus_is_identical(tmp_path: Path, opa_binary: Path) -> None:
    recorded = corpus.record(tmp_path / "store", tmp_path / "work", opa_binary)
    assert {name: r["verdict"] for name, r in recorded.items()} == {c.name: c.expected for c in corpus.CASES}
    decisions = sorted(p.stem for p in (tmp_path / "store" / "decisions").glob("*.json"))
    assert decisions == sorted(r["decision_id"] for r in recorded.values())

    result = CliRunner().invoke(
        app, ["replay", "--all", "--store", str(tmp_path / "store"), "--opa", str(opa_binary)]
    )
    assert result.exit_code == 0, result.output
    assert f"{len(corpus.CASES)} identical, 0 skipped, 0 differ, 0 cannot replay" in result.output


def test_recording_twice_gives_the_same_decisions(tmp_path: Path, opa_binary: Path) -> None:
    first = corpus.record(tmp_path / "a", tmp_path / "work-a", opa_binary)
    second = corpus.record(tmp_path / "b", tmp_path / "work-b", opa_binary)
    assert first == second


def test_a_case_that_stops_giving_its_verdict_fails_the_recording(
    tmp_path: Path, opa_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrong = corpus.Case("release-secret", "PASS", findings=(corpus.IN_CONFIG,))
    monkeypatch.setattr(corpus, "CASES", (wrong,))
    assert (
        corpus.main(
            ["--store", str(tmp_path / "store"), "--work", str(tmp_path / "w"), "--opa", str(opa_binary)]
        )
        == 1
    )


def test_main_prints_one_line_per_case(
    tmp_path: Path, opa_binary: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = corpus.main(
        ["--store", str(tmp_path / "store"), "--work", str(tmp_path / "w"), "--opa", str(opa_binary)]
    )
    assert code == 0
    # `sentinel evaluate` prints its own report per case first; the corpus table comes last.
    table = capsys.readouterr().out.splitlines()[-len(corpus.CASES) :]
    assert [line.split()[-1] for line in table] == [case.name for case in corpus.CASES]
    assert [line.split()[0] for line in table] == [case.expected for case in corpus.CASES]
