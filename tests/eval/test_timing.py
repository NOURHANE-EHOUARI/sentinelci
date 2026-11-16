"""B8's pipeline timing (eval/timing/run.py): each gate step on demo-shop, timed over N runs, p50 and p95."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_run() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sentinel_eval_timing_run", ROOT / "eval/timing/run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run = _load_run()


@pytest.mark.parametrize(
    ("values", "p50", "p95"),
    [
        ([4.0], 4.0, 4.0),
        ([3.0, 1.0, 2.0], 2.0, 3.0),
        ([float(v) for v in range(1, 21)], 10.0, 19.0),
        ([float(v) for v in range(1, 101)], 50.0, 95.0),
    ],
    ids=["one", "three", "twenty", "hundred"],
)
def test_percentiles_are_nearest_rank(values: list[float], p50: float, p95: float) -> None:
    """Nearest rank: always one of the measured values, never an interpolation between two runs."""
    assert run.percentile(values, 50) == p50
    assert run.percentile(values, 95) == p95


def test_no_value_has_no_percentile() -> None:
    with pytest.raises(ValueError, match="no value"):
        run.percentile([], 50)


class Clock:
    """A clock that advances by the scripted durations, one per step, in order."""

    def __init__(self, durations: list[float]) -> None:
        self.now = 0.0
        self.durations: Iterator[float] = iter(durations)
        self.started = False

    def __call__(self) -> float:
        if self.started:
            self.now += next(self.durations)
        self.started = not self.started
        return self.now


def ok(step: str, out: Path) -> tuple[bool, str | None, str]:
    return True, f"{step} 1.0.0", ""


def test_each_step_is_timed_and_the_report_has_p50_and_p95(tmp_path: Path) -> None:
    steps = list(run.STEPS)
    # Three runs; in each, every step takes (run number) seconds, except evaluate, which takes 0.5 s.
    durations = [float(r) if step != "evaluate" else 0.5 for r in (1, 2, 3) for step in steps]
    data = run.measure(3, step=ok, clock=Clock(durations), work=tmp_path)
    assert data["runs"] == 3
    assert data["steps"]["gitleaks"] == {"p50": 2.0, "p95": 3.0, "min": 1.0, "max": 3.0}
    assert data["steps"]["evaluate"] == {"p50": 0.5, "p95": 0.5, "min": 0.5, "max": 0.5}
    scans = len(steps) - 1
    assert data["total"]["p50"] == 2.0 * scans + 0.5 and data["total"]["p95"] == 3.0 * scans + 0.5
    assert data["target"] == {
        "p95_seconds": 600,
        "passes_per_pull_request": 2,
        "pull_request_p95_estimate": 2 * data["total"]["p95"],
        "met_here": True,
    }
    assert data["versions"]["gitleaks"] == "1.0.0"


def test_the_target_is_said_missed_when_the_p95_is_over_ten_minutes(tmp_path: Path) -> None:
    durations = [200.0 for _ in run.STEPS]
    data = run.measure(1, step=ok, clock=Clock(durations), work=tmp_path)
    assert data["total"]["p95"] > 600
    assert data["target"]["met_here"] is False
    assert "not met on this machine" in run.markdown(data)


def test_a_pull_request_scans_twice_so_the_target_takes_two_passes(tmp_path: Path) -> None:
    """sentinel-scan.yml scans the head, then the base as the baseline (#145 review): one pass of 301 s
    is under ten minutes, but a pull request's two passes are not."""
    durations = [301.0 if step == "gitleaks" else 0.0 for step in run.STEPS]
    data = run.measure(1, step=ok, clock=Clock(durations), work=tmp_path)
    assert data["total"]["p95"] == 301.0
    assert data["target"]["pull_request_p95_estimate"] == 602.0
    assert data["target"]["met_here"] is False
    text = run.markdown(data)
    assert "**One pass of the gate's steps on this machine: p50 301.0 s, p95 301.0 s over 1 run.**" in text
    assert "scans its head and then its base" in text
    assert "about 602.0 s" in text


def test_the_first_run_is_reported_on_its_own(tmp_path: Path) -> None:
    """The first run is cold (tool caches, the page cache of the Grype database), as a CI job always is."""
    per_run = [9.0, 1.0, 1.0]
    durations = [seconds if step == "gitleaks" else 0.0 for seconds in per_run for step in run.STEPS]
    data = run.measure(3, step=ok, clock=Clock(durations), work=tmp_path)
    assert data["first_run_seconds"] == 9.0
    assert "Run 1 took 9.0 s" in run.markdown(data)


def test_a_step_that_fails_stops_the_measurement(tmp_path: Path) -> None:
    def failing(step: str, out: Path) -> tuple[bool, str | None, str]:
        return (False, None, "exit 2: no Grype database") if step == "grype" else ok(step, out)

    with pytest.raises(run.EvalError, match="grype failed in run 1: exit 2: no Grype database"):
        run.measure(2, step=failing, clock=Clock([1.0] * 20), work=tmp_path)


def test_at_least_one_run(tmp_path: Path) -> None:
    with pytest.raises(run.EvalError, match="at least 1 run"):
        run.measure(0, step=ok, clock=Clock([]), work=tmp_path)


def test_the_steps_are_the_gates_and_make_evals(tmp_path: Path) -> None:
    """The five scans make eval runs, then the decision on their findings."""
    assert list(run.STEPS) == [*run.detection.SCANS, "evaluate"]


def test_the_report_says_what_it_measures_and_what_it_does_not(tmp_path: Path) -> None:
    data = run.measure(5, step=ok, clock=Clock([1.0] * 5 * len(run.STEPS)), work=tmp_path)
    text = run.markdown(data)
    assert "**One pass of the gate's steps on this machine: p50 6.0 s, p95 6.0 s over 5 runs.**" in text
    assert "not a CI measurement" in text
    assert "tool downloads" in text
    assert "with 5 runs, p95 is the slowest run (fewer than 20 runs)" in text
    assert "| gitleaks | 1.0 | 1.0 | 1.0 | 1.0 |" in text
    assert json.loads(json.dumps(data)) == data, "the report is JSON as it is"


def test_the_environment_is_recorded(tmp_path: Path) -> None:
    data = run.measure(1, step=ok, clock=Clock([1.0] * len(run.STEPS)), work=tmp_path)
    assert set(data["environment"]) == {"platform", "python", "cpus"}
    assert isinstance(data["environment"]["cpus"], int)


def test_main_writes_the_report_and_exits_2_when_it_cannot_measure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    def failing(*_: Any, **__: Any) -> dict[str, Any]:
        raise run.EvalError("gitleaks failed in run 1: exit 3: tampered binary")

    monkeypatch.setattr(run, "measure", failing)
    assert run.main(["--out", str(tmp_path)]) == 2
    assert "tampered binary" in capsys.readouterr().err
    assert not (tmp_path / "timing.json").exists()


def test_the_target_is_the_p95_not_the_p50(tmp_path: Path) -> None:
    """Twenty runs, two of them slow: p50 is well under ten minutes, p95 (the 19th run) is over."""
    per_run = [1.0] * 18 + [700.0] * 2
    durations = [seconds if step == "gitleaks" else 0.0 for seconds in per_run for step in run.STEPS]
    data = run.measure(20, step=ok, clock=Clock(durations), work=tmp_path)
    assert (data["total"]["p50"], data["total"]["p95"]) == (1.0, 700.0)
    assert data["target"]["met_here"] is False


def test_with_twenty_runs_the_p95_is_not_called_the_slowest_runs_only(tmp_path: Path) -> None:
    few = run.measure(5, step=ok, clock=Clock([1.0] * 5 * len(run.STEPS)), work=tmp_path)
    many = run.measure(20, step=ok, clock=Clock([1.0] * 20 * len(run.STEPS)), work=tmp_path)
    assert "(fewer than 20 runs)" in run.markdown(few)
    assert "(fewer than 20 runs)" not in run.markdown(many)
    assert "p95 is run 19 of 20, sorted from fastest to slowest" in run.markdown(many)
    assert "slowest run" not in run.markdown(many), "with 20 runs, p95 is not the slowest"


class Done:
    def __init__(self, returncode: int) -> None:
        self.returncode, self.stdout, self.stderr = returncode, "", "Error: the policy bundle is broken"


@pytest.mark.parametrize(
    ("returncode", "writes", "made"),
    [(0, True, True), (1, True, True), (1, False, False), (3, False, False)],
    ids=["pass", "block", "block-without-a-decision", "error"],
)
def test_the_evaluate_step_counts_only_a_decision_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int, writes: bool, made: bool
) -> None:
    """A BLOCK (exit 1) is a decision, as a PASS is; an error, or no decision file, fails the step."""
    for tool in run.detection.SCANS:
        (tmp_path / f"{tool}.ndjson").write_bytes(b"")

    def fake_run(command: list[str], **_: Any) -> Done:
        if writes:
            Path(command[command.index("--output") + 1]).write_text("{}", encoding="utf-8")
        return Done(returncode)

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    args = run.argparse.Namespace(opa=None)
    succeeded, _, reason = run.cli_step(args)("evaluate", tmp_path)
    assert succeeded is made
    if not made:
        assert reason.startswith(f"exit {returncode}: ")
