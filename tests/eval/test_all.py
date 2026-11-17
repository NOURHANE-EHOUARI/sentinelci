"""B8's whole evaluation run (eval/all/run.py, `make eval-all`): the checks before anything runs, the order,
what a failed or unmeasured step does to the others, and the manifest.

The steps are stand-ins: a scripted runner returns each command's exit code and writes the reports the step
would write. The environment (git, the scanners, Docker, Ollama) is a fake. Nothing scans, starts a container
or asks a model. One test asks `make -n` for each target's commands, so the run can't drift from the Makefile.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "b" * 64


def _load() -> ModuleType:
    name = "sentinel_eval_all_run"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "eval" / "all" / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


run = _load()


@dataclass
class Fake:
    """The environment: every check passes unless a test says otherwise."""

    clean: bool = True
    tools: str = ""
    docker: str = ""
    image: str = ""
    ollama: str = ""  # both models
    generation: str = ""
    embedding: str = ""

    def commit(self) -> str:
        return "c" * 40

    def dirty(self) -> bool:
        return not self.clean

    def verify_tools(self, tools_dir: Path, report: Path) -> str:
        return self.tools

    def docker_problem(self) -> str:
        return self.docker

    def image_problem(self, image: str) -> str:
        return self.image

    def ollama_problem(self, url: str, model: str) -> str:
        return self.ollama or {"generation": self.generation, "embedding": self.embedding}[model]


@dataclass
class Scripted:
    """Runs no command: answers each step's first script with the exit code given, writes its reports on 0."""

    out: Path
    codes: Mapping[str, int] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], log: Path) -> int:
        self.calls.append(tuple(argv))
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(" ".join(argv) + "\n", encoding="utf-8")
        step = next(s for s in run.STEPS if any(tuple(c) == tuple(argv) for c in s.commands(self.settings)))
        code = self.codes.get(step.name, 0)
        if code == 0 and tuple(argv) == tuple(step.commands(self.settings)[-1]):
            for report in step.reports:
                path = self.out / report
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{step.name}\n", encoding="utf-8")
        return code

    settings: Any = None


def settings(tmp_path: Path, **overrides: object) -> Any:
    values: dict[str, object] = {
        "tools_dir": tmp_path / "tools", "grype_db": tmp_path / "db", "test_image": DIGEST,
        "ollama": "http://127.0.0.1:11434", "runs": 20, "out": tmp_path / "out",
    }  # fmt: skip
    values.update(overrides)
    return run.Settings(**values)


def go(
    tmp_path: Path, fake: Fake | None = None, codes: Mapping[str, int] | None = None,
    steps: Sequence[str] | None = None, allow_dirty: bool = False, **overrides: object,
) -> tuple[int, dict[str, Any], Scripted]:  # fmt: skip
    s = settings(tmp_path, **overrides)
    (tmp_path / "db").mkdir(exist_ok=True)
    (tmp_path / "db" / "vulnerability.db").write_text("db", encoding="utf-8")
    runner = Scripted(out=s.out, codes=codes or {})
    runner.settings = s
    code = run.run_all(s, fake or Fake(), runner, steps=steps, allow_dirty=allow_dirty)
    manifest = json.loads((s.out / "all" / "manifest.json").read_text(encoding="utf-8"))
    return code, manifest, runner


def statuses(manifest: dict[str, Any]) -> dict[str, str]:
    return {step["name"]: step["status"] for step in manifest["steps"]}


# ---------------------------------------------------------------- a full run


def test_every_step_runs_in_order_and_each_report_is_named_by_its_sha256(tmp_path: Path) -> None:
    code, manifest, runner = go(tmp_path)
    assert code == 0
    assert [step["name"] for step in manifest["steps"]] == [step.name for step in run.STEPS]
    assert set(statuses(manifest).values()) == {"measured"}
    assert manifest["commit"] == "c" * 40 and manifest["clean"] is True and manifest["official"] is True
    detection = manifest["steps"][0]
    assert set(detection["reports"]) == {"detection.json", "detection.md"}
    assert all(len(digest) == 64 for digest in detection["reports"].values())
    # explanations runs its two scripts (generate, then judge) as `make eval-explanations` does
    assert sum("eval/explanations/run.py" in call for call in runner.calls) == 2
    summary = (tmp_path / "out" / "all" / "summary.md").read_text(encoding="utf-8")
    assert "8 of 8 steps measured" in summary and "make eval-rubric" in summary


def test_the_manifest_has_no_clock_and_is_the_same_on_a_second_run(tmp_path: Path) -> None:
    _, first, _ = go(tmp_path)
    _, second, _ = go(tmp_path)
    for manifest in (first, second):
        for step in manifest["steps"]:
            step.pop("seconds")
    assert first == second
    text = (tmp_path / "out" / "all" / "manifest.json").read_text(encoding="utf-8")
    assert "2026-" not in text and "T00:" not in text


# ---------------------------------------------------------------- what a step's outcome does to the others


def test_a_step_that_is_not_measured_is_reported_and_the_others_still_run(tmp_path: Path) -> None:
    code, manifest, _ = go(tmp_path, codes={"fixrate": 2})
    assert code == 2
    assert statuses(manifest)["fixrate"] == "not measured"
    assert [n for n, s in statuses(manifest).items() if s != "measured"] == ["fixrate"]
    assert manifest["summary"]["not_measured"] == ["fixrate"]


def test_a_failed_detection_stops_every_step_that_reads_its_findings_but_not_the_others(
    tmp_path: Path,
) -> None:
    code, manifest, _ = go(tmp_path, codes={"detection": 1})
    assert code == 1
    got = statuses(manifest)
    assert got["detection"] == "failed"
    assert got["timing"] == "measured"  # it scans demo-shop itself
    for name in ("ranking", "replay", "correlation", "canaries", "explanations", "fixrate"):
        assert got[name] == "not run", name
        step = next(s for s in manifest["steps"] if s["name"] == name)
        assert "detection" in step["reason"]


def test_a_step_that_exits_0_without_its_report_failed(tmp_path: Path) -> None:
    s = settings(tmp_path)

    class Silent(Scripted):
        def __call__(self, argv: Sequence[str], log: Path) -> int:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text("", encoding="utf-8")
            return 0

    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "vulnerability.db").write_text("db", encoding="utf-8")
    code = run.run_all(s, Fake(), Silent(out=s.out), steps=["ranking"], allow_dirty=False)
    manifest = json.loads((s.out / "all" / "manifest.json").read_text(encoding="utf-8"))
    assert code == 2
    assert manifest["steps"][0]["status"] == "not run"  # detection's reports are not there yet
    s.out.joinpath("findings").mkdir(parents=True)
    for report in ("detection.json", "detection.md"):
        s.out.joinpath(report).write_text("x", encoding="utf-8")
    code = run.run_all(s, Fake(), Silent(out=s.out), steps=["ranking"], allow_dirty=False)
    manifest = json.loads((s.out / "all" / "manifest.json").read_text(encoding="utf-8"))
    assert code == 1 and manifest["steps"][0]["status"] == "failed"
    assert "ranking.json" in manifest["steps"][0]["reason"]


def test_a_subset_runs_on_a_previous_detection_and_checks_only_what_it_needs(tmp_path: Path) -> None:
    go(tmp_path, steps=["detection"])
    code, manifest, runner = go(
        tmp_path, steps=["ranking", "replay"], fake=Fake(ollama="down", docker="down")
    )
    assert code == 0
    assert statuses(manifest) == {"ranking": "measured", "replay": "measured"}
    assert manifest["official"] is False  # a subset is not the 27 November run
    assert not any("detection/run.py" in " ".join(call) for call in runner.calls)


def test_an_unknown_step_is_refused() -> None:
    with pytest.raises(SystemExit):
        run.main(["--steps", "detection,everything"])


# ---------------------------------------------------------------- the checks before anything runs


@pytest.mark.parametrize(
    ("fake", "said"),
    [
        (Fake(tools="opengrep: sha256 differs from tools.lock.toml"), "opengrep"),
        (Fake(docker="no Docker daemon answers"), "Docker"),
        (Fake(image="not present"), "not present"),
        (Fake(ollama="gemma4:12b-it-qat has digest 1234..."), "gemma4"),
    ],
)
def test_a_failed_check_runs_nothing(tmp_path: Path, fake: Fake, said: str) -> None:
    code, manifest, runner = go(tmp_path, fake=fake)
    assert code == 2 and runner.calls == []
    assert set(statuses(manifest).values()) == {"not run"}
    assert any(said in problem for problem in manifest["preflight"].values())


def test_a_dirty_checkout_is_refused_unless_it_is_a_rehearsal(tmp_path: Path) -> None:
    code, manifest, runner = go(tmp_path, fake=Fake(clean=False))
    assert code == 2 and runner.calls == []
    assert "clean" in manifest["preflight"]["checkout"]
    code, manifest, _ = go(tmp_path, fake=Fake(clean=False), allow_dirty=True)
    assert code == 0 and manifest["clean"] is False and manifest["official"] is False
    summary = (tmp_path / "out" / "all" / "summary.md").read_text(encoding="utf-8")
    assert "rehearsal" in summary


@pytest.mark.parametrize("image", ["", "shop-api-test:latest", "sha256:abc"])
def test_the_test_image_must_be_pinned_by_digest(tmp_path: Path, image: str) -> None:
    code, manifest, runner = go(tmp_path, test_image=image)
    assert code == 2 and runner.calls == []
    assert "digest" in manifest["preflight"]["test image"]


def test_without_grype_database_nothing_runs(tmp_path: Path) -> None:
    s = settings(tmp_path, grype_db=tmp_path / "missing")
    runner = Scripted(out=s.out)
    runner.settings = s
    assert run.run_all(s, Fake(), runner, steps=None, allow_dirty=False) == 2
    manifest = json.loads((s.out / "all" / "manifest.json").read_text(encoding="utf-8"))
    assert "Grype" in manifest["preflight"]["grype database"] and runner.calls == []


# ---------------------------------------------------------------- the commands are the Makefile's


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
def test_each_step_runs_exactly_what_its_make_target_runs(tmp_path: Path) -> None:
    s = settings(tmp_path, out=ROOT / "out" / "eval")
    variables = [
        f"EVAL_TOOLS={s.tools_dir}", f"DB_DIR={s.grype_db}", f"GRYPE_DB={s.grype_db}",
        f"TEST_IMAGE={s.test_image}", f"OLLAMA_URL={s.ollama}", f"RUNS={s.runs}",
    ]  # fmt: skip
    for step in run.STEPS:
        done = subprocess.run(
            ["make", "-s", "-n", "-C", str(ROOT), step.target, *variables],
            capture_output=True, text=True, check=True,
        )  # fmt: skip
        joined = done.stdout.replace("\\\n", " ")  # a recipe continued on the next line
        expected = [shlex.split(line) for line in joined.splitlines() if line.strip()]
        assert [list(c) for c in step.commands(s)] == expected, step.target


def test_each_model_step_checks_only_the_model_it_uses(tmp_path: Path) -> None:
    """Correlation needs the embedding model only; canaries, explanations and the fix rate the generation
    model (#166 review: a laptop without room for the 12B model can still run correlation)."""
    go(tmp_path, steps=["detection"])
    code, manifest, _ = go(tmp_path, steps=["correlation"], fake=Fake(generation="gemma4 is not served"))
    assert code == 0 and statuses(manifest) == {"correlation": "measured"}
    assert "generation model" not in manifest["preflight"]
    code, manifest, runner = go(tmp_path, steps=["correlation"], fake=Fake(embedding="qwen3 is not served"))
    assert code == 2 and runner.calls == []
    assert "qwen3" in manifest["preflight"]["embedding model"]
    code, manifest, runner = go(tmp_path, steps=["canaries"], fake=Fake(embedding="qwen3 is not served"))
    assert code == 0 and "embedding model" not in manifest["preflight"]
    code, manifest, runner = go(tmp_path, steps=["canaries"], fake=Fake(generation="gemma4 is not served"))
    assert code == 2 and runner.calls == [] and "gemma4" in manifest["preflight"]["generation model"]
