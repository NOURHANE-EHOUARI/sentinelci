"""`make eval-all`: every automated evaluation of SPEC section 17, in order, on one checkout (task B8).

SPEC section 16 asks for "the full evaluation run on a clean checkout; its numbers committed with their input
digests" on 27 November. This runs the steps of docs/evaluation.md's command list, one after the other, and
writes what they ran on and what they wrote to out/eval/all/manifest.json and summary.md:

- detection (`make eval`), then ranking, replay, correlation (A7), canaries, explanations (generate and the
  LLM judge's ratings), the verified fix rate, and the pipeline timing;
- the rubric is not here: two people rate the explanation sheet first, then `make eval-rubric`.

Fail closed, before anything runs: the checkout must be clean, the scanners must match tools.lock.toml, the
Grype database must be there, Docker must answer and the shop-api test image must be pinned by digest and
present, and the model server must serve the pinned model each step uses (ADR-0009): the embedding model for
correlation, the generation model for canaries, explanations and the fix rate. Only what the chosen steps need
is checked. A failed check runs nothing and exits 2.

Each step keeps its script's own meaning: exit 0 is measured (and its reports must be there), exit 2 is "not
measured", anything else failed. Each step runs its scripts directly rather than through `make`, which
exits 2 for every failure; tests/eval/test_all.py checks that they are exactly each make target's commands. A
step whose findings come from a detection that failed is not run. The steps run one at a time, so the timing
and the model's time limits are measured on a machine doing nothing else.

Every step runs with the verified tools' bin/ first on PATH and SENTINEL_OPA set, so each finds the pinned
binaries the checks verified (`make eval-replay` alone needs OPA on PATH).

The manifest has no clock (only each step's duration): the commit, whether the checkout was clean, the
settings, each step's commands, exit codes and status, and each report by sha256. A run on a dirty checkout
(`--allow-dirty`) or on a subset of the steps is a rehearsal, never the official run.

Owner: Track B (B8).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[2]
PY = ("uv", "run", "python")
FINDINGS = "out/eval/findings"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# The pinned binaries the steps run (zizmor comes from uv.lock); not kind, cosign or the demo's tools.
TOOLS = ("gitleaks", "grype", "opa", "opengrep", "syft", "trivy")


@dataclass(frozen=True)
class Settings:
    tools_dir: Path
    grype_db: Path
    test_image: str
    ollama: str
    runs: int
    out: Path


@dataclass(frozen=True)
class Step:
    name: str
    target: str
    reports: tuple[str, ...]
    needs: tuple[str, ...] = ()  # steps whose reports this one reads
    uses: tuple[str, ...] = ()  # what the checks must find before it runs

    def commands(self, s: Settings) -> list[tuple[str, ...]]:
        """The scripts `make <target>` runs, with the same arguments."""
        tools, db = ("--tools-dir", str(s.tools_dir)), ("--db-dir", str(s.grype_db))
        ollama = ("--ollama", s.ollama) if s.ollama else ()
        match self.name:
            case "detection":
                return [(*PY, "eval/detection/run.py", *tools, *db)]
            case "ranking":
                return [(*PY, "eval/ranking/run.py")]
            case "replay":
                findings = ("--findings", FINDINGS) if (ROOT / FINDINGS / "gitleaks.ndjson").is_file() else ()
                return [(*PY, "eval/replay/run.py", *findings)]
            case "correlation":
                return [(*PY, "eval/correlation/run.py")]
            case "canaries":
                return [(*PY, "eval/canaries/run.py", "--findings", FINDINGS, *ollama)]
            case "explanations":
                return [
                    (
                        *PY,
                        "eval/explanations/run.py",
                        "generate",
                        "--findings",
                        FINDINGS,
                        "--ollama",
                        s.ollama,
                    ),
                    (*PY, "eval/explanations/run.py", "judge", "--ollama", s.ollama),
                ]
            case "fixrate":
                image = ("--test-image", s.test_image) if s.test_image else ()
                return [(*PY, "eval/fixrate/run.py", *tools, *image, "--grype-db", str(s.grype_db), *ollama)]
            case "timing":
                return [(*PY, "eval/timing/run.py", "--runs", str(s.runs), *tools, *db)]
        raise ValueError(self.name)


DETECTION = ("detection.json", "detection.md")
STEPS: tuple[Step, ...] = (
    Step("detection", "eval", DETECTION, uses=("tools", "grype database")),
    Step("ranking", "eval-ranking", ("ranking.json", "ranking.md"), needs=("detection",)),
    Step("replay", "eval-replay", ("replay.json", "replay.md"), needs=("detection",)),
    Step(
        "correlation",
        "eval-correlation",
        ("correlation.json", "correlation.md"),
        needs=("detection",),
        uses=("embedding model",),
    ),
    Step(
        "canaries",
        "eval-canaries",
        ("canaries.json", "canaries.md"),
        needs=("detection",),
        uses=("generation model",),
    ),
    Step(
        "explanations",
        "eval-explanations",
        ("explanations/explanations.json", "explanations/sheet.yaml", "explanations/ratings-judge.yaml"),
        needs=("detection",),
        uses=("generation model",),
    ),
    Step(
        "fixrate",
        "eval-fixrate",
        ("fixrate.json", "fixrate.md"),
        needs=("detection",),
        uses=("tools", "grype database", "docker", "test image", "generation model"),
    ),
    Step("timing", "eval-timing", ("timing.json", "timing.md"), uses=("tools", "grype database")),
)
BY_NAME = {step.name: step for step in STEPS}


class Environment(Protocol):
    def commit(self) -> str: ...
    def dirty(self) -> bool: ...
    def verify_tools(self, tools_dir: Path, report: Path) -> str: ...
    def docker_problem(self) -> str: ...
    def image_problem(self, image: str) -> str: ...
    def ollama_problem(self, url: str, model: str) -> str: ...


Runner = Callable[[Sequence[str], Path], int]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight(s: Settings, env: Environment, steps: Sequence[Step], allow_dirty: bool) -> dict[str, str]:
    """What each requirement of the chosen steps found: "ok", or why the run cannot start."""
    found: dict[str, str] = {"checkout": "ok"}
    if env.dirty():
        found["checkout"] = "allowed dirty (rehearsal)" if allow_dirty else "not clean: commit or stash first"
    uses = {use for step in steps for use in step.uses}
    if "tools" in uses:
        found["tools"] = env.verify_tools(s.tools_dir, s.out / "all" / "tools-manifest.json") or "ok"
    if "grype database" in uses:
        ok = s.grype_db.is_dir() and any(s.grype_db.iterdir())
        found["grype database"] = (
            "ok" if ok else f"no Grype database in {s.grype_db} (sentinel tools grype-db)"
        )
    if "docker" in uses:
        found["docker"] = env.docker_problem() or "ok"
    if "test image" in uses:
        if not DIGEST.match(s.test_image):
            found["test image"] = (
                f"{s.test_image or 'none'}: give the shop-api test image by digest (sha256:...)"
            )
        else:
            found["test image"] = env.image_problem(s.test_image) or "ok"
    for model in ("generation", "embedding"):
        if f"{model} model" in uses:
            found[f"{model} model"] = env.ollama_problem(s.ollama, model) or "ok"
    return found


def run_all(
    s: Settings, env: Environment, runner: Runner, steps: Sequence[str] | None, allow_dirty: bool
) -> int:
    chosen = [BY_NAME[name] for name in steps] if steps else list(STEPS)
    chosen.sort(key=STEPS.index)
    found = preflight(s, env, chosen, allow_dirty)
    blocked = {name: why for name, why in found.items() if why != "ok" and not why.startswith("allowed")}
    names = {step.name for step in chosen}
    records: list[dict[str, object]] = []
    status: dict[str, str] = {}
    for step in chosen:
        record: dict[str, object] = {"name": step.name, "target": f"make {step.target}"}
        record["commands"] = [list(command) for command in step.commands(s)]
        why = ""
        if blocked:
            why = "the checks before the run failed: " + ", ".join(sorted(blocked))
        for need in step.needs:
            if need in names and status.get(need) != "measured":
                why = why or f"{need} did not measure ({status.get(need, 'not run')})"
            elif need not in names and not all((s.out / r).is_file() for r in BY_NAME[need].reports):
                why = why or f"{need}'s reports are not in {s.out}: run it first"
        if why:
            record |= {"status": "not run", "reason": why, "exit_codes": [], "seconds": 0, "reports": {}}
            status[step.name] = "not run"
            records.append(record)
            continue
        codes: list[int] = []
        started = time.monotonic()
        for number, command in enumerate(step.commands(s), 1):
            log = s.out / "all" / "logs" / f"{step.name}-{number}.log"
            codes.append(runner(command, log))
            if codes[-1] != 0:
                break
        record["seconds"] = round(time.monotonic() - started, 1)
        record["exit_codes"] = codes
        missing = [r for r in step.reports if not (s.out / r).is_file()]
        if codes[-1] == 2:
            state, reason = "not measured", "the step reported it could not measure (exit 2): see its log"
        elif codes[-1] != 0:
            state, reason = "failed", f"exit {codes[-1]}: see its log"
        elif missing:
            state, reason = "failed", "exit 0 but it did not write " + ", ".join(missing)
        else:
            state, reason = "measured", ""
        record |= {"status": state, "reason": reason}
        record["reports"] = {r: sha256(s.out / r) for r in step.reports if (s.out / r).is_file()}
        status[step.name] = state
        records.append(record)
    official = not steps and found["checkout"] == "ok" and not blocked
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "commit": env.commit(),
        "clean": not env.dirty(),
        "official": official,
        "settings": {
            "tools_dir": str(s.tools_dir),
            "grype_db": str(s.grype_db),
            "test_image": s.test_image,
            "ollama": s.ollama,
            "runs": s.runs,
        },
        "preflight": found,
        "steps": records,
        "summary": {
            state: [n for n, v in status.items() if v == state]
            for state in ("measured", "not measured", "failed", "not run")
        },
    }
    manifest["summary"] = {k.replace(" ", "_"): v for k, v in manifest["summary"].items()}  # type: ignore[union-attr]
    out = s.out / "all"
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "summary.md").write_text(summary(manifest, records), encoding="utf-8")
    if any(state == "failed" for state in status.values()):
        return 1
    return 0 if all(state == "measured" for state in status.values()) else 2


def summary(manifest: dict[str, object], records: list[dict[str, object]]) -> str:
    measured = sum(r["status"] == "measured" for r in records)
    kind = (
        "the official run"
        if manifest["official"]
        else "a rehearsal (a subset, a dirty checkout or a failed check)"
    )
    lines = [
        "# The whole evaluation run (B8)",
        "",
        f"**{measured} of {len(records)} steps measured**, on `{manifest['commit']}`: {kind}.",
        "",
        "| Step | Target | Status | Exit | Seconds | Why |",
        "|---|---|---|---|---|---|",
    ]
    for r in records:
        codes = ", ".join(str(c) for c in r["exit_codes"]) or "—"  # type: ignore[attr-defined]
        lines.append(
            f"| {r['name']} | `{r['target']}` | {r['status']} | {codes} | {r['seconds']} | {r['reason']} |"
        )
    lines += ["", "## Checks before the run", ""]
    lines += [f"- {name}: {why}" for name, why in sorted(manifest["preflight"].items())]  # type: ignore[union-attr]
    lines += [
        "",
        "Next: each person rates out/eval/explanations/sheet.yaml alone (ratings-<name>.yaml), then "
        "`make eval-rubric`. Each report is named by its sha256 in manifest.json.",
        "",
    ]
    return "\n".join(lines)


class Real:
    """The environment on this machine."""

    def _git(self, *args: str) -> str:
        command = ["git", *args]
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)  # noqa: S603
        return done.stdout

    def commit(self) -> str:
        return self._git("rev-parse", "HEAD").strip()

    def dirty(self) -> bool:
        return bool(self._git("status", "--porcelain").strip())

    def verify_tools(self, tools_dir: Path, report: Path) -> str:
        report.parent.mkdir(parents=True, exist_ok=True)
        command = [*PY[:2], "sentinel", "tools", "verify", *TOOLS, "--dest", str(tools_dir)]
        command += ["--report", str(report)]
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
        if done.returncode == 0:
            return ""
        lines = [line.strip() for line in (done.stdout + done.stderr).splitlines() if line.strip()]
        errors = [line.removeprefix("Error: ") for line in lines if line.startswith("Error")]
        return "; ".join(errors) or (lines or ["sentinel tools verify failed"])[-1]

    def docker_problem(self) -> str:
        try:
            command = ["docker", "info"]
            done = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"no Docker daemon answers ({type(exc).__name__})"
        return "" if done.returncode == 0 else "no Docker daemon answers"

    def image_problem(self, image: str) -> str:
        command = ["docker", "image", "inspect", image]  # a sha256 digest, checked before
        done = subprocess.run(command, capture_output=True, check=False)  # noqa: S603
        return "" if done.returncode == 0 else f"{image} is not present: build Dockerfile.test and pin its id"

    def ollama_problem(self, url: str, model: str) -> str:
        try:
            from sentinel_ai.providers.ollama import EMBEDDING, GENERATION, OllamaProvider

            OllamaProvider(url).verify(GENERATION if model == "generation" else EMBEDDING)
        except Exception as exc:  # unreachable, refused, another digest: all the same here
            return f"{type(exc).__name__}: {exc}"
        return ""


def subprocess_runner(argv: Sequence[str], log: Path) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        done = subprocess.run(  # noqa: S603 (the steps' own fixed commands)
            list(argv), cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, check=False
        )
        return done.returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    tools = Path(os.environ.get("SENTINEL_TOOLS_DIR", ROOT / ".sentinel" / "tools"))
    parser.add_argument("--tools-dir", type=Path, default=tools)
    parser.add_argument("--grype-db", type=Path, default=ROOT / "out" / "grype-db")
    parser.add_argument("--test-image", default="", help="the shop-api test image, by digest (sha256:...)")
    parser.add_argument("--ollama", default="http://127.0.0.1:11434")
    parser.add_argument("--runs", type=int, default=20, help="timing runs (make eval-timing's RUNS)")
    parser.add_argument("--steps", default="", help="a comma-separated subset, in any order (a rehearsal)")
    parser.add_argument("--allow-dirty", action="store_true", help="run on a dirty checkout (a rehearsal)")
    args = parser.parse_args(argv)
    steps = [name.strip() for name in args.steps.split(",") if name.strip()]
    unknown = [name for name in steps if name not in BY_NAME]
    if unknown:
        parser.error(f"unknown step(s) {', '.join(unknown)}: choose from {', '.join(BY_NAME)}")
    settings = Settings(
        tools_dir=args.tools_dir.resolve(), grype_db=args.grype_db.resolve(), test_image=args.test_image,
        ollama=args.ollama, runs=args.runs, out=ROOT / "out" / "eval",
    )  # fmt: skip
    # Every step runs the verified binaries: replay and the timing find OPA and the scanners on PATH.
    os.environ["PATH"] = os.pathsep.join([str(settings.tools_dir / "bin"), os.environ.get("PATH", "")])
    os.environ["SENTINEL_OPA"] = str(settings.tools_dir / "bin" / "opa")
    code = run_all(settings, Real(), subprocess_runner, steps or None, args.allow_dirty)
    print((settings.out / "all" / "summary.md").read_text(encoding="utf-8"))
    return code


if __name__ == "__main__":
    sys.exit(main())
