"""`make eval-timing`: the gate's steps on demo-shop, timed (task B8, SPEC sections 3 and 17).

SPEC section 3 sets "PR feedback time: p95 <= 10 min" and section 17 asks for pipeline p50 and p95. Until
GitHub Actions can run, this times what the gate itself does, on this machine:
1. the five scans `make eval` runs (`sentinel scan secrets|iac|pipelines|sast|sca`, the same commands, the
   pinned tools);
2. the decision on their findings (`sentinel evaluate`, `local` context, the repository's policies).

Each run does every step in order, and the report gives each step's p50, p95, min and max, and the total's.
Percentiles are nearest-rank, so each one is a measured run. It is not a CI measurement: a CI job also
checks out the repository, installs the pinned tools, downloads the Grype database and uploads artifacts, and
its runner is another machine. The report says so, and names this machine.

A step that fails stops the measurement (exit 2): a time for a scan that did not run would be a fast lie.
Unlike B8's other reports, the output depends on the clock: it is a measurement of time.

Usage: uv run python eval/timing/run.py --tools-dir DIR --db-dir DIR [--runs 5] [--out out/eval]
Owner: Track B (B8).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TARGET_P95_SECONDS = 600  # SPEC section 3: PR feedback time, p95 <= 10 min
EVALUATED_AT = "2026-11-15T00:00:00Z"  # a fixed time: the decision is not what is measured


def _load_detection() -> Any:
    """eval/detection/run.py, for its scan commands (eval/ is not a package)."""
    path = ROOT / "eval" / "detection" / "run.py"
    spec = importlib.util.spec_from_file_location("sentinel_eval_timing_detection", path)
    if spec is None or spec.loader is None:
        raise ImportError("eval/detection/run.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


detection = _load_detection()
STEPS = (*detection.SCANS, "evaluate")

# One step: (did it succeed, the tool's summary line if it printed one, why it failed).
Step = Callable[[str, Path], tuple[bool, "str | None", str]]


class EvalError(Exception):
    """The timing cannot be measured from these inputs."""


def percentile(values: Sequence[float], p: int) -> float:
    """The nearest-rank percentile: the smallest value with at least p% of the values at or below it."""
    if not values:
        raise ValueError("no value to take a percentile of")
    ordered = sorted(values)
    return ordered[max(math.ceil(p / 100 * len(ordered)), 1) - 1]


def _summary(values: Sequence[float]) -> dict[str, float]:
    return {
        "p50": round(percentile(values, 50), 3),
        "p95": round(percentile(values, 95), 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
    }


def measure(runs: int, *, step: Step, clock: Callable[[], float], work: Path) -> dict[str, Any]:
    """Run every step `runs` times, in order, and time each one with `clock`."""
    if runs < 1:
        raise EvalError("the timing needs at least 1 run")
    seconds: dict[str, list[float]] = {name: [] for name in STEPS}
    totals: list[float] = []
    versions: dict[str, str] = {}
    for number in range(1, runs + 1):
        out = work / f"run-{number}"
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        total = 0.0
        for name in STEPS:
            started = clock()
            succeeded, summary, reason = step(name, out)
            elapsed = clock() - started
            if not succeeded:
                raise EvalError(f"{name} failed in run {number}: {reason}")
            if summary and (found := detection.SUMMARY.match(summary)):
                versions[found["tool"]] = found["version"]
            seconds[name].append(elapsed)
            total += elapsed
        totals.append(total)
    total_summary = _summary(totals)
    return {
        "runs": runs,
        "steps": {name: _summary(values) for name, values in seconds.items()},
        "total": total_summary,
        "target": {"p95_seconds": TARGET_P95_SECONDS, "met_here": total_summary["p95"] <= TARGET_P95_SECONDS},
        "versions": dict(sorted(versions.items())),
        "environment": {
            "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
            "python": platform.python_version(),
            "cpus": os.cpu_count() or 0,
        },
    }


def _row(name: str, row: Mapping[str, float]) -> str:
    return f"| {name} | " + " | ".join(f"{row[key]:.1f}" for key in ("p50", "p95", "min", "max")) + " |"


def markdown(data: Mapping[str, Any]) -> str:
    total, target, runs = data["total"], data["target"], data["runs"]
    met = "met on this machine" if target["met_here"] else "not met on this machine"
    counted = f"{runs} run" + ("" if runs == 1 else "s")
    env = data["environment"]
    lines = [
        "# Pipeline timing (B8)",
        "",
        f"**PR feedback time on this machine: p50 {total['p50']:.1f} s, p95 {total['p95']:.1f} s "
        f"over {counted}.**"
        f" SPEC section 3 asks for p95 <= {target['p95_seconds'] // 60} min: {met}.",
        "",
        f"Each run does the gate's steps in order on demo-shop: the five scans `make eval` runs, then "
        f"`sentinel evaluate` on their findings. Machine: {env['platform']}, {env['cpus']} CPUs, Python "
        f"{env['python']}. This is not a CI measurement: a CI job also checks out the repository, and pays "
        "for tool downloads, the Grype database and artifact uploads, on another machine. Percentiles are "
        f"nearest-rank, so each is one measured run. With {counted}, p95 is the slowest run"
        + ("" if runs >= 20 else " (fewer than 20 runs)")
        + ".",
        "",
        "| Step | p50 (s) | p95 (s) | min (s) | max (s) |",
        "|---|---|---|---|---|",
    ]
    for name, row in data["steps"].items():
        lines.append(_row(name, row))
    lines.append(_row("**total**", total))
    if data["versions"]:
        lines += ["", "Tools: " + ", ".join(f"{tool} {v}" for tool, v in data["versions"].items()) + "."]
    return "\n".join(lines) + "\n"


def cli_step(args: argparse.Namespace) -> Step:
    """The real steps: detection's own scan commands, then `sentinel evaluate` on their findings."""

    def step(name: str, out: Path) -> tuple[bool, str | None, str]:
        if name != "evaluate":
            tool_run, summary = detection.scan(name, out / f"{name}.ndjson", args)
            return tool_run.status == "ok", summary, tool_run.reason or tool_run.status
        combined = out / "findings.ndjson"
        combined.write_bytes(b"".join((out / f"{tool}.ndjson").read_bytes() for tool in detection.SCANS))
        (out / "waivers.yaml").write_text("", encoding="utf-8")
        command = [
            str(Path(sys.executable).parent / "sentinel"), "evaluate",
            "--findings", str(combined),
            "--repo", detection.REPO, "--commit", "0" * 40, "--context", "local",
            "--evaluated-at", EVALUATED_AT,
            "--policy-dir", str(ROOT / "policies"),
            "--waivers", str(out / "waivers.yaml"),
            "--output", str(out / "decision.json"),
        ]  # fmt: skip
        if args.opa is not None:
            command += ["--opa", str(args.opa)]
        # The workspace's own CLI, with fixed arguments. Exit 1 is a BLOCK: a decision was made.
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
        made = done.returncode in (0, 1) and (out / "decision.json").is_file()
        return made, None, f"exit {done.returncode}: {detection.reason(done.stderr)}"

    return step


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    parser.add_argument("--tools-dir", type=Path)
    parser.add_argument("--db-dir", type=Path, help="a `sentinel tools grype-db` directory (SCA is a step)")
    parser.add_argument("--allow-stale-db", action="store_true")
    parser.add_argument("--opa", type=Path, default=None, help="OPA binary (default: $SENTINEL_OPA, PATH)")
    args = parser.parse_args(argv)
    try:
        data = measure(args.runs, step=cli_step(args), clock=time.perf_counter, work=args.out / "timing")
    except EvalError as exc:
        print(f"eval-timing: {exc}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "timing.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (args.out / "timing.md").write_text(markdown(data), encoding="utf-8")
    print(markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
