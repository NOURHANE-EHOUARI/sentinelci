"""`make eval-replay`: replay identity, measured (task B8, SPEC sections 3 and 17).

SPEC section 3 asks for "replay determinism: 100% identical". This measures a narrower property than the
nightly job (`replay-nightly.yml`): it records and replays in the same run, with the same engine, OPA and
policies, so it shows that the store holds every input of a decision and that the engine decides the same way
twice in this environment. It cannot catch drift between the engine, OPA or policies that recorded a decision
and the ones that replay it later: that is the nightly's job. It writes the result as a report, like B8's
other measurements:

1. records the replay corpus (corpus.py: every gate case it covers, with its expected verdict);
2. with `--findings DIR` (what `make eval` wrote), also records a decision on demo-shop's real findings, in
   `local` context, so the replay covers real scanner output and not only contract fixtures;
3. replays every recorded decision with this checkout's engine (`sentinel replay --all`), and counts how many
   come out identical, byte for byte.

It writes out/eval/replay.json and out/eval/replay.md, and exits 1 if any decision differs or cannot be
replayed. The same inputs give the same report: no clock (decisions use fixed evaluation times), sorted keys,
inputs named by their digests.

Usage: uv run python eval/replay/run.py [--findings out/eval/findings] [--out out/eval] [--opa PATH]
Owner: Track B (B8).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ("gitleaks", "trivy", "zizmor", "opengrep", "grype")
DEMO_COMMIT = "0" * 40  # the commit `make eval` names its findings with
# One line of `sentinel replay --all` per decision, then its summary.
LINE = re.compile(
    r"^(?P<result>identical|differs|skipped|cannot replay)\s+(?P<id>[0-9a-f-]{36})\b(?P<rest>.*)$"
)
SUMMARY = re.compile(
    r"^(?P<identical>\d+) identical, (?P<skipped>\d+) skipped, (?P<differ>\d+) differ, "
    r"(?P<cannot>\d+) cannot replay$"
)


def _load_corpus() -> Any:
    """corpus.py, under a name no other module can take (eval/ is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "sentinel_eval_replay_corpus", Path(__file__).with_name("corpus.py")
    )
    if spec is None or spec.loader is None:
        raise ImportError("eval/replay/corpus.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


corpus = _load_corpus()


class EvalError(Exception):
    """Replay identity cannot be measured from these inputs."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse(output: str) -> dict[str, Any]:
    """`sentinel replay --all` output: each decision's result, and the summary's counts."""
    results = {}
    summary: dict[str, int] | None = None
    for line in output.splitlines():
        line = line.strip()
        if found := LINE.match(line):
            results[found["id"]] = found["result"]
        elif found := SUMMARY.match(line):
            summary = {key: int(value) for key, value in found.groupdict().items()}
    if summary is None:
        raise EvalError("`sentinel replay --all` printed no summary line")
    if sum(summary.values()) != len(results):
        raise EvalError(
            f"the replay summary counts {sum(summary.values())} decisions, its lines {len(results)}"
        )
    return {"results": results, "summary": summary}


def record_demo_shop(findings_dir: Path, store: Path, work: Path, opa: Path | None) -> dict[str, Any]:
    """A decision on demo-shop's real findings (`make eval`'s five files), recorded into `store`."""
    files = {tool: findings_dir / f"{tool}.ndjson" for tool in TOOLS}
    missing = [tool for tool, path in files.items() if not path.is_file()]
    if missing:
        names = ", ".join(f"{tool}.ndjson" for tool in missing)
        raise EvalError(f"no {names} in {findings_dir}: run `make eval` first, with every scanner")
    work.mkdir(parents=True, exist_ok=True)
    combined = work / "findings.ndjson"
    combined.write_bytes(b"".join(path.read_bytes() for _, path in sorted(files.items())))
    (work / "waivers.yaml").write_text("", encoding="utf-8")
    args = [
        "evaluate",
        "--findings", str(combined),
        "--repo", "acme/demo-shop",
        "--commit", DEMO_COMMIT,
        "--context", "local",
        "--evaluated-at", corpus.EVALUATED_AT,
        "--policy-dir", str(corpus.POLICIES),
        "--output", str(work / "decision.json"),
        "--store", str(store),
        "--waivers", str(work / "waivers.yaml"),
    ]  # fmt: skip
    if opa is not None:
        args += ["--opa", str(opa)]
    code = corpus.app(args, standalone_mode=False)
    if code not in (None, 0, 1):
        raise EvalError(f"demo-shop: sentinel evaluate made no decision (exit {code})")
    decision = json.loads((work / "decision.json").read_text(encoding="utf-8"))
    return {
        "decision_id": decision["decision_id"],
        "verdict": decision["verdict"],
        "findings_sha256": {tool: sha256(path.read_bytes()) for tool, path in sorted(files.items())},
    }


def replay(store: Path, opa: Path | None) -> dict[str, Any]:
    command = [str(Path(sys.executable).parent / "sentinel"), "replay", "--all", "--store", str(store)]
    if opa is not None:
        command += ["--opa", str(opa)]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
    # A decision that differs or cannot be replayed makes `sentinel replay` exit non-zero: that is a result to
    # report, so its summary is read whatever the exit code. No summary at all is a failure to measure.
    try:
        return parse(done.stdout)
    except EvalError as exc:
        tail = (done.stderr.strip().splitlines() or ["no message"])[-1]
        raise EvalError(f"sentinel replay failed (exit {done.returncode}): {tail} ({exc})") from exc


def report(recorded: Mapping[str, Mapping[str, Any]], replayed: Mapping[str, Any]) -> dict[str, Any]:
    results = replayed["results"]
    decisions = {
        name: {"decision_id": entry["decision_id"], "verdict": entry["verdict"],
               "replay": results.get(entry["decision_id"], "not replayed")}
        for name, entry in recorded.items()
    }  # fmt: skip
    total = len(decisions)
    identical = sum(entry["replay"] == "identical" for entry in decisions.values())
    inputs = {
        name: entry["findings_sha256"] for name, entry in recorded.items() if "findings_sha256" in entry
    }
    return {
        "decisions": decisions,
        "identical": identical,
        "total": total,
        "identity": None if total == 0 else round(identical / total, 4),
        "summary": replayed["summary"],
        "inputs": inputs,
    }


def markdown(data: Mapping[str, Any]) -> str:
    identity = "not measured" if data["identity"] is None else f"{100 * data['identity']:.1f}%"
    lines = [
        "# Replay identity (B8)",
        "",
        f"**{data['identical']} of {data['total']} decisions replay identically ({identity}).** "
        "SPEC section 3 asks for 100%. Each decision was recorded with `sentinel evaluate --store` and "
        "replayed with this checkout's engine (`sentinel replay --all`).",
        "",
        "Same checkout, same tools: this shows that the store holds every input and that the engine is "
        "deterministic here. A decision recorded with another engine, OPA or policy version is the nightly "
        "job's to replay (`replay-nightly.yml`).",
        "",
        "| Decision | Verdict | Replay |",
        "|---|---|---|",
    ]
    for name, entry in sorted(data["decisions"].items()):
        lines.append(f"| {name} | {entry['verdict']} | {entry['replay']} |")
    summary = data["summary"]
    lines += [
        "",
        f"`sentinel replay --all`: {summary['identical']} identical, {summary['skipped']} skipped, "
        f"{summary['differ']} differ, {summary['cannot']} cannot replay.",
    ]
    for name, digests in sorted(data["inputs"].items()):
        lines.append(
            f"{name} findings by sha256: " + ", ".join(f"{t} {d}" for t, d in sorted(digests.items()))
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--findings", type=Path, help="make eval's findings, for a decision on demo-shop")
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    parser.add_argument("--opa", type=Path, default=None, help="OPA binary (default: $SENTINEL_OPA, PATH)")
    args = parser.parse_args(argv)
    work = args.out / "replay"
    store = work / "store"
    shutil.rmtree(work, ignore_errors=True)  # a fresh store: only this run's decisions are replayed
    try:
        recorded: dict[str, dict[str, Any]] = dict(corpus.record(store, work / "corpus", args.opa))
        if args.findings is not None:
            recorded["demo-shop (make eval, local)"] = record_demo_shop(
                args.findings, store, work / "demo", args.opa
            )
        data = report(recorded, replay(store, args.opa))
    except (EvalError, corpus.CorpusError) as exc:
        print(f"eval-replay: {exc}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "replay.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.out / "replay.md").write_text(markdown(data), encoding="utf-8")
    print(markdown(data))
    return 0 if data["identical"] == data["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
