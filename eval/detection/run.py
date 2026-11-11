"""`make eval`: the demo-shop detection report (task B8, SPEC section 17).

Runs SentinelCI's own scanners on demo-shop (`sentinel scan secrets|iac|pipelines|sast|sca`, the pinned
tools, SentinelCI's configuration), scores their findings against demo-shop/ground-truth/findings.yaml
(score.py), and writes out/eval/detection.json and out/eval/detection.md. The same inputs give the same
report, byte for byte: no clock, sorted keys, and every input named by its digest.

- `--tools-dir`: where `sentinel tools install` put the scanners (default: the CLI's own default).
- `--db-dir`: a `sentinel tools grype-db` directory. Without it, SCA is not measured (never 0).
- `--findings DIR`: score existing findings files (`<tool>.ndjson`) instead of scanning, for a recorded run.

Usage: uv run python eval/detection/run.py [--tools-dir DIR] [--db-dir DIR] [--out out/eval]
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
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _load_score() -> Any:
    """score.py, under a name no other module can take (eval/ is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "sentinel_eval_detection_score", Path(__file__).with_name("score.py")
    )
    if spec is None or spec.loader is None:
        raise ImportError("eval/detection/score.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_score = _load_score()
ToolRun = _score.ToolRun
score = _score.score
GROUND_TRUTH = ROOT / "demo-shop" / "ground-truth" / "findings.yaml"
REPO = "acme/demo-shop"
# SPEC section 17: the size of the benchmark the evaluation is meant to have.
SPEC_TARGETS = {
    "SECRET": 5, "SAST": 10, "SCA": 8, "CONTAINER": 5, "IAC": 6, "PIPELINE": 3, "canaries": 5, "controls": 5,
}  # fmt: skip
# tool -> the scan command that runs it (each writes Finding v1 NDJSON with --out).
SCANS: dict[str, list[str]] = {
    "gitleaks": ["scan", "secrets", "demo-shop", "--mode", "dir"],
    "trivy": ["scan", "iac", "demo-shop"],
    "zizmor": ["scan", "pipelines", "demo-shop"],
    "opengrep": ["scan", "sast", "demo-shop"],
    "grype": ["scan", "sca", "demo-shop"],
}
SUMMARY = re.compile(r"^(?P<tool>[a-z]+) (?P<version>[0-9][0-9A-Za-z.+-]*)\b")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def demo_shop_tree() -> str | None:
    """The git tree id of demo-shop/ at HEAD, when the checkout is clean there (else None: not
    reproducible)."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        dirty = subprocess.run(  # noqa: S603 (a fixed git command)
            # --ignored: the scanners read ignored files too (a local `*.key`), so they make a tree unclean.
            [git, "status", "--porcelain", "--ignored", "--", "demo-shop"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        tree = subprocess.run(  # noqa: S603 (a fixed git command)
            [git, "rev-parse", "HEAD:demo-shop"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return None if dirty else tree


def scan(tool: str, out: Path, args: argparse.Namespace) -> tuple[ToolRun, str | None]:
    """Run one scanner through the CLI; its run status, and the summary line it printed."""
    if tool == "grype" and args.db_dir is None:
        return ToolRun(tool, "skipped", reason="no Grype database (--db-dir)"), None
    command = [
        str(Path(sys.executable).parent / "sentinel"),
        *SCANS[tool],
        "--repo-root",
        ".",
        "--out",
        str(out),
    ]
    command += ["--repo", REPO, "--commit", "0" * 40, "--context", "local"]
    if tool != "zizmor" and args.tools_dir is not None:
        command += ["--tools-dir", str(args.tools_dir)]
    if tool == "grype":
        command += ["--db-dir", str(args.db_dir)] + (["--allow-stale-db"] if args.allow_stale_db else [])
    # The workspace's own CLI, with fixed arguments and the operator's directories.
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S603
    lines = [line for line in done.stdout.splitlines() if SUMMARY.match(line)]
    if done.returncode != 0 or not out.is_file():
        return ToolRun(tool, "failed", reason=f"exit {done.returncode}: {reason(done.stderr)}"), None
    version = SUMMARY.match(lines[-1])["version"] if lines else None  # type: ignore[index]
    return ToolRun(tool, "ok", version=version), (lines[-1] if lines else None)


def reason(stderr: str) -> str:
    """The CLI's own words: its error lines, without the boxes Typer draws around them."""
    lines = [line.strip(" │╭╮╰╯─").strip() for line in stderr.splitlines()]
    words = [line for line in lines if line and not line.startswith(("Usage:", "Try "))]
    return (" ".join(words) or "(no output)")[:200]


def load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def benchmark_size(truth: dict[str, Any]) -> dict[str, Any]:
    present = {name: 0 for name in SPEC_TARGETS}
    for seed in truth["seeds"]:
        present[seed["category"]] = present.get(seed["category"], 0) + 1
    present["canaries"] = len(truth.get("canaries", []))
    present["controls"] = len(truth["controls"])
    return {name: {"present": present.get(name, 0), "spec": target} for name, target in SPEC_TARGETS.items()}


def report(truth_bytes: bytes, findings: dict[str, list[dict[str, Any]]], runs: list[ToolRun],
           inputs: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
    truth = yaml.safe_load(truth_bytes)
    everything = [finding for tool in sorted(findings) for finding in findings[tool]]
    result = score(truth, everything, runs)
    return {
        "schema_version": 1,
        "inputs": {"ground_truth_sha256": sha256(truth_bytes), **inputs},
        "benchmark": benchmark_size(truth),
        **result,
    }


def markdown(data: dict[str, Any]) -> str:
    out = ["# demo-shop detection report (B8)", ""]
    inputs = data["inputs"]
    out += [f"- Ground truth: `sha256:{inputs['ground_truth_sha256']}`"]
    if inputs.get("findings_recorded"):
        out += ["- demo-shop tree: recorded findings (`--findings`): their tree is not checked"]
    else:
        tree = inputs.get("demo_shop_tree") or "not a clean checkout: not reproducible"
        out += [f"- demo-shop tree: `{tree}`"]
    for tool, run in data["tools"].items():
        detail = run.get("version") or run.get("reason", "")
        out += [f"- {tool}: {run['status']}" + (f" ({detail})" if detail else "")]
    for line in inputs.get("scanner_summaries", []):
        out += [f"  - `{line}`"]
    out += [
        "",
        "## Recall per category",
        "",
        "| Category | Seeds | Detected | Recall | Missed |",
        "|---|---|---|---|---|",
    ]
    for name, entry in data["categories"].items():
        if entry["measured"]:
            missed = ", ".join(
                m["id"] + (" (known miss)" if m.get("known_miss") else "") for m in entry["missed"]
            )
            recall = f"{entry['recall']:.0%}"
            out += [f"| {name} | {entry['seeds']} | {entry['detected']} | {recall} | {missed or '—'} |"]
        else:
            out += [f"| {name} | {entry['seeds']} | — | not measured | {entry['reason']} |"]
    overall = data["overall"]
    out += ["", f"Measured: {overall['detected']} of {overall['seeds_measured']} seeds detected."]
    if overall["categories_not_measured"]:
        out += [f"Not measured: {', '.join(overall['categories_not_measured'])}."]
    out += ["", "## Clean controls", "", "| Control | Must not detect | False positives |", "|---|---|---|"]
    for name, entry in data["controls"].items():
        not_run = f" (not run: {', '.join(entry['not_run'])})" if entry.get("not_run") else ""
        out += [f"| {name} | {', '.join(entry['must_not_detect'])}{not_run} | {entry['false_positives']} |"]
    for fp in data["false_positives"]:
        out += [f"- {fp['control']}: {fp['tool']} `{fp['rule']}`"]
    out += ["", "## Unlisted findings (real, neither hits nor false positives)", ""]
    for name, counts in data["unlisted_findings"].items():
        out += [f"- {name}: {counts['in_seeded_files']} in seeded files, {counts['elsewhere']} elsewhere"]
    if not data["unlisted_findings"]:
        out += ["- none"]
    canaries = data["canaries"]
    out += [
        "",
        "## Prompt-injection canaries",
        "",
        f"{canaries['planted']} planted; not measured: {canaries['reason']}.",
    ]
    out += ["", "## Benchmark size (SPEC section 17)", "", "| Part | Present | SPEC |", "|---|---|---|"]
    for name, size in data["benchmark"].items():
        out += [f"| {name} | {size['present']} | {size['spec']} |"]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    parser.add_argument("--tools-dir", type=Path)
    parser.add_argument("--db-dir", type=Path)
    parser.add_argument("--allow-stale-db", action="store_true")
    parser.add_argument("--findings", type=Path, help="score <tool>.ndjson files from this directory")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    findings: dict[str, list[dict[str, Any]]] = {}
    files: dict[str, Path] = {}
    runs: list[ToolRun] = []
    summaries: list[str] = []
    for tool in SCANS:
        if args.findings is not None:
            path = args.findings / f"{tool}.ndjson"
            if not path.is_file():
                runs.append(ToolRun(tool, "skipped", reason=f"no {path.name} in --findings"))
                continue
            loaded = load(path)
            version = next((str(f["tool"].get("version")) for f in loaded if f.get("tool")), None)
            runs.append(ToolRun(tool, "ok", version=version))
            findings[tool] = loaded
            files[tool] = path
            continue
        path = args.out / "findings" / f"{tool}.ndjson"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        run, summary = scan(tool, path, args)
        runs.append(run)
        if summary:
            summaries.append(summary)
        if run.status == "ok":
            findings[tool] = load(path)
            files[tool] = path
    inputs: dict[str, Any] = {
        # Recorded findings may come from another tree than this checkout's: none is claimed for them.
        "demo_shop_tree": None if args.findings is not None else demo_shop_tree(),
        "findings_recorded": args.findings is not None,
        # The digests of the files themselves, so `sha256sum` checks them.
        "findings_sha256": {tool: sha256(files[tool].read_bytes()) for tool in sorted(findings)},
        "scanner_summaries": [re.sub(r" written to .*$", "", line) for line in summaries],
    }
    data = report(GROUND_TRUTH.read_bytes(), findings, runs, inputs)
    (args.out / "detection.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "detection.md").write_text(markdown(data), encoding="utf-8")
    print(markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
