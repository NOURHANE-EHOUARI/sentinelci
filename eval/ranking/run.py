"""`make eval-ranking`: how well the risk score ranks demo-shop's findings (task B8, SPEC section 17).

Reads the findings `make eval` wrote (out/eval/findings/<tool>.ndjson), enriches them offline with the
committed feed snapshot (eval/feeds/snapshot.json: the recorded EPSS, KEV and OSV answers for the seeded
packages, which the gate's fixtures use too), scores them with this checkout's policy bundle (`sentinel
score`), and compares two orders of the same findings with rank.py: the
risk score and the CVSS-only baseline. It writes out/eval/ranking.json and out/eval/ranking.md.

The relevance grades come from the ground truth, fixed before any ranking was computed (its README). The same
inputs give the same report, byte for byte: no clock, sorted keys, every input named by its digest.

Usage: uv run python eval/ranking/run.py [--findings out/eval/findings] [--out out/eval]
Owner: Track B (B8).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from sentinelci.risk import cvss_baseline

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> Any:
    """A module of eval/ under a name no other module can take (eval/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rank = _load("sentinel_eval_ranking_rank", Path(__file__).with_name("rank.py"))
detection = _load("sentinel_eval_detection_score", ROOT / "eval" / "detection" / "score.py")

GROUND_TRUTH = ROOT / "demo-shop" / "ground-truth" / "findings.yaml"
SNAPSHOT = ROOT / "eval" / "feeds" / "snapshot.json"
POLICIES = ROOT / "policies"
TOOLS = ("gitleaks", "trivy", "zizmor", "opengrep", "grype")
K = 10


class EvalError(Exception):
    """The ranking cannot be measured from these inputs."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sentinel(*args: str) -> None:
    """Run one `sentinel` command of this checkout; any failure stops the measurement."""
    done = subprocess.run(  # noqa: S603 (this checkout's own CLI, fixed arguments)
        [str(Path(sys.executable).parent / "sentinel"), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        tail = (done.stderr.strip().splitlines() or ["no message"])[-1]
        raise EvalError(f"sentinel {args[0]} failed (exit {done.returncode}): {tail}")


def scored_findings(findings_dir: Path, work: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The findings of `make eval`, enriched offline and scored, and the digests of what they came from."""
    files = {
        tool: findings_dir / f"{tool}.ndjson" for tool in TOOLS if (findings_dir / f"{tool}.ndjson").is_file()
    }
    if not files:
        raise EvalError(f"no <tool>.ndjson in {findings_dir}: run `make eval` first")
    work.mkdir(parents=True, exist_ok=True)
    combined = work / "findings.ndjson"
    combined.write_bytes(b"".join(path.read_bytes() for _, path in sorted(files.items())))
    enriched, scored = work / "enriched.ndjson", work / "scored.ndjson"
    for path in (enriched, scored):
        path.unlink(missing_ok=True)
    # The committed snapshot, not one built from the recordings: a request that was never recorded makes
    # `sentinel snapshot --offline` leave its whole feed out, and demo-shop's scan asks for more advisories
    # than the fixtures recorded.
    sentinel("enrich", "--findings", str(combined), "--snapshot", str(SNAPSHOT), "--out", str(enriched))
    sentinel("score", "--findings", str(enriched), "--out", str(scored), "--policy-dir", str(POLICIES))
    inputs = {
        "findings_sha256": {tool: sha256(path.read_bytes()) for tool, path in sorted(files.items())},
        "snapshot_sha256": sha256(SNAPSHOT.read_bytes()),
        "risk_model_sha256": sha256((POLICIES / "risk-model.yaml").read_bytes()),
    }
    return read_ndjson(scored), inputs


def coverage(findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """How much the two orders had to go on."""

    def has(finding: Mapping[str, Any], *keys: str) -> bool:
        value: Any = finding
        for key in keys:
            value = value.get(key) if isinstance(value, Mapping) else None
        return value is not None

    return {
        "findings": len(findings),
        "with_cvss": sum(cvss_baseline(f) is not None for f in findings),
        "with_epss": sum(has(f, "enrichment", "epss") for f in findings),
        "with_kev": sum(has(f, "enrichment", "kev") for f in findings),
        "scored": sum(has(f, "risk", "score") for f in findings),
    }


def measure(seeds: Sequence[Mapping[str, Any]], findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """NDCG@10 and NDCG over every item, for the risk order and the baseline, on these seeds and findings."""
    grades = [int(seed["relevance"]) for seed in seeds]
    orders = {
        "risk": lambda f: float(f["risk"]["score"]),
        "cvss_baseline": lambda f: rank.baseline_score(f, cvss_baseline),
    }
    out: dict[str, Any] = {
        "seeds": len(seeds),
        "seeds_detected": sum(any(detection.detects(s, f) for f in findings) for s in seeds),
        "findings": len(findings),
    }
    for name, score in orders.items():
        items = rank.items(seeds, findings, detection.detects, score)
        out[name] = {
            f"ndcg_at_{K}": _round(rank.ndcg(items, grades, K)),
            "ndcg": _round(rank.ndcg(items, grades, None)),
            "top": rank.top(items, K),
        }
    return out


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def report(
    truth_bytes: bytes, findings: Sequence[Mapping[str, Any]], inputs: Mapping[str, Any]
) -> dict[str, Any]:
    truth = yaml.safe_load(truth_bytes)
    seeds = [seed for seed in truth["seeds"] if "relevance" in seed]
    if len(seeds) != len(truth["seeds"]):
        raise EvalError("every seed needs a relevance grade (demo-shop/ground-truth/README.md)")
    unscored = [str(f.get("id")) for f in findings if not isinstance(f.get("risk"), Mapping)]
    if unscored:
        raise EvalError(
            f"{len(unscored)} finding(s) have no risk score: `sentinel score` did not run on them"
        )
    sca = [seed for seed in seeds if seed["category"] == "SCA"]
    return {
        "all": measure(seeds, findings),
        "sca_only": measure(sca, [f for f in findings if f.get("category") == "SCA"]),
        "coverage": coverage(findings),
        "inputs": {"ground_truth_sha256": sha256(truth_bytes), **inputs},
        "k": K,
        "rubric": "demo-shop/ground-truth/README.md, Ranking relevance (grades fixed before any ranking)",
    }


def _number(value: float | None) -> str:
    return "not measured" if value is None else f"{value:.3f}"


def markdown(data: Mapping[str, Any]) -> str:
    cover = data["coverage"]
    lines = [
        "# Ranking report (B8)",
        "",
        f"NDCG@{data['k']} of demo-shop's findings, ranked by SentinelCI's risk score and by the CVSS-only "
        "baseline. Relevance is each seed's grade (" + data["rubric"] + "); a finding that detects no seed "
        "counts 0, and a seed counts once, at the best place of its findings. Ties share their places' mean "
        "discount.",
        "",
        f"Inputs: {cover['findings']} findings, {cover['with_cvss']} with a CVSS score, {cover['with_epss']} "
        f"with EPSS and {cover['with_kev']} with KEV, from the committed feed snapshot "
        "(eval/feeds/snapshot.json, the seeded packages' advisories). The rest have no feed data: the "
        "baseline uses their severity's CVSS floor, and the risk score its no-data defaults (an unknown "
        "exposure counts as internet-facing).",
        "",
        "| Set | Seeds (detected) | Risk NDCG@10 | Baseline NDCG@10 | Risk NDCG | Baseline NDCG |",
        "|---|---|---|---|---|---|",
    ]
    at_k = f"ndcg_at_{data['k']}"
    for name, label in (("all", "All categories"), ("sca_only", "SCA only")):
        part = data[name]
        risk, base = part["risk"], part["cvss_baseline"]
        lines.append(
            f"| {label} | {part['seeds']} ({part['seeds_detected']}) | {_number(risk[at_k])} | "
            f"{_number(base[at_k])} | {_number(risk['ndcg'])} | {_number(base['ndcg'])} |"
        )
    for order, title in (("risk", "Risk score"), ("cvss_baseline", "CVSS baseline")):
        heading = f"## Top {data['k']}, {title.lower()} (all categories)"
        lines += ["", heading, "", "| Places | Item | Grade | Score |", "|---|---|---|---|"]
        for row in data["all"][order]["top"]:
            lines.append(f"| {row['places']} | {row['item']} | {row['gain']} | {row['score']} |")
    lines += ["", "Inputs by sha256: " + ", ".join(f"{k} {v}" for k, v in _flat(data["inputs"]))]
    return "\n".join(lines) + "\n"


def _flat(inputs: Mapping[str, Any]) -> list[tuple[str, str]]:
    flat: list[tuple[str, str]] = []
    for key, value in sorted(inputs.items()):
        if isinstance(value, Mapping):
            flat += [(f"{key}.{name}", str(digest)) for name, digest in sorted(value.items())]
        else:
            flat.append((key, str(value)))
    return flat


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--findings", type=Path, default=ROOT / "out" / "eval" / "findings")
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    args = parser.parse_args(argv)
    try:
        findings, inputs = scored_findings(args.findings, args.out / "ranking")
        data = report(GROUND_TRUTH.read_bytes(), findings, inputs)
    except EvalError as exc:
        print(f"eval-ranking: {exc}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ranking.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "ranking.md").write_text(markdown(data), encoding="utf-8")
    print(markdown(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
