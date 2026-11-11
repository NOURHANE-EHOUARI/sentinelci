"""`make eval-correlation`: the correlator measured on demo-shop (task A7 acceptance, SPEC section 17).

What it measures, on the findings of a `make eval` run (`out/eval/findings/<tool>.ndjson`, or `--findings`):
- **ARI** of the root-cause groups against the true root causes. A finding that detects a seed
  (`eval/detection/score.py`, `detects`) has the seed's root cause; another finding has the root cause
  `root-causes.yaml` labels it with (what one fix resolves). A finding neither labels is unlabelled: it stays
  in the run, out of the ARI, and is counted.
- **Alert reduction**: what a reviewer no longer sees, from the places the tools reported (a finding and
  each of its `other_locations`, the tools' own reports that the normalizer merged) to the groups.
- **Ablation**: each configuration of the stages (`sentinel_ai.correlate.evaluation`).

Without tuning on the test set (SPEC section 17). The root causes are split once, before any score
(`split.yaml` for the seeds, `half` in `root-causes.yaml`). Calibration sees the run without the test half's
findings; the test sees the run without the calibration half's (unlabelled findings are in both: they carry
no label).
1. `--calibrate` picks the stage 2b threshold with the best ARI on the calibration half (ties go to the
   highest threshold, which merges least) and writes `threshold.json` with the embedding model's digest. It
   is committed before the test half is measured.
2. Without `--calibrate`, the test half is measured with the committed threshold, which must name the model
   the provider serves. The ARI-vs-threshold curve on the test half is reported as sensitivity only.

The embedding model is the pinned one (ADR-0009) on a local Ollama (`SENTINEL_OLLAMA_URL`, default the
loopback). Without it, or with `--no-embedding`, the configurations without stage 2b are still measured and
the others say why they were not. The same inputs give the same report, byte for byte: no clock, sorted keys,
every input named by its sha256.

Usage: uv run python eval/correlation/run.py [--findings DIR] [--out out/eval] [--calibrate] [--no-embedding]
Owner: Track A (A7).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from sentinel_ai.correlate.evaluation import CONFIGURATIONS, Score, ablation, cached, calibrate, grid, sweep
from sentinel_ai.correlate.stages import CorrelationError, Embedder, EmbedderError

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
GROUND_TRUTH = ROOT / "demo-shop" / "ground-truth" / "findings.yaml"
SCAN_ROOT = "demo-shop/"
SPLIT = HERE / "split.yaml"
ROOT_CAUSES = HERE / "root-causes.yaml"
THRESHOLD = HERE / "threshold.json"
FINDINGS = ROOT / "out" / "eval" / "findings"
HALVES = ("calibration", "test")

Finding = Mapping[str, Any]


def _load_score() -> Any:
    """eval/detection/score.py (B8's matching rules), under a name no other module can take."""
    spec = importlib.util.spec_from_file_location(
        "sentinel_eval_correlation_score", ROOT / "eval" / "detection" / "score.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("eval/detection/score.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


detects: Callable[[Mapping[str, Any], Finding], bool] = _load_score().detects


class EvalError(Exception):
    """The inputs cannot give an honest measurement: said, never guessed around."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- inputs


def load_split(text: str, seeds: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """seed id -> its half. Every seed of the ground truth is in exactly one half, and no other id is."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or set(data) != set(HALVES):
        raise EvalError(f"split.yaml must have exactly the lists {', '.join(HALVES)}")
    half_of: dict[str, str] = {}
    for half in HALVES:
        ids = data[half] or []
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise EvalError(f"split.yaml: {half} must be a list of seed ids")
        for seed_id in ids:
            if half_of.setdefault(seed_id, half) != half or ids.count(seed_id) > 1:
                raise EvalError(f"split.yaml: {seed_id} is listed twice")
    known = {str(seed["id"]) for seed in seeds}
    if missing := sorted(known - set(half_of)):
        raise EvalError(
            f"split.yaml does not place {', '.join(missing)}: add each new seed to one half by the file's "
            "rule, in the commit that adds it"
        )
    if unknown := sorted(set(half_of) - known):
        raise EvalError(f"split.yaml names seeds the ground truth does not have: {', '.join(unknown)}")
    return half_of


def read_findings(directory: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Every finding of the `<tool>.ndjson` files, in file and line order, and each file's sha256."""
    files = sorted(directory.glob("*.ndjson"))
    if not files:
        raise EvalError(f"no findings in {directory}: run `make eval` first (or give --findings DIR)")
    findings: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for path in files:
        data = path.read_bytes()
        digests[path.stem] = sha256(data)
        # NDJSON lines end with "\n" only: str.splitlines() would also split inside strings on U+2028.
        for number, line in enumerate(data.decode("utf-8").split("\n"), start=1):
            if line.strip():
                try:
                    finding = json.loads(line)
                except ValueError as exc:
                    raise EvalError(f"{path.name}:{number} is not JSON: {exc}") from None
                if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
                    raise EvalError(f"{path.name}:{number} is not a finding with an id")
                findings.append(finding)
    return findings, digests


@dataclass(frozen=True)
class Label:
    """A finding's true root cause and the half it is in."""

    root: str
    half: str


@dataclass(frozen=True)
class RootCause:
    id: str
    half: str
    seeds: tuple[str, ...]
    matchers: tuple[tuple[str, str, frozenset[str]], ...]  # (tool, file under demo-shop/, rules)


def load_root_causes(text: str, split: Mapping[str, str]) -> list[RootCause]:
    """root-causes.yaml, checked: unique ids, a half each, a joined seed's half, and no (tool, file, rule) in
    two root causes."""
    data = yaml.safe_load(text)
    entries = data.get("root_causes") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise EvalError("root-causes.yaml must hold a list `root_causes`")
    causes: list[RootCause] = []
    owner: dict[tuple[str, str, str], str] = {}
    for entry in entries:
        cause_id, half = str(entry.get("id", "")), entry.get("half")
        if not cause_id or half not in HALVES or any(c.id == cause_id for c in causes):
            raise EvalError(f"root-causes.yaml: {cause_id or 'an entry'} needs a unique id and a half")
        seeds = tuple(str(seed) for seed in entry.get("seeds") or [])
        for seed in seeds:
            if split.get(seed) != half:
                raise EvalError(
                    f"root-causes.yaml: {cause_id} joins {seed}, which is not in its half ({half})"
                )
        matchers = []
        for matcher in entry.get("findings") or []:
            rules = frozenset(str(rule) for rule in matcher["rules"])
            for rule in rules:
                key = (str(matcher["tool"]), str(matcher["file"]), rule)
                if owner.setdefault(key, cause_id) != cause_id:
                    raise EvalError(f"root-causes.yaml: {key} is in {owner[key]} and {cause_id}")
            matchers.append((str(matcher["tool"]), str(matcher["file"]), rules))
        causes.append(RootCause(cause_id, half, seeds, tuple(matchers)))
    return causes


def _tool(finding: Finding) -> str:
    tool = finding.get("tool")
    return str(tool.get("name", "")) if isinstance(tool, Mapping) else ""


def _file(finding: Finding) -> str | None:
    location = finding.get("location")
    path = location.get("path") if isinstance(location, Mapping) else None
    return path.removeprefix(SCAN_ROOT) if isinstance(path, str) else None


def labels(
    findings: Sequence[Finding],
    seeds: Sequence[Mapping[str, Any]],
    split: Mapping[str, str],
    causes: Sequence[RootCause],
) -> dict[str, Label]:
    """finding id -> its true root cause and half, for every finding a seed or a root cause labels. A finding
    two labels disagree on cannot be labelled honestly: EvalError."""
    joined = {seed: cause.id for cause in causes for seed in cause.seeds}
    found: dict[str, Label] = {}
    for finding in findings:
        candidates: set[Label] = set()
        for seed in seeds:
            if detects(seed, finding):
                seed_id = str(seed["id"])
                candidates.add(
                    Label(joined.get(seed_id) or str(seed.get("group") or seed_id), split[seed_id])
                )
        key = (_tool(finding), _file(finding), str(finding.get("rule_id")))
        for cause in causes:
            if any(
                key[0] == tool and key[1] == file and key[2] in rules for tool, file, rules in cause.matchers
            ):
                candidates.add(Label(cause.id, cause.half))
        if not candidates:
            continue
        if len(candidates) > 1:
            names = ", ".join(sorted(label.root for label in candidates))
            raise EvalError(f"finding {finding['id']} has more than one true root cause: {names}")
        label = candidates.pop()
        if found.setdefault(str(finding["id"]), label) != label:
            raise EvalError(f"finding {finding['id']} is reported twice, with different root causes")
    return found


def half_of_run(findings: Sequence[Finding], label_of: Mapping[str, Label], half: str) -> list[Finding]:
    """The run without the other half's labelled findings: this half's findings and the unlabelled ones."""
    return [f for f in findings if str(f["id"]) not in label_of or label_of[str(f["id"])].half == half]


def reported_places(findings: Sequence[Finding]) -> int:
    """What the tools reported: each finding's place and each of its `other_locations`, per tool (stage 1
    merges the tools; the normalizer already merged one tool's places of one risk)."""
    return sum(1 + len(f.get("other_locations") or []) for f in findings)


# ---------------------------------------------------------------- the embedding model


@dataclass(frozen=True)
class Model:
    name: str
    digest: str


def model_embedder() -> tuple[Embedder | None, Model | None, str | None]:
    """The pinned embedding model on the local Ollama, checked by digest before any text is sent, or why
    it cannot be used."""
    try:
        from sentinel_ai.providers.ollama import EMBEDDING, OllamaProvider, ProviderError
    except ImportError:
        return None, None, "this checkout has no Ollama provider (B5)"
    model = Model(EMBEDDING.name, EMBEDDING.digest)
    try:
        provider = OllamaProvider.from_env()
        provider.verify(EMBEDDING)
    except (ProviderError, ValueError) as exc:
        return None, model, str(exc)
    return provider.embed, model, None


def read_threshold(text: str, model: Model | None) -> float:
    """The committed threshold, if it was calibrated with the model the provider serves."""
    data = json.loads(text)
    named = Model(**data["embedding_model"])
    if model is not None and named != model:
        raise EvalError(
            f"threshold.json was calibrated with {named.name} ({named.digest}), not the pinned "
            f"{model.name} ({model.digest}): calibrate again (`make eval-correlation-calibrate`)"
        )
    threshold = data["threshold"]
    if not isinstance(threshold, int | float) or not -1 <= threshold <= 1:
        raise EvalError("threshold.json holds no similarity threshold")
    return float(threshold)


# ---------------------------------------------------------------- the measurements


def _score(score: Score) -> dict[str, Any]:
    out = asdict(score)
    out["unlabelled"] = len(score.unlabelled)
    return out


def calibration_document(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    embed: Embedder,
    model: Model,
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    """threshold.json: the threshold with the best ARI on the calibration half, and the curve it came from."""
    thresholds = grid()
    embed = cached(embed)
    best = calibrate(findings, truth, embed, thresholds)
    curve = sweep(findings, truth, embed, thresholds)
    return {
        "embedding_model": asdict(model),
        "threshold": best.threshold,
        "calibration": {"ari": best.ari, "alert_reduction": best.alert_reduction, "labelled": len(truth)},
        "curve": [{"threshold": s.threshold, "ari": s.ari, "groups": s.groups} for s in curve],
        "inputs": dict(inputs),
    }


def measurement(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    *,
    embed: Embedder | None,
    threshold: float | None,
    why_not: str | None,
) -> dict[str, Any]:
    """The test half: every configuration of the stages (stage 2b only with a model and a committed
    threshold), and the ARI-vs-threshold curve as sensitivity."""
    places = reported_places(findings)
    measured = embed is not None and threshold is not None
    scores = ablation(
        findings, truth, embed=embed if measured else None, threshold=threshold or 0.0, raw_alerts=places
    )
    out: dict[str, Any] = {name: _score(score) for score in scores for name in [score.configuration]}
    for name, (_, embedding) in CONFIGURATIONS.items():
        if embedding and name not in out:
            out[name] = {"measured": False, "reason": why_not or "no calibrated threshold"}
    result: dict[str, Any] = {
        "findings": len(findings),
        "reported_places": places,
        "labelled": len(truth),
        "configurations": {name: out[name] for name in CONFIGURATIONS},
    }
    if measured and embed is not None:
        result["sensitivity"] = [
            {"threshold": s.threshold, "ari": s.ari, "alert_reduction": s.alert_reduction}
            for s in sweep(findings, truth, embed, grid(), raw_alerts=places)
        ]
    return result


# ---------------------------------------------------------------- the report


def markdown(report: Mapping[str, Any]) -> str:
    test = report["test"]
    lines = [
        "# Correlation on demo-shop",
        "",
        f"Test half: {test['findings']} findings ({test['reported_places']} places the tools reported), "
        f"{test['labelled']} of them labelled with their root cause. "
        f"Threshold: {report['threshold']['value']} ({report['threshold']['source']}). "
        f"Embedding model: {report['embedding_model']}.",
        "",
        "| Configuration | Groups | ARI | Alert reduction |",
        "|---|---|---|---|",
    ]
    for name, score in test["configurations"].items():
        if score.get("measured") is False:
            lines.append(f"| {name} | not measured: {score['reason']} | | |")
        else:
            lines.append(
                f"| {name} | {score['groups']} | {score['ari']:.3f} | {score['alert_reduction']:.1%} |"
            )
    if "sensitivity" in test:
        lines += [
            "",
            "Sensitivity only (the threshold was not chosen here):",
            "",
            "| Threshold | ARI | Reduction |",
        ]
        lines += ["|---|---|---|"]
        lines += [
            f"| {s['threshold']} | {s['ari']:.3f} | {s['alert_reduction']:.1%} |" for s in test["sensitivity"]
        ]
    lines += ["", f"Inputs: `{json.dumps(report['inputs'], sort_keys=True)}`", ""]
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict[str, Any]:
    truth_text = GROUND_TRUTH.read_bytes()
    seeds: list[Mapping[str, Any]] = yaml.safe_load(truth_text)["seeds"]
    split_text = SPLIT.read_bytes()
    split = load_split(split_text.decode("utf-8"), seeds)
    causes_text = ROOT_CAUSES.read_bytes()
    causes = load_root_causes(causes_text.decode("utf-8"), split)
    findings, digests = read_findings(args.findings)
    label_of = labels(findings, seeds, split, causes)
    inputs: dict[str, Any] = {
        "findings_sha256": digests,
        "ground_truth_sha256": sha256(truth_text),
        "root_causes_sha256": sha256(causes_text),
        "split_sha256": sha256(split_text),
    }
    embed, model, why_not = (None, None, "--no-embedding") if args.no_embedding else model_embedder()

    def half(name: str) -> tuple[list[Finding], dict[str, str]]:
        members = half_of_run(findings, label_of, name)
        return members, {f["id"]: label_of[f["id"]].root for f in members if f["id"] in label_of}

    if args.calibrate:
        if embed is None or model is None:
            raise EvalError(f"calibration needs the embedding model: {why_not}")
        document = calibration_document(*half("calibration"), embed, model, inputs)
        THRESHOLD.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return document

    threshold: float | None = None
    source = "not calibrated: `make eval-correlation-calibrate` writes threshold.json"
    if THRESHOLD.is_file():
        text = THRESHOLD.read_bytes()
        threshold = read_threshold(text.decode("utf-8"), model)
        inputs["threshold_sha256"] = sha256(text)
        source = "threshold.json, calibrated on the calibration half"
    try:
        test = measurement(*half("test"), embed=embed, threshold=threshold, why_not=why_not)
    except EmbedderError as exc:  # the model failed mid-run: the stages without it are still measured
        test = measurement(*half("test"), embed=None, threshold=None, why_not=f"the embedder failed: {exc}")
    return {
        "embedding_model": f"{model.name} ({model.digest})" if model else "none",
        "threshold": {"value": threshold, "source": source},
        "test": test,
        "inputs": inputs,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--findings", type=Path, default=FINDINGS, help="the <tool>.ndjson files of a make eval run"
    )
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    parser.add_argument(
        "--calibrate", action="store_true", help="write threshold.json from the calibration half"
    )
    parser.add_argument("--no-embedding", action="store_true", help="measure only the stages without a model")
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except (EvalError, CorrelationError) as exc:
        print(f"eval-correlation: {exc}", file=sys.stderr)
        return 2
    if args.calibrate:
        print(f"threshold {report['threshold']} (ARI {report['calibration']['ari']}) written to {THRESHOLD}")
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "correlation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", "utf-8")
    (args.out / "correlation.md").write_text(markdown(report), "utf-8")
    print(markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
