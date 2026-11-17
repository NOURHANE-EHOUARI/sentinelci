"""`make eval-fixrate`: the verified fix rate on demo-shop (task B8, SPEC sections 3, 9 and 17).

SPEC section 3 sets "Verified fix rate: >= 60% of attempted fixable seeds", measured by remediation runs. This
report runs the real remediation strategies of SPEC section 9 on demo-shop's seeds and lets the real
verification gate judge every proposal, exactly as the remediation runs do:

- container hygiene (Dockerfile seeds) and Kubernetes manifests: `sentinel remediate dockerfile|kubernetes`
  on the base commit's IaC findings, as the bot's `propose` job runs them (one proposal per strategy), then
  the bot's `verify` job's steps (`.github/workflows/sentinel-remediate.yml`): `remediate apply` on a bare
  copy, the patched commit exported whole and scanned with every scanner the pr gate requires, `remediate
  check` with the same IaC findings, `score`, `evaluate` in pr context with the base as baseline, `remediate
  verify`;
- SAST: the LLM code fixer, one finding at a time, through `make remediate-code`'s own loop
  (deploy/remediate/remediate_code.py: its unverifiable check, the model, up to three attempts with the
  rejection fed back, and its verification steps, the tests in the sandboxed container);
- SCA (and the container image's package): the dependency bump of section 9 is not implemented, so these seeds
  are listed as not attempted, never counted.

Each seed's outcome is the gate's: VERIFIED, REJECTED (with the conditions that failed), FAILED, PARTIAL (a
verified proposal left one of the seed's findings open), NO PROPOSAL (the strategy ran and proposed nothing
for it), or not attempted with the reason. The headline is VERIFIED over attempted (the README defines
attempted), with one row per strategy. The LLM never decides: the gate does.

Fail closed: a step that could not run (no Grype database, a scan that failed, no Docker, no pinned test
image, no model server) makes its seeds "not measured", withholds the headline and exits 2. It is never 0%
and never a pass. The base is this checkout's HEAD, which must be clean and hold the demo-shop tree `make
eval` scanned (out/eval/detection.json); the evidence of every step stays under out/eval/fixrate/<commit>/.

The report has no clock: inputs by sha256, tool and model versions and digests, sorted keys. The model's
answers may still differ from run to run; each proposal is named by its id and its diff's sha256.

Usage: uv run python eval/fixrate/run.py [--test-image IMAGE] [--tools-dir DIR] [--grype-db DIR]
       [--ollama URL] [--findings out/eval/findings] [--out out/eval]
Owner: Track B (B8).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Protocol

import yaml
from pydantic import ValidationError

from sentinelci.contracts.remediation import PatchProposal

ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = ROOT / "demo-shop" / "ground-truth" / "findings.yaml"
TARGET = Fraction(3, 5)  # SPEC section 3: 60%
TARGET_RATE = float(TARGET)
TOOLS = ("gitleaks", "grype", "opengrep", "trivy", "zizmor")  # make eval's findings files


def _load(name: str, path: Path) -> Any:
    """A module of eval/ or deploy/ (not packages), under a name no other module can take."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


score = _load("sentinel_eval_fixrate_score", ROOT / "eval" / "detection" / "score.py")  # `detects`
detection = _load("sentinel_eval_fixrate_detection", ROOT / "eval" / "detection" / "run.py")
rc = _load("sentinel_eval_fixrate_remediate", ROOT / "deploy" / "remediate" / "remediate_code.py")

# The strategies of SPEC section 9, in its order.
BUMP = "deterministic:dependency-bump"
DOCKERFILE = "deterministic:dockerfile"
KUBERNETES = "deterministic:kubernetes"
CODE = "llm:code"
STRATEGIES = (BUMP, DOCKERFILE, KUBERNETES, CODE)
IMPLEMENTED = (DOCKERFILE, KUBERNETES, CODE)
NONE = "none"  # the table's row for the seeds section 9 has no strategy for

NO_STRATEGY = {
    "SECRET": "no strategy in SPEC section 9: a leaked secret is revoked and rotated, not patched",
    "PIPELINE": "no strategy in SPEC section 9 for CI workflows",
    "IAC": "no strategy in SPEC section 9 for it: the Kubernetes fixer edits manifests (KSV rules), the "
    "Dockerfile fixer Dockerfiles (DS rules); Terraform has none",
}
NOT_IMPLEMENTED = (
    "the dependency bump of SPEC section 9 is not implemented (the schema names it, no fixer makes it): no "
    "strategy implemented"
)
NOT_DETECTED = "not detected by the base scan: no finding for a fixer to take"
# Rule of 17 November, set before the 27 November run: the LLM code fixer's fixes are verified with the seed's
# security tests, run by pytest in the shop-api test image (A6), so only a Python seed can be verified.
CODE_OUT_OF_SCOPE = (
    "the LLM code fixer verifies Python fixes only (A6: its security tests run with pytest in the shop-api "
    "test image): a SAST seed in another language is not attempted"
)


def in_code_scope(seed: Mapping[str, Any]) -> bool:
    """Whether the LLM code fixer can take a SAST seed: its file is Python."""
    return str(seed["location"]["path"]).endswith(".py")


# Outcomes. The first three are the verification gate's own (schemas/verification-result.v1.json).
VERIFIED, REJECTED, FAILED = "VERIFIED", "REJECTED", "FAILED"
PARTIAL, NO_PROPOSAL, NOT_MEASURED = "PARTIAL", "NO PROPOSAL", "NOT MEASURED"
GATE_OUTCOMES = (VERIFIED, REJECTED, FAILED)
ATTEMPTED_OUTCOMES = (VERIFIED, REJECTED, FAILED, PARTIAL, NO_PROPOSAL)
# What `make remediate-code` records for an attempt that made no proposal (the LLM fixer's statuses, and the
# loop's own for a finding no patch could verify), and why, as a reader of the rate needs it: how much of NO
# PROPOSAL is the model's, and how much the harness's. "unavailable" counts only with the cause "answer" (two
# answers, neither usable); the model server failing ("provider"), or no cause recorded, is not measured.
NOT_SENT, NOT_VERIFIABLE = "not sent", "no verifiable test"  # the harness's
NO_ANSWER, LEFT_OPEN = "no usable answer", "left open"  # the model's, the fixer's
NO_PROPOSAL_STATUSES = {"not sent": NOT_SENT, "not verifiable": NOT_VERIFIABLE, "unavailable": NO_ANSWER}
PINNED_IMAGE = re.compile(r"(?:[^\s@]+@)?sha256:[0-9a-f]{64}")
LEFT_ALONE = re.compile(r"^warning: (.+) left alone: (.+)$", re.MULTILINE)

ATTEMPTED = (
    "A seed is attempted when SPEC section 9 has a strategy for it, that strategy is implemented, the base "
    "scan detected it, and the strategy was run on its findings. SPEC section 3 counts the attempted "
    "fixable seeds: the seeds the remediation loop was given to fix, not those it chose to propose a fix "
    "for. A strategy that ran and proposed nothing for a seed (NO PROPOSAL), or whose proposal the gate did "
    "not verify, is an attempt that failed, and stays in the denominator: a fixer that declines the hard "
    "cases does not raise its own rate. A seed is VERIFIED only when every finding that detects it is "
    "claimed by a proposal the gate verified; a verified proposal that leaves one of them open makes the "
    "seed PARTIAL, attempted and not verified (rule fixed before any run, knowing the fixers' documented "
    "scope: the Kubernetes fixer leaves hostPath volumes open). Not attempted, listed and counted neither "
    "way: a seed section 9 has no strategy for, one whose strategy is not implemented, one the scan did not "
    "detect, and a SAST seed outside Python, which the LLM code fixer cannot verify (rule of 17 November, "
    "set before the 27 November run)."
)


class NotMeasured(Exception):
    """A step that could not run: what depends on it is not measured (exit 2), never 0% or a pass."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- what a strategy did


@dataclass(frozen=True)
class Attempt:
    """One attempt: the gate's outcome and the conditions that failed, or NO PROPOSAL and why."""

    number: int
    outcome: str
    failed: tuple[str, ...] = ()
    reason: str = ""
    proposal_id: str | None = None
    diff_sha256: str | None = None

    def record(self) -> dict[str, Any]:
        return {
            "number": self.number, "outcome": self.outcome, "failed": list(self.failed),
            "reason": self.reason or None, "proposal_id": self.proposal_id, "diff_sha256": self.diff_sha256,
        }  # fmt: skip


@dataclass(frozen=True)
class Run:
    """A strategy's run: the findings its proposal claims, its attempts, why it proposed nothing (or left a
    file alone)."""

    strategy: str
    claimed: frozenset[str]
    attempts: tuple[Attempt, ...] = ()
    reason: str = ""
    left_open: Mapping[str, str] = field(default_factory=dict)  # path -> why the fixer left it alone
    kind: str = ""  # why it proposed nothing, as counted (NO_PROPOSAL_STATUSES); a fixer's: LEFT_OPEN

    @property
    def outcome(self) -> str:
        """The gate's last word on this run's proposals, or NO PROPOSAL when none reached it."""
        judged = [attempt for attempt in self.attempts if attempt.outcome in GATE_OUTCOMES]
        return judged[-1].outcome if judged else NO_PROPOSAL


class Engine(Protocol):
    """The strategies and the gate. The real one runs the CLI; tests script it."""

    def prepare(self) -> list[dict[str, Any]]:
        """The base commit's findings, scanned as the remediation runs scan it (NotMeasured if not)."""
        ...

    def unavailable(self, strategy: str) -> str | None:
        """Why this strategy cannot run here, or None."""
        ...

    def deterministic(self, strategy: str) -> Run: ...

    def code(self, finding_id: str) -> Run: ...

    def evidence(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------- the gate's result, read honestly


def failed_conditions(result: Mapping[str, Any]) -> list[str]:
    """The conditions of the verification gate (SPEC section 9) that did not hold, in its order."""
    failed = []
    if result.get("build_ok") is not True:
        failed.append("build OK")
    if result.get("tests_ok") is not True:
        failed.append("tests pass")
    if result.get("target_resolved") is not True:
        failed.append("target fingerprint gone")
    new = result.get("new_findings")
    if not isinstance(new, list):
        failed.append("no new finding >= MEDIUM (unreadable)")
    elif new:
        failed.append(f"no new finding >= MEDIUM ({len(new)} new)")
    verdict = result.get("verdict")
    if verdict == "BLOCK":
        failed.append("verdict != BLOCK")
    elif verdict not in ("PASS", "WARN"):
        failed.append(f"verdict != BLOCK (no verdict: {verdict!r})")
    return failed


def gate_attempt(number: int, result: Mapping[str, Any], proposal_id: str, diff: str) -> Attempt:
    """An attempt from `remediate verify`'s result, checked against the gate's invariant (VERIFIED exactly
    when every condition holds), as the bot's report job checks it."""
    outcome = result.get("outcome")
    if outcome not in GATE_OUTCOMES:
        raise NotMeasured(f"attempt {number}: the gate's result has no outcome VERIFIED, REJECTED or FAILED")
    if result.get("proposal_id") != proposal_id:
        raise NotMeasured(f"attempt {number}: the gate's result is not this proposal's")
    failed = failed_conditions(result)
    if (outcome == VERIFIED) == bool(failed):
        raise NotMeasured(f"attempt {number}: the gate's result breaks its invariant ({outcome}, {failed})")
    return Attempt(
        number, str(outcome), tuple(failed), proposal_id=proposal_id, diff_sha256=sha256(diff.encode())
    )


Read = Callable[[int], "tuple[Mapping[str, Any], Mapping[str, Any]] | None"]


def code_run(finding_id: str, records: Sequence[Mapping[str, Any]], read: Read) -> Run:
    """The LLM fixer's attempts on one finding, as `make remediate-code` recorded them; `read(n)` gives
    attempt n's gate result and proposal, or None when the attempt never reached the gate."""
    attempts: list[Attempt] = []
    kind = ""
    for record in records:
        number, status = int(record["number"]), str(record.get("status"))
        reason = str(record.get("reason") or "")
        if status == "unavailable" and record.get("cause") != "answer":
            cause = record.get("cause")
            what = "the model server failed" if cause == "provider" else f"no usable cause ({cause!r})"
            raise NotMeasured(f"attempt {number} is unavailable: {what}: {reason}")
        if status in NO_PROPOSAL_STATUSES:
            attempts.append(Attempt(number, NO_PROPOSAL, reason=f"{status}: {reason}" if reason else status))
            kind = NO_PROPOSAL_STATUSES[status]
            continue
        if status not in GATE_OUTCOMES:
            raise NotMeasured(f"attempt {number} ended as {status!r}, which no step reports")
        found = read(number)
        if found is None:
            raise NotMeasured(f"attempt {number} did not reach the gate: {reason or 'no result'}")
        result, proposal = found
        attempt = gate_attempt(
            number, result, str(proposal.get("proposal_id")), str(proposal.get("diff", ""))
        )
        if attempt.outcome != status:
            raise NotMeasured(
                f"attempt {number}: the loop recorded {status}, the gate's result says otherwise"
            )
        attempts.append(attempt)
    claimed = frozenset({finding_id}) if any(a.outcome in GATE_OUTCOMES for a in attempts) else frozenset()
    why = "; ".join(f"attempt {a.number}: {a.reason}" for a in attempts if a.outcome == NO_PROPOSAL)
    return Run(CODE, claimed, tuple(attempts), reason=why, kind=kind)


# ---------------------------------------------------------------- seeds, strategies, outcomes


def strategy_of(seed: Mapping[str, Any]) -> tuple[str | None, str]:
    """The strategy of SPEC section 9 for a seed, from the ground truth alone; or None, and why."""
    category = str(seed["category"])
    rules = [str(d["rule"]) for d in seed["expected"]["detections"]]
    if category == "SAST":
        return CODE, ""
    if category in ("SCA", "CONTAINER"):  # a vulnerable package: fixed by a version bump
        return BUMP, ""
    if category == "IAC" and rules and all(rule.startswith("KSV-") for rule in rules):
        return KUBERNETES, ""
    if category == "IAC" and rules and all(rule.startswith("DS-") for rule in rules):
        return DOCKERFILE, ""
    return None, NO_STRATEGY.get(category, f"no strategy in SPEC section 9 for {category}")


def combine(outcomes: Iterable[str]) -> str:
    """A seed's outcome from its findings': VERIFIED only when all are, PARTIAL when only some are."""
    outcomes = list(outcomes)
    if NOT_MEASURED in outcomes:
        return NOT_MEASURED
    if outcomes and all(outcome == VERIFIED for outcome in outcomes):
        return VERIFIED
    if VERIFIED in outcomes:
        return PARTIAL
    for outcome in (FAILED, REJECTED):
        if outcome in outcomes:
            return outcome
    return NO_PROPOSAL


def _place(finding: Mapping[str, Any]) -> str | None:
    location = finding.get("location")
    return str(location["path"]) if isinstance(location, Mapping) and "path" in location else None


def _target(finding: Mapping[str, Any], run: Run | str) -> dict[str, Any]:
    """What happened to one finding of a seed under its strategy's run (a string: why it was not measured)."""
    me: dict[str, Any] = {
        "id": str(finding["id"]),
        "rule": finding.get("rule_id"),
        "failed": [],
        "attempts": [],
    }
    if isinstance(run, str):
        return me | {"outcome": NOT_MEASURED, "reason": run}
    me["attempts"] = [attempt.record() for attempt in run.attempts]
    if me["id"] not in run.claimed:
        why = run.reason or "the proposal does not claim it: the fixer left it open"
        path = _place(finding)
        if path is not None and path in run.left_open and run.left_open[path] not in why:
            why += f" ({path} left alone: {run.left_open[path]})"
        return me | {"outcome": NO_PROPOSAL, "reason": why, "kind": run.kind or LEFT_OPEN}
    judged = [attempt for attempt in run.attempts if attempt.outcome in GATE_OUTCOMES]
    if not judged:  # a claim no gate result backs is not a measurement
        return me | {"outcome": NOT_MEASURED, "reason": "claimed, never judged"}
    return me | {
        "outcome": judged[-1].outcome,
        "failed": list(judged[-1].failed),
        "reason": run.reason or None,
    }


def seed_row(
    seed: Mapping[str, Any],
    base: Sequence[Mapping[str, Any]] | None,
    runs: Mapping[str, Run | str],
    recorded: Sequence[Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """One seed: its strategy, whether it was attempted, and its outcome. `base` is None when the base scan
    could not be made; `runs` maps a deterministic strategy, or a code finding's id, to its run."""
    strategy, why = strategy_of(seed)
    row: dict[str, Any] = {
        "id": seed["id"], "category": seed["category"], "title": seed.get("title"), "strategy": strategy,
        "status": "not attempted", "outcome": None, "why": why or None, "failed": [], "findings": [],
        "make_eval_detected": None,
    }  # fmt: skip
    detecting = sorted(
        (finding for finding in base or [] if score.detects(seed, finding)), key=lambda f: str(f["id"])
    )
    if strategy == BUMP:
        fixed = {v for f in detecting for v in (f.get("package") or {}).get("fixed_versions") or []}
        row["fixed_versions"] = sorted(fixed)
    if strategy is None:
        return row
    if strategy not in IMPLEMENTED:
        row["why"] = NOT_IMPLEMENTED
        return row
    if strategy == CODE and not in_code_scope(seed):
        row["why"] = CODE_OUT_OF_SCOPE
        return row
    if recorded is not None:
        row["make_eval_detected"] = any(score.detects(seed, finding) for finding in recorded)
    if base is None:
        reason = str(runs.get("prepare", "the base was not scanned"))
        row |= {"status": "not measured", "outcome": NOT_MEASURED, "why": reason}
        return row
    if not detecting:
        row["why"] = NOT_DETECTED
        return row
    targets = [
        _target(finding, runs.get(strategy if strategy != CODE else str(finding["id"]), "not run"))
        for finding in detecting
    ]
    outcome = combine(target["outcome"] for target in targets)
    failed: list[str] = []
    for target in targets:
        failed += [condition for condition in target["failed"] if condition not in failed]
    row |= {
        "status": "not measured" if outcome == NOT_MEASURED else "attempted",
        "outcome": outcome,
        "why": next((t["reason"] for t in targets if t["outcome"] == NOT_MEASURED), None),
        "failed": failed,
        "findings": targets,
    }
    if outcome == NO_PROPOSAL:  # why, as counted: one kind, or "mixed" when its findings differ
        kinds = sorted({str(t["kind"]) for t in targets})
        row["no_proposal"] = kinds[0] if len(kinds) == 1 else "mixed"
    return row


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(numerator / denominator, 4)


def summarize(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    attempted = [row for row in rows if row["status"] == "attempted"]
    not_measured = [row for row in rows if row["status"] == "not measured"]
    verified = sum(row["outcome"] == VERIFIED for row in attempted)
    counts = Counter(row["outcome"] for row in attempted)
    strategies: dict[str, dict[str, Any]] = {}
    for strategy in (*STRATEGIES, NONE):
        mine = [row for row in rows if (row["strategy"] or NONE) == strategy]
        tried = [row for row in mine if row["status"] == "attempted"]
        missing = sum(row["status"] == "not measured" for row in mine)
        won = sum(row["outcome"] == VERIFIED for row in tried)
        strategies[strategy] = {
            "seeds": len(mine),
            "attempted": len(tried),
            "verified": won,
            "rejected": sum(row["outcome"] == REJECTED for row in tried),
            "failed": sum(row["outcome"] == FAILED for row in tried),
            "partial": sum(row["outcome"] == PARTIAL for row in tried),
            "no_proposal": sum(row["outcome"] == NO_PROPOSAL for row in tried),
            "no_proposal_why": dict(
                sorted(Counter(row["no_proposal"] for row in tried if row["outcome"] == NO_PROPOSAL).items())
            ),
            "not_attempted": sum(row["status"] == "not attempted" for row in mine),
            "not_measured": missing,
            "rate": None if missing else _rate(won, len(tried)),
        }
    reason = None
    if not_measured:
        reason = f"{len(not_measured)} seed(s) not measured: {not_measured[0]['why']}"
    elif not attempted:
        reason = "no fixable seed was attempted: the rate is undefined"
    headline = None
    if reason is None:
        rate = round(verified / len(attempted), 4)
        headline = {
            "verified": verified, "attempted": len(attempted), "rate": rate, "target": TARGET_RATE,
            "met": Fraction(verified, len(attempted)) >= TARGET,  # exact, not the rounded rate
        }  # fmt: skip
    differs = [
        row["id"]
        for row in rows
        if row["make_eval_detected"] is not None
        and row["status"] != "not measured"
        and row["make_eval_detected"] != bool(row["findings"])
    ]
    return {
        "measured": headline is not None,
        "reason": reason,
        "headline": headline,
        "outcomes": {outcome: counts.get(outcome, 0) for outcome in ATTEMPTED_OUTCOMES},
        "strategies": strategies,
        "not_attempted": [row["id"] for row in rows if row["status"] == "not attempted"],
        "not_measured": [row["id"] for row in not_measured],
        "detection_differs": differs,
    }


def measure(
    truth: Mapping[str, Any],
    engine: Engine,
    *,
    recorded: Sequence[Mapping[str, Any]] | None = None,
    inputs: Mapping[str, Any] | None = None,
    truth_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Run every implemented strategy on the seeds it can take, and judge each with the gate."""
    seeds = sorted(truth["seeds"], key=lambda seed: str(seed["id"]))
    runs: dict[str, Run | str] = {}
    base: list[dict[str, Any]] | None
    try:
        base = engine.prepare()
    except NotMeasured as exc:
        base, runs["prepare"] = None, str(exc)
    if base is not None:
        wanted: dict[str, list[str]] = {strategy: [] for strategy in IMPLEMENTED}
        for seed in seeds:
            strategy, _ = strategy_of(seed)
            if strategy in wanted and (strategy != CODE or in_code_scope(seed)):
                wanted[strategy] += [str(f["id"]) for f in base if score.detects(seed, f)]
        for strategy in (DOCKERFILE, KUBERNETES):
            if not wanted[strategy]:
                continue
            why = engine.unavailable(strategy)
            try:
                runs[strategy] = why if why is not None else engine.deterministic(strategy)
            except NotMeasured as exc:
                runs[strategy] = f"{strategy}: {exc}"
        stopped = engine.unavailable(CODE) if wanted[CODE] else None
        for finding_id in sorted(set(wanted[CODE])):
            if stopped is not None:
                runs[finding_id] = stopped
                continue
            try:
                runs[finding_id] = engine.code(finding_id)
            except NotMeasured as exc:
                runs[finding_id] = f"{CODE}: {exc}"
                stopped = f"not run: an earlier attempt could not run ({exc})"
    rows = [seed_row(seed, base, runs, recorded) for seed in seeds]
    return {
        "schema_version": 1,
        "attempted_means": ATTEMPTED,
        "inputs": {
            "ground_truth_sha256": None if truth_bytes is None else sha256(truth_bytes),
            **(inputs or {}),
        },
        "evidence": engine.evidence(),
        "seeds": rows,
        "summary": summarize(rows),
    }


def exit_code(data: Mapping[str, Any]) -> int:
    """0 when the rate was measured (met or not: the report says which), 2 when it was not."""
    return 0 if data["summary"]["measured"] else 2


# ---------------------------------------------------------------- the report


def _percent(value: float | None) -> str:
    return "—" if value is None else f"{100 * value:.1f}%"


def markdown(data: Mapping[str, Any]) -> str:
    summary = data["summary"]
    headline = summary["headline"]
    lines = ["# Verified fix rate (B8)", ""]
    if headline is None:
        lines += [f"**Verified fix rate: not measured.** {summary['reason']}. No rate is given (exit 2).", ""]
    else:
        met = "met" if headline["met"] else "not met"
        lines += [
            f"**Verified fix rate: {headline['verified']} of {headline['attempted']} attempted fixable seeds "
            f"({_percent(headline['rate'])})**. SPEC section 3 target: >= {100 * headline['target']:.0f}%: "
            f"{met}.",
            "",
        ]
    lines += [f"**Attempted.** {data['attempted_means']}", ""]
    if headline is not None:
        lines += [
            "Outcomes of the attempted seeds: "
            + ", ".join(f"{name} {count}" for name, count in summary["outcomes"].items())
            + ".",
            "",
        ]
    lines += [
        "## Per strategy",
        "",
        "| Strategy | Seeds | Attempted | Verified | Rejected | Failed | Partial | No proposal "
        "| Not attempted | Not measured | Rate |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, entry in summary["strategies"].items():
        rate = "not measured" if entry["not_measured"] else _percent(entry["rate"])
        cells = {key: str(entry[key]) for key in entry if key not in ("rate", "no_proposal_why")}
        if entry["no_proposal_why"]:  # how much of it is the model's, how much the harness's
            why = ", ".join(f"{count} {kind}" for kind, count in entry["no_proposal_why"].items())
            cells["no_proposal"] += f" ({why})"
        counts = " | ".join(
            cells[key]
            for key in (
                "seeds", "attempted", "verified", "rejected", "failed", "partial", "no_proposal",
                "not_attempted", "not_measured",
            )
        )  # fmt: skip
        lines.append(f"| {name} | {counts} | {rate} |")
    lines += [
        "",
        "## Per seed",
        "",
        "| Seed | Category | Strategy | Status | Outcome | Failed conditions, or why |",
        "|---|---|---|---|---|---|",
    ]
    for row in data["seeds"]:
        detail = ", ".join(row["failed"]) or row["why"] or ""
        if row["outcome"] in (NO_PROPOSAL, PARTIAL):
            detail = "; ".join(
                f"{t['rule']} ({t['id'][:12]}) {t['outcome']}" + (f": {t['reason']}" if t["reason"] else "")
                for t in row["findings"]
            )
        tries = max((len(t["attempts"]) for t in row["findings"]), default=0)
        if tries > 1:
            detail += f" (after {tries} attempts)"
        if row.get("fixed_versions"):
            detail += f" (fixed in {', '.join(row['fixed_versions'])})"
        lines.append(
            f"| {row['id']} | {row['category']} | {row['strategy'] or NONE} | {row['status']} | "
            f"{row['outcome'] or '—'} | {detail.replace('|', '/')} |"
        )
    if summary["detection_differs"]:
        lines += [
            "",
            "**The base scan and `make eval` disagree on whether these seeds are detected:** "
            + ", ".join(summary["detection_differs"])
            + ". The remediation works from the base scan.",
        ]
    lines += ["", "## Inputs and evidence", ""]
    for key, value in sorted(data["inputs"].items()):
        if isinstance(value, Mapping):
            value = ", ".join(f"{name} `{digest}`" for name, digest in sorted(value.items())) or "none"
        lines.append(f"- {key}: {value if value is not None else 'none'}")
    for key, value in sorted(data["evidence"].items()):
        if isinstance(value, Mapping):
            value = ", ".join(f"{name} {item}" for name, item in sorted(value.items())) or "none"
        lines.append(f"- {key}: {value if value is not None else 'none'}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- make eval's inputs


def recorded_inputs(
    findings_dir: Path, tree: Callable[[], str | None] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """`make eval`'s findings and their digests, once demo-shop/ is the tree it scanned (detection.json)."""
    report = findings_dir.parent / "detection.json"
    try:
        report_bytes = report.read_bytes()
        scanned = json.loads(report_bytes)["inputs"].get("demo_shop_tree")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise NotMeasured(f"no detection report at {report}: run `make eval` first") from exc
    if not scanned:
        raise NotMeasured(f"{report} names no demo-shop tree: run `make eval` on a clean checkout")
    current = (tree or detection.demo_shop_tree)()
    if current is None:
        raise NotMeasured("demo-shop/ is not a clean checkout: the code fixed would not be the code scanned")
    if current != scanned:
        raise NotMeasured(f"demo-shop/ is tree {current[:12]}, but `make eval` scanned {scanned[:12]}")
    recorded: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for tool in TOOLS:
        path = findings_dir / f"{tool}.ndjson"
        if path.is_file():
            data = path.read_bytes()
            digests[tool] = sha256(data)
            recorded += [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]
    inputs = {"demo_shop_tree": current, "detection_sha256": sha256(report_bytes), "findings_sha256": digests}
    return recorded, inputs


# ---------------------------------------------------------------- the real engine


class Refused:
    """An engine for a run refused before anything started: nothing is measured."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def prepare(self) -> list[dict[str, Any]]:
        raise NotMeasured(self.reason)

    def unavailable(self, strategy: str) -> str | None:
        return self.reason

    def deterministic(self, strategy: str) -> Run:
        raise NotMeasured(self.reason)

    def code(self, finding_id: str) -> Run:
        raise NotMeasured(self.reason)

    def evidence(self) -> dict[str, Any]:
        return {}


def _propose_code_fix(*args: Any, **kwargs: Any) -> Any:
    """B6's fixer, imported when the first finding is sent (the deterministic strategies do not need it)."""
    from sentinel_ai.patch import propose_code_fix

    return propose_code_fix(*args, **kwargs)


class RealEngine:
    """The remediation runs themselves: `make remediate-code`'s loop object (deploy/remediate/
    remediate_code.py) for its bare copy, exports, scans and the LLM fixer's attempts, and the bot's verify
    job's steps for the deterministic strategies. Every command is this checkout's CLI."""

    def __init__(
        self, settings: Any, provider: Any, out: Path, runner: Any = None, provider_error: str = ""
    ) -> None:
        model = getattr(provider, "generation", None)
        self.provider, self.provider_error = provider, provider_error
        self.loop: Any = rc.RemediateCode(
            settings, _propose_code_fix, provider, model.name if model else "none",
            model.digest if model else None, run=runner or rc.run_command, fetch=False, out=out, root=ROOT,
        )  # fmt: skip
        self.findings: list[Any] = []

    # -------------------------------------------------------------- the base

    def prepare(self) -> list[dict[str, Any]]:
        """The base commit (HEAD of a clean checkout) in a bare copy, exported whole, and scanned with every
        scanner the pr gate requires, as `make remediate-code` does (without its origin/main precondition)."""
        loop = self.loop
        try:
            if loop.run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).stdout.strip():
                raise NotMeasured(
                    "the checkout is not clean: the CLI, policies and waivers that judge must be a commit's"
                )
            base = loop.run(["git", "rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip()
            # From here as RemediateCode.__call__: the bare copy, its export, OPA, Grype's database, the scan.
            loop.work = loop.out / base[:12]
            loop._fresh(loop.work)
            loop.base, loop.repo = base, loop.work / "repo.git"
            loop.run(["git", "init", "--quiet", "--bare", str(loop.repo)])
            empty = loop.run(["git", "hash-object", "-t", "tree", "/dev/null"]).stdout.strip()
            loop.run(["git", "-C", str(loop.repo), "config", "attr.tree", empty])
            loop.run(["git", "-C", str(loop.repo), "fetch", "--quiet", "--no-tags", str(loop.root),
                      "+HEAD:refs/sentinel/base"])  # fmt: skip
            if (
                loop.run(["git", "-C", str(loop.repo), "rev-parse", "refs/sentinel/base"]).stdout.strip()
                != base
            ):
                raise NotMeasured("the bare copy is not the checked-out commit")
            loop.base_tree = loop._export(base, loop.work / "base", whole=True)
            loop.opa_manifest = loop.work / "opa-manifest.json"
            settings = loop.settings
            loop.run(rc.sentinel("tools", "verify", "opa", "--lock", str(settings.lock), "--dest",
                                 str(settings.tools_dir), "--report", str(loop.opa_manifest)))  # fmt: skip
            loop.run(rc.sentinel(
                "tools", "grype-db", "--db-dir", str(settings.grype_db), "--report",
                str(loop.work / "grype-db.json"), "--timeout", str(settings.timeout_s), "--lock",
                str(settings.lock), "--tools-dir", str(settings.tools_dir),
            ))  # fmt: skip
            loop.before = loop.work / "before.ndjson"
            loop._scan(loop.base_tree, base, loop.work / "base-scan", loop.before, git_range=None)
            self.findings = loop._findings(loop.before)
            text = loop.before.read_text(encoding="utf-8")
        except rc.RemediationError as exc:
            raise NotMeasured(f"the base could not be prepared: {exc}") from exc
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def unavailable(self, strategy: str) -> str | None:
        if strategy != CODE:
            return None  # the deterministic strategies need only what `prepare` already ran
        image = self.loop.settings.test_image
        if not image:
            return "no test image (`--test-image`, TEST_IMAGE=): the code fixes' tests cannot run"
        if not PINNED_IMAGE.fullmatch(image):
            return f"the test image {image} is not pinned by digest (name@sha256:... or a local sha256: id)"
        docker = shutil.which("docker")
        if docker is None:
            return "Docker is not installed: the code fixes' tests run only in its sandbox"
        inspected = self.loop.run([docker, "image", "inspect", "--format", "{{.Id}}", image], check=False)
        if inspected.returncode != 0:
            code = inspected.returncode
            return f"Docker cannot use the test image {image} (`docker image inspect` exit {code})"
        if self.provider is None:
            return f"no model provider: {self.provider_error or 'not configured'}"
        try:
            self.provider.verify(self.provider.generation)
        except Exception as exc:  # the model server is down or serves another digest: not measured
            return f"the pinned model is not served: {type(exc).__name__}: {exc}"
        return None

    # -------------------------------------------------------------- the deterministic strategies (the bot)

    def deterministic(self, strategy: str) -> Run:
        """The bot's propose job's fixer on the base IaC findings, then its verify job's steps."""
        loop = self.loop
        name = strategy.removeprefix("deterministic:")
        work = loop.work / name
        loop._fresh(work)
        path = work / "proposal.json"
        iac = loop.work / "base-scan" / "iac.ndjson"
        done = loop.run(rc.sentinel("remediate", name, "--findings", str(iac), "--out", str(path),
                                    "--repo-root", str(loop.base_tree)), check=False)  # fmt: skip
        if done.returncode != 0:
            last = ((done.stderr or "").strip().splitlines() or ["no output"])[-1]
            raise NotMeasured(f"the fixer could not run (exit {done.returncode}): {last}")
        left_open = dict(LEFT_ALONE.findall(done.stderr or ""))
        if not path.is_file():
            details = "; ".join(f"{place}: {why}" for place, why in sorted(left_open.items()))
            reason = "nothing to propose" + (f" ({details})" if details else "")
            return Run(strategy, frozenset(), reason=reason, left_open=left_open)
        try:
            proposal = PatchProposal.model_validate_json(path.read_bytes())
        except (OSError, ValidationError) as exc:
            raise NotMeasured(f"the fixer's proposal cannot be read: {exc}") from exc
        attempt = self._verify_iac(path, proposal, work)
        return Run(strategy, frozenset(proposal.finding_ids), (attempt,), left_open=left_open)

    def _verify_iac(self, path: Path, proposal: PatchProposal, work: Path) -> Attempt:
        """The bot's verify job (`verify_one`): apply, export whole, scan, check with the base IaC findings,
        score, evaluate in pr context with the base as baseline, verify. One attempt: a deterministic fixer
        makes the same proposal again, so the bot does not retry it."""
        loop = self.loop
        cli = rc.sentinel
        try:
            applied = json.loads(loop.run(cli(
                "remediate", "apply", "--proposal", str(path), "--findings", str(loop.before),
                "--repo-root", str(loop.repo), "--base", loop.base,
            )).stdout)  # fmt: skip
            branch, commit = str(applied["branch"]), str(applied["commit"])
            if not rc._BRANCH.fullmatch(branch) or not rc._COMMIT.fullmatch(commit):
                raise NotMeasured("the applied branch or commit is not one apply makes")
            patched = loop._export(commit, work / "patched", whole=True)
            after = work / "after.ndjson"
            status = loop._scan(patched, commit, work / "scan", after, git_range=f"{loop.base}..{commit}")
            checked = loop.run(cli(
                "remediate", "check", "--proposal", str(path), "--base-root", str(loop.base_tree),
                "--patched-root", str(patched), "--findings", str(loop.work / "base-scan" / "iac.ndjson"),
            ), check=False)  # fmt: skip
            if checked.returncode not in (0, 1):
                raise NotMeasured(f"its build and tests could not be checked (exit {checked.returncode})")
            (work / "check.json").write_text(checked.stdout, encoding="utf-8")
            check = json.loads(checked.stdout)
            if not (isinstance(check.get("build_ok"), bool) and isinstance(check.get("tests_ok"), bool)
                    and isinstance(check.get("problems"), list)):  # fmt: skip
                raise NotMeasured("its build and tests could not be checked (no whole result)")
            scored = work / "scored.ndjson"
            loop.run(cli("score", "--findings", str(after), "--policy-dir", str(loop.root / "policies"),
                         "--out", str(scored)))  # fmt: skip
            decision = work / "decision.json"
            evaluated = loop.run(cli(
                "evaluate", "--findings", str(scored), "--repo", rc.REPO, "--commit", commit,
                "--context", "pr", "--ref", f"refs/heads/{branch}", "--policy-dir", "policies",
                "--opa", str(loop.settings.tools_dir / "bin" / "opa"),
                *rc.tool_versions(loop.opa_manifest, status),
                "--tool-status", str(status), "--baseline", str(loop.before), "--output", str(decision),
            ), check=False)  # fmt: skip
            if evaluated.returncode not in (0, 1):
                raise NotMeasured("no decision on the patched commit")
            result = work / "result.json"
            verified = loop.run(cli(
                "remediate", "verify", "--proposal", str(path), "--before", str(loop.before),
                "--after", str(scored), "--decision", str(decision), "--tool-status", str(status),
                "--build-ok" if check["build_ok"] else "--build-failed",
                "--tests-ok" if check["tests_ok"] else "--tests-failed", "--out", str(result),
            ), check=False)  # fmt: skip
            if verified.returncode not in (0, 1):
                raise NotMeasured("the verification gate refused its inputs")
            outcome = json.loads(result.read_text(encoding="utf-8"))
        except (rc.RemediationError, NotMeasured, OSError, KeyError, ValueError, TypeError) as exc:
            raise NotMeasured(f"the verification did not reach the gate: {exc}") from exc
        return gate_attempt(1, outcome, proposal.proposal_id, proposal.diff)

    # -------------------------------------------------------------- the LLM code fixer (make remediate-code)

    def code(self, finding_id: str) -> Run:
        loop = self.loop
        target = next(finding for finding in self.findings if finding.id == finding_id)
        attempts = loop._remediate(target, self.findings)

        def read(number: int) -> tuple[dict[str, Any], dict[str, Any]] | None:
            work = loop.work / finding_id[:12] / f"attempt-{number}"
            result, proposal = work / "result.json", work / "proposal.json"
            if not (result.is_file() and proposal.is_file()):
                return None
            return (json.loads(result.read_text(encoding="utf-8")),
                    json.loads(proposal.read_text(encoding="utf-8")))  # fmt: skip

        return code_run(finding_id, [attempt.record() for attempt in attempts], read)

    # -------------------------------------------------------------- evidence

    def evidence(self) -> dict[str, Any]:
        loop = self.loop
        work: Path | None = getattr(loop, "work", None)
        settings = loop.settings
        tools: dict[str, str] = {}
        for document in (
            getattr(loop, "opa_manifest", None),
            work / "base-scan" / "status.json" if work else None,
        ):
            if document is not None and document.is_file():
                entries = json.loads(document.read_text(encoding="utf-8")).get("tools") or {}
                tools |= {name: str(e.get("version")) for name, e in entries.items() if e.get("version")}

        def digest(path: Path | None) -> str | None:
            return sha256(path.read_bytes()) if path is not None and path.is_file() else None

        model = getattr(self.provider, "generation", None)
        if model is not None:
            from sentinel_ai.patch import PROMPT_SHA256, PROMPT_VERSION

            described: dict[str, Any] | None = {
                "name": model.name, "digest": model.digest, "prompt_version": PROMPT_VERSION,
                "prompt_sha256": PROMPT_SHA256,
            }  # fmt: skip
        else:
            described = None
        return {
            "commit": getattr(loop, "base", None),
            "base_findings_sha256": digest(work / "before.ndjson" if work else None),
            "grype_db_report_sha256": digest(work / "grype-db.json" if work else None),
            "tools_lock_sha256": digest(settings.lock),
            "tools": dict(sorted(tools.items())),
            "test_image": settings.test_image or None,
            "model": described,
            "evidence_dir": str(work.relative_to(ROOT)) if work and work.is_relative_to(ROOT) else str(work),
        }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--findings", type=Path, default=ROOT / "out" / "eval" / "findings",
                        help="make eval's findings (its detection.json must be beside them)")  # fmt: skip
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "eval")
    parser.add_argument("--tools-dir", type=Path, default=ROOT / ".sentinel" / "tools")
    parser.add_argument("--grype-db", type=Path, default=ROOT / "out" / "grype-db",
                        help="where Grype's database is prepared (`sentinel tools grype-db`)")  # fmt: skip
    parser.add_argument("--test-image", default="", help="the shop-api test image, pinned by digest")
    parser.add_argument("--ollama", default=None, help="Ollama URL (default: SENTINEL_OLLAMA_URL, loopback)")
    args = parser.parse_args(argv)
    truth_bytes = GROUND_TRUTH.read_bytes()
    recorded: list[dict[str, Any]] | None = None
    inputs: dict[str, Any] = {}
    engine: Engine
    try:
        recorded, inputs = recorded_inputs(args.findings)
    except NotMeasured as exc:
        engine = Refused(str(exc))
    else:
        provider, provider_error = None, ""
        try:
            from sentinel_ai.providers.ollama import OllamaProvider

            provider = OllamaProvider(args.ollama) if args.ollama else OllamaProvider.from_env()
        except Exception as exc:  # a URL the provider refuses: the code fixes are not measured
            provider_error = f"{type(exc).__name__}: {exc}"
        settings = rc.Settings(
            test_image=args.test_image, tools_dir=args.tools_dir.resolve(), grype_db=args.grype_db.resolve()
        )
        engine = RealEngine(
            settings, provider, (args.out / "fixrate").resolve(), provider_error=provider_error
        )
    data = measure(
        yaml.safe_load(truth_bytes), engine, recorded=recorded, inputs=inputs, truth_bytes=truth_bytes
    )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "fixrate.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "fixrate.md").write_text(markdown(data), encoding="utf-8")
    print(markdown(data))
    return exit_code(data)


if __name__ == "__main__":
    sys.exit(main())
