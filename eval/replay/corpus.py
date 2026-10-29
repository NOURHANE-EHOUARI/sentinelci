"""Replay corpus for the nightly job (`.github/workflows/replay-nightly.yml`, SPEC section 6.5).

Records a fixed set of release-gate cases with `sentinel evaluate --store`, built from the shared contract
fixtures. Each night the job replays the previous night's corpus with today's engine
(`sentinel replay --all`), then records and uploads a fresh one. A decision that changes for the same inputs
without an engine or OPA version change turns the nightly red; decisions of another engine or OPA version are
skipped and counted.

Each case also states the verdict it exists to cover, so a corpus that silently stopped covering BLOCK or PASS
fails here rather than replaying identically forever.

Usage: uv run python eval/replay/corpus.py --store out/replay-corpus [--opa PATH]
Owner: Track B (B4, B8).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from sentinelci.cli import app

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "schemas" / "fixtures"
POLICIES = ROOT / "policies"
REPO = "NOURHANE-EHOUARI/sentinelci"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
EVALUATED_AT = "2026-11-10T10:00:00Z"

# Finding fixture names (schemas/fixtures/finding/valid/), not secrets.
IN_CONFIG = "secret-in-config"
IN_TWO_FILES = "secret-in-two-files-v1.1"
SECRET_ID = json.loads((FIXTURES / "finding" / "valid" / f"{IN_CONFIG}.json").read_text(encoding="utf-8"))[
    "id"
]
WAIVER = f"""\
version: 1
waivers:
  - id: waiver-2026-001
    finding_id: {SECRET_ID}
    owner: "@Hiba-elouazi"
    justification: Fake demo credential listed in the ground truth.
    expires_at: 2026-12-31T00:00:00Z
"""


@dataclass(frozen=True)
class Case:
    name: str
    expected: str
    context: str = "release"
    findings: tuple[str, ...] = ()
    baseline: tuple[str, ...] | None = None
    waivers: str | None = None
    tool_status: str | None = None


# Every case but the last two models a complete pipeline: all required scanners reported ok.
CASES = (
    Case("release-secret", "BLOCK", findings=(IN_CONFIG,), tool_status="all-ok"),
    Case(
        "pr-secret-already-on-base",
        "PASS",
        context="pr",
        findings=(IN_CONFIG,),
        baseline=(IN_CONFIG,),
        tool_status="all-ok",
    ),
    Case(
        "pr-secret-copied-to-new-file",
        "BLOCK",
        context="pr",
        findings=(IN_TWO_FILES,),
        baseline=(IN_CONFIG,),
        tool_status="all-ok",
    ),
    Case("release-waived-secret", "PASS", findings=(IN_CONFIG,), waivers=WAIVER, tool_status="all-ok"),
    Case(
        "release-waiver-without-owner",
        "BLOCK",
        findings=(IN_CONFIG,),
        waivers=WAIVER.replace("    owner:", "    #"),
        tool_status="all-ok",
    ),
    Case("release-clean", "PASS", tool_status="all-ok"),
    Case("release-scanner-timeout", "BLOCK", tool_status="one-timeout"),
    Case("release-without-tool-status", "BLOCK"),
)


class CorpusError(Exception):
    """A case could not be recorded, or did not give the verdict it exists to cover."""


def _ndjson(names: tuple[str, ...]) -> bytes:
    lines = []
    for name in names:
        finding = json.loads((FIXTURES / "finding" / "valid" / f"{name}.json").read_text(encoding="utf-8"))
        lines.append(json.dumps(finding, sort_keys=True) + "\n")
    return "".join(lines).encode("utf-8")


def record_case(case: Case, store: Path, work: Path, opa: Path | None) -> dict[str, str]:
    """Evaluate one case with `sentinel evaluate --store`; return its decision id and verdict."""
    work.mkdir(parents=True, exist_ok=True)
    (work / "findings.ndjson").write_bytes(_ndjson(case.findings))
    # An empty waivers file rather than the repository's `.sentinel/waivers.yaml`: the corpus stands alone.
    (work / "waivers.yaml").write_text(case.waivers or "", encoding="utf-8")
    args = [
        "evaluate",
        "--findings", str(work / "findings.ndjson"),
        "--repo", REPO,
        "--commit", COMMIT,
        "--context", case.context,
        "--evaluated-at", EVALUATED_AT,
        "--policy-dir", str(POLICIES),
        "--output", str(work / "decision.json"),
        "--store", str(store),
        "--waivers", str(work / "waivers.yaml"),
    ]  # fmt: skip
    if case.baseline is not None:
        (work / "baseline.ndjson").write_bytes(_ndjson(case.baseline))
        args += ["--baseline", str(work / "baseline.ndjson")]
    if case.tool_status is not None:
        args += ["--tool-status", str(FIXTURES / "tool-status" / "valid" / f"{case.tool_status}.json")]
    if opa is not None:
        args += ["--opa", str(opa)]
    code = app(args, standalone_mode=False)
    if code not in (None, 0, 1):
        raise CorpusError(f"{case.name}: sentinel evaluate made no decision (exit {code})")
    decision = json.loads((work / "decision.json").read_text(encoding="utf-8"))
    if decision["verdict"] != case.expected:
        raise CorpusError(f"{case.name}: verdict {decision['verdict']}, expected {case.expected}")
    return {"decision_id": decision["decision_id"], "verdict": decision["verdict"]}


def record(store: Path, work: Path, opa: Path | None = None) -> dict[str, dict[str, str]]:
    return {case.name: record_case(case, store, work / case.name, opa) for case in CASES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--store", type=Path, required=True, help="Evidence store to record into.")
    parser.add_argument(
        "--work", type=Path, default=Path("out/replay-corpus-work"), help="Scratch directory."
    )
    parser.add_argument("--opa", type=Path, default=None, help="OPA binary (default: $SENTINEL_OPA, PATH).")
    args = parser.parse_args(argv)
    try:
        recorded = record(args.store, args.work, args.opa)
    except CorpusError as exc:
        print(f"replay corpus: {exc}", file=sys.stderr)
        return 1
    for name, result in recorded.items():
        print(f"{result['verdict']:<5}  {result['decision_id']}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
