"""Rule catalogue (SPEC section 6.3): SC-002, SC-003 and SC-006 (WARN), end to end with the real OPA."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.opa import OpaRunner

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
FIXTURES = ROOT / "schemas" / "fixtures"
TOOLS_OK = FIXTURES / "tool-status" / "valid" / "all-ok.json"
SCORED = json.loads(
    (FIXTURES / "finding" / "valid" / "sca-enriched-and-scored.json").read_text(encoding="utf-8")
)
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def test_worst_case_priorities_follow_the_risk_model(opa_binary: Path) -> None:
    # risk = 100 x S x E x X x R with E, X, R <= 1: the worst case of a severity is 100 x its weight, banded.
    model = yaml.safe_load((POLICIES / "risk-model.yaml").read_text(encoding="utf-8"))
    bands = sorted(model["priority_bands"].items(), key=lambda band: -band[1])

    def band(score: float) -> str:
        return next((name for name, floor in bands if score >= floor), "P4")

    expected = {sev: band(100 * weight) for sev, weight in model["severity_weight"].items()}
    bundle = PolicyBundle.load(POLICIES)
    actual = OpaRunner(binary=opa_binary).eval(
        "data.sentinel.gate.worst_case_priority", bundle.rego_files, {}
    )
    assert actual == expected


def evaluate(tmp_path: Path, opa_binary: Path, *findings: dict[str, Any]) -> tuple[int, str, dict[str, Any]]:
    (tmp_path / "findings.ndjson").write_text(
        "".join(json.dumps(f) + "\n" for f in findings), encoding="utf-8"
    )
    output = tmp_path / "decision.json"
    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "--findings", str(tmp_path / "findings.ndjson"),
            "--repo", "NOURHANE-EHOUARI/sentinelci",
            "--commit", COMMIT,
            "--context", "release",
            "--evaluated-at", "2026-11-10T10:00:00Z",
            "--policy-dir", str(POLICIES),
            "--tool-status", str(TOOLS_OK),
            "--output", str(output),
            "--opa", str(opa_binary),
        ],
    )  # fmt: skip
    decision: dict[str, Any] = json.loads(output.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas" / "decision.v1.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(decision))
    return result.exit_code, result.output, decision


def with_priority(priority: str) -> dict[str, Any]:
    return {**SCORED, "risk": {**SCORED["risk"], "priority": priority}}


def test_a_p0_vulnerability_blocks_a_release(tmp_path: Path, opa_binary: Path) -> None:
    code, out, decision = evaluate(tmp_path, opa_binary, SCORED)
    assert code == 1, out
    assert [(v["rule"], v["finding_ids"]) for v in decision["violations"]] == [("SC-002", [SCORED["id"]])]


def test_a_p1_vulnerability_warns_and_exits_0(tmp_path: Path, opa_binary: Path) -> None:
    code, out, decision = evaluate(tmp_path, opa_binary, with_priority("P1"))
    assert code == 0, out
    assert decision["verdict"] == "WARN"
    assert decision["violations"] == [
        {"rule": "SC-006", "effect": "WARN", "finding_ids": [SCORED["id"]], "message": "P1 finding"}
    ]
    assert "SentinelCI verdict: WARN" in out


def test_a_known_exploited_fixable_vulnerability_blocks_even_at_p2(tmp_path: Path, opa_binary: Path) -> None:
    kev = {**with_priority("P2"), "enrichment": {**SCORED["enrichment"], "kev": {"listed": True}}}
    code, out, decision = evaluate(tmp_path, opa_binary, kev)
    assert code == 1, out
    assert [v["rule"] for v in decision["violations"]] == ["SC-003"]


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_an_unscored_high_vulnerability_blocks_at_its_worst_case(
    tmp_path: Path, opa_binary: Path, severity: str
) -> None:
    unscored = {k: v for k, v in SCORED.items() if k not in ("risk", "enrichment")} | {"severity": severity}
    code, out, decision = evaluate(tmp_path, opa_binary, unscored)
    assert code == 1, out
    assert decision["violations"][0]["message"] == (
        "P0 finding not waived (unscored findings count at their worst-case priority)"
    )
