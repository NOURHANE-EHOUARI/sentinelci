"""The verification gate, the remediation states and the `sentinel remediate` commands (SPEC §9)."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal, VerificationResult
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.remediation.gate import verify_proposal
from sentinelci.remediation.proposal import RemediationError, build_proposal
from sentinelci.remediation.states import advance, after_verification

from .conftest import NOW, ROOT, SEED, SEED_PATH, iac_finding, seed_findings

PROPOSAL = PatchProposal.model_validate_json(
    (ROOT / "schemas" / "fixtures" / "patch-proposal" / "valid" / "dependency-bump.json").read_bytes()
)
TARGET = PROPOSAL.finding_ids[0]


def _finding(rule: str, severity: str) -> Finding:
    return iac_finding(rule, path="demo-shop/infra/k8s/web.yaml", severity=severity)


EXISTING = _finding("KSV-0125", "MEDIUM")


def _verify(proposal: PatchProposal = PROPOSAL, **changes: Any) -> VerificationResult:
    target = iac_finding("KSV-0017", severity="HIGH").model_copy(update={"id": TARGET})
    inputs: dict[str, Any] = {
        "before": {TARGET: target, EXISTING.id: EXISTING},
        "after": {EXISTING.id: EXISTING},
        "build_ok": True,
        "tests_ok": True,
        "verdict": "PASS",
        "verified_at": NOW,
    }
    inputs.update(changes)
    return verify_proposal(proposal, **inputs)


def test_a_patch_is_verified_only_when_every_condition_holds(result_validator: Draft202012Validator) -> None:
    result = _verify(pull_request=42)
    assert (result.outcome, result.target_resolved, result.new_findings) == ("VERIFIED", True, [])
    assert after_verification(result) == "VERIFIED"
    assert not list(result_validator.iter_errors(json.loads(result.model_dump_json(exclude_none=True))))


NEW_HIGH = _finding("KSV-0014", "HIGH")
NEW_MEDIUM = _finding("KSV-0012", "MEDIUM")
NEW_LOW = _finding("KSV-0011", "LOW")


@pytest.mark.parametrize(
    ("changes", "failed"),
    [
        ({"build_ok": False}, "build_ok"),
        ({"tests_ok": False}, "tests_ok"),
        ({"verdict": "BLOCK"}, "verdict"),
        ({"after": {TARGET: iac_finding("KSV-0017"), EXISTING.id: EXISTING}}, "target_resolved"),
        ({"after": {EXISTING.id: EXISTING, NEW_HIGH.id: NEW_HIGH}}, "new_findings"),
        ({"after": {EXISTING.id: EXISTING, NEW_MEDIUM.id: NEW_MEDIUM}}, "new_medium"),
    ],
    ids=["build", "tests", "block", "target-still-there", "new-high-finding", "new-medium-finding"],
)
def test_any_failed_condition_rejects_the_patch(
    changes: dict[str, Any], failed: str, result_validator: Draft202012Validator
) -> None:
    result = _verify(**changes)
    assert result.outcome == "REJECTED"
    if failed == "new_findings":
        assert result.new_findings == [NEW_HIGH.id]
    assert not list(result_validator.iter_errors(json.loads(result.model_dump_json(exclude_none=True))))


def test_only_new_findings_of_medium_or_higher_count() -> None:
    assert _verify(after={EXISTING.id: EXISTING, NEW_LOW.id: NEW_LOW}).outcome == "VERIFIED"
    assert _verify(verdict="WARN").outcome == "VERIFIED", "WARN does not block a fix"


def test_the_last_attempt_fails_instead_of_retrying() -> None:
    second, last = (PROPOSAL.model_copy(update={"attempt": n}) for n in (2, 3))
    assert _verify(second, tests_ok=False).outcome == "REJECTED"
    assert _verify(last, tests_ok=False).outcome == "FAILED"
    assert _verify(last).outcome == "VERIFIED"


def test_a_result_that_claims_verified_against_the_gate_is_refused() -> None:
    claimed = _verify(tests_ok=False).model_dump() | {"outcome": "VERIFIED"}
    with pytest.raises(ValueError, match="VERIFIED needs"):
        VerificationResult.model_validate(claimed)


def test_a_proposal_touches_only_flagged_files_and_changes_something() -> None:
    common = {"strategy": "deterministic:kubernetes", "finding_ids": [TARGET], "rationale": "r", "attempt": 1,
              "created_at": NOW}  # fmt: skip
    with pytest.raises(RemediationError, match=r"touches files no finding flags: other\.yaml"):
        build_proposal(changes={"a.yaml": ("x\n", "y\n"), "other.yaml": ("x\n", "y\n")},
                       flagged_paths={"a.yaml"}, **common)  # type: ignore[arg-type]  # fmt: skip
    with pytest.raises(RemediationError, match="changes nothing"):
        build_proposal(changes={"a.yaml": ("x\n", "x\n")}, flagged_paths={"a.yaml"}, **common)  # type: ignore[arg-type]


def test_the_states_follow_section_9_only() -> None:
    state = "PROPOSED"
    for target in ("PATCH_READY", "PR_OPEN", "VERIFYING", "REJECTED", "PATCH_READY"):
        state = advance(state, target, attempt=1)  # type: ignore[arg-type]
    assert state == "PATCH_READY"
    for current, target in (("PROPOSED", "VERIFIED"), ("VERIFIED", "PATCH_READY"), ("FAILED", "PROPOSED"),
                            ("PR_OPEN", "REJECTED"), ("PATCH_READY", "VERIFYING")):  # fmt: skip
        with pytest.raises(RemediationError, match=f"from {current} to {target}"):
            advance(current, target, attempt=1)  # type: ignore[arg-type]
    with pytest.raises(RemediationError, match="no retry left after attempt 3"):
        advance("REJECTED", "PATCH_READY", attempt=3)
    assert advance("REJECTED", "FAILED", attempt=3) == "FAILED"


# ---------------------------------------------------------------- CLI


def _write_findings(path: Path, findings: list[Finding]) -> Path:
    path.write_text(dumps_ndjson(findings), encoding="utf-8")
    return path


def _decision(tmp_path: Path, verdict: str) -> Path:
    fixture = json.loads((ROOT / "schemas" / "fixtures" / "decision" / "valid" / "pass-pr.json").read_text())
    fixture["verdict"] = verdict
    if verdict != "PASS":
        violation = {
            "rule": "SC-009",
            "effect": verdict,
            "finding_ids": ["a" * 64],
            "message": "CI workflow issue",
        }
        fixture["violations"] = [violation]
    path = tmp_path / f"decision-{verdict}.json"
    path.write_text(json.dumps(fixture))
    return path


def test_cli_proposes_then_verifies_the_seed_fix(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "demo-shop" / "infra" / "k8s").mkdir(parents=True)
    shutil.copy(SEED, repo / SEED_PATH)
    before = _write_findings(tmp_path / "before.ndjson", seed_findings())
    out = tmp_path / "proposal.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["remediate", "kubernetes", "--findings", str(before), "--repo-root", str(repo), "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    proposal = PatchProposal.model_validate_json(out.read_bytes())
    assert "14 finding(s) in 1 file(s)" in result.output
    # After the patch, only the findings the fixer leaves alone are reported.
    fixed = set(proposal.finding_ids)
    after = _write_findings(tmp_path / "after.ndjson", [f for f in seed_findings() if f.id not in fixed])

    def verify(decision: Path, *flags: str) -> tuple[int, str, Path]:
        dest = tmp_path / f"result-{decision.stem}.json"
        args = ["remediate", "verify", "--proposal", str(out), "--before", str(before),
                "--after", str(after), "--decision", str(decision), "--build-ok", "--tests-ok",
                "--out", str(dest), *flags]  # fmt: skip
        run = runner.invoke(app, args)
        return run.exit_code, run.output, dest

    code, output, dest = verify(_decision(tmp_path, "WARN"), "--pull-request", "7")
    assert code == 0 and output.startswith("VERIFIED (attempt 1)"), output
    assert json.loads(dest.read_text())["pull_request"] == 7
    code, output, dest = verify(_decision(tmp_path, "BLOCK"))
    assert code == 1 and "REJECTED (attempt 1): the decision is BLOCK" in output
    assert json.loads(dest.read_text())["outcome"] == "REJECTED"


def test_cli_with_nothing_fixable_writes_no_proposal(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path / "f.ndjson", [iac_finding("KSV-0023")])
    out = tmp_path / "proposal.json"
    out.write_text("stale")
    result = CliRunner().invoke(
        app, ["remediate", "kubernetes", "--findings", str(findings), "--out", str(out)]
    )
    assert result.exit_code == 0 and "nothing to propose" in result.output and not out.exists()


@pytest.mark.parametrize("broken", ["findings", "proposal", "decision"])
def test_cli_untrusted_inputs_verify_nothing(tmp_path: Path, broken: str) -> None:
    findings = _write_findings(tmp_path / "f.ndjson", [])
    proposal = tmp_path / "p.json"
    proposal.write_text(PROPOSAL.model_dump_json())
    decision = _decision(tmp_path, "PASS")
    {"findings": findings, "proposal": proposal, "decision": decision}[broken].write_text("{not json\n")
    out = tmp_path / "result.json"
    out.write_text("stale")
    args = ["remediate", "verify", "--proposal", str(proposal), "--before", str(findings),
            "--after", str(findings), "--decision", str(decision), "--build-ok", "--tests-ok",
            "--out", str(out)]  # fmt: skip
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output and not out.exists()
