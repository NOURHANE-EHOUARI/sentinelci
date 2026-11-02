"""The PR comment is a deterministic, fail-closed view of a Decision v1 record (task A3)."""

import hashlib
import json
import os
import random
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Evidence, Finding, Location, Run, Tool
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.report.pr_comment import (
    EVIDENCE_ARTIFACT,
    MARKER,
    MAX_OTHER_LOCATIONS,
    MAX_ROWS,
    ReportError,
    introduced,
    load_inputs,
    render_no_decision,
    render_pr_comment,
)

GOLDEN = Path(__file__).parent / "golden"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr", ref="refs/pull/7/head")
UPDATE = os.environ.get("SENTINEL_UPDATE_GOLDEN") == "1"


def fid(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def secret(
    seed: str,
    path: str,
    line: int,
    *,
    rule: str = "generic-api-key",
    risk: Any = None,
    others: list[tuple[str, int]] | None = None,
) -> Finding:
    return Finding(
        schema_version="1.1" if others else "1.0",
        id=fid(seed),
        tool=Tool(name="gitleaks", version="8.30.1"),
        rule_id=rule,
        category="SECRET",
        title="Detected a Generic API Key, potentially exposing access to various services.",
        severity="HIGH",
        run=RUN,
        location=Location(path=path, start_line=line, end_line=line),
        evidence=Evidence(secret_hash=fid(seed + "-secret")),
        risk=risk,
        other_locations=[Location(path=p, start_line=n, end_line=n) for p, n in others] if others else None,
    )


def misconfig(seed: str, path: str) -> Finding:
    return Finding(
        id=fid(seed),
        tool=Tool(name="trivy", version="0.76.1"),
        rule_id="AVD-AWS-0086",
        category="IAC",
        title="S3 bucket does not block public ACLs",
        severity="HIGH",
        run=RUN,
        location=Location(path=path, start_line=1, end_line=1),
        evidence=Evidence(snippet='resource "aws_s3_bucket" "shop" {}'),
    )


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def decision_for(findings_bytes: bytes, **changes: Any) -> dict[str, Any]:
    decision: dict[str, Any] = {
        "schema_version": "1.1",
        "decision_id": "0193f2c4-7a1e-5b3c-9d2e-4f5a6b7c8d9e",
        "evaluated_at": "2026-11-10T10:00:00Z",
        "subject": {"repo": RUN.repo, "ref": "refs/pull/7/head", "commit": COMMIT, "context": "pr"},
        "verdict": "PASS",
        "violations": [],
        "waivers_applied": [],
        "inputs": {
            "findings_digest": "sha256:" + hashlib.sha256(findings_bytes).hexdigest(),
            "enrichment_snapshot_digest": "sha256:" + "3" * 64,
            "policy_bundle_digest": "sha256:" + "4" * 64,
            "waivers_digest": "sha256:" + "5" * 64,
            "risk_model_version": "1.0.0",
            "tool_versions": {"gitleaks": "8.30.1", "opa": "1.21.4"},
        },
        "engine_version": "0.1.0",
    }
    decision.update(changes)
    return decision


def write_case(tmp_path: Path, findings: list[Finding], **changes: Any) -> tuple[Path, Path, dict[str, Any]]:
    findings_path = tmp_path / "findings.ndjson"
    findings_path.write_text(dumps_ndjson(findings), encoding="utf-8", newline="\n")
    decision = decision_for(findings_path.read_bytes(), **changes)
    decision_path = tmp_path / "decision.json"
    decision_path.write_text(json.dumps(decision, indent=2), encoding="utf-8")
    return decision_path, findings_path, decision


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / name
    if UPDATE:
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8"), f"{name} changed (SENTINEL_UPDATE_GOLDEN=1 to accept)"


# ---------------------------------------------------------------- golden files


def block_case(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    hostile_path = "demo-shop/@NOURHANE-EHOUARI/<img src=x>|`#1`/con\u202efig.py"
    findings = [
        secret(
            "aws",
            "demo-shop/services/shop-api/app/config.py",
            12,
            rule="aws-access-token",
            others=[("demo-shop/services/web/.env.example", 2)],
        ),
        secret("hostile", hostile_path, 3),
        secret(
            "old",
            "demo-shop/infra/terraform/main.tf",
            40,
            risk={"score": 55.0, "priority": "P1", "model_version": "1.0.0"},
        ),
    ]
    violations = [
        {"rule": "SC-006", "effect": "WARN", "finding_ids": [fid("old")], "message": "P1 finding"},
        {
            "rule": "SC-001",
            "effect": "BLOCK",
            "finding_ids": [fid("hostile"), fid("aws")],
            "message": "Hard-coded secret",
        },
        {
            "rule": "SC-010",
            "effect": "BLOCK",
            "finding_ids": [],
            "message": "Scanner failure: opengrep timed out",
        },
    ]
    baseline = tmp_path / "baseline.ndjson"
    baseline.write_text(dumps_ndjson([findings[2]]), encoding="utf-8", newline="\n")
    decision_path, findings_path, decision = write_case(
        tmp_path, findings, verdict="BLOCK", violations=violations, waivers_applied=["W-2026-001"]
    )
    decision["schema_version"] = "1.2"
    decision["inputs"]["baseline_digest"] = digest(baseline.read_bytes())
    decision["inputs"]["tool_status_digest"] = "sha256:" + "6" * 64
    decision_path.write_text(json.dumps(decision, indent=2), encoding="utf-8")
    changes = tmp_path / "changes.txt"
    changes.write_text(
        "tools.lock.toml\npolicies/gate.rego\n\ntools.lock.toml\n.sentinel/waivers.yaml\n", encoding="utf-8"
    )
    return decision_path, findings_path, baseline, changes


def test_golden_block(tmp_path: Path) -> None:
    decision, findings, baseline, changes = block_case(tmp_path)
    inputs = load_inputs(decision, findings, baseline_path=baseline, pipeline_changes_path=changes)
    check_golden("block.md", render_pr_comment(inputs))


def test_waiver_warning_appears_only_when_the_waivers_file_changes(tmp_path: Path) -> None:
    decision, findings, _ = write_case(tmp_path, [])
    changes = tmp_path / "changes.txt"
    changes.write_text("policies/gate.rego\n", encoding="utf-8")
    without = render_pr_comment(load_inputs(decision, findings, pipeline_changes_path=changes))
    changes.write_text("policies/gate.rego\n.sentinel/waivers.yaml\n", encoding="utf-8")
    with_waivers = render_pr_comment(load_inputs(decision, findings, pipeline_changes_path=changes))
    assert "cannot waive its own" not in without
    assert "cannot waive its own" in with_waivers


def test_golden_pass_without_findings(tmp_path: Path) -> None:
    decision, findings, _ = write_case(tmp_path, [])
    check_golden("pass.md", render_pr_comment(load_inputs(decision, findings)))


def test_golden_no_decision() -> None:
    check_golden("no-decision.md", render_no_decision("decision file not found: out/decision.v1.json"))


# ---------------------------------------------------------------- determinism


def test_same_inputs_give_the_same_bytes_whatever_the_order_in_the_decision(tmp_path: Path) -> None:
    decision, findings, baseline, changes = block_case(tmp_path)
    first = render_pr_comment(
        load_inputs(decision, findings, baseline_path=baseline, pipeline_changes_path=changes)
    )
    data = json.loads(decision.read_text(encoding="utf-8"))
    rng = random.Random(7)
    for _ in range(5):
        rng.shuffle(data["violations"])
        for violation in data["violations"]:
            rng.shuffle(violation["finding_ids"])
        decision.write_text(json.dumps(data), encoding="utf-8")
        again = load_inputs(decision, findings, baseline_path=baseline, pipeline_changes_path=changes)
        assert render_pr_comment(again) == first


def test_rows_are_capped(tmp_path: Path) -> None:
    findings = [secret(f"s{i}", f"app/f{i:03}.py", 1) for i in range(MAX_ROWS + 7)]
    violation = {"rule": "SC-001", "effect": "BLOCK", "finding_ids": [f.id for f in findings], "message": "x"}
    decision, findings_path, _ = write_case(tmp_path, findings, verdict="BLOCK", violations=[violation])
    text = render_pr_comment(load_inputs(decision, findings_path))
    assert sum(1 for line in text.splitlines() if line.startswith("| `SC-001`")) == MAX_ROWS
    assert "… and 7 more rows" in text
    assert "57 HIGH (57 total)" in text


def test_violation_naming_an_unknown_finding_is_shown_not_dropped(tmp_path: Path) -> None:
    violation = {"rule": "SC-001", "effect": "BLOCK", "finding_ids": [fid("ghost")], "message": "x"}
    decision, findings, _ = write_case(tmp_path, [], verdict="BLOCK", violations=[violation])
    text = render_pr_comment(load_inputs(decision, findings))
    assert f"`{fid('ghost')[:12]}` (not in the findings file)" in text


def test_priorities_replace_severities_once_every_finding_is_scored(tmp_path: Path) -> None:
    risk = {"score": 80.0, "priority": "P0", "model_version": "1.0.0"}
    decision, findings, _ = write_case(
        tmp_path, [secret("a", "a.py", 1, risk=risk), secret("b", "b.py", 2, risk=risk)]
    )
    assert "**Findings:** 2 P0 (2 total)" in render_pr_comment(load_inputs(decision, findings))


def baseline_case(
    tmp_path: Path,
    findings: list[Finding],
    base: list[Finding],
    *,
    context: str = "pr",
    recorded: bool = True,
) -> tuple[Path, Path, Path]:
    baseline = tmp_path / "baseline.ndjson"
    baseline.write_text(dumps_ndjson(base), encoding="utf-8", newline="\n")
    decision, findings_path, data = write_case(tmp_path, findings, schema_version="1.2")
    data["subject"]["context"] = context
    if recorded:
        data["inputs"]["baseline_digest"] = digest(baseline.read_bytes())
    decision.write_text(json.dumps(data), encoding="utf-8")
    return decision, findings_path, baseline


def test_new_means_what_the_gate_calls_introduced(tmp_path: Path) -> None:
    kept = secret("kept", "a.py", 1)
    moved_down = secret("moved", "b.py", 9)  # same file as on the base branch, another line: not new
    copied = secret("copied", "c.py", 1, others=[("d.py", 1)])  # also in a file the base did not have: new
    fresh = secret("fresh", "e.py", 1)
    renamed = misconfig("iac", "infra/b.tf")  # only a secret counts again in a new file: not new
    base = [kept, secret("moved", "b.py", 2), secret("copied", "c.py", 1), misconfig("iac", "infra/a.tf")]
    decision, findings, baseline = baseline_case(tmp_path, [kept, moved_down, copied, fresh, renamed], base)

    text = render_pr_comment(load_inputs(decision, findings, baseline_path=baseline))

    assert "(5 total, 2 new)" in text
    assert f"- Baseline `{digest(baseline.read_bytes())}` (verified against this report)" in text


def test_the_report_and_the_gate_agree_on_what_is_new(
    tmp_path: Path, opa_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The real gate.rego decides; SC-001 lists exactly the secrets it considers introduced (none is waived).
    current = [
        secret("kept", "a.py", 1),
        secret("moved", "b.py", 9),
        secret("copied", "c.py", 1, others=[("d.py", 1)]),
        secret("fresh", "e.py", 1),
        misconfig("iac", "infra/b.tf"),
    ]
    base = [
        secret("kept", "a.py", 1),
        secret("moved", "b.py", 2),
        secret("copied", "c.py", 1),
        misconfig("iac", "infra/a.tf"),
    ]
    findings, baseline = tmp_path / "findings.ndjson", tmp_path / "baseline.ndjson"
    findings.write_text(dumps_ndjson(current), encoding="utf-8", newline="\n")
    baseline.write_text(dumps_ndjson(base), encoding="utf-8", newline="\n")
    decision = tmp_path / "decision.json"
    monkeypatch.chdir(tmp_path)  # no default waivers file
    result = CliRunner().invoke(
        app,
        [
            "evaluate", "--findings", str(findings), "--baseline", str(baseline),
            "--repo", RUN.repo, "--commit", COMMIT, "--context", "pr",
            "--evaluated-at", "2026-11-10T10:00:00Z", "--tool-version", "gitleaks=8.30.1",
            "--policy-dir", str(Path(__file__).resolve().parents[3] / "policies"),
            "--opa", str(opa_binary), "--output", str(decision),
        ],
    )  # fmt: skip
    assert result.exit_code == 1, result.output  # BLOCK

    inputs = load_inputs(decision, findings, baseline_path=baseline)
    assert inputs.baseline is not None
    gate_new = {i for v in inputs.decision.violations if v.rule == "SC-001" for i in v.finding_ids}
    report_new = {f.id for f in inputs.findings.values() if introduced(f, inputs.baseline)}
    assert report_new == gate_new == {fid("copied"), fid("fresh")}


@pytest.mark.parametrize(
    ("context", "recorded"),
    [("pr", False), ("release", True)],
    ids=["the-gate-used-no-baseline", "release-ignores-the-baseline"],
)
def test_a_baseline_the_gate_did_not_use_is_ignored(tmp_path: Path, context: str, recorded: bool) -> None:
    decision, findings, baseline = baseline_case(
        tmp_path, [secret("a", "a.py", 1)], [secret("a", "a.py", 1)], context=context, recorded=recorded
    )
    lines = render_pr_comment(load_inputs(decision, findings, baseline_path=baseline)).splitlines()
    assert "**Findings:** 1 HIGH (1 total)" in lines
    assert not any(
        "(verified against this report)" in line for line in lines if line.startswith("- Baseline")
    )


def test_a_baseline_that_is_not_the_gate_s_one_is_refused(tmp_path: Path) -> None:
    decision, findings, baseline = baseline_case(tmp_path, [secret("a", "a.py", 1)], [secret("a", "a.py", 1)])
    baseline.write_text("", encoding="utf-8")  # an empty baseline would make every finding look new
    with pytest.raises(ReportError, match="baseline_digest mismatch"):
        load_inputs(decision, findings, baseline_path=baseline)


def test_other_locations_are_listed_and_capped(tmp_path: Path) -> None:
    others = [(f"copies/c{i}.py", i + 1) for i in range(MAX_OTHER_LOCATIONS + 2)]
    finding = secret("spread", "app/a.py", 3, others=others)
    violation = {"rule": "SC-001", "effect": "BLOCK", "finding_ids": [finding.id], "message": "x"}
    decision, findings, _ = write_case(tmp_path, [finding], verdict="BLOCK", violations=[violation])
    row = next(
        line for line in render_pr_comment(load_inputs(decision, findings)).splitlines() if "SC-001" in line
    )
    shown = " · ".join(f"`copies/c{i}.py:{i + 1}`" for i in range(MAX_OTHER_LOCATIONS))
    assert f"| `app/a.py:3` · {shown} and 2 more |" in row


def test_the_replay_line_names_the_evidence_artifact(tmp_path: Path) -> None:
    decision, findings, data = write_case(tmp_path, [])
    text = render_pr_comment(load_inputs(decision, findings))
    assert f"`sentinel replay {data['decision_id']} --store {EVIDENCE_ARTIFACT}`" in text
    assert f"`{EVIDENCE_ARTIFACT}` artifact" in text


# ---------------------------------------------------------------- fail closed


def test_findings_that_do_not_match_the_decision_are_refused(tmp_path: Path) -> None:
    decision, findings, _ = write_case(tmp_path, [secret("a", "a.py", 1)])
    findings.write_text(dumps_ndjson([secret("b", "b.py", 1)]), encoding="utf-8", newline="\n")
    with pytest.raises(ReportError, match="findings_digest mismatch"):
        load_inputs(decision, findings)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda d: d.update(
                verdict="PASS",
                violations=[{"rule": "SC-001", "effect": "BLOCK", "finding_ids": [], "message": "x"}],
            ),
            "not a valid Decision v1",
        ),
        (lambda d: d.update(verdict="BLOCK"), "not a valid Decision v1"),
        (lambda d: d.pop("inputs"), "not a valid Decision v1"),
    ],
)
def test_inconsistent_decisions_are_refused(tmp_path: Path, mutate: Any, message: str) -> None:
    decision, findings, data = write_case(tmp_path, [])
    mutate(data)
    decision.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReportError, match=message):
        load_inputs(decision, findings)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"not json\n", "line 1 is not a Finding v1"),
        (b'{"id": "abc"}\n', "line 1 is not a Finding v1"),
        (b"\xff\xfe\n", "not UTF-8"),
    ],
)
def test_malformed_findings_are_refused(tmp_path: Path, content: bytes, message: str) -> None:
    findings = tmp_path / "findings.ndjson"
    findings.write_bytes(content)
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps(decision_for(content)), encoding="utf-8")
    with pytest.raises(ReportError, match=message):
        load_inputs(decision, findings)


def test_duplicate_finding_ids_are_refused(tmp_path: Path) -> None:
    line = dumps_ndjson([secret("a", "a.py", 1)])
    findings = tmp_path / "findings.ndjson"
    findings.write_text(line + line, encoding="utf-8", newline="\n")
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps(decision_for(findings.read_bytes())), encoding="utf-8")
    with pytest.raises(ReportError, match="duplicate finding id"):
        load_inputs(decision, findings)


def test_missing_files_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="cannot read the report inputs"):
        load_inputs(tmp_path / "decision.json", tmp_path / "findings.ndjson")


# ---------------------------------------------------------------- CLI


def _invoke(*args: str) -> Any:
    return CliRunner().invoke(app, ["report", "pr-comment", *args])


def test_cli_writes_the_comment(tmp_path: Path) -> None:
    decision, findings, _ = write_case(tmp_path, [])
    out = tmp_path / "out" / "comment.md"
    result = _invoke("--decision", str(decision), "--findings", str(findings), "--out", str(out))
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8").startswith(MARKER + "\n## SentinelCI verdict: ✅ PASS")


def test_cli_without_a_decision_writes_a_blocking_comment_and_exits_3(tmp_path: Path) -> None:
    findings = tmp_path / "findings.ndjson"
    findings.write_text("", encoding="utf-8")
    out = tmp_path / "comment.md"
    out.write_text("an older, passing comment", encoding="utf-8")
    result = _invoke(
        "--decision", str(tmp_path / "missing.json"), "--findings", str(findings), "--out", str(out)
    )
    assert result.exit_code == 3
    assert "SC-010" in result.output
    text = out.read_text(encoding="utf-8")
    assert "NO DECISION (treated as BLOCK, rule SC-010)" in text
    assert "an older, passing comment" not in text


def test_cli_crash_never_leaves_an_older_comment_to_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(_: object) -> str:
        raise RuntimeError("unexpected")

    monkeypatch.setattr("sentinelci.cli.render_pr_comment", crash)
    decision, findings, _ = write_case(tmp_path, [])
    out = tmp_path / "comment.md"
    out.write_text("an older, passing comment", encoding="utf-8")
    result = _invoke("--decision", str(decision), "--findings", str(findings), "--out", str(out))
    assert result.exit_code != 0
    assert not out.exists()


# ---------------------------------------------------------------- line terminators (same class as #14)


def test_a_raw_line_separator_inside_a_finding_does_not_split_its_line(tmp_path: Path) -> None:
    # The normalizer writes ensure_ascii=False, so U+2028 / U+2029 from a scanned file stay raw inside JSON
    # strings. Only "\n" separates NDJSON records; str.splitlines() would cut the record in two.
    finding = secret("ls", "app/settings.py", 1).model_copy(update={"title": "token \u2028 next \u2029 end"})
    decision, findings, _ = write_case(tmp_path, [finding])
    assert "\u2028" in findings.read_text(encoding="utf-8")
    inputs = load_inputs(decision, findings)
    assert list(inputs.findings) == [finding.id]


def test_a_finding_id_with_a_trailing_newline_is_refused(tmp_path: Path) -> None:
    line = dumps_ndjson([secret("a", "a.py", 1)]).replace('"id":"', '"id":"', 1)
    record = json.loads(line)
    record["id"] = record["id"] + "\n"
    findings = tmp_path / "findings.ndjson"
    findings.write_text(json.dumps(record) + "\n", encoding="utf-8")
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps(decision_for(findings.read_bytes())), encoding="utf-8")
    with pytest.raises(ReportError, match="not a sha256 fingerprint"):
        load_inputs(decision, findings)
