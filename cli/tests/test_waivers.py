"""Waivers (SPEC section 6.4) and rule SC-005: loading `.sentinel/waivers.yaml` and the gate's verdicts."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.decision import EvaluationError, Subject, evaluate
from sentinelci.policy.opa import OpaRunner
from sentinelci.policy.waivers import load_waivers

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
FIXTURES = ROOT / "schemas" / "fixtures" / "waivers"
SECRET = json.loads(
    (ROOT / "schemas" / "fixtures" / "finding" / "valid" / "secret-in-config.json").read_text(
        encoding="utf-8"
    )
)
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
WHEN = "2026-11-10T10:00:00Z"

VALID_WAIVERS_YAML = f"""\
version: 1
waivers:
  - id: waiver-2026-001
    finding_id: {SECRET["id"]}
    owner: "@Hiba-elouazi"
    justification: Fake demo credential listed in the ground truth.
    expires_at: 2026-12-31T00:00:00Z
"""


# ---------------------------------------------------------------- loading


@pytest.mark.parametrize(
    "text", ["", "# no waivers yet\n", "version: 1\nwaivers:\n", "version: 1\nwaivers: []\n"]
)
def test_empty_waivers_file_means_no_waivers(text: str) -> None:
    assert load_waivers(text.encode("utf-8")) == []


def test_timestamps_reach_the_policy_exactly_as_written() -> None:
    text = (
        "version: 1\nwaivers:\n"
        "  - {id: a, expires_at: 2026-12-31}\n"
        "  - {id: b, expires_at: 2026-12-31T00:00:00+01:00}\n"
    )
    assert load_waivers(text.encode("utf-8")) == [
        {"id": "a", "expires_at": "2026-12-31"},
        {"id": "b", "expires_at": "2026-12-31T00:00:00+01:00"},
    ]


def test_entries_are_passed_through_unjudged() -> None:
    # Missing owner, not a mapping: the policy reports these as SC-005, the loader must not hide them.
    text = "version: 1\nwaivers:\n  - {id: a}\n  - just a string\n"
    assert load_waivers(text.encode("utf-8")) == [{"id": "a"}, "just a string"]


@pytest.mark.parametrize(
    "data",
    [
        b"version: 1\nwaivers: [\n",
        b"- a list\n",
        b"waivers: []\n",
        b"version: 1\nwaivers: []\nextra: true\n",
        b"version: 2\nwaivers: []\n",
        b"version: true\nwaivers: []\n",
        b"version: 1\nwaivers: {id: a}\n",
        b"version: 1\nwaivers:\n  - !!binary aGVsbG8=\n",
        b"version: 1\nwaivers:\n  - .nan\n",
        b"\xff\xfe",
    ],
    ids=[
        "bad-yaml",
        "not-mapping",
        "no-version",
        "extra-key",
        "wrong-version",
        "bool-version",
        "waivers-not-list",
        "binary-value",
        "nan-value",
        "not-utf8",
    ],
)
def test_unreadable_waivers_file_fails_the_evaluation(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_waivers(data)


# ---------------------------------------------------------------- schema and policy agree


def gate(opa_binary: Path, waivers: list[Any], findings: bytes = b"") -> dict[str, Any]:
    return evaluate(
        findings_data=findings,
        subject=Subject(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr"),
        evaluated_at=WHEN,
        bundle=PolicyBundle.load(POLICIES),
        opa=OpaRunner(binary=opa_binary),
        waivers=waivers,
    )


def fixture_waivers(path: Path) -> list[Any]:
    # JSON is YAML: the fixtures go through the same loader as a real waivers file.
    return load_waivers(path.read_bytes())


@pytest.mark.parametrize("path", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_schema_valid_waivers_pass_the_policy(path: Path, opa_binary: Path) -> None:
    decision = gate(opa_binary, fixture_waivers(path))
    assert decision["violations"] == []


@pytest.mark.parametrize("path", sorted((FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_schema_invalid_waivers_are_blocked_by_sc005(path: Path, opa_binary: Path) -> None:
    decision = gate(opa_binary, fixture_waivers(path))
    assert decision["verdict"] == "BLOCK"
    assert {v["rule"] for v in decision["violations"]} == {"SC-005"}


# ---------------------------------------------------------------- sentinel evaluate


def run_evaluate(tmp_path: Path, opa_binary: Path, *extra: str) -> tuple[int, str, Path]:
    findings = tmp_path / "findings.v1.ndjson"
    findings.write_text(json.dumps(SECRET) + "\n", encoding="utf-8")
    output = tmp_path / "out" / "decision.v1.json"
    args = [
        "evaluate",
        "--findings", str(findings),
        "--repo", "NOURHANE-EHOUARI/sentinelci",
        "--commit", COMMIT,
        "--evaluated-at", WHEN,
        "--policy-dir", str(POLICIES),
        "--output", str(output),
        "--opa", str(opa_binary),
        *extra,
    ]  # fmt: skip
    result = CliRunner().invoke(app, args)
    return result.exit_code, result.output, output


def decision_at(path: Path) -> dict[str, Any]:
    decision: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return decision


def test_waived_secret_passes(tmp_path: Path, opa_binary: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(VALID_WAIVERS_YAML, encoding="utf-8")
    code, out, output = run_evaluate(tmp_path, opa_binary, "--waivers", str(waivers))
    assert code == 0, out
    decision = decision_at(output)
    assert decision["verdict"] == "PASS"
    assert decision["waivers_applied"] == ["waiver-2026-001"]
    assert "Waivers applied: waiver-2026-001" in out


def test_default_waivers_file_is_used(
    tmp_path: Path, opa_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".sentinel").mkdir()
    (tmp_path / ".sentinel" / "waivers.yaml").write_text(VALID_WAIVERS_YAML, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code, out, output = run_evaluate(tmp_path, opa_binary)
    assert code == 0, out
    assert decision_at(output)["waivers_applied"] == ["waiver-2026-001"]


def test_waiver_without_owner_blocks_and_does_not_apply(tmp_path: Path, opa_binary: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(VALID_WAIVERS_YAML.replace('    owner: "@Hiba-elouazi"\n', ""), encoding="utf-8")
    code, out, output = run_evaluate(tmp_path, opa_binary, "--waivers", str(waivers))
    assert code == 1, out
    decision = decision_at(output)
    assert [v["rule"] for v in decision["violations"]] == ["SC-001", "SC-005"]
    assert decision["violations"][1]["message"] == "Invalid waiver waiver-2026-001 (entry 1): missing owner"
    assert decision["waivers_applied"] == []


def test_waiver_valid_for_more_than_90_days_blocks(tmp_path: Path, opa_binary: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(VALID_WAIVERS_YAML.replace("2026-12-31", "2027-03-01"), encoding="utf-8")
    code, _, output = run_evaluate(tmp_path, opa_binary, "--waivers", str(waivers))
    assert code == 1
    assert "expires more than 90 days after evaluation" in decision_at(output)["violations"][1]["message"]


@pytest.mark.parametrize("content", [None, "version: 1\nwaivers: [\n"], ids=["missing-file", "bad-yaml"])
def test_unreadable_waivers_file_makes_no_decision(
    tmp_path: Path, opa_binary: Path, content: str | None
) -> None:
    waivers = tmp_path / "waivers.yaml"
    if content is not None:
        waivers.write_text(content, encoding="utf-8")
    code, out, output = run_evaluate(tmp_path, opa_binary, "--waivers", str(waivers))
    assert code == 2, out
    assert not output.exists()
