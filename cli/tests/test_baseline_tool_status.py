"""Diff-aware PR mode (`--baseline`) and scanner failures as decisions (`--tool-status`), Decision 1.2."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.tool_status import load_tool_status

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
FIXTURES = ROOT / "schemas" / "fixtures"
SECRET = json.loads((FIXTURES / "finding" / "valid" / "secret-in-config.json").read_text(encoding="utf-8"))
SECRET_IN_TWO_FILES = json.loads(
    (FIXTURES / "finding" / "valid" / "secret-in-two-files-v1.1.json").read_text(encoding="utf-8")
)
TOOLS_OK = (FIXTURES / "tool-status" / "valid" / "all-ok.json").read_bytes()
TOOLS_TIMEOUT = (FIXTURES / "tool-status" / "valid" / "one-timeout.json").read_bytes()
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def ndjson(*findings: dict[str, Any]) -> bytes:
    return "".join(json.dumps(f) + "\n" for f in findings).encode("utf-8")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def schema_errors(decision: dict[str, Any]) -> list[str]:
    schema = json.loads((ROOT / "schemas" / "decision.v1.json").read_text(encoding="utf-8"))
    return [
        e.message for e in Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(decision)
    ]


# ---------------------------------------------------------------- the model agrees with the schema


@pytest.mark.parametrize(
    "path", sorted((FIXTURES / "tool-status" / "valid").glob("*.json")), ids=lambda p: p.stem
)
def test_schema_valid_tool_status_loads(path: Path) -> None:
    assert load_tool_status(path.read_bytes()) == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "path", sorted((FIXTURES / "tool-status" / "invalid").glob("*.json")), ids=lambda p: p.stem
)
def test_schema_invalid_tool_status_is_no_decision(path: Path) -> None:
    with pytest.raises(EvaluationError):
        load_tool_status(path.read_bytes())


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"\xff",
        b'{"schema_version": true, "lock_sha256": "' + b"a" * 64 + b'", "tools": {}}',
        TOOLS_OK.replace(
            json.loads(TOOLS_OK)["lock_sha256"].encode(),
            json.loads(TOOLS_OK)["lock_sha256"].encode() + b"\\n",
        ),
    ],
    ids=["empty", "not-json", "not-utf8", "bool-version", "lock-hash-trailing-newline"],
)
def test_unreadable_tool_status_is_no_decision(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_tool_status(data)


# ---------------------------------------------------------------- sentinel evaluate, real OPA


def run(
    tmp_path: Path, findings: bytes, *extra: str, context: str = "pr", **files: bytes
) -> tuple[int, str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings.ndjson").write_bytes(findings)
    args = []
    for option, data in files.items():
        path = tmp_path / option
        path.write_bytes(data)
        args += [f"--{option.replace('_', '-')}", str(path)]
    output = tmp_path / "decision.json"
    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "--findings", str(tmp_path / "findings.ndjson"),
            "--repo", "NOURHANE-EHOUARI/sentinelci",
            "--commit", COMMIT,
            "--context", context,
            "--evaluated-at", "2026-11-10T10:00:00Z",
            "--policy-dir", str(POLICIES),
            "--output", str(output),
            *args,
            *extra,
        ],
    )  # fmt: skip
    return result.exit_code, result.output, output


def decision_at(path: Path) -> dict[str, Any]:
    decision: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return decision


def test_scanner_timeout_is_a_recorded_sc010_block(tmp_path: Path, opa_binary: Path) -> None:
    code, out, output = run(tmp_path, b"", "--opa", str(opa_binary), tool_status=TOOLS_TIMEOUT)
    assert code == 1, out
    decision = decision_at(output)
    assert schema_errors(decision) == []
    assert decision["schema_version"] == "1.2"
    assert decision["violations"] == [
        {
            "rule": "SC-010",
            "effect": "BLOCK",
            "finding_ids": [],
            "message": "Scanner failure: opengrep timeout (opengrep timed out after 900 s)",
        }
    ]
    assert decision["inputs"]["tool_status_digest"] == digest(TOOLS_TIMEOUT)
    assert decision["inputs"]["tool_versions"]["opengrep"] == "1.6.0"


def test_all_tools_ok_pass_as_decision_1_2(tmp_path: Path, opa_binary: Path) -> None:
    code, out, output = run(tmp_path, b"", "--opa", str(opa_binary), tool_status=TOOLS_OK)
    assert code == 0, out
    decision = decision_at(output)
    assert schema_errors(decision) == []
    assert (decision["schema_version"], decision["verdict"]) == ("1.2", "PASS")
    assert "baseline_digest" not in decision["inputs"]


def test_secret_already_on_the_base_branch_does_not_block_a_pr(tmp_path: Path, opa_binary: Path) -> None:
    code, out, output = run(
        tmp_path, ndjson(SECRET), "--opa", str(opa_binary), baseline=ndjson(SECRET), tool_status=TOOLS_OK
    )
    assert code == 0, out
    decision = decision_at(output)
    assert schema_errors(decision) == []
    assert decision["inputs"]["baseline_digest"] == digest(ndjson(SECRET))


def test_secret_copied_to_another_file_blocks_a_pr(tmp_path: Path, opa_binary: Path) -> None:
    copy = {**SECRET, "location": {**SECRET["location"], "path": "demo-shop/services/web/settings.py"}}
    code, out, _ = run(tmp_path, ndjson(copy), "--opa", str(opa_binary), baseline=ndjson(SECRET))
    assert code == 1, out
    assert "SC-001" in out


def test_copy_listed_in_other_locations_blocks_a_pr(tmp_path: Path, opa_binary: Path) -> None:
    # Finding 1.1 fixture: the same secret in config.py (twice) and in web/settings.py, one finding.
    assert SECRET_IN_TWO_FILES["id"] == SECRET["id"]
    code, out, output = run(
        tmp_path,
        ndjson(SECRET_IN_TWO_FILES),
        "--opa",
        str(opa_binary),
        baseline=ndjson(SECRET),
        tool_status=TOOLS_OK,
    )
    assert code == 1, out
    assert [v["rule"] for v in decision_at(output)["violations"]] == ["SC-001"]


def test_every_place_already_on_the_base_branch_passes_a_pr(tmp_path: Path, opa_binary: Path) -> None:
    both = ndjson(SECRET_IN_TWO_FILES)
    code, out, _ = run(tmp_path, both, "--opa", str(opa_binary), baseline=both, tool_status=TOOLS_OK)
    assert code == 0, out


def test_release_ignores_the_baseline(tmp_path: Path, opa_binary: Path) -> None:
    code, out, _ = run(
        tmp_path, ndjson(SECRET), "--opa", str(opa_binary), context="release", baseline=ndjson(SECRET)
    )
    assert code == 1, out


def test_without_new_inputs_the_decision_stays_1_1(tmp_path: Path, opa_binary: Path) -> None:
    code, _, output = run(tmp_path, ndjson(SECRET), "--opa", str(opa_binary))
    assert code == 1
    decision = decision_at(output)
    assert decision["schema_version"] == "1.1"
    assert not {"baseline_digest", "tool_status_digest"} & set(decision["inputs"])
    assert schema_errors(decision) == []


@pytest.mark.parametrize(
    "files",
    [
        {"tool_status": (FIXTURES / "tool-status" / "invalid" / "failed-without-detail.json").read_bytes()},
        {"baseline": ndjson({**SECRET, "category": "secret"})},
        {"baseline": b"{broken\n"},
    ],
    ids=["invalid-tool-status", "baseline-not-finding-v1", "baseline-not-json"],
)
def test_unreadable_new_inputs_make_no_decision(
    tmp_path: Path, opa_binary: Path, files: dict[str, bytes]
) -> None:
    code, out, output = run(tmp_path, ndjson(SECRET), "--opa", str(opa_binary), **files)
    assert code == 3, out
    assert not output.exists()


def test_decision_id_covers_the_new_inputs(tmp_path: Path, opa_binary: Path) -> None:
    ids = set()
    for name, files in {
        "plain": {},
        "baseline": {"baseline": ndjson(SECRET)},
        "tools": {"tool_status": TOOLS_OK},
    }.items():
        _, _, output = run(tmp_path / name, b"", "--opa", str(opa_binary), **files)
        ids.add(decision_at(output)["decision_id"])
    assert len(ids) == 3


# ---------------------------------------------------------------- required tools (required_tools.rego)


def test_release_without_tool_status_is_a_recorded_sc010_block(tmp_path: Path, opa_binary: Path) -> None:
    code, out, output = run(tmp_path, b"", "--opa", str(opa_binary), context="release")
    assert code == 1, out
    decision = decision_at(output)
    assert schema_errors(decision) == []
    assert decision["violations"] == [
        {
            "rule": "SC-010",
            "effect": "BLOCK",
            "finding_ids": [],
            "message": "Tool status missing: release requires gitleaks, grype, opengrep, syft, trivy, zizmor",
        }
    ]


def test_a_required_scanner_left_out_of_the_tool_status_blocks(tmp_path: Path, opa_binary: Path) -> None:
    without_gitleaks = json.loads(TOOLS_OK)
    del without_gitleaks["tools"]["gitleaks"]
    code, out, output = run(
        tmp_path, b"", "--opa", str(opa_binary), tool_status=json.dumps(without_gitleaks).encode("utf-8")
    )
    assert code == 1, out
    assert [v["message"] for v in decision_at(output)["violations"]] == [
        "Scanner missing: gitleaks (required in pr)"
    ]


def test_local_runs_need_no_tool_status(tmp_path: Path, opa_binary: Path) -> None:
    code, out, _ = run(tmp_path, b"", "--opa", str(opa_binary), context="local")
    assert code == 0, out
