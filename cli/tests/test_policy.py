"""Release gate (task B4): policy bundle, OPA wrapper, Decision v1 records and `sentinel evaluate`.

Tests that need the real OPA binary skip when it is absent, unless SENTINEL_REQUIRE_OPA is set (CI).
"""

import json
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.policy.bundle import BundleError, PolicyBundle
from sentinelci.policy.decision import (
    EvaluationError,
    Subject,
    canonical_time,
    dumps_decision,
    evaluate,
    load_findings,
)
from sentinelci.policy.opa import OpaError, OpaRunner, parse_eval_output

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
FINDING_FIXTURES = ROOT / "schemas" / "fixtures" / "finding" / "valid"
SECRET = json.loads((FINDING_FIXTURES / "secret-in-config.json").read_text(encoding="utf-8"))
CONTAINER = json.loads((FINDING_FIXTURES / "container-os-package.json").read_text(encoding="utf-8"))
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
SUBJECT = Subject(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr", ref="refs/pull/12/merge")
WHEN = "2026-11-10T10:00:00Z"


def ndjson(*findings: dict[str, Any]) -> bytes:
    return "".join(json.dumps(f) + "\n" for f in findings).encode("utf-8")


def assert_valid_decision(decision: dict[str, Any]) -> None:
    schema = json.loads((ROOT / "schemas" / "decision.v1.json").read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(decision))
    assert not errors, "\n".join(e.message for e in errors)


class FakeOpa(OpaRunner):
    """Returns a canned policy result, to test how the engine handles what OPA gives back."""

    def __init__(self, result: Any) -> None:
        super().__init__(binary=Path("fake-opa"))
        object.__setattr__(self, "_result", result)

    def version(self) -> str:
        return "0.0.0-fake"

    def eval(self, query: str, policies: Sequence[Path], input_doc: Any) -> Any:
        return self._result  # type: ignore[attr-defined]


@pytest.fixture
def bundle_copy(tmp_path: Path) -> Path:
    return Path(shutil.copytree(POLICIES, tmp_path / "policies"))


# ---------------------------------------------------------------- policy bundle


def test_bundle_excludes_rego_tests_and_reads_risk_model_version() -> None:
    bundle = PolicyBundle.load(POLICIES)
    names = [p.as_posix() for p in bundle.files]
    assert "gate.rego" in names
    assert "risk-model.yaml" in names
    assert not [n for n in names if n.endswith("_test.rego")]
    assert bundle.risk_model_version == "1.0.0"


def test_bundle_digest_ignores_tests_but_tracks_policies(bundle_copy: Path) -> None:
    before = PolicyBundle.load(bundle_copy).digest
    (bundle_copy / "gate_test.rego").write_text("package changed\n", encoding="utf-8")
    assert PolicyBundle.load(bundle_copy).digest == before
    with (bundle_copy / "gate.rego").open("a", encoding="utf-8") as handle:
        handle.write("\n# edited\n")
    assert PolicyBundle.load(bundle_copy).digest != before


def test_bundle_without_rego_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(BundleError):
        PolicyBundle.load(tmp_path)
    with pytest.raises(BundleError):
        PolicyBundle.load(tmp_path / "missing")


@pytest.mark.parametrize("content", ["version: latest\n", "version: 1\n", "- a list\n"])
def test_bundle_rejects_bad_risk_model_version(bundle_copy: Path, content: str) -> None:
    (bundle_copy / "risk-model.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(BundleError):
        _ = PolicyBundle.load(bundle_copy).risk_model_version


# ---------------------------------------------------------------- inputs


def test_load_findings_skips_blank_lines() -> None:
    assert load_findings(ndjson(SECRET) + b"\n  \n" + ndjson(CONTAINER)) == [SECRET, CONTAINER]


@pytest.mark.parametrize(
    "data",
    [
        b"{not json}\n",
        b"[1, 2]\n",
        b'{"category": "SECRET"}\n',
        b'{"id": "../../etc", "category": "SECRET"}\n',
        b'{"id": "' + b"a" * 64 + b'"}\n',
        b"\xff\xfe",
    ],
    ids=["invalid-json", "not-object", "no-id", "bad-id", "no-category", "not-utf8"],
)
def test_load_findings_rejects_malformed_input(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_findings(ndjson(SECRET) + data)


def test_canonical_time_converts_to_utc() -> None:
    assert canonical_time("2026-11-10T12:00:00+02:00") == WHEN


@pytest.mark.parametrize("value", ["2026-11-10T10:00:00", "yesterday"])
def test_canonical_time_requires_an_offset(value: str) -> None:
    with pytest.raises(EvaluationError):
        canonical_time(value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"repo": "no-slash"},
        {"commit": "abc123"},
        {"context": "prod"},
        {"image_digest": "latest"},
    ],
)
def test_subject_rejects_values_the_schema_would_reject(kwargs: dict[str, str]) -> None:
    fields = {"repo": "a/b", "commit": COMMIT, "context": "pr", **kwargs}
    with pytest.raises(EvaluationError):
        Subject(**fields)


# ---------------------------------------------------------------- OPA output handling (fail closed)


@pytest.mark.parametrize("stdout", ["{}", '{"result": []}', "not json", "[]"])
def test_undefined_or_garbled_opa_output_is_an_error(stdout: str) -> None:
    with pytest.raises(OpaError):
        parse_eval_output(stdout)


@pytest.mark.parametrize(
    "result",
    [
        None,
        {"verdict": "PASS"},
        {"verdict": "MAYBE", "violations": [], "waivers_applied": []},
        {"verdict": "PASS", "violations": [{"rule": "SC-001", "effect": "BLOCK"}], "waivers_applied": []},
        {"verdict": "WARN", "violations": [], "waivers_applied": []},
        {"verdict": "BLOCK", "violations": [{"rule": "SC-006", "effect": "WARN"}], "waivers_applied": []},
        {"verdict": "BLOCK", "violations": ["SC-001"], "waivers_applied": []},
    ],
    ids=[
        "none",
        "partial",
        "unknown-verdict",
        "pass-with-block",
        "warn-without-warning",
        "block-without-block",
        "string-violation",
    ],
)
def test_inconsistent_policy_result_never_becomes_a_decision(result: Any) -> None:
    with pytest.raises(EvaluationError):
        evaluate(
            findings_data=ndjson(SECRET),
            subject=SUBJECT,
            evaluated_at=WHEN,
            bundle=PolicyBundle.load(POLICIES),
            opa=FakeOpa(result),
        )


def test_decision_records_inputs_and_matches_the_schema() -> None:
    result = {
        "verdict": "WARN",
        "violations": [
            {"rule": "SC-006", "effect": "WARN", "finding_ids": [CONTAINER["id"]], "message": "P1"}
        ],
        "waivers_applied": [],
    }
    decision = evaluate(
        findings_data=ndjson(SECRET, CONTAINER),
        subject=SUBJECT,
        evaluated_at=WHEN,
        bundle=PolicyBundle.load(POLICIES),
        opa=FakeOpa(result),
        tool_versions={"gitleaks": "8.24.0", "zizmor": "1.31.1"},
        sbom=b"{}",
    )
    assert_valid_decision(decision)
    assert decision["verdict"] == "WARN"
    assert decision["inputs"]["policy_bundle_digest"] == PolicyBundle.load(POLICIES).digest
    assert decision["inputs"]["tool_versions"] == {
        "gitleaks": "8.24.0",
        CONTAINER["tool"]["name"]: CONTAINER["tool"]["version"],
        "opa": "0.0.0-fake",
        "zizmor": "1.31.1",
    }
    assert "sbom_digest" in decision["inputs"]


def test_decision_id_depends_on_inputs() -> None:
    passing = {"verdict": "PASS", "violations": [], "waivers_applied": []}

    def decide(findings: bytes, when: str) -> dict[str, Any]:
        return evaluate(
            findings_data=findings,
            subject=SUBJECT,
            evaluated_at=when,
            bundle=PolicyBundle.load(POLICIES),
            opa=FakeOpa(passing),
        )

    first = decide(ndjson(CONTAINER), WHEN)
    assert decide(ndjson(CONTAINER), WHEN)["decision_id"] == first["decision_id"]
    assert decide(ndjson(CONTAINER), "2026-11-10T10:00:01Z")["decision_id"] != first["decision_id"]
    assert decide(ndjson(CONTAINER) + b"\n", WHEN)["decision_id"] != first["decision_id"]


# ---------------------------------------------------------------- end to end with the real OPA


def run_evaluate(tmp_path: Path, findings: bytes, *extra: str) -> tuple[int, str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    findings_path = tmp_path / "findings.v1.ndjson"
    findings_path.write_bytes(findings)
    output = tmp_path / "out" / "decision.v1.json"
    args = [
        "evaluate",
        "--findings",
        str(findings_path),
        "--repo",
        SUBJECT.repo,
        "--commit",
        SUBJECT.commit,
        "--context",
        "pr",
        "--evaluated-at",
        WHEN,
        "--policy-dir",
        str(POLICIES),
        "--output",
        str(output),
        *extra,
    ]
    result = CliRunner().invoke(app, args)
    return result.exit_code, result.output, output


def test_secret_is_blocked_by_sc001(tmp_path: Path, opa_binary: Path) -> None:
    code, out, output = run_evaluate(tmp_path, ndjson(CONTAINER, SECRET), "--opa", str(opa_binary))
    assert code == 1, out
    decision = json.loads(output.read_text(encoding="utf-8"))
    assert_valid_decision(decision)
    assert decision["verdict"] == "BLOCK"
    assert decision["violations"] == [
        {"rule": "SC-001", "effect": "BLOCK", "finding_ids": [SECRET["id"]], "message": "Hard-coded secret"}
    ]
    assert "SC-001" in out


@pytest.mark.parametrize("findings", [b"", ndjson(CONTAINER)], ids=["no-findings", "no-secret"])
def test_change_without_secret_passes(tmp_path: Path, opa_binary: Path, findings: bytes) -> None:
    code, out, output = run_evaluate(
        tmp_path, findings, "--opa", str(opa_binary), "--tool-version", "gitleaks=8.24.0"
    )
    assert code == 0, out
    decision = json.loads(output.read_text(encoding="utf-8"))
    assert_valid_decision(decision)
    assert decision["verdict"] == "PASS"
    assert decision["inputs"]["tool_versions"]["gitleaks"] == "8.24.0"


def test_same_inputs_give_a_byte_identical_decision(tmp_path: Path, opa_binary: Path) -> None:
    _, _, first = run_evaluate(tmp_path / "a", ndjson(SECRET, CONTAINER), "--opa", str(opa_binary))
    _, _, second = run_evaluate(tmp_path / "b", ndjson(SECRET, CONTAINER), "--opa", str(opa_binary))
    assert first.read_bytes() == second.read_bytes()
    decision = json.loads(first.read_text(encoding="utf-8"))
    assert dumps_decision(decision) == first.read_text(encoding="utf-8")


def test_malformed_findings_fail_closed_and_remove_stale_decision(tmp_path: Path, opa_binary: Path) -> None:
    stale = tmp_path / "out" / "decision.v1.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"verdict": "PASS"}', encoding="utf-8")
    code, out, output = run_evaluate(tmp_path, b"{broken\n", "--opa", str(opa_binary))
    assert code == 2
    assert "no decision was made" in out
    assert not output.exists()


def test_unusable_opa_binary_fails_closed(tmp_path: Path) -> None:
    not_opa = tmp_path / "opa"
    not_opa.write_text("this is not an executable", encoding="utf-8")
    for opa in (tmp_path / "missing-opa", not_opa):
        code, out, output = run_evaluate(tmp_path, ndjson(CONTAINER), "--opa", str(opa))
        assert code == 2, out
        assert not output.exists()


def test_failing_process_is_an_error() -> None:
    # The Python interpreter exits non-zero on `python version` (no such script): stands in for OPA.
    with pytest.raises(OpaError, match="exited with"):
        OpaRunner(binary=Path(sys.executable)).version()


def test_policy_that_does_not_compile_is_an_error(tmp_path: Path, opa_binary: Path) -> None:
    broken = tmp_path / "broken.rego"
    broken.write_text("package sentinel.gate\n\nverdict := \n", encoding="utf-8")
    with pytest.raises(OpaError, match="exited with"):
        OpaRunner(binary=opa_binary).eval("data.sentinel.gate.decision", [broken], {})


def test_slow_opa_times_out(opa_binary: Path) -> None:
    with pytest.raises(OpaError, match="timed out"):
        OpaRunner(binary=opa_binary, timeout_s=1e-6).eval("data", [POLICIES / "gate.rego"], {})
