"""Release gate (task B4): policy bundle, OPA wrapper, Decision v1 records and `sentinel evaluate`.

Tests that need the real OPA binary skip when it is absent, unless SENTINEL_REQUIRE_OPA is set (CI).
"""

import hashlib
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
TOOLS_OK = ROOT / "schemas" / "fixtures" / "tool-status" / "valid" / "all-ok.json"
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
    assert "required_tools.rego" in names  # the required scanners are part of the recorded bundle
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


@pytest.mark.parametrize(
    "content",
    ["version: latest\n", "version: 1\n", "- a list\n", 'version: "1.0.0\\n"\n', "version: |\n  1.0.0\n"],
    ids=["word", "int", "list", "trailing-newline", "block-scalar"],
)
def test_bundle_rejects_bad_risk_model_version(bundle_copy: Path, content: str) -> None:
    (bundle_copy / "risk-model.yaml").write_text(content, encoding="utf-8")
    with pytest.raises(BundleError):
        _ = PolicyBundle.load(bundle_copy).risk_model_version


# ---------------------------------------------------------------- inputs


def test_load_findings_skips_blank_lines() -> None:
    assert load_findings(ndjson(SECRET) + b"\n  \n" + ndjson(CONTAINER)) == [SECRET, CONTAINER]


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85"])
def test_load_findings_splits_on_newlines_only(separator: str) -> None:
    # JSON allows these raw inside strings, and the normalizer writes ensure_ascii=False; str.splitlines()
    # broke such a line in two, so one scanned file could leave the gate with no decision.
    finding = {**SECRET, "title": f"Hard-coded key{separator}next to a separator"}
    data = (json.dumps(finding, ensure_ascii=False) + "\n").encode("utf-8")
    assert load_findings(data) == [finding]


@pytest.mark.parametrize(
    "data",
    [
        b"{not json}\n",
        b"[1, 2]\n",
        b'{"category": "SECRET"}\n',
        b'{"id": "../../etc", "category": "SECRET"}\n',
        b'{"id": "' + b"a" * 64 + b'"}\n',
        b"\xff\xfe",
        ndjson({**SECRET, "id": SECRET["id"] + "\n"}),
    ],
    ids=["invalid-json", "not-object", "no-id", "bad-id", "no-category", "not-utf8", "id-trailing-newline"],
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
        # A complete PR pipeline: every required scanner reported ok (policies/required_tools.rego).
        "--tool-status",
        str(TOOLS_OK),
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
    assert code == 3
    assert "no decision was made" in out
    assert not output.exists()


def test_unusable_opa_binary_fails_closed(tmp_path: Path) -> None:
    not_opa = tmp_path / "opa"
    not_opa.write_text("this is not an executable", encoding="utf-8")
    for opa in (tmp_path / "missing-opa", not_opa):
        code, out, output = run_evaluate(tmp_path, ndjson(CONTAINER), "--opa", str(opa))
        assert code == 3, out
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


# ---------------------------------------------------------------- input that is not Finding v1


@pytest.mark.parametrize(
    "change",
    [
        {"category": "secret"},
        {"category": "Secret"},
        {"category": "CREDENTIAL"},
        {"severity": "high"},
        {"tool": None},
        {"unexpected": "field"},
    ],
    ids=[
        "lowercase-category",
        "mixed-case-category",
        "unknown-category",
        "lowercase-severity",
        "no-tool",
        "extra",
    ],
)
def test_findings_outside_finding_v1_are_rejected(change: dict[str, Any]) -> None:
    finding = {k: v for k, v in {**SECRET, **change}.items() if v is not None}
    with pytest.raises(EvaluationError, match="not a Finding v1"):
        load_findings(ndjson(finding))


def test_lowercase_secret_category_is_no_decision_not_pass(tmp_path: Path, opa_binary: Path) -> None:
    # Reported in review: `"category": "secret"` used to slip past `== "SECRET"` and PASS.
    code, out, output = run_evaluate(
        tmp_path, ndjson({**SECRET, "category": "secret"}), "--opa", str(opa_binary)
    )
    assert code == 3, out
    assert not output.exists()


@pytest.mark.parametrize(
    "call",
    ["time.now_ns()", "opa.runtime().env", 'rand.intn("x", 10)', 'http.send({"method": "get", "url": "x"})'],
    ids=["clock", "environment", "randomness", "network"],
)
def test_policies_cannot_compile_non_deterministic_builtins(
    tmp_path: Path, opa_binary: Path, call: str
) -> None:
    # Enforces "policies never read the clock" (and the environment, the network, randomness) at compile time.
    probe = tmp_path / "probe.rego"
    probe.write_text(f"package probe\n\nvalue := {call}\n", encoding="utf-8")
    with pytest.raises(OpaError, match="undefined function"):
        OpaRunner(binary=opa_binary).eval("data.probe.value", [probe], {})


def test_restricted_capabilities_keep_what_the_gate_uses(opa_binary: Path) -> None:
    allowed = {b["name"] for b in OpaRunner(binary=opa_binary).restricted_capabilities()["builtins"]}
    assert {"time.parse_rfc3339_ns", "regex.match", "sprintf", "object.get"} <= allowed
    denied = {"time.now_ns", "opa.runtime", "http.send", "net.lookup_ip_addr", "rand.intn", "uuid.rfc4122"}
    assert not denied & allowed
    assert "crypto.x509.parse_and_verify_certificates" not in allowed


def test_policy_capabilities_command_writes_the_document(tmp_path: Path, opa_binary: Path) -> None:
    out = tmp_path / "caps.json"
    result = CliRunner().invoke(app, ["policy", "capabilities", "--opa", str(opa_binary), "--out", str(out)])
    assert result.exit_code == 0, result.output
    names = {b["name"] for b in json.loads(out.read_text(encoding="utf-8"))["builtins"]}
    assert "time.now_ns" not in names
    assert "time.parse_rfc3339_ns" in names


# Python's `$` also matches before a final newline: every identifier check must match the whole string.
@pytest.mark.parametrize(
    "field",
    [
        {"repo": "NOURHANE-EHOUARI/sentinelci\n"},
        {"commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"},
        {"image_digest": "sha256:" + "a" * 64 + "\n"},
    ],
    ids=["repo", "commit", "image-digest"],
)
def test_subject_identifiers_cannot_end_with_a_newline(field: dict[str, str]) -> None:
    values = {"repo": "NOURHANE-EHOUARI/sentinelci", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}
    with pytest.raises(EvaluationError):
        Subject(**{**values, "context": "pr", **field})


def test_an_invalid_enrichment_snapshot_is_never_recorded(tmp_path: Path, opa_binary: Path) -> None:
    (tmp_path / "snapshot.json").write_text("not a snapshot", encoding="utf-8")
    code, out, decision = run_evaluate(
        tmp_path, b"", "--enrichment-snapshot", str(tmp_path / "snapshot.json"), "--opa", str(opa_binary)
    )
    assert code == 3, out
    assert not decision.exists()


def test_no_snapshot_has_one_digest_in_evaluate_and_enrich(tmp_path: Path, opa_binary: Path) -> None:
    from sentinelci.enrich import EMPTY_SNAPSHOT, load_snapshot

    load_snapshot(EMPTY_SNAPSHOT)  # a valid snapshot, unlike b"{}"
    code, out, decision = run_evaluate(tmp_path, b"", "--opa", str(opa_binary))
    assert code == 0, out
    recorded = json.loads(decision.read_text(encoding="utf-8"))["inputs"]["enrichment_snapshot_digest"]
    assert recorded == "sha256:" + hashlib.sha256(EMPTY_SNAPSHOT).hexdigest()


@pytest.mark.parametrize(
    "text",
    [
        b"version: 1\nservice: demo\nexposure: dmz\n",
        b"version: 1\nservice: demo\nexposure: a\nexposure: b\n",
        b"\xff",
    ],
    ids=["unknown-exposure", "duplicate-key", "not-utf8"],
)
def test_an_invalid_service_context_is_never_recorded(tmp_path: Path, opa_binary: Path, text: bytes) -> None:
    (tmp_path / "sentinel.yaml").write_bytes(text)
    code, out, decision = run_evaluate(
        tmp_path, b"", "--service-context", str(tmp_path / "sentinel.yaml"), "--opa", str(opa_binary)
    )
    assert code == 3, out
    assert "--service-context" in out
    assert not decision.exists()


def test_an_invalid_vex_document_is_never_recorded(tmp_path: Path, opa_binary: Path) -> None:
    bad = ROOT / "schemas" / "fixtures" / "vex" / "invalid" / "not-affected-without-justification.json"
    code, out, decision = run_evaluate(tmp_path, b"", "--vex", str(bad), "--opa", str(opa_binary))
    assert code == 3, out
    assert not decision.exists()
