"""The Decision read model must accept exactly what schemas/decision.v1.json accepts (contract fixtures)."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinelci.contracts.decision import Decision

FIXTURES = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "decision"
VALID = sorted((FIXTURES / "valid").glob("*.json"))
INVALID = sorted((FIXTURES / "invalid").glob("*.json"))


def _load(path: Path) -> dict[str, object]:
    data: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.name)
def test_valid_fixtures_are_accepted(path: Path) -> None:
    Decision.model_validate_json(path.read_bytes())


@pytest.mark.parametrize("path", INVALID, ids=lambda p: p.name)
def test_invalid_fixtures_are_rejected(path: Path) -> None:
    with pytest.raises(ValidationError):
        Decision.model_validate_json(path.read_bytes())


def test_there_are_fixtures_of_both_kinds() -> None:
    assert VALID and INVALID


def _variant(**changes: object) -> bytes:
    data = _load(FIXTURES / "valid" / "block-release.json")
    data.update(changes)
    return json.dumps(data).encode()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"verdict": "PASS"}, "PASS verdict cannot have violations"),
        ({"verdict": "WARN"}, "WARN violations only"),
        ({"violations": [], "verdict": "BLOCK"}, "BLOCK verdict needs at least one BLOCK violation"),
        ({"schema_version": "1.1"}, "waivers_digest is required"),
        ({"schema_version": "2.0"}, "schema_version"),
        ({"decision_id": "not-a-uuid"}, "decision_id must be a UUID"),
        ({"evaluated_at": "2026-13-01T00:00:00Z"}, "month must be in 1..12"),
        ({"evaluated_at": "yesterday"}, "RFC 3339"),
        ({"evaluated_at": "2026-11-10T10:00:00Z\n"}, "RFC 3339"),
        ({"waivers_applied": ["w1", "w1"]}, "unique"),
        ({"extra": True}, "Extra inputs are not permitted"),
    ],
)
def test_rules_the_schema_enforces(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Decision.model_validate_json(_variant(**changes))


def test_finding_ids_must_be_fingerprints() -> None:
    data = _load(FIXTURES / "valid" / "block-release.json")
    data["violations"] = [{"rule": "SC-001", "effect": "BLOCK", "finding_ids": ["abc"], "message": "x"}]
    with pytest.raises(ValidationError, match="sha256 fingerprint"):
        Decision.model_validate_json(json.dumps(data))


def test_schema_1_1_with_waivers_digest_is_accepted() -> None:
    data = _load(FIXTURES / "valid" / "pass-pr.json")
    data["schema_version"] = "1.1"
    inputs = dict(data["inputs"])  # type: ignore[call-overload]
    inputs["waivers_digest"] = "sha256:" + "5" * 64
    data["inputs"] = inputs
    decision = Decision.model_validate_json(json.dumps(data))
    assert decision.inputs.waivers_digest == "sha256:" + "5" * 64


def _with_inputs(version: str, **extra: str) -> bytes:
    data = _load(FIXTURES / "valid" / "pass-pr.json")
    data["schema_version"] = version
    inputs = dict(data["inputs"])  # type: ignore[call-overload]
    inputs.update(extra)
    data["inputs"] = inputs
    return json.dumps(data).encode()


DIGEST = "sha256:" + "6" * 64


@pytest.mark.parametrize(
    "extra",
    [
        {"waivers_digest": DIGEST},
        {"waivers_digest": DIGEST, "baseline_digest": DIGEST},
        {"waivers_digest": DIGEST, "tool_status_digest": DIGEST},
        {"waivers_digest": DIGEST, "baseline_digest": DIGEST, "tool_status_digest": DIGEST},
    ],
)
def test_decision_1_2_accepts_the_new_input_digests(extra: dict[str, str]) -> None:
    decision = Decision.model_validate_json(_with_inputs("1.2", **extra))
    assert decision.inputs.baseline_digest == extra.get("baseline_digest")
    assert decision.inputs.tool_status_digest == extra.get("tool_status_digest")


@pytest.mark.parametrize(
    ("version", "extra", "message"),
    [
        ("1.2", {}, "waivers_digest is required"),
        ("1.2", {"waivers_digest": DIGEST, "baseline_digest": "6" * 64}, "String should match pattern"),
        ("1.1", {"waivers_digest": DIGEST, "baseline_digest": DIGEST}, "only from schema 1.2"),
        ("1.1", {"waivers_digest": DIGEST, "tool_status_digest": DIGEST}, "only from schema 1.2"),
        ("1.0", {"tool_status_digest": DIGEST}, "only from schema 1.2"),
    ],
)
def test_decision_minor_versions_keep_their_meaning(
    version: str, extra: dict[str, str], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        Decision.model_validate_json(_with_inputs(version, **extra))
