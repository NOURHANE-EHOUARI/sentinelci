"""Trust report v1 and release evidence v1 (A4, A8): the models are pinned to the schemas by the contract
fixtures, and `problem()` refuses what the schemas cannot."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinelci.contracts.release import ReleaseEvidence, TrustReport

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "schemas" / "fixtures"
HEX = "0" * 64
ZERO = "sha256:" + HEX
MODELS: dict[str, type[TrustReport] | type[ReleaseEvidence]] = {
    "trust-report": TrustReport,
    "release-evidence": ReleaseEvidence,
}


def fixtures(kind: str) -> list[tuple[str, Path]]:
    return [(name, path) for name in MODELS for path in sorted((FIXTURES / name / kind).glob("*.json"))]


def stem(value: object) -> str:
    return value.stem if isinstance(value, Path) else str(value)


@pytest.mark.parametrize(("name", "path"), fixtures("valid"), ids=stem)
def test_every_valid_fixture_is_accepted_and_consistent(name: str, path: Path) -> None:
    document = MODELS[name].model_validate_json(path.read_bytes())
    assert document.problem() is None


@pytest.mark.parametrize(("name", "path"), fixtures("invalid"), ids=stem)
def test_every_invalid_fixture_is_refused(name: str, path: Path) -> None:
    with pytest.raises(ValidationError):
        MODELS[name].model_validate_json(path.read_bytes())


def evidence() -> dict[str, Any]:
    name = "warn-verified-in-the-registry-and-from-the-evidence.json"
    document: dict[str, Any] = json.loads((FIXTURES / "release-evidence" / "valid" / name).read_text())
    return document


def problem(document: dict[str, Any]) -> str | None:
    return ReleaseEvidence.model_validate_json(json.dumps(document)).problem()


def test_a_release_is_trusted_when_every_report_trusts_it() -> None:
    parsed = ReleaseEvidence.model_validate_json(json.dumps(evidence()))
    assert parsed.trusted is True and parsed.image_digest == parsed.decision.subject.image_digest
    block = FIXTURES / "release-evidence" / "valid" / "block-without-a-trust-report.json"
    assert ReleaseEvidence.model_validate_json(block.read_bytes()).trusted is None


OTHER_DECISION = "00000000-0000-0000-0000-000000000002"


def block_with_a_report_that_does_not_trust_it(document: dict[str, Any]) -> None:
    """Review of #86: a BLOCK was recorded with a not-trusted report, and counted as a verification."""
    document["decision"].update(
        verdict="BLOCK",
        violations=[{"rule": "SC-002", "effect": "BLOCK", "finding_ids": [HEX], "message": "P0"}],
    )
    report = document["trust_reports"][0]
    report["checks"][2] = {**report["checks"][2], "ok": False}
    report["trusted"] = False
    del document["trust_reports"][1]


def changed(change: Any) -> dict[str, Any]:
    document = copy.deepcopy(evidence())
    change(document)
    return document


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["decision"]["subject"].update(context="pr"), "a pr decision, not a release decision"),
        (lambda d: d["decision"]["subject"].pop("image_digest"), "names no image digest"),
        (lambda d: d["trust_reports"][1].update(mode="registry"), "two trust reports of the same mode"),
        (lambda d: d["trust_reports"][0]["image"].update(digest=ZERO), "is about sha256:0000"),
        (lambda d: d["trust_reports"][0].update(repo="someone/fork"), "required someone/fork"),
        (lambda d: d["trust_reports"][0].update(trusted=False), "trusted is False, but 0 of 16 checks"),
        (lambda d: d["trust_reports"][0]["checks"][3].update(ok=False), "trusted is True, but 1 of 16"),
        (lambda d: d["trust_reports"][0].update(verified_at="2026-13-45T25:61:00Z"), "not a date and time"),
        (
            lambda d: d["decision"].update(
                verdict="BLOCK",
                violations=[{"rule": "SC-002", "effect": "BLOCK", "finding_ids": [HEX], "message": "P0"}],
            ),
            "a BLOCK decision comes without a trust report: nothing was signed",
        ),
        (lambda d: d["trust_reports"][0].update(decision_id=OTHER_DECISION), "verified decision 00000000-"),
        (lambda d: d["trust_reports"][0].update(decision_id=None), "names the decision it verified"),
        (block_with_a_report_that_does_not_trust_it, "a BLOCK decision comes without a trust report"),
    ],
)  # fmt: skip
def test_evidence_that_contradicts_itself_has_a_problem(change: Any, message: str) -> None:
    found = problem(changed(change))
    assert found is not None and message in found, found
