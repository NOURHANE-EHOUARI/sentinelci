"""Remediation attempt v1 (A6, A8): the model is pinned to the schema by the contract fixtures, and
`problem()` refuses a result that is not the proposal's."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinelci.contracts.remediation import RemediationAttempt

FIXTURES = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "remediation-attempt"


@pytest.mark.parametrize("path", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_every_valid_fixture_is_accepted_and_consistent(path: Path) -> None:
    assert RemediationAttempt.model_validate_json(path.read_bytes()).problem() is None


@pytest.mark.parametrize("path", sorted((FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_every_invalid_fixture_is_refused(path: Path) -> None:
    with pytest.raises(ValidationError):
        RemediationAttempt.model_validate_json(path.read_bytes())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["result"].update(proposal_id="0193f2c5-0000-7000-8000-00000000ffff"), "about proposal"),
        (lambda d: d["result"].update(attempt=2), "about attempt 2, not 1"),
        (lambda d: d["result"].update(verified_at="2026-11-11T08:59:59Z"), "verified before the proposal"),
    ],
)
def test_a_result_that_is_not_the_proposals_has_a_problem(change: Any, message: str) -> None:
    document = json.loads((FIXTURES / "valid" / "kubernetes-verified.json").read_text())
    changed = copy.deepcopy(document)
    change(changed)
    found = RemediationAttempt.model_validate_json(json.dumps(changed)).problem()
    assert found is not None and message in found
