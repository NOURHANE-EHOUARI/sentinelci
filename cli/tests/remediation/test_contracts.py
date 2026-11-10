"""The remediation read models accept exactly what their schemas accept (the contract fixtures)."""

from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from sentinelci.contracts.remediation import PatchProposal, VerificationResult

from .conftest import ROOT

FIXTURES = ROOT / "schemas" / "fixtures"
CASES = [
    (model, path)
    for name, model in (("patch-proposal", PatchProposal), ("verification-result", VerificationResult))
    for path in sorted((FIXTURES / name).glob("*/*.json"))
]


@pytest.mark.parametrize(
    ("model", "path"), CASES, ids=[f"{p.parent.parent.name}/{p.parent.name}/{p.stem}" for _, p in CASES]
)
def test_the_read_model_agrees_with_the_contract_fixtures(model: type[BaseModel], path: Path) -> None:
    valid = path.parent.name == "valid"
    try:
        model.model_validate_json(path.read_bytes())
    except ValidationError:
        assert not valid, f"{path.name} is valid for the schema"
    else:
        assert valid, f"{path.name} is invalid for the schema"
