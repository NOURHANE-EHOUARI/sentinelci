"""Contract tests: every schema is valid, every valid fixture passes, every invalid fixture fails.

These fixtures are what both tracks build against before the producer exists (SPEC section 13).
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
FIXTURES = SCHEMAS / "fixtures"

CONTRACTS = {
    "finding": "finding.v1.json",
    "decision": "decision.v1.json",
    "patch-proposal": "patch-proposal.v1.json",
    "verification-result": "verification-result.v1.json",
    "waivers": "waivers.v1.json",
    "tool-status": "tool-status.v1.json",
    "enrichment-snapshot": "enrichment-snapshot.v1.json",
    "sentinel-config": "sentinel-config.v1.json",
    "root-cause-group": "root-cause-group.v1.json",
    "correlation": "correlation.v1.json",
}


def _registry() -> Registry:
    """Every contract by its `$id`, so that one contract can refer to another (correlation -> group)."""
    resources = []
    for name in CONTRACTS.values():
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _validator(contract: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / CONTRACTS[contract]).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker(), registry=_registry())


def _fixtures(kind: str) -> list[tuple[str, Path]]:
    cases = [
        (contract, path)
        for contract in CONTRACTS
        for path in sorted((FIXTURES / contract / kind).glob("*.json"))
    ]
    assert cases, f"no {kind} fixtures found"
    return cases


@pytest.mark.parametrize("schema_file", sorted(CONTRACTS.values()))
def test_schema_is_valid_draft_2020_12(schema_file: str) -> None:
    schema = json.loads((SCHEMAS / schema_file).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("contract", sorted(CONTRACTS))
def test_each_contract_has_valid_and_invalid_fixtures(contract: str) -> None:
    for kind in ("valid", "invalid"):
        assert list((FIXTURES / contract / kind).glob("*.json")), f"{contract}: missing {kind} fixtures"


@pytest.mark.parametrize(("contract", "path"), _fixtures("valid"), ids=lambda v: getattr(v, "name", v))
def test_valid_fixture_is_accepted(contract: str, path: Path) -> None:
    instance = json.loads(path.read_text(encoding="utf-8"))
    errors = sorted(_validator(contract).iter_errors(instance), key=str)
    assert not errors, "\n".join(e.message for e in errors)


@pytest.mark.parametrize(("contract", "path"), _fixtures("invalid"), ids=lambda v: getattr(v, "name", v))
def test_invalid_fixture_is_rejected(contract: str, path: Path) -> None:
    instance = json.loads(path.read_text(encoding="utf-8"))
    assert list(_validator(contract).iter_errors(instance)), f"{path.name} should be rejected"
