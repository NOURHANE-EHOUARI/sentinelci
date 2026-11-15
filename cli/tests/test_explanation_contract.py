"""The Explanation v1 read model accepts exactly what `schemas/explanation.v1.json` accepts (its fixtures)."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinelci.contracts.explanation import Explanation

ROOT = Path(__file__).resolve().parents[2]
CASES = sorted((ROOT / "schemas" / "fixtures" / "explanation").glob("*/*.json"))


@pytest.mark.parametrize("path", CASES, ids=[f"{p.parent.name}/{p.stem}" for p in CASES])
def test_the_read_model_agrees_with_the_contract_fixtures(path: Path) -> None:
    valid = path.parent.name == "valid"
    try:
        Explanation.model_validate_json(path.read_bytes())
    except ValidationError:
        assert not valid, f"{path.name} is valid for the schema"
    else:
        assert valid, f"{path.name} is invalid for the schema"


def valid_document() -> dict[str, object]:
    import json

    document: dict[str, object] = json.loads(
        (ROOT / "schemas/fixtures/explanation/valid/sql-injection.json").read_text(encoding="utf-8")
    )
    return document


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confidence", True),  # a boolean is not a number in JSON Schema
        ("confidence", "0.5"),
        ("summary", " "),
        ("summary", "one\u2028two"),
        ("references", ["CWE-89", "CWE-89"]),
        ("references", ["https://example.org/a b"]),
        ("created_at", "2026-11-12"),
        ("created_at", "yesterday"),
        ("schema_version", "1.1"),
        ("finding_id", "A" * 64),
    ],
)
def test_values_the_schema_refuses_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Explanation.model_validate(valid_document() | {field: value})


def test_a_model_record_without_its_hashes_or_with_another_field_is_refused() -> None:
    document = valid_document()
    model = dict(document["model"])  # type: ignore[call-overload]
    for broken in ({k: v for k, v in model.items() if k != "prompt_sha256"}, model | {"temperature": 0}):
        with pytest.raises(ValidationError):
            Explanation.model_validate(document | {"model": broken})
