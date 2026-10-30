"""The Finding model (contracts/finding.py) agrees with schemas/finding.v1.json, other_locations included."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from sentinelci.contracts.finding import _RELATIVE_PATH, Finding

FIXTURES = Path(__file__).resolve().parents[2] / "schemas" / "fixtures" / "finding"
# Invalid fixtures for the 1.1 rules and for paths; the model checks these exactly like the schema. The
# other invalid fixtures test hash patterns and enums the model leaves to the schema.
OTHER_LOCATIONS_RULES = sorted((FIXTURES / "invalid").glob("*other-locations*.json"))
MODEL_CHECKED = [*OTHER_LOCATIONS_RULES, FIXTURES / "invalid" / "path-traversal-location.json"]


def load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


@pytest.mark.parametrize("path", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_valid_fixture_round_trips_through_the_model(path: Path) -> None:
    document = load(path)
    assert Finding.model_validate(document).to_json_dict() == document


def test_every_other_locations_rule_has_an_invalid_fixture() -> None:
    assert {p.stem for p in OTHER_LOCATIONS_RULES} == {
        "v1.0-with-other-locations",
        "other-locations-empty",
        "other-locations-duplicate",
        "other-locations-path-traversal",
        "other-locations-without-location",
    }


@pytest.mark.parametrize("path", MODEL_CHECKED, ids=lambda p: p.stem)
def test_model_rejects_what_the_schema_rejects(path: Path, finding_validator: Draft202012Validator) -> None:
    document = load(path)
    assert list(finding_validator.iter_errors(document))
    with pytest.raises(ValidationError):
        Finding.model_validate(document)


def test_model_default_stays_1_0() -> None:
    document = load(FIXTURES / "valid" / "secret-in-config.json")
    del document["schema_version"]
    assert Finding.model_validate(document).schema_version == "1.0"


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "..", "a/../b", "a/..", "x\n/../y", "a\nb", "a\n", "a\r", "a\u2028b"]
)
def test_location_paths_must_stay_inside_the_repository(
    path: str, finding_validator: Draft202012Validator
) -> None:
    document = load(FIXTURES / "valid" / "secret-in-config.json")
    document["location"]["path"] = path
    assert list(finding_validator.iter_errors(document))
    with pytest.raises(ValidationError):
        Finding.model_validate(document)


@pytest.mark.parametrize("path", ["a..b/c", "..x/y", "dir/.hidden", "./a"])
def test_dots_inside_names_are_fine(path: str, finding_validator: Draft202012Validator) -> None:
    document = load(FIXTURES / "valid" / "secret-in-config.json")
    document["location"]["path"] = path
    assert not list(finding_validator.iter_errors(document))
    assert Finding.model_validate(document).location is not None


def test_model_path_rule_is_the_schema_rule() -> None:
    schema = json.loads((FIXTURES.parents[1] / "finding.v1.json").read_text(encoding="utf-8"))
    assert _RELATIVE_PATH.pattern == schema["$defs"]["relative_path"]["pattern"]
