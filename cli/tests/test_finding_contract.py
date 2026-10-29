"""The Finding model (contracts/finding.py) agrees with schemas/finding.v1.json, other_locations included."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from sentinelci.contracts.finding import Finding

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


@pytest.mark.parametrize("path", ["/etc/passwd", "..", "a/../b", "a/..", "x\n/../y", "a\nb"])
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


ENRICHED = FIXTURES / "valid" / "sca-enriched-and-scored.json"


@pytest.mark.parametrize(
    "change",
    [
        {"epss": {"score": "0.41", "percentile": 0.95, "date": "2026-11-10"}},
        {"epss": {"score": 0.41, "percentile": "0.95", "date": "2026-11-10"}},
        {"cvss": {"score": "9.8"}},
        {"epss": {"score": 1.5, "percentile": 0.95, "date": "2026-11-10"}},
        {"epss": {"score": 0.41, "percentile": -0.1, "date": "2026-11-10"}},
        {"epss": {"score": 0.41, "percentile": 1.01, "date": "2026-11-10"}},
        {"cvss": {"score": 10.5}},
        {"cvss": {"score": -1}},
        {"fix_available": "yes"},
        {"kev": {"listed": 1}},
    ],
    ids=[
        "epss-score-string",
        "epss-percentile-string",
        "cvss-string",
        "epss-score-above-1",
        "epss-percentile-below-0",
        "epss-percentile-above-1",
        "cvss-above-10",
        "cvss-below-0",
        "fix-string",
        "kev-int",
    ],
)
def test_enrichment_numbers_are_numbers_within_their_range(
    change: dict[str, Any], finding_validator: Draft202012Validator
) -> None:
    """#17 N4: the typed Finding.enrichment refuses what the schema refuses."""
    document = load(ENRICHED)
    document["enrichment"] = {**document["enrichment"], **change}
    assert list(finding_validator.iter_errors(document)), "the schema must refuse it"
    with pytest.raises(ValidationError):
        Finding.model_validate(document)
