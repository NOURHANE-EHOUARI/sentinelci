"""Shared test helpers for the sentinelci package."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def finding_validator() -> Draft202012Validator:
    """Validator for the Finding v1 contract (schemas/finding.v1.json)."""
    schema = json.loads((REPO_ROOT / "schemas" / "finding.v1.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())
