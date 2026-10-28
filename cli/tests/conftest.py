"""Shared test helpers for the sentinelci package."""

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from sentinelci.policy.opa import OpaError, OpaRunner

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def finding_validator() -> Draft202012Validator:
    """Validator for the Finding v1 contract (schemas/finding.v1.json)."""
    schema = json.loads((REPO_ROOT / "schemas" / "finding.v1.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture
def opa_binary() -> Path:
    """The real OPA binary. Skips when absent, unless SENTINEL_REQUIRE_OPA is set (CI)."""
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")
