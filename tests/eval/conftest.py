"""Fixtures for the evaluation harness tests."""

import os
from pathlib import Path

import pytest

from sentinelci.policy.opa import OpaError, OpaRunner


@pytest.fixture
def opa_binary() -> Path:
    """The real OPA binary. Skips when absent, unless SENTINEL_REQUIRE_OPA is set (CI)."""
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")
