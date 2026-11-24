"""The engine's version is both packages' version (A10, #101 review): `sentinelci.__version__` is what every
Decision v1 records as `engine_version`, and the release builds the two packages under that version."""

from __future__ import annotations

import tomllib
from pathlib import Path

import sentinelci

ROOT = Path(__file__).resolve().parents[2]


def test_the_engine_version_is_both_packages_version() -> None:
    versions = {
        d: tomllib.loads((ROOT / d / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        for d in ("cli", "ai")
    }
    assert versions == {"cli": sentinelci.__version__, "ai": sentinelci.__version__}
