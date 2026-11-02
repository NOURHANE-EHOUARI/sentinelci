"""Repository-wide pytest setup.

This repository has a top-level directory named platform/. In importlib import mode, pytest imports the
parent directories of a test module as modules, and re-imports one that has no `__path__`
(_pytest/pathlib.py, `need_reimport`). Collecting anything under platform/ therefore puts that directory in
sys.modules["platform"], in place of the standard library module, and a library that imports `platform`
afterwards (SQLAlchemy, attrs through jsonschema) fails. Put the standard module back before each collector
runs, whatever the order of the test paths (#38 review). platform/api/tests/conftest.py also restores it for
its own imports.
"""

from __future__ import annotations

import platform as _stdlib_platform
import sys
from typing import Any


def pytest_collectstart(collector: Any) -> None:
    sys.modules["platform"] = _stdlib_platform


def pytest_collection_finish(session: Any) -> None:
    sys.modules["platform"] = _stdlib_platform
