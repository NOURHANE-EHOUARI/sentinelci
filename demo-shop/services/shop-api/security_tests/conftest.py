"""shop-api's security tests (B9, ADR-0014): one file per SAST seed, named after its Opengrep rule
(`test_<rule, with - as _>.py`), so a check can run the target finding's own test from the finding alone.

Each test FAILS on the seeded code (that is the seed) and passes once the weakness is fixed. They are not in
`tests/`, which must pass on the seeded code too: a fix of one seed leaves the other five. They run only in the
test image (Dockerfile.test), never outside a container.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    # An exception is an answer here (a refused payload may raise): the test reads the status code.
    return TestClient(app, raise_server_exceptions=False)
