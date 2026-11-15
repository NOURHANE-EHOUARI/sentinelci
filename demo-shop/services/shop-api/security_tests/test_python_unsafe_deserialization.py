"""GT-SAST-003: the order import loads untrusted YAML with FullLoader (app/main.py)."""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize("body", ["!!python/tuple [1, 2]"])
def test_python_tags_in_an_order_are_refused(client: TestClient, body: str) -> None:
    """A safe loader builds only plain YAML: a Python tag is never constructed, so the import fails."""
    assert client.post("/orders/import", content=body).status_code != 200
