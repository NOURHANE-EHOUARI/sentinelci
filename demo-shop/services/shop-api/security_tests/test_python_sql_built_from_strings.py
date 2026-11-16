"""GT-SAST-001: the product search builds its SQL from the query string (app/main.py)."""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize("q", ["x' OR 1=1 --", "'", "%' UNION SELECT sku, sku, price FROM products --"])
def test_a_search_is_text_never_sql(client: TestClient, q: str) -> None:
    """The search text is matched as text: no product is named like that, so nothing comes back."""
    answer = client.get("/products", params={"q": q})
    assert (answer.status_code, answer.json()) == (200, [])
