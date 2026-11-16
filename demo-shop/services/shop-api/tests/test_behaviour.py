"""shop-api's behaviour (B9, ADR-0014): what every correct fix of a seed must keep.

These tests pass on the seeded code and must still pass on a patched one: A6's `llm:code` check runs them on
both, in the test image (Dockerfile.test), with no network, a read-only file system and as `nobody`. They
never run outside that container (CLAUDE.md: demo-shop's code runs only in a container). The ping and the
proxy call fakes: there is no network, and a test must not depend on one.
"""

from types import SimpleNamespace
from typing import Any

import pytest
import requests
import subprocess
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_the_health_check_answers() -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_a_search_finds_products_by_part_of_their_name() -> None:
    found = client.get("/products", params={"q": "mug"})
    assert found.status_code == 200
    assert sorted(product["name"] for product in found.json()) == ["Blue mug", "Red mug"]


def test_an_empty_search_lists_the_catalogue() -> None:
    assert sorted(p["sku"] for p in client.get("/products").json()) == ["SKU-001", "SKU-002", "SKU-003"]


def test_a_search_that_matches_nothing_is_empty() -> None:
    assert client.get("/products", params={"q": "kettle"}).json() == []


def test_a_product_is_found_by_its_sku_and_an_unknown_one_is_404() -> None:
    assert client.get("/products/SKU-003").json() == {"sku": "SKU-003", "name": "Teapot", "price": 39.0}
    assert client.get("/products/SKU-999").status_code == 404


def test_ping_reports_what_the_ping_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(stdout="1 packets transmitted, 1 received", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    answer = client.get("/admin/ping", params={"host": "status.example.com"})
    assert answer.status_code == 200
    assert answer.json() == {"output": "1 packets transmitted, 1 received"}
    assert len(calls) == 1 and "status.example.com" in repr(calls[0][0])


def test_an_order_import_counts_the_orders() -> None:
    body = "- sku: SKU-001\n  quantity: 2\n- sku: SKU-003\n  quantity: 1\n"
    assert client.post("/orders/import", content=body).json() == {"orders": 2}


def test_an_empty_import_counts_no_order() -> None:
    assert client.post("/orders/import", content="").json() == {"orders": 0}


def test_the_proxy_reports_the_status_and_size_of_the_price_list(monkeypatch: pytest.MonkeyPatch) -> None:
    fetched: list[str] = []

    def fake_get(url: str, *args: Any, **kwargs: Any) -> SimpleNamespace:
        fetched.append(url)
        return SimpleNamespace(status_code=200, content=b"SKU-001;12.5\n")

    monkeypatch.setattr(requests, "get", fake_get)
    answer = client.get("/proxy", params={"url": "https://status.example.com/prices.csv"})
    assert answer.json() == {"status": 200, "length": 13}
    assert fetched == ["https://status.example.com/prices.csv"]


@pytest.mark.parametrize(("rule", "price"), [("price * 0.9", 35.1), ("price - 5", 34.0), ("price", 39.0)])
def test_a_discount_rule_is_applied_to_the_price(rule: str, price: float) -> None:
    answer = client.get("/discount", params={"rule": rule})
    assert answer.status_code == 200
    assert answer.json()["price"] == pytest.approx(price)
