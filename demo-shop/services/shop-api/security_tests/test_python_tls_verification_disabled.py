"""GT-SAST-004: the price-list proxy fetches any URL with TLS verification turned off (app/main.py)."""

from types import SimpleNamespace
from typing import Any

import pytest
import requests
from fastapi.testclient import TestClient


def test_the_proxy_verifies_tls(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    options: list[dict[str, Any]] = []

    def fake_get(url: str, *args: Any, **kwargs: Any) -> SimpleNamespace:
        options.append(kwargs)
        return SimpleNamespace(status_code=200, content=b"")

    monkeypatch.setattr(requests, "get", fake_get)
    client.get("/proxy", params={"url": "https://status.example.com/prices.csv"})
    assert options, "the proxy still fetches the price list"
    assert all(kwargs.get("verify", True) is not False for kwargs in options)
