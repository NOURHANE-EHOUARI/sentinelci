"""GT-SAST-005: the discount rule is evaluated as Python from a query parameter (app/main.py)."""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.parametrize(
    "rule",
    [
        "price * (__import__('os').getpid() > 0)",
        "price * len(open('/etc/hostname').read() * 0 + 'x')",
        "price * ().__class__.__mro__[-1].__subclasses__().__len__() ** 0",
    ],
    ids=["import", "open", "subclasses"],
)
def test_a_rule_is_arithmetic_on_the_price_never_python(client: TestClient, rule: str) -> None:
    """Each of these is a price under eval (so the seed answers 200); a rule evaluator refuses them."""
    assert client.get("/discount", params={"rule": rule}).status_code != 200
