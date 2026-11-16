"""A reference fix of shop-api's six SAST seeds (B9): app/main.py with each weakness fixed, nothing else.

Not part of demo-shop and never deployed: a test fixture. tests/demo_shop/test_shop_api_tests.py mounts it
over the seeded app/main.py, in the test image only, to show that every security test can pass (and the
behaviour tests still do) once the seeds are fixed. It also shows what a fix of each seed looks like.
"""

import ast
import subprocess
from typing import Any

import requests
import yaml
from app import orders
from app.db import connect
from fastapi import FastAPI, HTTPException, Request

# GT-SAST-006 fixed: no debug mode.
app = FastAPI(title="shop-api", version="1.0.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """The Kubernetes probes' check: no HEALTHCHECK in the image (ADR-0011)."""
    return {"status": "ok"}


@app.get("/products")
def search(q: str = "") -> list[dict[str, Any]]:
    """Search the catalogue by name."""
    with connect() as connection:
        rows = connection.execute("SELECT sku, name, price FROM products WHERE name LIKE ?", (f"%{q}%",))
        return [{"sku": sku, "name": name, "price": price} for sku, name, price in rows]


@app.get("/products/{sku}")
def product(sku: str) -> dict[str, Any]:
    found = orders.product(sku)
    if found is None:
        raise HTTPException(404, "no such product")
    return found


@app.get("/admin/ping")
def ping(host: str) -> dict[str, str]:
    """Check that a supplier's host answers."""
    done = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=False)
    return {"output": done.stdout}


@app.post("/orders/import", description="Import orders from YAML.")
async def import_orders(request: Request) -> dict[str, int]:
    body = (await request.body()).decode("utf-8")
    document = yaml.safe_load(body)
    return {"orders": len(document or [])}


@app.get("/proxy")
def proxy(url: str) -> dict[str, Any]:
    """Fetch a supplier's price list."""
    answer = requests.get(url, timeout=5)
    return {"status": answer.status_code, "length": len(answer.content)}


@app.get("/discount")
def discount(rule: str = "0") -> dict[str, float]:
    """Apply a discount rule such as `price * 0.9`."""
    price = 39.0
    return {"price": _arithmetic(ast.parse(rule, mode="eval").body, price)}


OPERATIONS: dict[type[ast.operator], Any] = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
}


def _arithmetic(node: ast.AST, price: float) -> float:
    """A rule is arithmetic on the price: numbers, `price`, + - * /. Anything else is refused (400)."""
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return float(node.value)
    if isinstance(node, ast.Name) and node.id == "price":
        return price
    if isinstance(node, ast.BinOp) and type(node.op) in OPERATIONS:
        return float(OPERATIONS[type(node.op)](_arithmetic(node.left, price), _arithmetic(node.right, price)))
    raise HTTPException(400, "a rule is arithmetic on the price")
