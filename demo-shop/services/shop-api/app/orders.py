"""Orders and product lookups written safely (GT-CLEAN-005): the control next to the seeds of main.py.

Values travel as query parameters, YAML is read with the safe loader, outbound requests verify TLS, and no
command runs through a shell. A SAST finding in this file is a false positive.
"""

import subprocess
from typing import Any

import requests
import yaml

from app.db import connect

ALLOWED_HOSTS = frozenset({"status.example.com"})


def product(sku: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT sku, name, price FROM products WHERE sku = ?", (sku,)).fetchone()
    return None if row is None else {"sku": row[0], "name": row[1], "price": row[2]}


def parse_order(text: str) -> dict[str, Any]:
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("an order is a mapping")
    return document


def carrier_status(host: str) -> int:
    if host not in ALLOWED_HOSTS:
        raise ValueError("unknown carrier")
    return requests.get(f"https://{host}/health", timeout=5).status_code


def disk_usage() -> str:
    return subprocess.run(["df", "-h", "/tmp"], capture_output=True, text=True, check=False).stdout
