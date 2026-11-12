"""The shop's catalogue: a SQLite file in /tmp, the only place the image may write (ADR-0011, decision 6)."""

import sqlite3
import tempfile
from pathlib import Path

DATABASE = Path(tempfile.gettempdir()) / "shop.sqlite3"
PRODUCTS = [
    ("SKU-001", "Blue mug", 12.5),
    ("SKU-002", "Red mug", 12.5),
    ("SKU-003", "Teapot", 39.0),
]


def connect() -> sqlite3.Connection:
    """A connection to the catalogue, created with its demo rows on first use."""
    connection = sqlite3.connect(DATABASE)
    connection.execute("CREATE TABLE IF NOT EXISTS products (sku TEXT PRIMARY KEY, name TEXT, price REAL)")
    connection.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?)", PRODUCTS)
    connection.commit()
    return connection
