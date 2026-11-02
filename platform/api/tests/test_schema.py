"""The database schema comes from the migrations only, and the API matches its committed contract."""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import yaml
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from sentinel_api.config import Settings, sqlalchemy_url
from sentinel_api.main import create_app
from sentinel_api.migrate import downgrade, upgrade
from sentinel_api.models import Base

ROOT = Path(__file__).resolve().parents[3]
OPENAPI = ROOT / "schemas" / "openapi.yaml"


def test_the_migrations_build_exactly_the_models(database_url: str) -> None:
    engine = create_engine(sqlalchemy_url(database_url))
    try:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    finally:
        engine.dispose()
    assert diff == [], "a model changed without a migration (or the reverse)"


def test_the_migrations_go_down_and_up_again(postgres_server: str) -> None:
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    url = f"{postgres_server}/{name}"
    upgrade(url)
    downgrade(url, "base")
    engine = create_engine(sqlalchemy_url(url))
    try:
        assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    finally:
        engine.dispose()
    upgrade(url)


def test_the_api_matches_its_committed_contract() -> None:
    """schemas/openapi.yaml is the contract with A3, A6, A8 and B7 (SPEC section 13.2).

    Regenerate it with `uv run python -m sentinel_api.openapi > schemas/openapi.yaml` and review the diff.
    """
    app = create_app(Settings(database_url=None, token_sha256=frozenset()))
    assert yaml.safe_load(OPENAPI.read_text(encoding="utf-8")) == app.openapi()
