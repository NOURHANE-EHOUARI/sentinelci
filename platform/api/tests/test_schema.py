"""The database schema comes from the migrations only, and the API matches its committed contract."""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest
import yaml
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from psycopg import sql
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
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
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


def test_a_ci_run_recorded_twice_stops_the_unique_index_migration(postgres_server: str) -> None:
    """A database from before 0003 may hold a CI run twice: the migration stops and changes nothing."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url, "0002")
    insert = (
        "INSERT INTO runs (id, repo, commit, context, ci_run_id) "
        "VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'pr', '7')"
    )
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(insert)
        conn.execute(insert)
    with pytest.raises(RuntimeError, match=r"1 CI run\(s\) are recorded more than once"):
        upgrade(url)
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("0002",)
        assert conn.execute("SELECT count(*) FROM runs").fetchone() == (2,)


def test_going_below_0004_stops_while_a_run_keeps_its_uploaded_bytes(postgres_server: str) -> None:
    """Dropping `runs.findings_ndjson` would lose the only bytes `findings_sha256` was taken of.

    The downgrade stops, changing nothing, while any run keeps them. Without kept bytes it still goes down
    (test_the_migrations_go_down_and_up_again).
    """
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO runs (id, repo, commit, context, findings_sha256, findings_uploaded_at, "
            "findings_ndjson) VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'pr', "
            "encode(sha256('{}'::bytea), 'hex'), now(), '{}'::bytea)"
        )
    with pytest.raises(RuntimeError, match=r"1 run\(s\) keep their uploaded findings bytes"):
        downgrade(url, "0003")
    with psycopg.connect(url) as conn:  # one transaction: nothing changed, the head included
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("0005",)
        assert conn.execute("SELECT findings_ndjson FROM runs").fetchone() == (b"{}",)


def test_going_below_0005_stops_while_a_correlation_is_kept(postgres_server: str) -> None:
    """Dropping `correlations` would lose the only copy of what the correlator posted: the downgrade stops,
    changing nothing, while any version is kept."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    document = b'{"findings_sha256": "' + b"b" * 64 + b'"}'
    with psycopg.connect(url, autocommit=True) as conn:
        run = conn.execute(
            "INSERT INTO runs (id, repo, commit, context, findings_sha256, findings_uploaded_at) "
            "VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'pr', repeat('b', 64), now()) RETURNING id"
        ).fetchone()
        assert run is not None
        conn.execute(
            "INSERT INTO correlations (run_id, sha256, correlator_version, group_count, document) "
            "VALUES (%s, encode(sha256(%s), 'hex'), '0.1.0', 0, %s)",
            (run[0], document, document),
        )
    with pytest.raises(RuntimeError, match=r"1 correlation version\(s\) are kept"):
        downgrade(url, "0004")
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("0005",)
        assert conn.execute("SELECT count(*) FROM correlations").fetchone() == (1,)
