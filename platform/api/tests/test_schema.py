"""The database schema comes from the migrations only, and the API matches its committed contract."""

from __future__ import annotations

import hashlib
import json
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
HEAD = "0009"  # the latest migration: a downgrade that stops leaves the database there


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
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
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
        downgrade(url, "0004")  # 0009, 0008, 0007 and 0006 go down (nothing is kept there), 0005 stops
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
        assert conn.execute("SELECT count(*) FROM correlations").fetchone() == (1,)


def test_going_below_0006_stops_while_a_decision_is_kept(postgres_server: str) -> None:
    """Dropping `decisions` would lose the only copy of what the gate decided: the downgrade stops, changing
    nothing, while any decision is kept."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    decision_id = str(uuid.uuid4())
    document = json.dumps(
        {
            "decision_id": decision_id,
            "verdict": "PASS",
            "subject": {"repo": "o/r", "commit": "a" * 40, "context": "pr"},
            "inputs": {"findings_digest": "sha256:" + "b" * 64},
        }
    ).encode()
    with psycopg.connect(url, autocommit=True) as conn:
        run = conn.execute(
            "INSERT INTO runs (id, repo, commit, context, findings_sha256, findings_uploaded_at) "
            "VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'pr', repeat('b', 64), now()) RETURNING id"
        ).fetchone()
        assert run is not None
        conn.execute(
            "INSERT INTO decisions (run_id, sha256, decision_id, verdict, evaluated_at, engine_version, "
            "document) VALUES (%s, encode(sha256(%s), 'hex'), %s, 'PASS', now(), '0.1.0', %s)",
            (run[0], document, decision_id, document),
        )
    with pytest.raises(RuntimeError, match=r"1 decision\(s\) are kept"):
        downgrade(url, "0005")  # 0009, 0008 and 0007 go down (nothing is kept there), 0006 stops
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
        assert conn.execute("SELECT count(*) FROM decisions").fetchone() == (1,)


def test_going_below_0007_stops_while_a_release_is_kept(postgres_server: str) -> None:
    """Dropping `releases` would lose the only copy of the evidence `make release` posted: the downgrade
    stops, changing nothing, while any release is kept."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    document = b'{"schema_version": "1.0"}'
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO releases (decision_id, repo, commit, image_digest, verdict, evaluated_at, sha256, "
            "document) VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'sha256:' || repeat('c', 64), "
            "'BLOCK', now(), encode(sha256(%s), 'hex'), %s)",
            (document, document),
        )
    with pytest.raises(RuntimeError, match=r"1 release\(s\) are kept"):
        downgrade(url, "0006")  # 0009 and 0008 go down (nothing is kept there), 0007 stops
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
        assert conn.execute("SELECT count(*) FROM releases").fetchone() == (1,)


def test_going_below_0008_stops_while_a_remediation_attempt_is_kept(postgres_server: str) -> None:
    """Dropping `remediations` would lose the only copy of what the loop reported: the downgrade stops,
    changing nothing, while any attempt is kept."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    document = b'{"schema_version": "1.0"}'
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO remediations (proposal_id, repo, strategy, attempt, finding_count, outcome, "
            "verdict, build_ok, tests_ok, target_resolved, new_finding_count, proposed_at, verified_at, "
            "sha256, document) VALUES (gen_random_uuid(), 'o/r', 'llm:code', 1, 1, 'FAILED', 'PASS', "
            "false, false, false, 0, now(), now(), encode(sha256(%s), 'hex'), %s)",
            (document, document),
        )
    with pytest.raises(RuntimeError, match=r"1 remediation attempt\(s\) are kept"):
        downgrade(url, "0007")  # 0009 goes down (no waivers file is kept), 0008 stops
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
        assert conn.execute("SELECT count(*) FROM remediations").fetchone() == (1,)


def test_going_below_0009_stops_while_a_waivers_file_is_kept(postgres_server: str) -> None:
    """Dropping `waivers_files` would lose the only copy of the waivers the gate read: the downgrade stops,
    changing nothing, while any file is kept."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    url = f"{postgres_server}/{name}"
    upgrade(url)
    waivers = b"version: 1\nwaivers: []\n"
    document = json.dumps(
        {"decision": {"inputs": {"waivers_digest": "sha256:" + hashlib.sha256(waivers).hexdigest()}}}
    ).encode()
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO releases (decision_id, repo, commit, image_digest, verdict, evaluated_at, sha256, "
            "document) VALUES (gen_random_uuid(), 'o/r', repeat('a', 40), 'sha256:' || repeat('c', 64), "
            "'BLOCK', now(), encode(sha256(%s), 'hex'), %s)",
            (document, document),
        )
        conn.execute(
            "INSERT INTO waivers_files (sha256, document) VALUES (encode(sha256(%s), 'hex'), %s)",
            (waivers, waivers),
        )
    with pytest.raises(RuntimeError, match=r"1 waivers file\(s\) are kept"):
        downgrade(url, "0008")
    with psycopg.connect(url) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (HEAD,)
        assert conn.execute("SELECT count(*) FROM waivers_files").fetchone() == (1,)
