"""The worker's own database role (`sentinel_worker`, migration 0011, #111 review), against a real PostgreSQL.

The worker reaches the database, the queue and the model, and the model's input is a finding a scanner wrote.
So it logs in as a role that can only do its jobs: read runs and findings, claim and finish explanation
requests, and record explanations. It cannot write a run, a finding or a decision, read a decision, a waiver
or a release, or change the schema. The migration creates the role without a login; `sentinel-api migrate`
gives it one with the password in `SENTINEL_WORKER_DATABASE_PASSWORD` (Compose sets it from `.env`).
"""

from __future__ import annotations

import json
import re
import secrets
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel_api import migrate
from sentinel_api.config import sqlalchemy_url
from sentinel_worker.tasks import run_explain

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
JSON = {"Content-Type": "application/json"}
NDJSON = {"Content-Type": "application/x-ndjson"}
RUN = {"repo": "acme/shop", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "context": "release"}
NOW = datetime(2026, 11, 12, 9, 0, tzinfo=UTC)
SCA: dict[str, Any] = json.loads((VALID / "sca-enriched-and-scored.json").read_text(encoding="utf-8"))
ANSWER = {
    "summary": "PyYAML before 5.4 runs code from a crafted YAML document.",
    "impact": "An attacker who controls a YAML document can run code as the service.",
    "exploit_scenario": "A document with a python/object tag given to full_load runs a command.",
    "fix_guidance": "Upgrade PyYAML to 5.4 or later and load untrusted YAML with safe_load.",
    "references": [],
    "confidence": 0.8,
}


class Scripted:
    name = "fake"

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = list(answers)

    def complete(self, system: str, user: str, schema: type[Any]) -> Any:
        return schema.model_validate(self.answers.pop(0))

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise AssertionError("an explanation never embeds")


def as_worker(database_url: str, password: str) -> str:
    return re.sub(
        r"^(postgresql://)[^@]+@", rf"\g<1>{migrate.WORKER_ROLE}:{quote(password, safe='')}@", database_url
    )


@pytest.fixture
def worker_url(database_url: str) -> str:
    password = secrets.token_urlsafe(24)
    migrate.set_worker_password(database_url, password)
    return as_worker(database_url, password)


@pytest.fixture
def worker_sessions(worker_url: str) -> Iterator[Callable[[], Session]]:
    engine = create_engine(sqlalchemy_url(worker_url))
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def explain_request(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    """A run with one SCA finding, and a queued explanation request for it: (run id, request id)."""
    client.app.state.enqueue = lambda name, args: None  # type: ignore[attr-defined]
    created = client.post("/api/v1/runs", json=RUN, headers=headers)
    assert created.status_code == 201, created.text
    run_id: str = created.json()["id"]
    body = (json.dumps(SCA | {"run": RUN}) + "\n").encode()
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers=headers | NDJSON)
    assert uploaded.status_code == 201, uploaded.text
    asked = client.post(f"/api/v1/findings/{SCA['id']}/explain", content=b"", headers=headers | JSON)
    assert asked.status_code == 202, asked.text
    request_id: str = asked.json()["id"]
    return run_id, request_id


def test_the_worker_role_does_the_workers_job(
    client: TestClient, headers: dict[str, str], worker_sessions: Callable[[], Session]
) -> None:
    run_id, request_id = explain_request(client, headers)
    outcome = run_explain(request_id, sessions=worker_sessions, provider=Scripted(ANSWER), now=NOW)
    assert outcome == "explained"
    done = client.get(f"/api/v1/explain-requests/{request_id}").json()
    assert (done["status"], done["run_id"]) == ("explained", run_id)
    assert client.get(f"/api/v1/findings/{SCA['id']}/explanation").status_code == 200


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE runs SET findings_sha256 = NULL",
        "DELETE FROM runs",
        "INSERT INTO runs (id) VALUES (gen_random_uuid())",
        "UPDATE findings SET severity = 'LOW'",
        "DELETE FROM findings",
        "SELECT * FROM decisions",
        "SELECT * FROM waivers_files",
        "SELECT * FROM releases",
        "SELECT * FROM remediations",
        "SELECT * FROM correlations",
        "INSERT INTO explain_requests (id) VALUES (gen_random_uuid())",
        "DELETE FROM explain_requests",
        "UPDATE explain_requests SET finding_id = repeat('0', 64)",
        "UPDATE explain_requests SET run_id = gen_random_uuid()",
        "UPDATE explanations SET finding_id = finding_id",
        "SELECT document FROM explanations",
        "SELECT * FROM explanations",
        "DELETE FROM explanations",
        "SELECT * FROM alembic_version",
        "CREATE TABLE worker_owned (id int)",
        "ALTER TABLE runs ADD COLUMN x int",
        "TRUNCATE explain_requests",
    ],
)
def test_the_worker_role_can_do_nothing_else(worker_url: str, statement: str) -> None:
    with psycopg.connect(worker_url) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(statement)


def test_the_role_has_no_login_until_migrate_gives_it_one(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    password = secrets.token_urlsafe(24)
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(as_worker(database_url, password)).close()
    monkeypatch.setenv("SENTINEL_DATABASE_URL", database_url)
    monkeypatch.setenv(migrate.WORKER_PASSWORD_VARIABLE, password)
    assert migrate.main() == 0
    with psycopg.connect(as_worker(database_url, password)) as conn:
        assert conn.execute("SELECT current_user").fetchone() == (migrate.WORKER_ROLE,)
    # Without the variable, migrate leaves the password as it is (the worker keeps logging in).
    monkeypatch.delenv(migrate.WORKER_PASSWORD_VARIABLE)
    assert migrate.main() == 0
    psycopg.connect(as_worker(database_url, password)).close()


def test_a_password_with_quotes_is_set_as_given(database_url: str) -> None:
    """The password is a literal, never SQL: one with quotes and a semicolon is set as it is."""
    password = "it's; DROP TABLE runs; --"  # noqa: S105  (a test value)
    migrate.set_worker_password(database_url, password)
    with psycopg.connect(as_worker(database_url, password)) as conn:
        assert conn.execute("SELECT current_user").fetchone() == (migrate.WORKER_ROLE,)
    with psycopg.connect(database_url) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone() == (0,)


def test_an_empty_password_is_refused(database_url: str) -> None:
    with pytest.raises(ValueError, match="empty"):
        migrate.set_worker_password(database_url, "")


def test_going_below_0011_takes_the_workers_rights_back(database_url: str) -> None:
    password = secrets.token_urlsafe(24)
    migrate.set_worker_password(database_url, password)
    migrate.downgrade(database_url, "0010")
    for statement in ("SELECT * FROM runs", "SELECT seq FROM explanations"):
        with (
            psycopg.connect(as_worker(database_url, password)) as conn,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            conn.execute(statement)
    migrate.upgrade(database_url)
    with psycopg.connect(as_worker(database_url, password)) as conn:
        assert conn.execute("SELECT count(*) FROM runs").fetchone() == (0,)


def test_the_role_is_created_once_per_server(database_url: str, postgres_server: str) -> None:
    """Roles belong to the server, not to one database: a second database's migration reuses the role."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    migrate.upgrade(f"{postgres_server}/{name}")  # does not fail on the existing role
    with psycopg.connect(database_url) as conn:
        row = conn.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = %s",
            (migrate.WORKER_ROLE,),
        ).fetchone()
    assert row == (False, False, False, False)


def test_the_server_never_sees_the_clear_password(database_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """migrate sends a SCRAM verifier, never the password: no statement log can hold it."""
    sent: list[str] = []
    execute = psycopg.Connection.execute

    def spy(self: psycopg.Connection[Any], query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(query.as_string(self) if isinstance(query, sql.Composable) else str(query))
        return execute(self, query, *args, **kwargs)

    password = secrets.token_urlsafe(24)
    monkeypatch.setattr(psycopg.Connection, "execute", spy)
    migrate.set_worker_password(database_url, password)
    monkeypatch.undo()
    assert sent and not any(password in statement for statement in sent)
    assert any("SCRAM-SHA-256$" in statement for statement in sent)
    with psycopg.connect(as_worker(database_url, password)) as conn:
        assert conn.execute("SELECT current_user").fetchone() == (migrate.WORKER_ROLE,)
