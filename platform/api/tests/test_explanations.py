"""Explanations of findings (`/api/v1/findings/{id}/explain`, `/api/v1/explain-requests/{id}`,
`/api/v1/findings/{id}/explanation`, API 1.10.0, B5c) and the worker's job, against a real PostgreSQL.

Advisory: an explanation never changes a verdict and the gate never reads it. The API queues a job
(Celery, `sentinel.explain`), the worker claims it, asks the model through `sentinel_ai.explain`, and records
the outcome through the same checks; an explanation is kept byte for byte, named by its sha256, never changed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel_api.config import sqlalchemy_url
from sentinel_api.explanations import NotRunning, claim, finish
from sentinel_worker import tasks
from sentinel_worker.tasks import run_explain

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
JSON = {"Content-Type": "application/json"}
NDJSON = {"Content-Type": "application/x-ndjson"}
RUN = {"repo": "acme/shop", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "context": "release"}
NOW = datetime(2026, 11, 12, 9, 0, tzinfo=UTC)


def finding(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    return document


SCA = finding("sca-enriched-and-scored.json")
SECRET = finding("secret-in-config.json")
ANSWER = {
    "summary": "PyYAML before 5.4 runs code from a crafted YAML document.",
    "impact": "An attacker who controls a YAML document can run code as the service.",
    "exploit_scenario": "A document with a python/object tag given to full_load runs a command.",
    "fix_guidance": "Upgrade PyYAML to 5.4 or later and load untrusted YAML with safe_load.",
    "references": [],
    "confidence": 0.8,
}


class Scripted:
    """A model that gives the scripted answers, in order (an Exception is raised instead)."""

    name = "fake"

    def __init__(self, *answers: dict[str, Any] | Exception) -> None:
        self.answers = list(answers)
        self.calls: list[str] = []

    def complete(self, system: str, user: str, schema: type[Any]) -> Any:
        self.calls.append(user)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return schema.model_validate(answer)

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise AssertionError("an explanation never embeds")


class Queue:
    """The job queue the API sends to: records each job, or fails like a broker that is down."""

    def __init__(self, fail: bool = False) -> None:
        self.jobs: list[tuple[str, list[str]]] = []
        self.fail = fail

    def __call__(self, name: str, args: list[str]) -> None:
        if self.fail:
            raise ConnectionError("redis is down")
        self.jobs.append((name, args))


@pytest.fixture
def queue(client: TestClient) -> Queue:
    q = Queue()
    client.app.state.enqueue = q  # type: ignore[attr-defined]
    return q


@pytest.fixture
def sessions(database_url: str) -> Iterator[Callable[[], Session]]:
    engine = create_engine(sqlalchemy_url(database_url))
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def recorded_run(client: TestClient, headers: dict[str, str], *findings: dict[str, Any], **run: str) -> str:
    fields = RUN | run
    created = client.post("/api/v1/runs", json=fields, headers=headers)
    assert created.status_code == 201, created.text
    run_id: str = created.json()["id"]
    body = "".join(json.dumps(f | {"run": fields}) + "\n" for f in findings).encode()
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers=headers | NDJSON)
    assert uploaded.status_code == 201, uploaded.text
    return run_id


def ask(client: TestClient, headers: dict[str, str], finding_id: str, **body: str) -> Any:
    return client.post(
        f"/api/v1/findings/{finding_id}/explain",
        content=json.dumps(body) if body else b"",
        headers=headers | JSON,
    )


def worker(sessions: Callable[[], Session], request_id: str, *answers: dict[str, Any] | Exception) -> str:
    return run_explain(request_id, sessions=sessions, provider=Scripted(*answers), now=NOW)


# ---------------------------------------------------------------- asking for one


def test_a_request_is_queued_once_for_the_findings_latest_run(
    client: TestClient, headers: dict[str, str], queue: Queue
) -> None:
    recorded_run(client, headers, SCA)
    latest = recorded_run(client, headers, SCA, commit="1" * 40)
    asked = ask(client, headers, SCA["id"])
    assert asked.status_code == 202, asked.text
    request = asked.json()
    assert (request["finding_id"], request["run_id"], request["status"]) == (SCA["id"], latest, "queued")
    assert request["reason"] is None and request["explanation_sha256"] is None
    assert queue.jobs == [("sentinel.explain", [request["id"]])]
    again = ask(client, headers, SCA["id"])
    assert again.status_code == 200 and again.json() == request  # still open: the same request, no new job
    assert len(queue.jobs) == 1
    assert client.get(f"/api/v1/explain-requests/{request['id']}").json() == request


def test_a_named_run(client: TestClient, headers: dict[str, str], queue: Queue) -> None:
    first = recorded_run(client, headers, SCA)
    recorded_run(client, headers, SCA, commit="1" * 40)
    asked = ask(client, headers, SCA["id"], run_id=first)
    assert asked.status_code == 202 and asked.json()["run_id"] == first


def test_an_unknown_finding_or_a_run_that_did_not_record_it(
    client: TestClient, headers: dict[str, str], queue: Queue
) -> None:
    other = recorded_run(client, headers, SECRET)
    assert ask(client, headers, SCA["id"]).status_code == 404
    recorded_run(client, headers, SCA, commit="1" * 40)
    assert ask(client, headers, SCA["id"], run_id=other).status_code == 404
    assert ask(client, headers, SCA["id"], run_id=str(uuid.uuid4())).status_code == 404
    assert ask(client, headers, "A" * 64).status_code == 422
    assert (
        client.post(
            f"/api/v1/findings/{SCA['id']}/explain", json={"run_id": other, "model": "x"}, headers=headers
        ).status_code
        == 422
    )
    assert queue.jobs[1:] == []


def test_a_secrets_finding_is_never_sent(client: TestClient, headers: dict[str, str], queue: Queue) -> None:
    recorded_run(client, headers, SECRET)
    refused = ask(client, headers, SECRET["id"])
    assert refused.status_code == 422, refused.text
    assert "never sent" in json.dumps(refused.json())
    assert queue.jobs == []


def test_asking_needs_the_token(client: TestClient, headers: dict[str, str], queue: Queue) -> None:
    recorded_run(client, headers, SCA)
    assert ask(client, {}, SCA["id"]).status_code == 401
    assert ask(client, {"Authorization": "Bearer nope"}, SCA["id"]).status_code == 401
    assert queue.jobs == []


def test_without_a_queue_nothing_is_recorded(client: TestClient, headers: dict[str, str]) -> None:
    recorded_run(client, headers, SCA)
    client.app.state.enqueue = None  # type: ignore[attr-defined]
    refused = ask(client, headers, SCA["id"])
    assert refused.status_code == 503 and "SENTINEL_REDIS_URL" in refused.json()["detail"]


def test_a_queue_that_fails_fails_the_request_and_a_new_one_can_follow(
    client: TestClient, headers: dict[str, str]
) -> None:
    recorded_run(client, headers, SCA)
    client.app.state.enqueue = Queue(fail=True)  # type: ignore[attr-defined]
    refused = ask(client, headers, SCA["id"])
    assert refused.status_code == 503, refused.text
    request_id = refused.json()["request"]["id"]
    failed = client.get(f"/api/v1/explain-requests/{request_id}").json()
    assert (failed["status"], failed["reason"]) == ("failed", "the job queue did not take the job")
    queue = Queue()
    client.app.state.enqueue = queue  # type: ignore[attr-defined]
    retried = ask(client, headers, SCA["id"])
    assert retried.status_code == 202 and retried.json()["id"] != request_id
    assert len(queue.jobs) == 1


def test_a_request_no_worker_finished_within_an_hour_is_failed_and_replaced(
    client: TestClient, headers: dict[str, str], queue: Queue, database_url: str
) -> None:
    recorded_run(client, headers, SCA)
    stale = ask(client, headers, SCA["id"]).json()
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "UPDATE explain_requests SET status = 'running', updated_at = now() - interval '61 minutes' "
            "WHERE id = %s",
            (stale["id"],),
        )
    fresh = ask(client, headers, SCA["id"])
    assert fresh.status_code == 202 and fresh.json()["id"] != stale["id"]
    old = client.get(f"/api/v1/explain-requests/{stale['id']}").json()
    assert (old["status"], old["reason"]) == ("failed", "no worker finished it within an hour")


def test_an_unknown_request_and_no_explanation(client: TestClient) -> None:
    assert client.get(f"/api/v1/explain-requests/{uuid.uuid4()}").status_code == 404
    assert client.get("/api/v1/explain-requests/not-a-uuid").status_code == 422
    assert client.get(f"/api/v1/findings/{SCA['id']}/explanation").status_code == 404


# ---------------------------------------------------------------- the worker's job


def test_the_worker_explains_and_the_explanation_is_served_byte_for_byte(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    run_id = recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    provider = Scripted(ANSWER)
    assert run_explain(request["id"], sessions=sessions, provider=provider, now=NOW) == "explained"
    assert "<finding>" in provider.calls[0] and SCA["id"] not in provider.calls[0]  # the id is never sent
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert (done["status"], done["reason"], done["run_id"]) == ("explained", None, run_id)
    served = client.get(f"/api/v1/findings/{SCA['id']}/explanation")
    assert served.status_code == 200
    assert served.headers["Content-Type"] == "application/json"
    assert hashlib.sha256(served.content).hexdigest() == done["explanation_sha256"]
    assert served.headers["ETag"] == f'"{done["explanation_sha256"]}"'
    document = json.loads(served.content)
    assert document["finding_id"] == SCA["id"] and document["summary"] == ANSWER["summary"]
    assert document["created_at"] == "2026-11-12T09:00:00Z"
    assert document["model"]["name"] == "gemma4:12b-it-qat" and document["model"]["provider"] == "fake"
    assert len(document["model"]["digest"]) == 71
    # A second job for the same request does nothing: it is claimed once.
    assert worker(sessions, request["id"], ANSWER) == "skipped"


def test_the_latest_explanation_is_served(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    first = recorded_run(client, headers, SCA)
    worker(sessions, ask(client, headers, SCA["id"], run_id=first).json()["id"], ANSWER)
    second = recorded_run(client, headers, SCA, commit="1" * 40)
    request = ask(client, headers, SCA["id"], run_id=second).json()
    worker(sessions, request["id"], ANSWER | {"summary": "The second explanation."})
    served = client.get(f"/api/v1/findings/{SCA['id']}/explanation")
    assert json.loads(served.content)["summary"] == "The second explanation."


def test_an_answer_the_guardrails_refuse_twice_is_unavailable(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    invented = ANSWER | {"references": ["https://evil.example/x"]}
    assert worker(sessions, request["id"], invented, invented) == "unavailable"
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert done["status"] == "unavailable" and "reference" in done["reason"]
    assert done["explanation_sha256"] is None
    assert client.get(f"/api/v1/findings/{SCA['id']}/explanation").status_code == 404


def test_a_provider_that_fails_is_unavailable(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    assert worker(sessions, request["id"], ConnectionError("ollama is down at 10.0.0.1")) == "unavailable"
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert done["reason"] == "the provider failed: ConnectionError"  # never the provider's own words


def test_an_unexpected_error_fails_the_request_naming_only_its_type(
    client: TestClient,
    headers: dict[str, str],
    queue: Queue,
    sessions: Callable[[], Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise KeyError("api_key=sk-live-123")

    monkeypatch.setattr("sentinel_worker.tasks.explain_finding", broken)
    assert worker(sessions, request["id"]) == "failed"
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert (done["status"], done["reason"]) == ("failed", "the worker failed: KeyError")


def test_a_request_failed_as_stale_while_the_model_ran_drops_its_outcome_and_says_so(
    client: TestClient,
    headers: dict[str, str],
    queue: Queue,
    sessions: Callable[[], Session],
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    real = tasks.explain_finding

    def slow(*args: Any, **kwargs: Any) -> Any:
        # A later ask fails the request as stale while the model is still answering.
        with psycopg.connect(database_url, autocommit=True) as connection:
            connection.execute(
                "UPDATE explain_requests SET status = 'failed', "
                "reason = 'no worker finished it within an hour' WHERE id = %s",
                (request["id"],),
            )
        return real(*args, **kwargs)

    monkeypatch.setattr(tasks, "explain_finding", slow)
    with caplog.at_level(logging.WARNING, logger="sentinel_worker.tasks"):
        assert worker(sessions, request["id"], ANSWER) == "stale"
    assert f"request {request['id']} was failed as stale while the model ran" in caplog.text
    assert "(explained) is dropped" in caplog.text
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert (done["status"], done["reason"]) == ("failed", "no worker finished it within an hour")
    assert client.get(f"/api/v1/findings/{SCA['id']}/explanation").status_code == 404


def test_a_stale_ask_that_lands_while_the_worker_records_waits_for_it(
    client: TestClient, headers: dict[str, str], queue: Queue, database_url: str
) -> None:
    """The worker holds the row while it records an outcome: a stale ask in between waits, then sees the
    request finished, leaves it as recorded and opens a new one (#111 review)."""
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    with psycopg.connect(database_url) as worker:  # the worker, in the middle of `finish`
        worker.execute(
            "UPDATE explain_requests SET status = 'running', updated_at = now() - interval '61 minutes' "
            "WHERE id = %s",
            (request["id"],),
        )
        worker.commit()
        worker.execute("SELECT 1 FROM explain_requests WHERE id = %s FOR UPDATE", (request["id"],))
        worker.execute(
            "UPDATE explain_requests SET status = 'unavailable', reason = 'the provider failed' "
            "WHERE id = %s",
            (request["id"],),
        )
        answers: list[Any] = []
        stale_ask = threading.Thread(target=lambda: answers.append(ask(client, headers, SCA["id"])))
        stale_ask.start()
        time.sleep(0.5)
        assert stale_ask.is_alive(), "the ask waits for the worker's row"
        worker.commit()
    stale_ask.join(10)
    assert answers[0].status_code == 202 and answers[0].json()["id"] != request["id"]
    old = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert (old["status"], old["reason"]) == ("unavailable", "the provider failed"), "not failed over it"


def test_a_worker_that_records_while_a_stale_ask_fails_the_request_waits_and_keeps_nothing(
    client: TestClient,
    headers: dict[str, str],
    queue: Queue,
    sessions: Callable[[], Session],
    database_url: str,
) -> None:
    """A stale ask holds the row while it fails the request: the worker's `finish` waits, then finds the
    request no longer running (#111 review)."""
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    with sessions() as session:
        assert claim(session, uuid.UUID(request["id"])) is not None
    raised: list[BaseException] = []

    def record() -> None:
        with sessions() as session:
            try:
                finish(session, uuid.UUID(request["id"]), "unavailable", reason="the provider failed")
            except NotRunning as exc:
                raised.append(exc)

    with psycopg.connect(database_url) as stale_ask:
        stale_ask.execute("SELECT 1 FROM explain_requests WHERE id = %s FOR UPDATE", (request["id"],))
        stale_ask.execute(
            "UPDATE explain_requests SET status = 'failed', "
            "reason = 'no worker finished it within an hour' WHERE id = %s",
            (request["id"],),
        )
        worker = threading.Thread(target=record)
        worker.start()
        time.sleep(0.5)
        assert worker.is_alive(), "finish waits for the stale ask's row"
        stale_ask.commit()
    worker.join(10)
    assert len(raised) == 1
    done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
    assert (done["status"], done["reason"]) == ("failed", "no worker finished it within an hour")


def test_an_explanation_that_breaks_the_contract_or_is_about_another_finding_is_not_kept(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    recorded_run(client, headers, SCA)
    document = json.loads((ROOT / "schemas/fixtures/explanation/valid/sql-injection.json").read_text("utf-8"))
    for broken, why in (
        (document, "about another finding"),
        (document | {"finding_id": SCA["id"], "summary": "two\nlines"}, "not a valid Explanation v1"),
        (b"{not json", "not a valid Explanation v1"),
    ):
        request = ask(client, headers, SCA["id"]).json()
        with sessions() as session:
            assert claim(session, uuid.UUID(request["id"])) is not None
            raw = broken if isinstance(broken, bytes) else json.dumps(broken).encode()
            finish(session, uuid.UUID(request["id"]), "explained", document=raw)
        done = client.get(f"/api/v1/explain-requests/{request['id']}").json()
        assert done["status"] == "failed" and why in done["reason"], done
    assert client.get(f"/api/v1/findings/{SCA['id']}/explanation").status_code == 404


def test_only_a_running_request_is_finished(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    with sessions() as session, pytest.raises(RuntimeError, match="not running"):
        finish(session, uuid.UUID(request["id"]), "unavailable", reason="x")
    with sessions() as session:
        assert claim(session, uuid.UUID(str(uuid.uuid4()))) is None


def test_the_database_keeps_an_explanation_as_recorded(
    client: TestClient,
    headers: dict[str, str],
    queue: Queue,
    sessions: Callable[[], Session],
    database_url: str,
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    worker(sessions, request["id"], ANSWER)
    with psycopg.connect(database_url, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException, match="kept as recorded"):
            connection.execute("UPDATE explanations SET created_at = now()")
        with pytest.raises(psycopg.errors.RaiseException, match="kept as recorded"):
            connection.execute("DELETE FROM explanations")
        other = json.dumps({"finding_id": "b" * 64}).encode()
        with pytest.raises(psycopg.errors.RaiseException, match="its own finding"):
            connection.execute(
                "INSERT INTO explanations (sha256, finding_id, run_id, request_id, document) "
                "SELECT encode(sha256(%s), 'hex'), finding_id, run_id, id, %s FROM explain_requests",
                (other, other),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute("UPDATE explain_requests SET status = 'explained', explanation_sha256 = NULL")
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute("UPDATE explain_requests SET status = 'done'")
        connection.execute("UPDATE explain_requests SET status = 'queued', explanation_sha256 = NULL")
        with pytest.raises(psycopg.errors.UniqueViolation):  # one open request per finding and run
            connection.execute(
                "INSERT INTO explain_requests (id, finding_id, run_id, status) "
                "SELECT gen_random_uuid(), finding_id, run_id, 'running' FROM explain_requests"
            )


def test_the_worker_never_sends_a_secrets_finding_even_if_a_request_got_past_the_api(
    client: TestClient, headers: dict[str, str], sessions: Callable[[], Session], database_url: str
) -> None:
    run_id = recorded_run(client, headers, SECRET)
    request_id = str(uuid.uuid4())
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "INSERT INTO explain_requests (id, finding_id, run_id, status) VALUES (%s, %s, %s, 'queued')",
            (request_id, SECRET["id"], run_id),
        )
    provider = Scripted()
    assert run_explain(request_id, sessions=sessions, provider=provider, now=NOW) == "not_sent"
    assert provider.calls == []
    done = client.get(f"/api/v1/explain-requests/{request_id}").json()
    assert done["status"] == "not_sent" and "never sent" in done["reason"]


def test_a_long_reason_is_clipped(
    client: TestClient, headers: dict[str, str], queue: Queue, sessions: Callable[[], Session]
) -> None:
    recorded_run(client, headers, SCA)
    request = ask(client, headers, SCA["id"]).json()
    with sessions() as session:
        assert claim(session, uuid.UUID(request["id"])) is not None
        finish(session, uuid.UUID(request["id"]), "unavailable", reason="x" * 2000)
    assert client.get(f"/api/v1/explain-requests/{request['id']}").json()["reason"] == "x" * 500
