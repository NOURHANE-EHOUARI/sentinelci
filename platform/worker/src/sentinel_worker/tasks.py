"""The worker's jobs (Celery over Redis, SPEC section 11): explanations of findings (task B5c).

`celery -A sentinel_worker.tasks worker --concurrency 1` runs them. A job carries only the request's id, as
JSON (pickle is never accepted, so a message on the queue cannot run code here). The worker claims the request
in the database (a job delivered twice runs once), asks the pinned model through `sentinel_ai.explain`, and
records the outcome with `sentinel_api.explanations.finish`, which keeps only a valid explanation about the
request's own finding. Advisory: nothing here reads or changes a verdict.

Settings: `SENTINEL_REDIS_URL` (the queue), `SENTINEL_DATABASE_URL`, `SENTINEL_OLLAMA_URL` (the model).
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cache

from celery import Celery  # type: ignore[import-untyped]
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel_ai.explain import explain_finding
from sentinel_ai.guardrails import ModelInfo
from sentinel_ai.providers import LLMProvider
from sentinel_ai.providers.ollama import GENERATION, OllamaProvider
from sentinel_api.config import sqlalchemy_url
from sentinel_api.explanations import TASK, Finished, NotRunning, as_bytes, claim, finish

log = logging.getLogger(__name__)

app = Celery("sentinel-worker", broker=os.environ.get("SENTINEL_REDIS_URL"), set_as_current=False)
app.conf.update(
    task_serializer="json",
    accept_content=["json"],  # never pickle
    task_ignore_result=True,  # the outcome is recorded in the database
    task_acks_late=True,  # a job is acknowledged once done; one delivered twice is claimed once
    worker_prefetch_multiplier=1,  # one model call at a time per process: they take minutes on a CPU
    broker_connection_retry_on_startup=True,
)

PINNED = ModelInfo(GENERATION.name, GENERATION.digest)


def run_explain(
    request_id: str,
    *,
    sessions: Callable[[], Session],
    provider: LLMProvider,
    now: datetime,
    model: ModelInfo = PINNED,
) -> str:
    """Explain a request's finding and record the outcome; its status, "skipped" if it was not queued, or
    "stale" if a later ask failed it as stale while the model ran (its outcome is then dropped, never kept).
    An unexpected error fails the request naming only its type: its message could quote anything."""
    with sessions() as session:
        claimed = claim(session, uuid.UUID(request_id))
        if claimed is None:
            log.info("request %s is not queued: skipped", request_id)
            return "skipped"
        state: Finished
        reason: str | None = None
        document: bytes | None = None
        try:
            outcome = explain_finding(
                claimed.finding, claimed.findings, provider, model=model, created_at=now
            )
        except Exception as exc:
            log.warning("request %s failed: %s", request_id, type(exc).__name__)
            state, reason = "failed", f"the worker failed: {type(exc).__name__}"
        else:
            if outcome.status == "explained" and outcome.explanation is not None:
                state, document = "explained", as_bytes(outcome.explanation)
            else:
                state = "not_sent" if outcome.status == "not sent" else "unavailable"
                reason = outcome.reason
        try:
            return finish(session, claimed.request_id, state, reason=reason, document=document)
        except NotRunning:
            log.warning(
                "request %s was failed as stale while the model ran (no worker finished it within an hour): "
                "its outcome (%s) is dropped",
                request_id,
                state,
            )
            return "stale"


@cache
def _sessions() -> Callable[[], Session]:
    """One engine (and its connection pool) per worker process."""
    url = os.environ.get("SENTINEL_DATABASE_URL")
    if not url:
        raise RuntimeError(
            "SENTINEL_DATABASE_URL is not set: the worker records into the platform's database"
        )
    return sessionmaker(create_engine(sqlalchemy_url(url)), expire_on_commit=False)


@app.task(name=TASK)  # type: ignore[untyped-decorator]
def explain(request_id: str) -> str:
    """The `sentinel.explain` job: explain one request's finding with the pinned model (ADR-0009)."""
    return run_explain(
        request_id, sessions=_sessions(), provider=OllamaProvider.from_env(), now=datetime.now(UTC)
    )
