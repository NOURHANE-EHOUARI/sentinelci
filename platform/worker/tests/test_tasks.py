"""The worker's Celery app and its `sentinel.explain` job (B5c). The job's database flow is tested against a
real PostgreSQL in platform/api/tests/test_explanations.py."""

from __future__ import annotations

from typing import Any

import pytest

from sentinel_worker import tasks


def test_only_json_crosses_the_queue_and_jobs_run_one_at_a_time() -> None:
    conf = tasks.app.conf
    assert conf.accept_content == ["json"] and conf.task_serializer == "json"
    assert conf.task_acks_late is True and conf.worker_prefetch_multiplier == 1
    assert conf.task_ignore_result is True


def test_the_job_is_registered_under_the_name_the_api_sends() -> None:
    from sentinel_api.explanations import TASK

    assert TASK == "sentinel.explain" and tasks.explain.name == TASK
    assert tasks.app.tasks[TASK].name == TASK and tasks.app.tasks[TASK].run is tasks.explain.run


def test_the_job_explains_with_the_pinned_model_and_the_configured_ollama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def run(request_id: str, **kwargs: Any) -> str:
        seen.update(kwargs, request_id=request_id)
        return "explained"

    monkeypatch.setattr(tasks, "run_explain", run)
    tasks._sessions.cache_clear()
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql://u:p@127.0.0.1:1/db")
    monkeypatch.setenv("SENTINEL_OLLAMA_URL", "http://ollama:11434")
    assert tasks.explain("6f1c1e1e-0000-4000-8000-000000000001") == "explained"
    assert seen["request_id"] == "6f1c1e1e-0000-4000-8000-000000000001"
    assert seen["provider"].url == "http://ollama:11434"
    assert seen["now"].tzinfo is not None
    assert tasks.PINNED.name == "gemma4:12b-it-qat" and tasks.PINNED.digest.startswith("sha256:")


def test_without_a_database_the_job_fails_saying_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    tasks._sessions.cache_clear()
    with pytest.raises(RuntimeError, match="SENTINEL_DATABASE_URL"):
        tasks.explain("6f1c1e1e-0000-4000-8000-000000000001")
