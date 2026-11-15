"""GT-SAST-002: the supplier ping runs a shell command built from a query parameter (app/main.py)."""

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient


def test_a_host_never_reaches_a_shell(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Either the host is refused, or it is one argument of a command run without a shell."""
    calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_run(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    host = "status.example.com; cat /etc/passwd"
    answer = client.get("/admin/ping", params={"host": host})
    if 400 <= answer.status_code < 500:
        return
    assert len(calls) == 1
    args, kwargs = calls[0]
    command = args[0] if args else kwargs.get("args")
    assert not kwargs.get("shell"), "no shell"
    assert isinstance(command, (list, tuple)) and host in command, "the host is one argument, as given"
