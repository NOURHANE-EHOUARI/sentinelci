"""GT-SAST-006: FastAPI's debug mode shows stack traces to any client (app/main.py)."""

from fastapi.testclient import TestClient

from app.main import app


def test_debug_mode_is_off() -> None:
    assert app.debug is False


def test_an_error_shows_no_stack_trace(client: TestClient) -> None:
    """A rule that divides by zero fails: the client gets no traceback, whatever the fix of the rule does."""
    answer = client.get("/discount", params={"rule": "price / 0"})
    assert "Traceback" not in answer.text and "ZeroDivisionError" not in answer.text
