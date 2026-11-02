"""Settings from the environment, and the migration entry point (no database needed)."""

from __future__ import annotations

import hashlib

import pytest

from sentinel_api import migrate
from sentinel_api.config import DEFAULT_MAX_UPLOAD_BYTES, ConfigError, Settings

GOOD = hashlib.sha256(b"token").hexdigest()
OTHER = hashlib.sha256(b"other").hexdigest()


def test_hashes_and_limits_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_API_TOKEN_SHA256", f" {GOOD} ,{OTHER},, ")
    monkeypatch.setenv("SENTINEL_API_MAX_UPLOAD_BYTES", "1024")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql://u:p@h/db")
    settings = Settings.from_env()
    assert settings.token_sha256 == frozenset({GOOD, OTHER})
    assert (settings.max_upload_bytes, settings.database_url) == (1024, "postgresql://u:p@h/db")


def test_defaults_refuse_every_write(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SENTINEL_API_TOKEN_SHA256", "SENTINEL_API_MAX_UPLOAD_BYTES", "SENTINEL_DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.from_env()
    assert (settings.token_sha256, settings.database_url) == (frozenset(), None)
    assert settings.max_upload_bytes == DEFAULT_MAX_UPLOAD_BYTES


@pytest.mark.parametrize(
    ("value", "position"),
    [
        ("Zq3x9VbN-a-pasted-token-not-its-hash_0123456789", 1),
        (f"{GOOD},{GOOD.upper()}", 2),
        (f"{GOOD},abc", 2),
    ],
    ids=["pasted-token", "uppercase", "short"],
)
def test_a_bad_hash_is_reported_by_position_never_by_value(
    monkeypatch: pytest.MonkeyPatch, value: str, position: int
) -> None:
    """#38 review: the likeliest mistake is pasting the token itself; none of it may reach the logs."""
    monkeypatch.setenv("SENTINEL_API_TOKEN_SHA256", value)
    with pytest.raises(ConfigError) as caught:
        Settings.from_env()
    message = str(caught.value)
    assert f"entry {position}" in message
    bad = value.split(",")[position - 1]
    assert not any(bad[i : i + 4] in message for i in range(len(bad) - 3)), message


@pytest.mark.parametrize("value", ["12k", "-1", "0x10"])
def test_a_bad_upload_limit_is_refused(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("SENTINEL_API_MAX_UPLOAD_BYTES", value)
    with pytest.raises(ConfigError):
        Settings.from_env()


def test_migrate_refuses_to_run_without_a_usable_configuration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SENTINEL_DATABASE_URL", raising=False)
    monkeypatch.delenv("SENTINEL_API_TOKEN_SHA256", raising=False)
    assert migrate.main() == 3
    assert "SENTINEL_DATABASE_URL is not set" in capsys.readouterr().err
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql://u:p@h/db")
    monkeypatch.setenv("SENTINEL_API_TOKEN_SHA256", "not-a-hash")
    assert migrate.main() == 3
    assert "not-a-hash" not in capsys.readouterr().err
