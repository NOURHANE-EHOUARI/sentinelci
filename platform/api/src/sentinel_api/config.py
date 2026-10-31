"""API settings, read from the environment (deploy/compose passes them; see deploy/compose/make_env.py)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Self

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
DEFAULT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024


class ConfigError(ValueError):
    """The environment does not describe a usable API."""


@dataclass(frozen=True)
class Settings:
    # postgresql://user:password@host:port/db. None: only /healthz and the OpenAPI document work.
    database_url: str | None
    # SHA-256 (hex) of every token allowed to write. Empty: every write is refused, never allowed.
    token_sha256: frozenset[str]
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES

    @classmethod
    def from_env(cls) -> Self:
        hashes = frozenset(
            h.strip() for h in os.environ.get("SENTINEL_API_TOKEN_SHA256", "").split(",") if h.strip()
        )
        if bad := sorted(h for h in hashes if not _SHA256_HEX.fullmatch(h)):
            raise ConfigError(
                f"SENTINEL_API_TOKEN_SHA256 holds a value that is not a lowercase sha256: {bad[0][:12]}…"
            )
        limit = os.environ.get("SENTINEL_API_MAX_UPLOAD_BYTES", "")
        if limit and not limit.isdigit():
            raise ConfigError("SENTINEL_API_MAX_UPLOAD_BYTES must be a number of bytes")
        return cls(
            database_url=os.environ.get("SENTINEL_DATABASE_URL") or None,
            token_sha256=hashes,
            max_upload_bytes=int(limit) if limit else DEFAULT_MAX_UPLOAD_BYTES,
        )


def sqlalchemy_url(database_url: str) -> str:
    """The SQLAlchemy URL for psycopg 3, from the plain postgresql:// URL Compose passes."""
    for prefix in ("postgresql+psycopg://", "postgresql://", "postgres://"):
        if database_url.startswith(prefix):
            return "postgresql+psycopg://" + database_url.removeprefix(prefix)
    raise ConfigError("SENTINEL_DATABASE_URL must be a postgresql:// URL")
