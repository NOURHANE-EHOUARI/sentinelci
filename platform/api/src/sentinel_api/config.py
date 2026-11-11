"""API settings, read from the environment (deploy/compose passes them; see deploy/compose/make_env.py)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Self

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
DEFAULT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024
# What the default branch's release runs record as `ref`: the open findings are theirs (GET /metrics).
DEFAULT_REF = "refs/heads/main"
_REF = re.compile(r"refs/[^\x00-\x20\x7f]{1,240}")


class ConfigError(ValueError):
    """The environment does not describe a usable API."""


@dataclass(frozen=True)
class Settings:
    # postgresql://user:password@host:port/db. None: only /healthz and the OpenAPI document work.
    database_url: str | None
    # SHA-256 (hex) of every token allowed to write. Empty: every write is refused, never allowed.
    token_sha256: frozenset[str]
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    default_ref: str = DEFAULT_REF

    @classmethod
    def from_env(cls) -> Self:
        entries = [h.strip() for h in os.environ.get("SENTINEL_API_TOKEN_SHA256", "").split(",") if h.strip()]
        for position, entry in enumerate(entries, start=1):
            if not _SHA256_HEX.fullmatch(entry):
                # The position only: the likeliest mistake is pasting the token itself, and logs must never
                # show any part of it.
                raise ConfigError(
                    f"SENTINEL_API_TOKEN_SHA256 entry {position} is not a lowercase sha256 (64 hex digits)"
                )
        hashes = frozenset(entries)
        limit = os.environ.get("SENTINEL_API_MAX_UPLOAD_BYTES", "")
        if limit and not limit.isdigit():
            raise ConfigError("SENTINEL_API_MAX_UPLOAD_BYTES must be a number of bytes")
        default_ref = os.environ.get("SENTINEL_DEFAULT_REF", "") or DEFAULT_REF
        if not _REF.fullmatch(default_ref):
            raise ConfigError("SENTINEL_DEFAULT_REF must be a full git ref, such as refs/heads/main")
        return cls(
            database_url=os.environ.get("SENTINEL_DATABASE_URL") or None,
            token_sha256=hashes,
            max_upload_bytes=int(limit) if limit else DEFAULT_MAX_UPLOAD_BYTES,
            default_ref=default_ref,
        )


def sqlalchemy_url(database_url: str) -> str:
    """The SQLAlchemy URL for psycopg 3, from the plain postgresql:// URL Compose passes."""
    for prefix in ("postgresql+psycopg://", "postgresql://", "postgres://"):
        if database_url.startswith(prefix):
            return "postgresql+psycopg://" + database_url.removeprefix(prefix)
    raise ConfigError("SENTINEL_DATABASE_URL must be a postgresql:// URL")
