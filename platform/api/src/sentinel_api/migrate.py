"""Apply the database migrations (Alembic), without an alembic.ini: the image ships them in the package.

Usage: python -m sentinel_api.migrate   (reads SENTINEL_DATABASE_URL)

With `SENTINEL_WORKER_DATABASE_PASSWORD` set, it also gives the worker's role (`sentinel_worker`, migration
0011) a login with that password. Without it, the role is left as it is: no login on a new database, the same
password on one that has it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

from sentinel_api.config import ConfigError, Settings, sqlalchemy_url

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
WORKER_ROLE = "sentinel_worker"
WORKER_PASSWORD_VARIABLE = "SENTINEL_WORKER_DATABASE_PASSWORD"  # noqa: S105  (a variable name)


def _config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    # Kept out of the ini parser: a password may contain "%", which configparser would interpolate.
    config.attributes["sqlalchemy_url"] = sqlalchemy_url(database_url)
    return config


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(_config(database_url), revision)


def downgrade(database_url: str, revision: str) -> None:
    command.downgrade(_config(database_url), revision)


def set_worker_password(database_url: str, password: str) -> None:
    """Give the worker's role a login with this password, sent as its SCRAM verifier only."""
    if not password:
        raise ValueError(f"{WORKER_PASSWORD_VARIABLE} is empty: the worker's role needs a password")
    with psycopg.connect(database_url, autocommit=True) as conn:
        # Hashed here (SCRAM, as libpq's PQencryptPasswordConn does): the clear password never reaches the
        # server, so no statement log or pg_stat_statements can hold it (#140 review).
        verifier = conn.pgconn.encrypt_password(password.encode(), WORKER_ROLE.encode(), b"scram-sha-256")
        statement = sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
            sql.Identifier(WORKER_ROLE), sql.Literal(verifier.decode())
        )
        conn.execute(statement)


def main() -> int:
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"sentinel-api migrate: {exc}", file=sys.stderr)
        return 3
    if settings.database_url is None:
        print("sentinel-api migrate: SENTINEL_DATABASE_URL is not set", file=sys.stderr)
        return 3
    upgrade(settings.database_url)
    password = os.environ.get(WORKER_PASSWORD_VARIABLE)
    if password is not None:
        try:
            set_worker_password(settings.database_url, password)
        except ValueError as exc:
            print(f"sentinel-api migrate: {exc}", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
