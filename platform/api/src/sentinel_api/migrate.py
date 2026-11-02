"""Apply the database migrations (Alembic), without an alembic.ini: the image ships them in the package.

Usage: python -m sentinel_api.migrate   (reads SENTINEL_DATABASE_URL)
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from sentinel_api.config import ConfigError, Settings, sqlalchemy_url

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
