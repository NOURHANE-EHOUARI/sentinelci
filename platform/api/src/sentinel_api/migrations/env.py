"""Alembic environment: online migrations only, on the URL sentinel_api.migrate passes."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from sentinel_api.models import Base

url = context.config.attributes["sqlalchemy_url"]
engine = create_engine(url)
try:
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
