"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel_api.api import router
from sentinel_api.config import Settings, sqlalchemy_url
from sentinel_api.correlations import router as correlations_router
from sentinel_api.limits import BodyLimit
from sentinel_api.metrics import router as metrics_router
from sentinelci import __version__ as engine_version

# The version of the API contract (schemas/openapi.yaml), not of the engine: it changes only with the API.
API_VERSION = "1.5.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the API application (routes: docs/spec/SPEC.md, section 13.3; contract: schemas/openapi.yaml)."""
    settings = settings or Settings.from_env()
    engine = create_engine(sqlalchemy_url(settings.database_url)) if settings.database_url else None

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if engine is not None:
                engine.dispose()

    app = FastAPI(title="SentinelCI API", version=API_VERSION, lifespan=lifespan)
    # Outermost: bodies are capped before routing, parsing or authentication.
    app.add_middleware(BodyLimit, upload_limit=lambda: settings.max_upload_bytes)
    app.state.settings = settings
    app.state.sessions = sessionmaker(engine, expire_on_commit=False) if engine is not None else None

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "engine_version": engine_version}

    app.include_router(router)
    app.include_router(correlations_router)
    app.include_router(metrics_router)
    return app


def app_from_env() -> FastAPI:
    """The ASGI app uvicorn serves: `uvicorn --factory sentinel_api.main:app_from_env`."""
    return create_app()
