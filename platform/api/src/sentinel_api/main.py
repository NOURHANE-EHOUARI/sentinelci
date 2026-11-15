"""FastAPI application factory."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel_api.api import router
from sentinel_api.config import Settings, sqlalchemy_url
from sentinel_api.correlations import router as correlations_router
from sentinel_api.decisions import router as decisions_router
from sentinel_api.limits import BodyLimit
from sentinel_api.metrics import router as metrics_router
from sentinel_api.releases import router as releases_router
from sentinel_api.remediations import router as remediations_router
from sentinelci import __version__ as engine_version

# The version of the API contract (schemas/openapi.yaml), not of the engine: it changes only with the API.
API_VERSION = "1.8.2"


def _json(errors: list[dict[str, Any]]) -> str:
    """A 422 body as Starlette's JSONResponse writes it (compact, no NaN), but in ASCII."""
    return json.dumps({"detail": errors}, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


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

    @app.exception_handler(RequestValidationError)
    async def unprocessable(_: Request, exc: RequestValidationError) -> Response:
        """FastAPI's own 422 body, written as ASCII JSON: it echoes the input it refused, and a lone UTF-16
        surrogate in that input cannot be encoded as UTF-8, so the default rendering failed as a 500. An
        echoed NaN or Infinity, which JSON has not, is dropped from `input` (#126 review)."""
        errors = jsonable_encoder(exc.errors())
        try:
            body = _json(errors)
        except ValueError:
            body = _json([error | {"input": None} for error in errors])
        return Response(body, status_code=422, media_type="application/json")

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "engine_version": engine_version}

    app.include_router(router)
    app.include_router(correlations_router)
    app.include_router(decisions_router)
    app.include_router(releases_router)
    app.include_router(remediations_router)
    app.include_router(metrics_router)
    return app


def app_from_env() -> FastAPI:
    """The ASGI app uvicorn serves: `uvicorn --factory sentinel_api.main:app_from_env`."""
    return create_app()
