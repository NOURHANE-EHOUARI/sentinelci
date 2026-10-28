"""FastAPI application factory."""

from fastapi import FastAPI

from sentinelci import __version__ as engine_version


def create_app() -> FastAPI:
    """Build the API application. Routers are added by task B1 (see docs/spec/SPEC.md, section 13.3)."""
    app = FastAPI(title="SentinelCI API", version=engine_version)

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "engine_version": engine_version}

    return app


app = create_app()
