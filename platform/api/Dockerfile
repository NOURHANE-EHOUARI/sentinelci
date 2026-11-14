# SentinelCI control-plane API image (local platform, deploy/compose). Build context: repository root.
# Base images are pinned by digest; dependencies come from uv.lock only (--locked).

FROM ghcr.io/astral-sh/uv:0.11.33@sha256:77280f2f771df71f90786c314fe1bbc1e023feac652969bbf139c280babf2eb7 AS uv

FROM python:3.12.16-slim@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
COPY cli cli
COPY platform platform
COPY ai ai
RUN uv sync --locked --no-dev --no-editable --package sentinel-api

FROM python:3.12.16-slim@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sentinel
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000
# Migrations first (idempotent), then the API. A failed migration stops the container instead of serving.
CMD ["sh", "-c", "python -m sentinel_api.migrate && exec uvicorn --factory sentinel_api.main:app_from_env --host 0.0.0.0 --port 8000"]
