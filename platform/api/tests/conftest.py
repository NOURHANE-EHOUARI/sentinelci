"""Fixtures for the API tests: a real PostgreSQL (the pinned Compose image) and an app wired to it.

The database tests need Docker: they start one throwaway container per session and give each test a fresh,
migrated database. They skip without a daemon, unless SENTINEL_REQUIRE_DOCKER_DAEMON is set (CI).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import sys
import sysconfig
import time
import uuid
from collections.abc import Iterator
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType


def _stdlib_platform() -> ModuleType:
    """The standard library's `platform` module, loaded from its file.

    In importlib import mode, pytest imports the parents of a test module as modules, and it re-imports one
    that has no `__path__` (_pytest/pathlib.py, `need_reimport`). While it collects platform/api/tests, this
    repository's platform/ directory therefore replaces the standard `platform` in sys.modules, and
    SQLAlchemy, which reads it at import time, fails. Put the standard module back before importing them.
    """
    spec = spec_from_file_location("platform", Path(sysconfig.get_path("stdlib")) / "platform.py")
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STDLIB_PLATFORM = _stdlib_platform()
sys.modules["platform"] = STDLIB_PLATFORM


def pytest_collection_finish() -> None:
    # Collecting later test modules under platform/ swapped it again: restore it before any test runs.
    sys.modules["platform"] = STDLIB_PLATFORM


import psycopg  # noqa: E402  (after the standard platform module is back)
import pytest  # noqa: E402
import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sentinel_api.config import Settings  # noqa: E402
from sentinel_api.main import create_app  # noqa: E402
from sentinel_api.migrate import upgrade  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "deploy" / "compose" / "compose.yaml"
TOKEN = "test-token-" + "x" * 32


def postgres_image() -> str:
    """The image Compose runs, so the tests and `make up` use the same PostgreSQL and pgvector."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    image: str = services["postgres"]["image"]
    return image


def _docker_problem(docker: str | None) -> str | None:
    if docker is None:
        return "docker is not installed"
    try:
        if subprocess.run([docker, "info"], capture_output=True, timeout=30, check=False).returncode != 0:
            return "no Docker daemon answers"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker did not answer: {exc}"
    return None


def _wait_for(url: str, deadline: float) -> None:
    while True:
        try:
            with psycopg.connect(url, connect_timeout=2) as conn:
                conn.execute("SELECT 1")
            return
        except psycopg.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


@pytest.fixture(scope="session")
def postgres_server() -> Iterator[str]:
    """Base URL (without a database name) of a PostgreSQL server that lives for the test session."""
    docker = shutil.which("docker")
    problem = _docker_problem(docker)
    if problem is not None:
        if os.environ.get("SENTINEL_REQUIRE_DOCKER_DAEMON"):
            pytest.fail(f"SENTINEL_REQUIRE_DOCKER_DAEMON is set but {problem}")
        pytest.skip(problem)
    assert docker is not None
    name = f"sentinel-pgtest-{uuid.uuid4().hex}"
    password = secrets.token_urlsafe(16)
    subprocess.run(
        [docker, "run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::5432",
         "--tmpfs", "/var/lib/postgresql", "--env", "POSTGRES_USER=sentinel",
         "--env", "POSTGRES_DB=sentinel", "--env", f"POSTGRES_PASSWORD={password}", postgres_image()],
        capture_output=True, timeout=600, check=True,
    )  # fmt: skip
    try:
        port = (
            subprocess.run(
                [docker, "port", name, "5432/tcp"], capture_output=True, text=True, timeout=30, check=True
            )
            .stdout.split("\n")[0]
            .rsplit(":", 1)[1]
        )
        base = f"postgresql://sentinel:{password}@127.0.0.1:{port}"
        _wait_for(f"{base}/sentinel", time.monotonic() + 120)
        yield base
    finally:
        subprocess.run([docker, "rm", "--force", name], capture_output=True, timeout=60, check=False)


@pytest.fixture
def database_url(postgres_server: str) -> str:
    """A fresh database for one test, migrated to the latest schema."""
    name = f"t_{uuid.uuid4().hex}"
    with psycopg.connect(f"{postgres_server}/sentinel", autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    url = f"{postgres_server}/{name}"
    upgrade(url)
    return url


@pytest.fixture
def client(database_url: str) -> Iterator[TestClient]:
    settings = Settings(
        database_url=database_url,
        token_sha256=frozenset({hashlib.sha256(TOKEN.encode()).hexdigest()}),
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def headers() -> dict[str, str]:
    """The headers of a client holding a valid ingestion token."""
    return {"Authorization": f"Bearer {TOKEN}"}
