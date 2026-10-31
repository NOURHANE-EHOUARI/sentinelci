"""Security invariants of the local platform (deploy/compose, SPEC §4.4).

The rendered configuration comes from `docker compose config`, so interpolation, profiles and the
`x-hardening` anchor are checked as Compose itself resolves them. No container is started and no Docker
daemon is needed. Tests skip without the Docker CLI, unless SENTINEL_REQUIRE_DOCKER is set (CI).
"""

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = ROOT / "deploy" / "compose"
COMPOSE_FILE = COMPOSE_DIR / "compose.yaml"
PROFILES = "ai,observability"
PINNED_IMAGE = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$")


def _load_make_env() -> ModuleType:
    spec = importlib.util.spec_from_file_location("make_env", COMPOSE_DIR / "make_env.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAKE_ENV = _load_make_env()
# Recognizable stand-ins: any credential in the rendered config must be one of these, i.e. come from .env.
DUMMY_ENV = {name: f"dummy-{name.lower()}" for name in sorted(MAKE_ENV.COMPOSE_VARIABLES)}


def _render(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    if docker is None:
        if os.environ.get("SENTINEL_REQUIRE_DOCKER"):
            pytest.fail("SENTINEL_REQUIRE_DOCKER is set but the docker CLI was not found")
        pytest.skip("docker CLI not installed")
    clean = {
        k: v
        for k, v in os.environ.items()
        if k not in MAKE_ENV.VARIABLES and k not in MAKE_ENV.DERIVED and not k.startswith("COMPOSE_")
    }
    # --env-file /dev/null: never read the developer's real deploy/compose/.env in tests.
    # Fixed arguments, docker resolved from PATH (S603 is ignored for tests in pyproject.toml).
    return subprocess.run(
        [docker, "compose", "-f", str(COMPOSE_FILE), "--env-file", os.devnull, "config", "--format", "json"],
        env={**clean, **env, "COMPOSE_PROFILES": PROFILES},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.fixture(scope="module")
def services() -> dict[str, Any]:
    result = _render(DUMMY_ENV)
    assert result.returncode == 0, result.stderr
    rendered: dict[str, Any] = json.loads(result.stdout)["services"]
    return rendered


def test_all_planned_services_are_defined(services: dict[str, Any]) -> None:
    assert set(services) == {"postgres", "redis", "seaweedfs", "api", "ollama", "prometheus", "grafana"}


def test_every_image_is_pinned_by_tag_and_digest(services: dict[str, Any]) -> None:
    for name, service in services.items():
        if "build" in service:
            continue
        assert PINNED_IMAGE.match(service["image"]), f"{name}: {service['image']} is not tag@sha256-pinned"
        assert ":latest@" not in service["image"], name


def test_dockerfile_base_images_are_pinned_by_digest() -> None:
    dockerfile = (ROOT / "platform" / "api" / "Dockerfile").read_text(encoding="utf-8")
    bases = re.findall(r"^FROM\s+(\S+)", dockerfile, flags=re.MULTILINE)
    assert bases
    for base in bases:
        assert PINNED_IMAGE.match(base), f"{base} is not tag@sha256-pinned"


def test_ports_are_published_on_localhost_only(services: dict[str, Any]) -> None:
    for name, service in services.items():
        for port in service.get("ports", []):
            assert port.get("host_ip") == "127.0.0.1", f"{name}: {port} is reachable from the network"


def test_every_service_is_hardened_and_health_checked(services: dict[str, Any]) -> None:
    for name, service in services.items():
        assert "no-new-privileges:true" in service.get("security_opt", []), name
        assert service.get("healthcheck", {}).get("test"), f"{name}: no healthcheck"
        assert not service.get("privileged"), name
        assert service.get("network_mode") != "host", name
        mounts = " ".join(str(v.get("source", "")) for v in service.get("volumes", []))
        assert "docker.sock" not in mounts, f"{name}: mounts the Docker socket"


def test_credentials_only_come_from_the_env_file(services: dict[str, Any]) -> None:
    secret_name = re.compile(r"PASSWORD|SECRET|_KEY|_URL$")
    for name, service in services.items():
        for var, value in (service.get("environment") or {}).items():
            if not secret_name.search(var) or var == "SENTINEL_S3_ENDPOINT":
                continue
            assert any(dummy in str(value) for dummy in DUMMY_ENV.values()), f"{name}.{var} is hard-coded"


def test_every_credential_reference_fails_when_unset() -> None:
    # `${VAR:-default}` or a bare `${VAR}` in any one place would start a service with a guessable password.
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    for name in sorted(MAKE_ENV.COMPOSE_VARIABLES):
        references = re.findall(r"\$\{" + name + r"([^}]*)\}", text)
        assert references, f"{name} is never used"
        for suffix in references:
            assert suffix.startswith(":?"), f"${{{name}{suffix}}} does not fail when {name} is unset"


@pytest.mark.parametrize("missing", sorted(DUMMY_ENV))
def test_missing_credential_stops_compose_instead_of_using_a_default(missing: str) -> None:
    env = {k: v for k, v in DUMMY_ENV.items() if k != missing}
    result = _render(env)
    assert result.returncode != 0
    assert missing in result.stderr


def test_seaweedfs_exposes_only_the_authenticated_s3_gateway(services: dict[str, Any]) -> None:
    command = services["seaweedfs"]["command"]
    for flag in ("-ip.bind=127.0.0.1", "-s3.ip.bind=0.0.0.0", "-s3.port.iceberg=0", "-s3.port.lance=0"):
        assert flag in command, flag


def test_api_runs_unprivileged_on_a_read_only_root(services: dict[str, Any]) -> None:
    api = services["api"]
    assert api.get("read_only") is True, "api: root filesystem must be read-only"
    dockerfile = (ROOT / "platform" / "api" / "Dockerfile").read_text(encoding="utf-8")
    users = re.findall(r"^USER\s+(\S+)", dockerfile, flags=re.MULTILINE)
    assert users, "the API image must set a USER"
    assert users[-1] not in {"root", "0", "0:0"}, "the API image must end with a non-root USER"


@pytest.mark.parametrize("name", ["api", "prometheus", "grafana"])
def test_capabilities_are_dropped(services: dict[str, Any], name: str) -> None:
    assert services[name].get("cap_drop") == ["ALL"], name


def test_grafana_has_no_anonymous_access_and_no_sign_up(services: dict[str, Any]) -> None:
    env = services["grafana"]["environment"]
    assert env.get("GF_AUTH_ANONYMOUS_ENABLED") == "false"
    assert env.get("GF_USERS_ALLOW_SIGN_UP") == "false"


# ---------------------------------------------------------------- make_env.py


def test_make_env_writes_every_variable_owner_only(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    assert MAKE_ENV.write_env(target) is True
    lines = target.read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in lines if not line.startswith("#"))
    assert set(values) == set(MAKE_ENV.VARIABLES) | set(MAKE_ENV.DERIVED)
    for value in values.values():
        assert re.fullmatch(r"[A-Za-z0-9_-]{16,}", value), value
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_make_env_never_overwrites_existing_credentials(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    complete = "".join(f"{name}=keep-{name.lower()}\n" for name in [*MAKE_ENV.VARIABLES, *MAKE_ENV.DERIVED])
    target.write_text(complete, encoding="utf-8")
    assert MAKE_ENV.write_env(target) is False
    assert target.read_text(encoding="utf-8") == complete


def test_make_env_adds_new_variables_to_an_older_file_without_rotating_any(tmp_path: Path) -> None:
    """A .env from before B1 has no API token: `make up` must not stop, and running services keep theirs."""
    target = tmp_path / ".env"
    target.write_text(
        "# old\nPOSTGRES_PASSWORD=keep-me\nSENTINEL_API_TOKEN=old-token-0123456789\n", encoding="utf-8"
    )
    assert MAKE_ENV.write_env(target) is True
    text = target.read_text(encoding="utf-8")
    assert text.startswith("# old\nPOSTGRES_PASSWORD=keep-me\nSENTINEL_API_TOKEN=old-token-0123456789\n")
    values = dict(
        line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("#")
    )
    assert set(values) == set(MAKE_ENV.VARIABLES) | set(MAKE_ENV.DERIVED)
    assert values["POSTGRES_PASSWORD"] == "keep-me"  # noqa: S105  (a test value)
    assert values["SENTINEL_API_TOKEN_SHA256"] == hashlib.sha256(b"old-token-0123456789").hexdigest()
    assert MAKE_ENV.write_env(target) is False, "a complete file is left alone"


def test_make_env_generates_fresh_values(tmp_path: Path) -> None:
    MAKE_ENV.write_env(tmp_path / "a")
    MAKE_ENV.write_env(tmp_path / "b")
    assert (tmp_path / "a").read_text(encoding="utf-8") != (tmp_path / "b").read_text(encoding="utf-8")


def test_make_env_writes_the_api_token_with_its_hash(tmp_path: Path) -> None:
    """Clients send SENTINEL_API_TOKEN; the API only ever receives its SHA-256 (B1)."""
    target = tmp_path / ".env"
    MAKE_ENV.write_env(target)
    values = dict(
        line.split("=", 1) for line in target.read_text(encoding="utf-8").splitlines() if "=" in line
    )
    token = values["SENTINEL_API_TOKEN"]
    assert len(token) >= 32
    assert values["SENTINEL_API_TOKEN_SHA256"] == hashlib.sha256(token.encode()).hexdigest()


def test_the_api_receives_the_token_hash_never_the_token(services: dict[str, Any]) -> None:
    environment = services["api"]["environment"]
    assert environment["SENTINEL_API_TOKEN_SHA256"] == DUMMY_ENV["SENTINEL_API_TOKEN_SHA256"]
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    for name in MAKE_ENV.CLIENT_ONLY:
        assert not re.search(r"\$\{" + name + r"\b(?!_)", text), f"{name} must not reach any container"
