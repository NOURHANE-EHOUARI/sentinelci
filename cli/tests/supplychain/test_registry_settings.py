"""Registry mode settings without a registry: which Cosign exit codes mean "not trusted" (1) and which mean
"could not run" (3), and where plain HTTP is allowed (#44 review, nits 3 and 5)."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import sentinelci.scanners.runner as runner
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import load_lock
from sentinelci.supplychain.attestations import DECISION_TYPE, AttestationError, parse_image
from sentinelci.supplychain.cosign import Registry, Verifier, registry_for

from .conftest import IMAGE, IMAGE_HEX, ROOT

LOCK = load_lock(ROOT / "tools.lock.toml")


def _cosign_exits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: int) -> None:
    entry = SimpleNamespace(path=tmp_path / "cosign", version="3.1.4", binary_sha256="0" * 64)
    monkeypatch.setattr(runner, "verify_tools", lambda *_, **__: SimpleNamespace(entries=[entry]))

    def run(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, code, "", "cosign: some reason\n")

    monkeypatch.setattr(runner.subprocess, "run", run)


@pytest.mark.parametrize("code", [1, 10, 11, 12, 13])
def test_a_verification_that_ran_and_failed_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    _cosign_exits(monkeypatch, tmp_path, code)
    verifier, image = Verifier(tmp_path / "k.pub", LOCK, tmp_path), parse_image(IMAGE)
    assert verifier.verify_signature(image, Registry(), {}).problem
    assert verifier.verify_in_registry(image, DECISION_TYPE, Registry(), {}).problem


@pytest.mark.parametrize("code", [2, 125, -11])
def test_any_other_cosign_exit_code_could_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    _cosign_exits(monkeypatch, tmp_path, code)
    verifier, image = Verifier(tmp_path / "k.pub", LOCK, tmp_path), parse_image(IMAGE)
    with pytest.raises(ScannerError):
        verifier.verify_signature(image, Registry(), {})
    with pytest.raises(ScannerError):
        verifier.verify_in_registry(image, DECISION_TYPE, Registry(), {})


@pytest.mark.parametrize(
    "name",
    ["localhost/demo-shop/api", "localhost:5000/demo-shop/api", "127.0.0.1:5000/demo-shop/api",
     "127.8.9.1/a", "kind-registry:5000/demo-shop/api:v1"],
)  # fmt: skip
def test_plain_http_is_allowed_for_a_local_registry(name: str) -> None:
    assert registry_for(parse_image(f"{name}@sha256:{IMAGE_HEX}"), allow_http=True).flags() == [
        "--allow-http-registry"
    ]


@pytest.mark.parametrize(
    "name",
    ["registry.example.com:5000/demo-shop/api", "registry.example.com/a", "10.0.0.5:5000/a",
     "kind-registry/a", "demo-shop/api", "ghcr.io/o/r"],
)  # fmt: skip
def test_plain_http_is_refused_anywhere_else(name: str) -> None:
    """A dotted host or a non-loopback address is a real registry, and `kind-registry/a` or `demo-shop/api`
    name no registry at all (Docker Hub): credentials would cross the network in clear."""
    image = parse_image(f"{name}@sha256:{IMAGE_HEX}")
    with pytest.raises(AttestationError, match="plain HTTP"):
        registry_for(image, allow_http=True)
    assert registry_for(image, allow_http=False).flags() == []
