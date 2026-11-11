"""A throwaway OCI registry, release inputs and images for the registry-mode and admission tests (A4d, A5).

Everything runs with the pinned tools from SENTINEL_TOOLS_DIR (crane, cosign): the registry is crane's
`registry serve`, in memory on 127.0.0.1, gone when the test module ends; key pairs are made per test.
"""

import io
import os
import socket
import subprocess
import tarfile
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from sentinelci.cli import app
from sentinelci.scanners.installer import verify_tools
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.attestations import KINDS, parse_image, release_predicates
from sentinelci.supplychain.cosign import Registry, Signer

from .conftest import ROOT, decision_bytes, findings_bytes, sbom_bytes

REPO_LOCK = ROOT / "tools.lock.toml"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
needs_tools = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@pytest.fixture(scope="module")
def crane() -> Path:
    (entry,) = verify_tools(load_lock(REPO_LOCK), Path(str(TOOLS_DIR)), only=["crane"]).entries
    return entry.path


@pytest.fixture(scope="module")
def registry(crane: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A throwaway OCI registry on 127.0.0.1, in memory: gone when the module's tests end."""
    port = free_port()
    server = subprocess.Popen(
        [str(crane), "registry", "serve", "--address", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path_factory.mktemp("crane-home"))},
    )
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/v2/", timeout=1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("the test registry did not start")
        yield f"127.0.0.1:{port}"
    finally:
        server.terminate()
        server.wait(timeout=10)


def layer_tar(content: bytes) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        info = tarfile.TarInfo("app/main.py")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return data.getvalue()


def push_image(crane: Path, registry: str, tmp_path: Path, name: str = "demo-shop/shop-api") -> str:
    """A one-layer image pushed by digest; its content is unique to the test, so is its digest."""
    layer = tmp_path / f"layer-{len(list(tmp_path.glob('layer-*')))}.tar"
    layer.write_bytes(layer_tar(f"print({str(layer)!r})\n".encode()))
    run = run_verified_tool(
        "crane",
        ["append", "--new_layer", str(layer), "--new_tag", f"{registry}/{name}:candidate", "--insecure"],
        lock=load_lock(REPO_LOCK),
        tools_dir=Path(str(TOOLS_DIR)),
        cwd=tmp_path,
    )
    reference = run.stdout.strip()
    assert parse_image(reference).name == f"{registry}/{name}", reference
    return reference


def make_keys(directory: Path) -> dict[str, Path]:
    """Two key pairs made by the pinned Cosign, for one test or module only: never committed, never reused."""
    directory.mkdir(parents=True)
    for prefix in ("release", "other"):
        run_verified_tool(
            "cosign", ["generate-key-pair", "--output-key-prefix", prefix], lock=load_lock(REPO_LOCK),
            tools_dir=Path(str(TOOLS_DIR)), cwd=directory, extra_env={"COSIGN_PASSWORD": ""},
        )  # fmt: skip
    return {name: directory / name for name in ("release.key", "release.pub", "other.key", "other.pub")}


@pytest.fixture
def keys(tmp_path: Path) -> dict[str, Path]:
    return make_keys(tmp_path / "keys")


def release_files(tmp_path: Path, image: str, **changes: Any) -> dict[str, Path]:
    files = {
        "decision": decision_bytes(subject__image_digest=parse_image(image).digest, **changes),
        "findings": findings_bytes(),
        "sbom": sbom_bytes(),
    }
    paths = {name: tmp_path / f"{name}.json" for name in files}
    for name, data in files.items():
        paths[name].write_bytes(data)
    return paths


def attest(tmp_path: Path, image: str, key: Path, *extra: str, **changes: Any) -> Result:
    release = release_files(tmp_path, image, **changes)
    return CliRunner().invoke(
        app,
        [
            "attest", image, "--decision", str(release["decision"]), "--findings", str(release["findings"]),
            "--sbom", str(release["sbom"]), "--key", str(key), "--out", str(tmp_path / "evidence"),
            "--push", "--registry-http", "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR), *extra,
        ],
    )  # fmt: skip


def attach(image: str, key: Path, predicates: dict[str, Any], *, sign: bool = True) -> None:
    """Sign and attach with the release key directly, bypassing the checks `sentinel attest` makes: what an
    insider holding the key, or a buggy release job, could put in the registry."""
    signer = Signer(str(key), load_lock(REPO_LOCK), Path(str(TOOLS_DIR)))
    target, registry = parse_image(image), Registry(allow_http=True)
    if sign:
        signer.sign_image(target, registry, os.environ)
    for kind, predicate in predicates.items():
        signer.attest_image(target, KINDS[kind], predicate, registry, os.environ)


def predicates(tmp_path: Path, image: str) -> dict[str, Any]:
    release = release_files(tmp_path, image)
    return release_predicates(
        parse_image(image),
        decision_data=release["decision"].read_bytes(),
        findings_data=release["findings"].read_bytes(),
        sbom_data=release["sbom"].read_bytes(),
        env=os.environ,
    )
