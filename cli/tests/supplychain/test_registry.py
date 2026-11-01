"""Registry mode (A4, ADR-0010 decision 4): `sentinel attest --push`, then `sentinel verify` without
--evidence, with the real Cosign against a real OCI registry (the pinned crane's `registry serve`, on
127.0.0.1 only).

What is attached to the image in its registry is what Kyverno reads at admission (A5), so each bad case here
changes one thing in an otherwise trusted release, as in the evidence-mode tests. Real-tool tests are opt-in:
set SENTINEL_TOOLS_DIR (crane and cosign installed there).

crane's registry has no OCI referrers API (it answers METHOD_UNKNOWN), so Cosign stores every bundle in the
`sha256-<hex>` tag index here: the referrers-API path of Cosign is not exercised by these tests.
"""

import io
import json
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

from .conftest import BUILDER, REPO, ROOT, decision_bytes, findings_bytes, sbom_bytes

REPO_LOCK = ROOT / "tools.lock.toml"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
pytestmark = [
    pytest.mark.skipif(
        not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
    ),
    pytest.mark.integration,
]


def _free_port() -> int:
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
    port = _free_port()
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


def _layer(content: bytes) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        info = tarfile.TarInfo("app/main.py")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return data.getvalue()


def push_image(crane: Path, registry: str, tmp_path: Path, name: str = "demo-shop/shop-api") -> str:
    """A one-layer image pushed by digest; its content is unique to the test, so is its digest."""
    layer = tmp_path / f"layer-{len(list(tmp_path.glob('layer-*')))}.tar"
    layer.write_bytes(_layer(f"print({str(layer)!r})\n".encode()))
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


@pytest.fixture
def keys(tmp_path: Path) -> dict[str, Path]:
    """Two key pairs made by the pinned Cosign for this test only: never committed, never reused."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    for prefix in ("release", "other"):
        run_verified_tool(
            "cosign", ["generate-key-pair", "--output-key-prefix", prefix], lock=load_lock(REPO_LOCK),
            tools_dir=Path(str(TOOLS_DIR)), cwd=keys_dir, extra_env={"COSIGN_PASSWORD": ""},
        )  # fmt: skip
    return {name: keys_dir / name for name in ("release.key", "release.pub", "other.key", "other.pub")}


def _release(tmp_path: Path, image: str, **changes: Any) -> dict[str, Path]:
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
    release = _release(tmp_path, image, **changes)
    return CliRunner().invoke(
        app,
        [
            "attest", image, "--decision", str(release["decision"]), "--findings", str(release["findings"]),
            "--sbom", str(release["sbom"]), "--key", str(key), "--out", str(tmp_path / "evidence"),
            "--push", "--registry-http", "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR), *extra,
        ],
    )  # fmt: skip


def verify(image: str, public_key: Path) -> Result:
    return CliRunner().invoke(
        app,
        [
            "verify", image, "--key", str(public_key), "--repo", REPO, "--builder-id", BUILDER,
            "--registry-http", "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR),
        ],
    )  # fmt: skip


def failures(result: Result) -> list[str]:
    return [line.split("] ", 1)[1].split(":", 2)[0] + ":" + line.split("] ", 1)[1].split(":", 2)[1]
            for line in result.output.splitlines() if line.lstrip().startswith("[FAIL]")]  # fmt: skip


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
    release = _release(tmp_path, image)
    return release_predicates(
        parse_image(image),
        decision_data=release["decision"].read_bytes(),
        findings_data=release["findings"].read_bytes(),
        sbom_data=release["sbom"].read_bytes(),
        env=os.environ,
    )


@pytest.fixture
def pushed(
    crane: Path, registry: str, tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> str:
    image = push_image(crane, registry, tmp_path)
    result = attest(tmp_path, image, keys["release.key"])
    assert result.exit_code == 0, result.output
    assert "image signed and the 4 attached in its registry" in result.output
    return image


def test_a_release_attested_with_push_is_trusted_from_its_registry(
    pushed: str, keys: dict[str, Path]
) -> None:
    result = verify(pushed, keys["release.pub"])
    assert result.exit_code == 0, result.output
    assert "TRUSTED: 16/16 checks passed" in result.output
    assert "[ok] signature: the image itself: signed by the key (1 signature(s))" in result.output


def test_the_evidence_bundles_are_written_too(pushed: str, tmp_path: Path, keys: dict[str, Path]) -> None:
    result = CliRunner().invoke(
        app,
        [
            "verify", pushed, "--key", str(keys["release.pub"]), "--repo", REPO, "--builder-id", BUILDER,
            "--evidence", str(tmp_path / "evidence"), "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR),
        ],
    )  # fmt: skip
    assert result.exit_code == 0 and "TRUSTED: 15/15 checks passed" in result.output, result.output


def test_a_re_run_of_the_attest_job_is_still_trusted(
    pushed: str, tmp_path: Path, keys: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#44 review, blocking 1: GitHub's "Re-run jobs" increments GITHUB_RUN_ATTEMPT; the run's statements must
    not change with it, or the re-run makes the release ambiguous."""
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    again = tmp_path / "again"
    again.mkdir()
    assert attest(again, pushed, keys["release.key"]).exit_code == 0
    result = verify(pushed, keys["release.pub"])
    assert result.exit_code == 0, result.output
    assert "TRUSTED: 16/16" in result.output and "signed by the key (2 signature(s))" in result.output


SECOND_DECISION = "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8da0"


def test_a_second_release_of_the_digest_is_refused_before_anything_is_signed(
    pushed: str, tmp_path: Path, keys: dict[str, Path], crane: Path
) -> None:
    """#44 review, should fix 1: two different releases of one digest are ambiguous for `sentinel verify`
    while Kyverno reads one of them. A digest has one release per registry: the second is refused."""
    again = tmp_path / "again"
    again.mkdir()
    second = attest(again, pushed, keys["release.key"], decision_id=SECOND_DECISION)
    assert second.exit_code == 3, second.output
    assert "already holds a different decision attestation" in second.output
    assert "one release per registry" in second.output and "nothing was signed" in second.output
    assert not list((again / "evidence" / "attestations").glob("*"))
    result = verify(pushed, keys["release.pub"])
    assert result.exit_code == 0 and "signed by the key (1 signature(s))" in result.output, result.output

    # The documented way out: remove the old release (the tag index, on a registry without referrers), then
    # attest again.
    image = parse_image(pushed)
    run_verified_tool(
        "crane", ["delete", f"{image.name}:sha256-{image.digest_hex}", "--insecure"],
        lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=tmp_path,
    )  # fmt: skip
    third = tmp_path / "third"
    third.mkdir()
    assert attest(third, pushed, keys["release.key"], decision_id=SECOND_DECISION).exit_code == 0
    result = verify(pushed, keys["release.pub"])
    assert result.exit_code == 0 and "TRUSTED: 16/16" in result.output, result.output


def test_an_image_never_attested_is_not_trusted(
    crane: Path, registry: str, tmp_path: Path, keys: dict[str, Path]
) -> None:
    result = verify(push_image(crane, registry, tmp_path), keys["release.pub"])
    assert result.exit_code == 1
    assert failures(result)[:5] == [
        "signature: the image itself", "signature: release decision", "signature: SBOM (CycloneDX)",
        "signature: vulnerability scan", "signature: provenance (SLSA v1)",
    ]  # fmt: skip


def test_the_wrong_key_is_not_trusted(pushed: str, keys: dict[str, Path]) -> None:
    result = verify(pushed, keys["other.pub"])
    assert result.exit_code == 1
    assert "NOT TRUSTED: 0/16 checks passed" in result.output


def test_the_same_content_in_another_repository_carries_no_attestation(
    pushed: str, registry: str, crane: Path, tmp_path: Path, keys: dict[str, Path]
) -> None:
    """Attestations live next to the image in its repository: a copy elsewhere is not a release."""
    copy = f"{registry}/demo-shop/elsewhere@{parse_image(pushed).digest}"
    run_verified_tool(
        "crane", ["copy", pushed, copy, "--insecure"], lock=load_lock(REPO_LOCK),
        tools_dir=Path(str(TOOLS_DIR)), cwd=tmp_path,
    )  # fmt: skip
    assert verify(copy, keys["release.pub"]).exit_code == 1


def test_attestations_without_an_image_signature_are_not_trusted(
    crane: Path, registry: str, tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    """Cosign 3 counts any statement the key signed about the digest as a signature (`cosign verify`, and
    Kyverno's verifyImageSignatures, both pass here): `sentinel verify` requires a `cosign sign` statement."""
    image = push_image(crane, registry, tmp_path)
    attach(image, keys["release.key"], predicates(tmp_path, image), sign=False)
    result = verify(image, keys["release.pub"])
    assert result.exit_code == 1
    assert failures(result) == ["signature: the image itself"]
    assert "NOT TRUSTED: 15/16 checks passed" in result.output


def test_a_second_different_decision_makes_the_release_ambiguous(
    pushed: str, tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    other = json.loads(decision_bytes(subject__image_digest=parse_image(pushed).digest, verdict="PASS"))
    attach(pushed, keys["release.key"], {"decision": other}, sign=False)
    result = verify(pushed, keys["release.pub"])
    assert result.exit_code == 1
    assert (
        "[FAIL] signature: release decision: 2 different attestations of this type: ambiguous"
        in result.output
    )


def test_a_block_decision_attached_with_the_key_is_not_trusted(
    crane: Path, registry: str, tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    image = push_image(crane, registry, tmp_path)
    signed = predicates(tmp_path, image)
    blocking = [{"rule": "SC-002", "effect": "BLOCK", "finding_ids": ["c" * 64], "message": "P0 finding"}]
    signed["decision"] = json.loads(
        decision_bytes(subject__image_digest=parse_image(image).digest, verdict="BLOCK", violations=blocking)
    )
    attach(image, keys["release.key"], signed)
    result = verify(image, keys["release.pub"])
    assert result.exit_code == 1
    assert failures(result) == ["decision: verdict is not BLOCK"]


def test_attestations_for_another_image_do_not_count(
    crane: Path, registry: str, tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    """A decision about image A attached to image B: Cosign checks the subject, and so do we."""
    first, second = push_image(crane, registry, tmp_path), push_image(crane, registry, tmp_path)
    signer = Signer(str(keys["release.key"]), load_lock(REPO_LOCK), Path(str(TOOLS_DIR)))
    signer.sign_image(parse_image(second), Registry(allow_http=True), os.environ)
    for kind, predicate in predicates(tmp_path, first).items():
        signer.attest_image(
            parse_image(second), KINDS[kind], predicate, Registry(allow_http=True), os.environ
        )
    result = verify(second, keys["release.pub"])
    assert result.exit_code == 1
    assert "[FAIL] decision: about this image" in result.output


def test_an_unreachable_registry_signs_nothing_and_verifies_nothing(
    tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    image = f"127.0.0.1:{_free_port()}/demo-shop/shop-api@sha256:{'b' * 64}"
    result = attest(tmp_path, image, keys["release.key"])
    assert result.exit_code == 3 and "the registry may hold part of the set (not trusted)" in result.output
    assert not list((tmp_path / "evidence" / "attestations").glob("*")), "all four or none"
    assert verify(image, keys["release.pub"]).exit_code == 1


def test_plain_http_is_refused_for_a_registry_that_is_not_local(
    tmp_path: Path, keys: dict[str, Path], github_env: dict[str, str]
) -> None:
    """#44 review, nit 3: with --registry-http, credentials (DOCKER_CONFIG) would cross in clear."""
    image = f"registry.example.com:5000/demo-shop/shop-api@sha256:{'b' * 64}"
    result = attest(tmp_path, image, keys["release.key"])
    assert (
        result.exit_code == 3 and "plain HTTP (--registry-http) is for a local registry only" in result.output
    )
    assert "nothing was signed" in result.output
    assert verify(image, keys["release.pub"]).exit_code == 3
