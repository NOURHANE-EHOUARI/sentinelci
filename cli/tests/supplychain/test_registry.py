"""Registry mode (A4, ADR-0010 decision 4): `sentinel attest --push`, then `sentinel verify` without
--evidence, with the real Cosign against a real OCI registry (the pinned crane's `registry serve`, on
127.0.0.1 only).

What is attached to the image in its registry is what Kyverno reads at admission (A5), so each bad case here
changes one thing in an otherwise trusted release, as in the evidence-mode tests. Real-tool tests are opt-in:
set SENTINEL_TOOLS_DIR (crane and cosign installed there).

crane's registry has no OCI referrers API (it answers METHOD_UNKNOWN), so Cosign stores every bundle in the
`sha256-<hex>` tag index here: the referrers-API path of Cosign is not exercised by these tests.
"""

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from sentinelci.cli import app
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.attestations import KINDS, parse_image
from sentinelci.supplychain.cosign import Registry, Signer

from .conftest import BUILDER, REPO, decision_bytes
from .oci import REPO_LOCK, TOOLS_DIR, attach, attest, free_port, needs_tools, predicates, push_image

pytestmark = [needs_tools, pytest.mark.integration]


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
    image = f"127.0.0.1:{free_port()}/demo-shop/shop-api@sha256:{'b' * 64}"
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
