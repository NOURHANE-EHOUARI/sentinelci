"""The release bundle's way into the demo cluster's registry (`make demo-release`, task A5b, ADR-0011
decision 5), with the pinned tools and two throwaway registries: the one the release was attested in, and the
cluster's.

`cosign save` writes the release with its signature and attestations; deploy/kind/demo.py reads the image's
digest from it, `cosign load`s it into the other registry with that digest, and `sentinel verify` trusts it
there, with the release key only. Both registries serve plain HTTP on 127.0.0.1, which cosign falls back to on
a loopback address with no flag; the cluster's own registry serves TLS (test_kind_demo.py). Opt-in:
SENTINEL_TOOLS_DIR (crane and cosign).
"""

import json
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.attestations import parse_image

from .conftest import BUILDER, GITHUB_ENV, REPO
from .deploy_modules import cluster, demo
from .oci import REPO_LOCK, TOOLS_DIR, attest, make_keys, needs_tools, push_image, serve_registry

pytestmark = [needs_tools, pytest.mark.integration]


def save(image: str, bundle: Path) -> Path:
    run_verified_tool(
        "cosign", ["save", "--allow-http-registry", "--dir", str(bundle), image],
        lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=bundle.parent,
    )  # fmt: skip
    return bundle


@dataclass(frozen=True)
class Saved:
    keys: dict[str, Path]
    images: dict[str, str]
    bundles: dict[str, Path]
    pins: Any  # the cluster's pins, with the throwaway registry's port


@pytest.fixture(scope="module")
def saved(crane: Path, registry: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Saved]:
    """A release attested in one registry and saved, an unsigned image saved, and the cluster's registry."""
    work = tmp_path_factory.mktemp("bundle")
    with pytest.MonkeyPatch.context() as env:
        for name, value in GITHUB_ENV.items():
            env.setenv(name, value)
        env.setenv("COSIGN_PASSWORD", "")
        keys = make_keys(work / "keys")
        good = push_image(crane, registry, work)
        (work / "good").mkdir()
        assert attest(work / "good", good, keys["release.key"]).exit_code == 0
        unsigned = push_image(crane, registry, work)
        bundles = {
            "good": save(good, work / "good-bundle"),
            "unsigned": save(unsigned, work / "unsigned-bundle"),
        }
        with serve_registry(crane, work / "home") as cluster_registry:
            port = int(cluster_registry.rsplit(":", 1)[1])
            yield Saved(keys, {"good": good, "unsigned": unsigned}, bundles,
                        replace(cluster.load_pins(), registry_port=port))  # fmt: skip


def load(saved: Saved, case: str, key: str = "release.pub") -> str:
    bundle = saved.bundles[case]
    report = demo.load_and_verify(
        bundle, demo.bundle_digest(bundle), saved.pins, key=saved.keys[key], repo=REPO, builder_id=BUILDER,
        tools_dir=Path(str(TOOLS_DIR)), run=cluster.run_command,
    )  # fmt: skip
    return str(report)


def test_the_bundle_names_the_digest_that_was_attested(saved: Saved) -> None:
    for case in ("good", "unsigned"):
        assert demo.bundle_digest(saved.bundles[case]) == parse_image(saved.images[case]).digest


def test_a_saved_release_is_loaded_with_its_digest_and_trusted_in_the_clusters_registry(
    saved: Saved,
) -> None:
    report = load(saved, "good")
    assert "TRUSTED: 16/16 checks passed" in report, report


def test_the_other_key_or_an_unsigned_image_is_not_trusted_there(saved: Saved) -> None:
    with pytest.raises(demo.NotTrusted, match="not deployed"):
        load(saved, "good", key="other.pub")
    with pytest.raises(demo.NotTrusted, match="not deployed"):
        load(saved, "unsigned")


def test_a_tampered_release_has_another_digest_and_is_not_trusted(saved: Saved) -> None:
    """`make demo-attack`'s first attack, with the pinned crane: one layer appended to the release in the
    cluster's registry gives a new digest, which nothing signed, so `sentinel verify` does not trust it."""
    load(saved, "good")
    digest = demo.bundle_digest(saved.bundles["good"])
    repository = demo.on_host(saved.pins)
    tampered = demo.tamper(f"{repository}@{digest}", saved.pins, Path(str(TOOLS_DIR)), cluster.run_command)
    assert tampered != digest

    def manifest(reference: str) -> dict[str, Any]:
        run = run_verified_tool("crane", ["manifest", reference, "--insecure"], lock=load_lock(REPO_LOCK),
                                tools_dir=Path(str(TOOLS_DIR)), cwd=Path.cwd())  # fmt: skip
        parsed: dict[str, Any] = json.loads(run.stdout)
        return parsed

    release, changed = manifest(f"{repository}@{digest}"), manifest(f"{repository}@{tampered}")
    assert changed["layers"][:-1] == release["layers"], "the release's layers, and one more"
    verify = {
        reference: demo.sentinel_verify(
            reference, key=saved.keys["release.pub"], repo=REPO, builder_id=BUILDER,
            tools_dir=Path(str(TOOLS_DIR)), run=cluster.run_command,
        )
        for reference in (f"{repository}@{tampered}", f"{repository}@{digest}")
    }  # fmt: skip
    assert verify[f"{repository}@{tampered}"].returncode == 1
    assert "signed by the key" not in verify[f"{repository}@{tampered}"].stdout.split("\n")[0]
    assert verify[f"{repository}@{digest}"].returncode == 0, "the release itself is untouched"
