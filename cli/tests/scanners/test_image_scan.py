"""`sentinel scan image` (task A1, the image adapter): the pinned Syft's SBOM of an image's OCI layout,
matched by the pinned Grype, as CONTAINER findings; every failure recorded per tool for the gate (SC-010).

Real-tool tests are opt-in: SENTINEL_TOOLS_DIR (Syft and Grype installed there), and SENTINEL_GRYPE_DB_DIR (a
directory `sentinel tools grype-db` filled) for the end-to-end match. The images are OCI layout archives built
here byte by byte, as `docker buildx build --output type=oci` writes them: no registry, no Docker daemon.
"""

import gzip
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner, Result

from sentinelci.cli import app

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / "tools.lock.toml"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
REF = "kind-registry:5000/demo-shop/shop-api"
PYYAML_METADATA = "usr/local/lib/python3.12/site-packages/PyYAML-5.3.1.dist-info/METADATA"
pytestmark = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


def _layer(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(content), 0, 0o644
            tar.addfile(info, io.BytesIO(content))
    return raw.getvalue()


def oci_archive(path: Path, files: dict[str, bytes]) -> str:
    """Write a one-layer OCI layout archive holding `files`; return its manifest digest."""
    layer_tar = _layer(files)
    layer = gzip.compress(layer_tar, mtime=0)
    config = json.dumps({
        "architecture": "amd64", "os": "linux", "config": {"User": "10001:10001"},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer_tar).hexdigest()]},
    }, sort_keys=True).encode()  # fmt: skip

    def descriptor(media_type: str, data: bytes) -> dict[str, Any]:
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": descriptor("application/vnd.oci.image.config.v1+json", config),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer)],
    }, sort_keys=True).encode()  # fmt: skip
    index = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [descriptor("application/vnd.oci.image.manifest.v1+json", manifest)],
    }).encode()  # fmt: skip
    with tarfile.open(path, "w") as archive:
        for name, data in [("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'), ("index.json", index)] + [
            (f"blobs/sha256/{hashlib.sha256(blob).hexdigest()}", blob) for blob in (config, layer, manifest)
        ]:
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            archive.addfile(info, io.BytesIO(data))
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def shop_api_image(path: Path) -> str:
    """An image holding the seeded pyyaml 5.3.1 (GT-SCA-001's package) and a Debian package database."""
    return oci_archive(path, {
        "etc/os-release": b'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n',
        "var/lib/dpkg/status": b"Package: openssl\nStatus: install ok installed\nArchitecture: amd64\n"
                               b"Version: 3.0.11-1\nDescription: TLS toolkit\n\n",
        PYYAML_METADATA: b"Metadata-Version: 2.1\nName: PyYAML\nVersion: 5.3.1\n",
    })  # fmt: skip


def scan(archive: Path, digest: str, tmp_path: Path, db_dir: Path, *extra: str) -> Result:
    return CliRunner().invoke(app, [
        "scan", "image", str(archive), "--image-digest", digest, "--image-ref", REF,
        "--out", str(tmp_path / "out" / "container.ndjson"), "--repo", "NOURHANE-EHOUARI/sentinelci",
        "--commit", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "--context", "release",
        "--db-dir", str(db_dir), "--lock", str(LOCK), "--tools-dir", str(TOOLS_DIR),
        "--tool-status-out", str(tmp_path / "out" / "status.json"), *extra,
    ])  # fmt: skip


def status_of(tmp_path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((tmp_path / "out" / "status.json").read_text())
    schema = json.loads((ROOT / "schemas" / "tool-status.v1.json").read_text())
    assert not [error.message for error in Draft202012Validator(schema).iter_errors(document)]
    tools: dict[str, Any] = document["tools"]
    return tools


# ---------------------------------------------------------------- failures, recorded per tool


def test_without_a_database_syft_is_ok_and_grype_failed(tmp_path: Path) -> None:
    archive = tmp_path / "image.oci.tar"
    digest = shop_api_image(archive)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "container.ndjson").write_text("stale")
    result = scan(archive, digest, tmp_path, tmp_path / "no-database")
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output, result.output
    assert not (tmp_path / "out" / "container.ndjson").exists(), "a failed scan leaves no findings file"
    tools = status_of(tmp_path)
    assert tools["syft"]["status"] == "ok" and tools["syft"]["version"] == "1.55.0"
    assert tools["grype"]["status"] == "failed" and "does not exist" in tools["grype"]["detail"]


def test_an_archive_without_that_image_fails_syft_and_grype_never_runs(tmp_path: Path) -> None:
    archive = tmp_path / "image.oci.tar"
    shop_api_image(archive)
    result = scan(archive, "sha256:" + "0" * 64, tmp_path, tmp_path)
    assert result.exit_code == 3, result.output
    tools = status_of(tmp_path)
    assert tools["syft"]["status"] == "failed"
    assert tools["grype"] == {
        "version": "0.121.0", "status": "not_run",
        "detail": "not started: Syft produced no SBOM",
    }  # fmt: skip


def test_a_directory_is_not_an_image_archive(tmp_path: Path) -> None:
    result = scan(tmp_path, "sha256:" + "0" * 64, tmp_path, tmp_path)
    assert result.exit_code == 3 and "is not a file" in result.output
    assert status_of(tmp_path)["syft"]["status"] == "failed"


# ---------------------------------------------------------------- end to end, with a database


@pytest.mark.skipif(not GRYPE_DB, reason="set SENTINEL_GRYPE_DB_DIR to a `sentinel tools grype-db` directory")
def test_the_seeded_pyyaml_in_an_image_is_a_container_finding_of_its_layer(
    tmp_path: Path, finding_validator: Draft202012Validator
) -> None:
    archive = tmp_path / "image.oci.tar"
    digest = shop_api_image(archive)
    result = scan(archive, digest, tmp_path, Path(str(GRYPE_DB)), "--allow-stale-db")
    assert result.exit_code == 0, result.output
    findings = [json.loads(line) for line in (tmp_path / "out" / "container.ndjson").read_text().splitlines()]
    assert findings and {f["category"] for f in findings} == {"CONTAINER"}
    for finding in findings:
        assert not [e.message for e in finding_validator.iter_errors(finding)]
        assert finding["image"]["digest"] == digest and finding["image"]["ref"] == REF
    pyyaml = [f for f in findings if f["package"]["purl"] == "pkg:pypi/pyyaml@5.3.1"]
    assert "GHSA-8q59-q68h-6hv4" in {f["rule_id"] for f in pyyaml}, "GT-SCA-001's advisory, now in an image"
    assert {tool["status"] for tool in status_of(tmp_path).values()} == {"ok"}
