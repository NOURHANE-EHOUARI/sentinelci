"""The OCI layout check that runs before Syft reads an image (review of #70, should fix 1).

Syft checks the manifest against the digest it is asked for, not the layer blobs: a layer swapped under its
original name was described as the named image. Every blob must now hold the content its name digests, and the
layout must hold nothing else, as a directory (`oci-dir`) and as a tar (`oci-archive`).
"""

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinelci.scanners.errors import ScannerError
from sentinelci.supplychain.layout import check_oci_layout

from .conftest import FakeReleases
from .test_syft_sbom import DIGEST, LAYOUT, _generate, _tar, fake_syft, oci_archive, oci_layout

MANIFEST_BLOB = "blobs/sha256/" + DIGEST.removeprefix("sha256:")
MANIFEST = json.loads(LAYOUT[MANIFEST_BLOB])
LAYER = "blobs/sha256/" + MANIFEST["layers"][0]["digest"].removeprefix("sha256:")
CONFIG = "blobs/sha256/" + MANIFEST["config"]["digest"].removeprefix("sha256:")
OTHER = "sha256:" + "5c" * 32


def write(tmp_path: Path, kind: str, layout: dict[str, bytes]) -> Path:
    if kind == "oci-dir":
        oci_layout(tmp_path / "layout", layout)
        return tmp_path / "layout"
    return oci_archive(tmp_path / "image.oci.tar", layout)


def check(path: Path, kind: str, digest: str = DIGEST) -> None:
    check_oci_layout(path, archive=kind == "oci-archive", image_digest=digest)


def changed(**files: bytes | None) -> dict[str, bytes]:
    layout = dict(LAYOUT)
    for name, data in files.items():
        if data is None:
            del layout[name]
        else:
            layout[name] = data
    return layout


def index_of(*digests: str) -> bytes:
    return json.dumps({"schemaVersion": 2, "manifests": [{"digest": d} for d in digests]}).encode()


def without_layers() -> tuple[dict[str, bytes], str]:
    """An image built FROM scratch that adds nothing: a config and no layer at all."""
    config = LAYOUT[CONFIG]
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": "sha256:" + hashlib.sha256(config).hexdigest(), "size": len(config)},
        "layers": [],
    }).encode()  # fmt: skip
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    return {
        "oci-layout": LAYOUT["oci-layout"], "index.json": index_of(digest),
        CONFIG: config, f"blobs/sha256/{digest.removeprefix('sha256:')}": manifest,
    }, digest  # fmt: skip


KINDS = ["oci-dir", "oci-archive"]


@pytest.mark.parametrize("kind", KINDS)
def test_the_layout_the_build_wrote_passes(tmp_path: Path, kind: str) -> None:
    check(write(tmp_path, kind, LAYOUT), kind)


@pytest.mark.parametrize("kind", KINDS)
def test_an_image_without_any_layer_passes(tmp_path: Path, kind: str) -> None:
    layout, digest = without_layers()
    check(write(tmp_path, kind, layout), kind, digest)


SWAPPED_LAYER = _tar([("etc/os-release", b"ID=alpine\n")])


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    ("layout", "message"),
    [
        (changed(**{LAYER: SWAPPED_LAYER}), "does not hold the content its digest names"),
        (changed(**{CONFIG: b'{"architecture": "arm64"}'}), "does not hold the content its digest names"),
        (changed(**{MANIFEST_BLOB: LAYOUT[MANIFEST_BLOB] + b" "}), "does not hold the content its digest"),
        (changed(**{LAYER: None}), "does not hold the blob"),
        (changed(**{CONFIG: None}), "does not hold the blob"),
        (changed(**{MANIFEST_BLOB: None}), "does not hold the manifest"),
        (changed(**{"index.json": index_of(OTHER)}), "index.json does not name the image"),
        (changed(**{"index.json": b"{not json"}), "index.json is not JSON"),
        (changed(**{"index.json": None}), "index.json is not a JSON object"),
        (changed(**{"index.json": index_of()}), "index.json lists nothing"),
        (changed(**{"oci-layout": None}), "has no oci-layout file"),
        (changed(**{"manifest.json": b"[]"}), "is not part of an OCI image layout"),
        (changed(**{"blobs/sha256/x": b""}), "is not part of an OCI image layout"),
        (changed(**{"blobs/sha512/" + "0" * 128: b""}), "not part of an OCI image layout"),
    ],
    ids=["layer-bytes-swapped", "config-bytes-swapped", "manifest-bytes-changed", "layer-missing",
         "config-missing", "manifest-missing", "index-names-another-image", "index-not-json", "no-index",
         "index-empty", "no-oci-layout", "docker-manifest-json", "blob-not-a-digest", "other-algorithm"],
)  # fmt: skip
def test_a_layout_that_is_not_exactly_the_image_is_refused(
    tmp_path: Path, kind: str, layout: dict[str, bytes], message: str
) -> None:
    with pytest.raises(ScannerError, match=message):
        check(write(tmp_path, kind, layout), kind)


def test_the_digest_asked_about_must_be_a_sha256(tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="is not sha256:<64 lowercase hex>"):
        check(write(tmp_path, "oci-dir", LAYOUT), "oci-dir", DIGEST.upper())


def _entries(*extra: tarfile.TarInfo) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in LAYOUT.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra:
            tar.addfile(info, io.BytesIO(LAYOUT[LAYER]) if info.isfile() else None)
    return buffer.getvalue()


def _member(name: str, kind: bytes = tarfile.REGTYPE, link: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    info.size = len(LAYOUT[LAYER]) if kind == tarfile.REGTYPE else 0
    return info


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (_member(LAYER), "appears twice"),
        (_member("./" + LAYER), "appears twice"),
        (_member("../../tmp/escaped"), "is not part of an OCI image layout"),
        (_member("/etc/escaped"), "is not part of an OCI image layout"),
        (_member("blobs/sha256/link", tarfile.SYMTYPE, "/etc/passwd"), "a link or a special file"),
        (_member("blobs/sha256/hard", tarfile.LNKTYPE, LAYER), "a link or a special file"),
        (_member("blobs/sha256/fifo", tarfile.FIFOTYPE), "a link or a special file"),
        (_member("blobs/other", tarfile.DIRTYPE), "directory 'blobs/other' is not part"),
    ],
    ids=["duplicate", "duplicate-dot-slash", "dot-dot", "absolute", "symlink", "hard-link", "fifo",
         "other-directory"],
)  # fmt: skip
def test_an_archive_holds_only_the_layout_s_files_once(
    tmp_path: Path, extra: tarfile.TarInfo, message: str
) -> None:
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(_entries(extra))
    with pytest.raises(ScannerError, match=message):
        check(archive, "oci-archive")


def test_the_directories_buildkit_writes_are_part_of_the_layout(tmp_path: Path) -> None:
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(
        _entries(_member("blobs/", tarfile.DIRTYPE), _member("./blobs/sha256/", tarfile.DIRTYPE))
    )
    check(archive, "oci-archive")


@pytest.mark.parametrize(
    ("content", "message"),
    [(b"", "cannot read the OCI layout"), (b"garbage" * 100, "cannot read the OCI layout")],
    ids=["empty", "garbage"],
)
def test_an_unreadable_archive_is_refused(tmp_path: Path, content: bytes, message: str) -> None:
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(content)
    with pytest.raises(ScannerError, match=message):
        check(archive, "oci-archive")


def test_a_compressed_archive_is_not_the_layout_buildkit_writes(tmp_path: Path) -> None:
    archive = tmp_path / "image.oci.tar.gz"
    archive.write_bytes(gzip.compress(_tar(list(LAYOUT.items()))))
    with pytest.raises(ScannerError, match="cannot read the OCI layout"):
        check(archive, "oci-archive")


def test_a_directory_holds_no_link(tmp_path: Path) -> None:
    root = write(tmp_path, "oci-dir", changed(**{LAYER: None}))
    (root / LAYER).symlink_to(tmp_path / "elsewhere")
    (tmp_path / "elsewhere").write_bytes(LAYOUT[LAYER])
    with pytest.raises(ScannerError, match="a link or a special file"):
        check(root, "oci-dir")


def test_the_empty_ingest_directory_buildkit_leaves_passes(tmp_path: Path) -> None:
    """#70 review: `--output type=oci,tar=false` writes an empty ingest/ next to blobs/."""
    root = write(tmp_path, "oci-dir", LAYOUT)
    (root / "ingest").mkdir()
    check(root, "oci-dir")
    (root / "ingest" / "partial").write_bytes(b"x")
    with pytest.raises(ScannerError, match="is not part of an OCI image layout"):
        check(root, "oci-dir")


def _bad_header() -> bytes:
    """A tar header block whose checksum is wrong: tarfile stops there, Go's reader refuses it."""
    header = bytearray(tarfile.TarInfo("blobs/sha256/hidden").tobuf())
    header[148:156] = b"0000000\0"
    return bytes(header)


@pytest.mark.parametrize("stop", [b"\0" * 512, _bad_header()], ids=["one-zero-block", "bad-checksum"])
def test_nothing_may_follow_where_tarfile_stops(tmp_path: Path, stop: bytes) -> None:
    """#70 review: what follows the point where tarfile stops must be zeros, or the layout checked is not the
    one Go's reader (Syft's) would go on to read. Here, a second copy of the layer blob hides there."""
    layout = _tar(list(LAYOUT.items())).rstrip(b"\0")
    hidden = _tar([(LAYER, LAYOUT[LAYER])])
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(layout + b"\0" * (-len(layout) % 512) + stop + hidden)
    with pytest.raises(ScannerError, match="data after the end of the archive"):
        check(archive, "oci-archive")


@pytest.mark.parametrize("kind", KINDS)
def test_index_json_larger_than_1_mib_is_refused(tmp_path: Path, kind: str) -> None:
    padded = LAYOUT["index.json"] + b" " * (1 << 20)
    with pytest.raises(ScannerError, match=r"index\.json is larger than 1 MiB"):
        check(write(tmp_path, kind, changed(**{"index.json": padded})), kind)


@pytest.mark.parametrize("kind", KINDS)
def test_a_manifest_larger_than_1_mib_is_refused(tmp_path: Path, kind: str) -> None:
    manifest = LAYOUT[MANIFEST_BLOB] + b" " * (1 << 20)
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    layout = changed(**{"index.json": index_of(digest), "blobs/sha256/" + digest[7:]: manifest})
    with pytest.raises(ScannerError, match="is larger than 1 MiB"):
        check(write(tmp_path, kind, layout), kind, digest)


def test_a_directory_holds_no_other_directory(tmp_path: Path) -> None:
    root = write(tmp_path, "oci-dir", LAYOUT)
    (root / "blobs" / "sha256" / "nested").mkdir()
    with pytest.raises(ScannerError, match="is not part of an OCI image layout"):
        check(root, "oci-dir")


@pytest.mark.parametrize("kind", KINDS)
def test_syft_never_reads_a_swapped_layer(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], kind: str
) -> None:
    """The fake Syft would describe the image as DIGEST whatever the layer holds, as the real one does."""
    dest, record = fake_syft(tmp_path, releases, write_lock)
    image = write(tmp_path, kind, changed(**{LAYER: SWAPPED_LAYER}))
    with pytest.raises(ScannerError, match="does not hold the content its digest names"):
        _generate(tmp_path, dest, image, kind=kind, image_digest=DIGEST)
    assert not (record / "argv").exists(), "Syft never ran"
