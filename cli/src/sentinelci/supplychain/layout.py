"""An image's OCI layout, checked before any tool reads it (A1, A4; review of #70, should fix 1).

Syft refuses a manifest that does not hash to the digest it was asked for, but it reads the layer blobs as
they are. A layout whose layer bytes were swapped under the original blob name was described as the image of
the manifest digest: its SBOM, and the image scan built on it, vouched for an image that was never built. A
registry refuses such a blob on push. This does the same, before Syft runs:

- every blob holds the content its name digests (sha256), and each name appears once;
- the layout holds nothing else: `oci-layout`, `index.json`, `blobs/sha256/<digest>` and their two
  directories, as regular files and directories (no link, device or path outside the layout);
- `index.json` names the image's manifest, and the manifest's config and every layer it lists are blobs of
  the layout, so all the bytes the image is made of were checked.

The manifest digest itself comes from the build (`docker buildx build --metadata-file`), not from the layout:
a layout can only show it holds the image it was asked about.
"""

import hashlib
import json
import os
import re
import stat
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from sentinelci.scanners.errors import ScannerError

_BLOB = re.compile(r"blobs/sha256/([a-f0-9]{64})")
_DIGEST = re.compile(r"sha256:([a-f0-9]{64})")
_DIRECTORIES = frozenset({"", "blobs", "blobs/sha256"})
_JSON_LIMIT = 1 << 20  # index.json and the manifest are small documents; anything larger is refused
_CHUNK = 1 << 20


def _name(raw: str) -> str:
    """A member name as the layout means it: `./blobs/` and `blobs` are the same directory."""
    name = raw
    while name.startswith("./"):
        name = name[2:]
    return "" if name == "." else name.rstrip("/")


class _Walk:
    """What one walk over a layout found: the names seen, index.json, and the manifest's bytes."""

    def __init__(self, where: str, manifest: str) -> None:
        self.where = where
        self.manifest_hex = manifest
        self.seen: set[str] = set()
        self.index: bytes | None = None
        self.manifest: bytes | None = None

    def directory(self, raw: str) -> None:
        if _name(raw) not in _DIRECTORIES:
            raise ScannerError(f"{self.where}: directory {raw!r} is not part of an OCI image layout")

    def file(self, raw: str, open_: Callable[[], IO[bytes]]) -> None:
        name = _name(raw)
        if name in self.seen:
            raise ScannerError(f"{self.where}: {raw!r} appears twice")
        self.seen.add(name)
        if name == "oci-layout":
            return
        if name == "index.json":
            with open_() as source:
                self.index = _small(source, f"{self.where}: index.json")
            return
        blob = _BLOB.fullmatch(name)
        if blob is None:
            raise ScannerError(f"{self.where}: {raw!r} is not part of an OCI image layout")
        with open_() as source:
            digest, data = hashlib.sha256(), bytearray()
            keep = blob.group(1) == self.manifest_hex
            while chunk := source.read(_CHUNK):
                digest.update(chunk)
                if keep:
                    data += chunk
                    if len(data) > _JSON_LIMIT:
                        raise ScannerError(f"{self.where}: the manifest {raw!r} is larger than 1 MiB")
        if digest.hexdigest() != blob.group(1):
            raise ScannerError(f"{self.where}: blob {raw!r} does not hold the content its digest names")
        if keep:
            self.manifest = bytes(data)


def _small(source: IO[bytes], what: str) -> bytes:
    data = source.read(_JSON_LIMIT + 1)
    if len(data) > _JSON_LIMIT:
        raise ScannerError(f"{what} is larger than 1 MiB")
    return data


def _walk_archive(archive: Path, walk: _Walk) -> None:
    with tarfile.open(archive, mode="r:") as tar:  # the uncompressed tar BuildKit's OCI exporter writes
        for member in tar:
            if member.isdir():
                walk.directory(member.name)
            elif member.isfile():

                def open_(member: tarfile.TarInfo = member) -> IO[bytes]:
                    source = tar.extractfile(member)
                    if source is None:  # isfile() said otherwise; kept for the type checker
                        raise ScannerError(f"{walk.where}: cannot read {member.name!r}")
                    return source

                walk.file(member.name, open_)
            else:
                raise ScannerError(f"{walk.where}: {member.name!r} is a link or a special file, not a blob")


def _walk_directory(root: Path, walk: _Walk) -> None:
    for current, directories, names in os.walk(root, followlinks=False):
        for entry in sorted(directories + names):
            path = Path(current) / entry
            name = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                walk.directory(name)
            elif stat.S_ISREG(mode):

                def open_(path: Path = path) -> IO[bytes]:
                    return path.open("rb")

                walk.file(name, open_)
            else:
                raise ScannerError(f"{walk.where}: {name!r} is a link or a special file, not a blob")


def _document(data: bytes | None, what: str) -> dict[str, Any]:
    try:
        document = json.loads(data if data is not None else b"null")
    except ValueError as exc:
        raise ScannerError(f"{what} is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ScannerError(f"{what} is not a JSON object")
    return document


def _digests(entries: object, what: str, *, may_be_empty: bool = False) -> list[str]:
    if not isinstance(entries, list) or not (entries or may_be_empty):
        raise ScannerError(f"{what} lists nothing")
    found = [entry.get("digest") if isinstance(entry, dict) else None for entry in entries]
    if not all(isinstance(digest, str) and _DIGEST.fullmatch(digest) for digest in found):
        raise ScannerError(f"{what} names something that is not a sha256 digest")
    return [str(digest) for digest in found]


def check_oci_layout(source: Path, *, archive: bool, image_digest: str) -> None:
    """Refuse `source` (an OCI layout archive, or a directory with `archive=False`) unless every byte of the
    image `image_digest` is there and checked against its digest, and nothing else is. Fails closed with a
    ScannerError naming what is wrong; nothing is extracted or run."""
    match = _DIGEST.fullmatch(image_digest)
    if match is None:
        raise ScannerError(f"image digest {image_digest!r} is not sha256:<64 lowercase hex>")
    walk = _Walk(f"OCI layout {source}", match.group(1))
    try:
        if archive:
            _walk_archive(source, walk)
        else:
            _walk_directory(source, walk)
    except (OSError, tarfile.TarError) as exc:
        raise ScannerError(f"cannot read the OCI layout {source}: {exc}") from exc
    if "oci-layout" not in walk.seen:
        raise ScannerError(f"{walk.where} has no oci-layout file")
    index = _document(walk.index, f"{walk.where}: index.json")
    if image_digest not in _digests(index.get("manifests"), f"{walk.where}: index.json"):
        raise ScannerError(f"{walk.where}: index.json does not name the image {image_digest}")
    if walk.manifest is None:
        raise ScannerError(f"{walk.where} does not hold the manifest of {image_digest}")
    manifest = _document(walk.manifest, f"{walk.where}: the manifest of {image_digest}")
    config = manifest.get("config")
    needed = _digests([config], f"{walk.where}: the manifest's config")
    # An image built `FROM scratch` that adds nothing has no layer at all.
    needed += _digests(manifest.get("layers"), f"{walk.where}: the manifest's layers", may_be_empty=True)
    missing = sorted(d for d in needed if f"blobs/sha256/{d.removeprefix('sha256:')}" not in walk.seen)
    if missing:
        raise ScannerError(f"{walk.where} does not hold the blob(s) {', '.join(missing)} of its image")
