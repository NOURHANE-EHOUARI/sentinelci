"""Offline fixtures for tool installation tests: fake release artifacts served by an in-memory fetcher."""

import hashlib
import io
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest

FAKE_BINARY = b"#!/bin/sh\necho fake-scanner 1.0.0\n"
BASE = "https://github.com/example/{tool}/releases/download/v1.0.0"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_tar_gz(members: dict[str, bytes], symlinks: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(content))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buffer.getvalue()


class FakeReleases:
    """Maps URL -> bytes and records every fetch, like a tiny offline GitHub Releases."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.fetched: list[str] = []

    def fetch(self, url: str, destination: Path) -> None:
        self.fetched.append(url)
        destination.write_bytes(self.files[url])


@pytest.fixture
def releases() -> FakeReleases:
    return FakeReleases()


@pytest.fixture
def write_lock(tmp_path: Path) -> Callable[[str], Path]:
    def _write(content: str) -> Path:
        path = tmp_path / "tools.lock.toml"
        path.write_text(content, encoding="utf-8")
        return path

    return _write


def archive_tool_lock(archive_sha: str, *, tool: str = "fakescan", platform: str = "linux-amd64") -> str:
    base = BASE.format(tool=tool)
    return f"""
schema_version = 1

[tools.{tool}]
version = "1.0.0"
homepage = "https://github.com/example/{tool}"
checksums_url = "{base}/checksums.txt"
binary = "{tool}"
archive = "tar.gz"

[tools.{tool}.artifacts.{platform}]
url = "{base}/{tool}_1.0.0_linux_amd64.tar.gz"
sha256 = "{archive_sha}"
"""


def raw_tool_lock(binary_sha: str, *, tool: str = "rawtool", platform: str = "linux-amd64") -> str:
    base = BASE.format(tool=tool)
    return f"""
schema_version = 1

[tools.{tool}]
version = "1.0.0"
homepage = "https://github.com/example/{tool}"
binary = "{tool}"
archive = "none"

[tools.{tool}.artifacts.{platform}]
url = "{base}/{tool}-linux-amd64"
checksums_url = "{base}/{tool}-linux-amd64.sha256"
sha256 = "{binary_sha}"
"""
