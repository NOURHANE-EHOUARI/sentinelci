"""tools.lock.toml parsing and validation."""

from collections.abc import Callable
from pathlib import Path

import pytest

from sentinelci.scanners.errors import ToolIntegrityError
from sentinelci.scanners.lock import PLATFORMS, load_lock

from .conftest import archive_tool_lock, raw_tool_lock, sha256

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
GOOD_SHA = sha256(b"x")


def test_repository_lock_is_valid_and_complete() -> None:
    lock = load_lock(REPO_LOCK)
    assert set(lock.tools) >= {"gitleaks", "syft", "grype", "trivy", "cosign", "opa"}
    hashes: list[str] = []
    for name, tool in lock.tools.items():
        assert set(tool.artifacts) == set(PLATFORMS), f"{name}: every supported platform must be pinned"
        for artifact in tool.artifacts.values():
            assert f"/releases/download/v{tool.version}/" in artifact.url
            assert artifact.url.startswith(f"{tool.homepage}/releases/download/")
            hashes.append(artifact.sha256)
    assert len(hashes) == len(set(hashes)), "two artifacts share a hash: copy-paste mistake"


def test_trivy_is_pinned_to_a_version_outside_the_compromised_release() -> None:
    # CVE-2026-33634: v0.69.4 was the malicious release.
    assert load_lock(REPO_LOCK).tools["trivy"].version != "0.69.4"


def test_archive_and_raw_entries_load(write_lock: Callable[[str], Path]) -> None:
    assert load_lock(write_lock(archive_tool_lock(GOOD_SHA))).tools["fakescan"].archive == "tar.gz"
    assert load_lock(write_lock(raw_tool_lock(GOOD_SHA))).tools["rawtool"].archive == "none"


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        (
            "https://github.com/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0",
            "http://github.com/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0",
            "https",
        ),
        (
            "https://github.com/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0",
            "https://evil.example/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0",
            "github.com",
        ),
        (
            "https://github.com/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0",
            "https://github.com/example/fakescan/releases/download/v9.9.9/fakescan_1.0.0",
            "version",
        ),
        (f'sha256 = "{GOOD_SHA}"', 'sha256 = "DEADBEEF"', "sha256"),
        ('archive = "tar.gz"', 'archive = "rar"', "archive"),
        ('binary = "fakescan"', 'binary = "../fakescan"', "binary"),
        ("artifacts.linux-amd64", "artifacts.windows-amd64", "platform"),
        ("schema_version = 1", "schema_version = 2", "schema_version"),
    ],
)
def test_invalid_lock_is_rejected(write_lock: Callable[[str], Path], old: str, new: str, reason: str) -> None:
    content = archive_tool_lock(GOOD_SHA)
    assert old in content
    with pytest.raises(ToolIntegrityError, match=r"tools\.lock\.toml"):
        load_lock(write_lock(content.replace(old, new)))


def test_unknown_field_is_rejected(write_lock: Callable[[str], Path]) -> None:
    content = archive_tool_lock(GOOD_SHA).replace(
        'binary = "fakescan"', 'binary = "fakescan"\nskip_verify = true'
    )
    with pytest.raises(ToolIntegrityError):
        load_lock(write_lock(content))


def test_missing_or_malformed_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ToolIntegrityError):
        load_lock(tmp_path / "absent.toml")
    broken = tmp_path / "tools.lock.toml"
    broken.write_text("schema_version = [", encoding="utf-8")
    with pytest.raises(ToolIntegrityError):
        load_lock(broken)
