"""Installing and verifying pinned tools, fully offline (task A1).

The security property under test: a binary only runs if its bytes can be traced back to a hash in the
repository's lock file. Anything else is a ToolIntegrityError, which the CLI maps to SC-010 (fail closed).
"""

import json
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners import installer
from sentinelci.scanners.errors import ToolIntegrityError
from sentinelci.scanners.installer import install_tools, verify_tools
from sentinelci.scanners.lock import load_lock

from .conftest import (
    BASE,
    FAKE_BINARY,
    FakeReleases,
    archive_tool_lock,
    make_tar_gz,
    raw_tool_lock,
    sha256,
)

PLATFORM = "linux-amd64"
ARCHIVE_URL = BASE.format(tool="fakescan") + "/fakescan_1.0.0_linux_amd64.tar.gz"
RAW_URL = BASE.format(tool="rawtool") + "/rawtool-linux-amd64"


def _archive_setup(releases: FakeReleases, write_lock: Callable[[str], Path], archive: bytes) -> Path:
    releases.files[ARCHIVE_URL] = archive
    return write_lock(archive_tool_lock(sha256(archive)))


def test_install_then_verify_archive_tool(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    archive = make_tar_gz({"fakescan": FAKE_BINARY, "LICENSE": b"MIT"})
    lock = load_lock(_archive_setup(releases, write_lock, archive))
    dest = tmp_path / "tools"

    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)

    binary = dest / "bin" / "fakescan"
    assert binary.read_bytes() == FAKE_BINARY
    assert binary.stat().st_mode & stat.S_IXUSR
    assert not (dest / "bin" / "LICENSE").exists(), "only the pinned binary is extracted"
    report = verify_tools(lock, dest, platform=PLATFORM)
    assert report.entries[0].binary_sha256 == sha256(FAKE_BINARY)
    assert report.entries[0].artifact_sha256 == sha256(archive)


def test_install_then_verify_raw_binary_tool(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    releases.files[RAW_URL] = FAKE_BINARY
    lock = load_lock(write_lock(raw_tool_lock(sha256(FAKE_BINARY))))

    install_tools(lock, tmp_path / "tools", platform=PLATFORM, fetch=releases.fetch)

    report = verify_tools(lock, tmp_path / "tools", platform=PLATFORM)
    assert report.entries[0].binary_sha256 == sha256(FAKE_BINARY)


def test_download_with_wrong_hash_installs_nothing(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # Simulates a force-pushed / replaced release asset (the 2026 trivy-action attack pattern).
    lock = load_lock(write_lock(archive_tool_lock(sha256(b"the archive we reviewed"))))
    releases.files[ARCHIVE_URL] = make_tar_gz({"fakescan": b"#!/bin/sh\nsteal-credentials\n"})
    dest = tmp_path / "tools"

    with pytest.raises(
        ToolIntegrityError, match=r"fakescan 1\.0\.0: hash mismatch for .*nothing was installed"
    ):
        install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)

    assert not (dest / "bin" / "fakescan").exists()
    assert not list((dest / "cache").glob("*")), "a rejected download must not stay in the cache"


def test_tampered_binary_is_detected(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)

    (dest / "bin" / "fakescan").write_bytes(b"#!/bin/sh\nexfiltrate\n")

    with pytest.raises(ToolIntegrityError, match="fakescan: installed binary was modified"):
        verify_tools(lock, dest, platform=PLATFORM)


def test_tampered_cache_is_detected_even_if_binary_matches_it(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)

    # An attacker who swaps both the cached archive and the binary still cannot match the lock.
    evil = b"#!/bin/sh\nevil\n"
    (cached,) = list((dest / "cache").iterdir())
    cached.write_bytes(make_tar_gz({"fakescan": evil}))
    (dest / "bin" / "fakescan").write_bytes(evil)

    with pytest.raises(
        ToolIntegrityError, match=r"fakescan: cached archive .* does not match tools\.lock\.toml"
    ):
        verify_tools(lock, dest, platform=PLATFORM)


def test_missing_binary_fails_closed(tmp_path: Path, write_lock: Callable[[str], Path]) -> None:
    lock = load_lock(write_lock(archive_tool_lock(sha256(b"x"))))
    with pytest.raises(ToolIntegrityError, match=r"is not installed \(run `sentinel tools install`\)"):
        verify_tools(lock, tmp_path / "tools", platform=PLATFORM)


def test_symlinked_binary_is_rejected(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)
    binary = dest / "bin" / "fakescan"
    # Same bytes and executable: only the symlink check can reject it.
    real = tmp_path / "real-fakescan"
    real.write_bytes(binary.read_bytes())
    real.chmod(0o755)
    binary.unlink()
    binary.symlink_to(real)

    with pytest.raises(ToolIntegrityError, match="is a symlink; refusing to trust it"):
        verify_tools(lock, dest, platform=PLATFORM)


@pytest.mark.parametrize(
    ("members", "symlinks", "message"),
    [
        ({"README.md": b"no binary here"}, None, "binary 'fakescan' not found in"),
        ({"../fakescan": FAKE_BINARY}, None, "binary 'fakescan' not found in"),
        ({}, {"fakescan": "/usr/bin/curl"}, "is not a regular file"),
        (
            {"fakescan": FAKE_BINARY, "dist/fakescan": FAKE_BINARY},
            None,
            "ambiguous archive, several files named",
        ),
    ],
)
def test_unsafe_or_unexpected_archives_are_rejected(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    members: dict[str, bytes],
    symlinks: dict[str, str] | None,
    message: str,
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz(members, symlinks)))
    with pytest.raises(ToolIntegrityError, match=message):
        install_tools(lock, tmp_path / "tools", platform=PLATFORM, fetch=releases.fetch)
    assert not (tmp_path / "tools" / "bin" / "fakescan").exists()


def test_binary_inside_a_single_folder_is_found(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(
        _archive_setup(releases, write_lock, make_tar_gz({"fakescan_1.0.0/fakescan": FAKE_BINARY}))
    )
    install_tools(lock, tmp_path / "tools", platform=PLATFORM, fetch=releases.fetch)
    assert (tmp_path / "tools" / "bin" / "fakescan").read_bytes() == FAKE_BINARY


def test_cached_verified_artifact_is_not_downloaded_again(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    install_tools(lock, tmp_path / "tools", platform=PLATFORM, fetch=releases.fetch)
    install_tools(lock, tmp_path / "tools", platform=PLATFORM, fetch=releases.fetch)
    assert releases.fetched == [ARCHIVE_URL]


def test_corrupted_cache_is_downloaded_again_instead_of_trusted(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)
    (cached,) = list((dest / "cache").iterdir())
    cached.write_bytes(make_tar_gz({"fakescan": b"#!/bin/sh\nevil\n"}))

    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)

    assert releases.fetched == [ARCHIVE_URL, ARCHIVE_URL]
    assert (dest / "bin" / "fakescan").read_bytes() == FAKE_BINARY


def test_unsupported_platform_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock = load_lock(_archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY})))
    with pytest.raises(ToolIntegrityError, match="has no artifact pinned for platform darwin-arm64"):
        install_tools(lock, tmp_path / "tools", platform="darwin-arm64", fetch=releases.fetch)


def test_unknown_tool_selection_fails(tmp_path: Path, write_lock: Callable[[str], Path]) -> None:
    lock = load_lock(write_lock(archive_tool_lock(sha256(b"x"))))
    with pytest.raises(ToolIntegrityError, match=r"not in tools\.lock\.toml"):
        verify_tools(lock, tmp_path, platform=PLATFORM, only=["nmap"])


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "arm64", "darwin-arm64"),
        ("Darwin", "x86_64", "darwin-amd64"),
    ],
)
def test_platform_detection(system: str, machine: str, expected: str) -> None:
    assert installer.detect_platform(system=system, machine=machine) == expected


def test_platform_detection_rejects_unknown() -> None:
    with pytest.raises(ToolIntegrityError, match="unsupported platform Windows/AMD64"):
        installer.detect_platform(system="Windows", machine="AMD64")


def test_https_download_refuses_non_https(tmp_path: Path) -> None:
    with pytest.raises(ToolIntegrityError, match="refusing to download over a non-https URL"):
        installer.https_download("http://github.com/x/y", tmp_path / "out")


# ------------------------------------------------------------------ CLI


def _cli_env(tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]) -> tuple[Path, Path]:
    lock_path = _archive_setup(releases, write_lock, make_tar_gz({"fakescan": FAKE_BINARY}))
    dest = tmp_path / "tools"
    install_tools(load_lock(lock_path), dest, platform=PLATFORM, fetch=releases.fetch)
    return lock_path, dest


def test_cli_verify_writes_a_deterministic_manifest(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock_path, dest = _cli_env(tmp_path, releases, write_lock)
    report = tmp_path / "out" / "tools-manifest.json"
    args = [
        "tools",
        "verify",
        "--lock",
        str(lock_path),
        "--dest",
        str(dest),
        "--platform",
        PLATFORM,
        "--report",
        str(report),
    ]

    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    first = report.read_text(encoding="utf-8")
    CliRunner().invoke(app, args)
    assert report.read_text(encoding="utf-8") == first

    manifest = json.loads(first)
    assert manifest["platform"] == PLATFORM
    assert manifest["tools"]["fakescan"]["version"] == "1.0.0"
    assert manifest["tools"]["fakescan"]["binary_sha256"] == sha256(FAKE_BINARY)
    assert manifest["lock_sha256"] == sha256(lock_path.read_bytes())


def test_cli_verify_fails_closed_with_exit_code_3(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock_path, dest = _cli_env(tmp_path, releases, write_lock)
    (dest / "bin" / "fakescan").write_bytes(b"tampered")
    report = tmp_path / "out" / "tools-manifest.json"

    result = CliRunner().invoke(
        app,
        [
            "tools",
            "verify",
            "--lock",
            str(lock_path),
            "--dest",
            str(dest),
            "--platform",
            PLATFORM,
            "--report",
            str(report),
        ],
    )

    assert result.exit_code == 3
    assert "SC-010" in result.output
    assert not report.exists(), "no manifest may be produced for an unverified toolchain"


def test_cli_list_shows_pinned_tools() -> None:
    result = CliRunner().invoke(
        app, ["tools", "list", "--lock", str(Path(__file__).resolve().parents[3] / "tools.lock.toml")]
    )
    assert result.exit_code == 0
    assert "trivy" in result.output and "0.76.1" in result.output
