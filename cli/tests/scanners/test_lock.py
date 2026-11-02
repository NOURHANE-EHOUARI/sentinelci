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


@pytest.mark.parametrize(
    ("field", "bad_url"),
    [
        # `..` segments: passes a naive prefix check but points to another repository once normalized.
        (
            "url",
            "https://github.com/example/fakescan/releases/download/v1.0.0/../../../../attacker/tools/releases/download/v1/x.tar.gz",
        ),
        ("url", "https://github.com/example/fakescan/releases/download/v1.0.0/sub/dir/fakescan.tar.gz"),
        ("url", "https://github.com/example/fakescan/releases/download/v1.0.0/fakescan.tar.gz?redirect=evil"),
        ("checksums_url", "https://github.com/attacker/tools/releases/download/v1.0.0/checksums.txt"),
        ("checksums_url", "https://github.com/example/fakescan/releases/download/v9.9.9/checksums.txt"),
        (
            "checksums_url",
            "https://github.com/example/fakescan/releases/download/v1.0.0/../../../../attacker/t/releases/download/v1/c.txt",
        ),
    ],
)
def test_release_urls_must_be_assets_of_the_pinned_release(
    write_lock: Callable[[str], Path], field: str, bad_url: str
) -> None:
    content = archive_tool_lock(GOOD_SHA)
    if field == "url":
        old = "https://github.com/example/fakescan/releases/download/v1.0.0/fakescan_1.0.0_linux_amd64.tar.gz"
    else:
        old = "https://github.com/example/fakescan/releases/download/v1.0.0/checksums.txt"
    assert old in content
    with pytest.raises(ToolIntegrityError, match="release asset directly under"):
        load_lock(write_lock(content.replace(old, bad_url)))


def test_per_artifact_checksums_url_must_be_under_the_pinned_release(
    write_lock: Callable[[str], Path],
) -> None:
    content = raw_tool_lock(GOOD_SHA).replace(
        "https://github.com/example/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.sha256",
        "https://github.com/attacker/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.sha256",
    )
    with pytest.raises(ToolIntegrityError, match="release asset directly under"):
        load_lock(write_lock(content))


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


def _signed_lock(binary_sha: str) -> str:
    """A tool with no checksum file whose assets are signed keyless (like Opengrep)."""
    return (
        raw_tool_lock(binary_sha)
        .replace(
            'archive = "none"',
            'archive = "none"\n'
            'signer_identity = "https://github.com/example/rawtool/.github/workflows/release.yml@refs/tags/v1.0.0"\n'
            'signer_issuer = "https://token.actions.githubusercontent.com"',
        )
        .replace(
            'checksums_url = "https://github.com/example/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.sha256"',
            'certificate_url = "https://github.com/example/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.cert"\n'
            'signature_url = "https://github.com/example/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.sig"',
        )
    )


def test_opengrep_is_pinned_by_its_signed_assets() -> None:
    opengrep = load_lock(REPO_LOCK).tools["opengrep"]
    assert opengrep.checksums_url is None and opengrep.signer_identity == (
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.1"
    )
    for artifact in opengrep.artifacts.values():
        assert (artifact.certificate_url, artifact.signature_url) == (
            f"{artifact.url}.cert",
            f"{artifact.url}.sig",
        )


def test_a_signed_entry_loads(write_lock: Callable[[str], Path]) -> None:
    tool = load_lock(write_lock(_signed_lock(GOOD_SHA))).tools["rawtool"]
    assert tool.signer_issuer == "https://token.actions.githubusercontent.com"
    assert all(artifact.signed for artifact in tool.artifacts.values())


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        ('signer_identity = "https://github.com/example/rawtool/', 'signer_identity = "https://github.com/evil/rawtool/',
         "a workflow of another repository"),
        ("token.actions.githubusercontent.com", "accounts.google.com", "another OIDC issuer"),
        ('signer_issuer = "https://token.actions.githubusercontent.com"\n', "",
         "an identity without its issuer"),
        ('signature_url = "https://github.com/example/rawtool/releases/download/v1.0.0/rawtool-linux-amd64.sig"',
         "", "a certificate without its signature"),
        ("v1.0.0/rawtool-linux-amd64.cert", "v0.9.0/rawtool-linux-amd64.cert",
         "a certificate of another release"),
        ('signer_identity = "https://github.com/example/rawtool/.github/workflows/release.yml@refs/tags/v1.0.0"\n'
         'signer_issuer = "https://token.actions.githubusercontent.com"', "", "signed assets but no signer"),
    ],
)  # fmt: skip
def test_an_invalid_signed_entry_is_rejected(
    write_lock: Callable[[str], Path], old: str, new: str, reason: str
) -> None:
    content = _signed_lock(GOOD_SHA)
    assert old in content, reason
    with pytest.raises(ToolIntegrityError):
        load_lock(write_lock(content.replace(old, new, 1)))


OPENGREP_IDENTITY = (
    "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.1"
)


@pytest.mark.parametrize(
    "identity",
    [
        "https://github.com/opengrep/opengrep/.github/workflows/",
        "https://github.com/opengrep/opengrep/.github/workflows/evil.yml@refs/heads/attacker-branch",
        "https://github.com/opengrep/opengrep/.github/workflows/../../../evil/x/.github/workflows/r.yml",
        "https://github.com/opengrep/opengrep/.github/workflows/../../../evil/x/.github/workflows/r.yml"
        "@refs/heads/release-v1.33.1",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.0",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/release-v1.33.10",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/tags/v11.33.1",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/pull/1/release-v1.33.1",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.sh@refs/heads/release-v1.33.1",
        f"{OPENGREP_IDENTITY} ",
        f"{OPENGREP_IDENTITY}\n",
        OPENGREP_IDENTITY.replace("opengrep/opengrep", "opengrep/opengrep-fork"),
    ],
    ids=["no-file-no-ref", "attacker-branch", "dot-dot-no-ref", "dot-dot", "older-version", "longer-version",
         "version-ending-like-this-one", "pull-request-ref", "not-a-workflow-file", "trailing-space",
         "trailing-newline", "other-repository"],
)  # fmt: skip
def test_a_signer_identity_that_is_not_this_releases_workflow_is_refused(
    tmp_path: Path, identity: str
) -> None:
    lock = REPO_LOCK.read_text(encoding="utf-8")
    assert f'signer_identity = "{OPENGREP_IDENTITY}"' in lock
    changed = tmp_path / "tools.lock.toml"
    changed.write_text(lock.replace(OPENGREP_IDENTITY, identity.replace("\n", "\\n"), 1), encoding="utf-8")
    with pytest.raises(ToolIntegrityError, match="signer_identity must be a workflow file"):
        load_lock(changed)


@pytest.mark.parametrize(
    "ref",
    ["refs/tags/v1.0.0", "refs/tags/1.0.0", "refs/heads/release-v1.0.0", "refs/heads/release/v1.0.0",
     "refs/heads/release_2.x-v1.0.0"],
)  # fmt: skip
def test_a_release_workflow_at_a_ref_named_after_the_version_loads(
    write_lock: Callable[[str], Path], ref: str
) -> None:
    content = _signed_lock(GOOD_SHA).replace("release.yml@refs/tags/v1.0.0", f"release.yaml@{ref}")
    tool = load_lock(write_lock(content)).tools["rawtool"]
    assert tool.signer_identity == f"https://github.com/example/rawtool/.github/workflows/release.yaml@{ref}"
