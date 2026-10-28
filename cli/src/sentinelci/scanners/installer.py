"""Install and verify the pinned security tools (SPEC §5, stage 0 — task A1).

Trust chain: tools.lock.toml (reviewed in a PR) -> SHA-256 of the release artifact -> the binary
extracted from that exact artifact. `verify_tools` re-derives the expected binary hash from the cached
artifact every time, so an attacker who replaces the binary, the cache, or both, cannot pass
verification without changing the lock.
"""

import hashlib
import os
import platform as platform_module
import stat
import tarfile
import tempfile
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from sentinelci.scanners.errors import ToolIntegrityError
from sentinelci.scanners.lock import Artifact, Tool, ToolLock

Fetcher = Callable[[str, Path], None]

MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 120
_CHUNK = 1024 * 1024

_SYSTEMS = {"linux": "linux", "darwin": "darwin"}
_MACHINES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


@dataclass(frozen=True)
class VerifiedTool:
    name: str
    version: str
    artifact_sha256: str
    binary_sha256: str
    path: Path


@dataclass(frozen=True)
class VerificationReport:
    platform: str
    entries: tuple[VerifiedTool, ...]


def detect_platform(*, system: str | None = None, machine: str | None = None) -> str:
    """Map the current OS/CPU to a lock platform key (linux-amd64, darwin-arm64, ...)."""
    raw_system = system or platform_module.system()
    raw_machine = machine or platform_module.machine()
    os_key = _SYSTEMS.get(raw_system.lower())
    cpu_key = _MACHINES.get(raw_machine.lower())
    if os_key is None or cpu_key is None:
        raise ToolIntegrityError(
            f"unsupported platform {raw_system}/{raw_machine} "
            "(supported: Linux and macOS; use WSL on Windows)"
        )
    return f"{os_key}-{cpu_key}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urlparse(newurl).scheme != "https":
            raise ToolIntegrityError(f"refusing redirect to a non-https URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_download(url: str, destination: Path) -> None:
    """Download over https only, with a size cap. Integrity is checked by the caller against the lock."""
    if urlparse(url).scheme != "https":
        raise ToolIntegrityError(f"refusing to download over a non-https URL: {url}")
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    request = urllib.request.Request(url, headers={"User-Agent": "sentinelci-tools"})  # noqa: S310 (https enforced)
    total = 0
    try:
        with (
            opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response,
            destination.open("wb") as out,
        ):
            for chunk in iter(lambda: response.read(_CHUNK), b""):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ToolIntegrityError(f"download larger than {MAX_DOWNLOAD_BYTES} bytes: {url}")
                out.write(chunk)
    except OSError as exc:
        raise ToolIntegrityError(f"download failed for {url}: {exc}") from exc


def _select(lock: ToolLock, only: Iterable[str] | None) -> list[tuple[str, Tool]]:
    names = list(only) if only else sorted(lock.tools)
    unknown = [name for name in names if name not in lock.tools]
    if unknown:
        raise ToolIntegrityError(f"{', '.join(unknown)} not in tools.lock.toml")
    return [(name, lock.tools[name]) for name in names]


def _artifact_for(name: str, tool: Tool, platform: str) -> Artifact:
    for key, artifact in tool.artifacts.items():
        if key == platform:
            return artifact
    raise ToolIntegrityError(f"{name} {tool.version} has no artifact pinned for platform {platform}")


def _binary_bytes_from_archive(name: str, tool: Tool, archive_path: Path) -> bytes:
    """Read the one regular file named `tool.binary` from a verified tar.gz; nothing is extracted to disk."""
    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            candidates = [
                member
                for member in tar.getmembers()
                if Path(member.name).name == tool.binary
                and ".." not in Path(member.name).parts
                and not Path(member.name).is_absolute()
                and len(Path(member.name).parts) <= 2
            ]
            if not candidates:
                raise ToolIntegrityError(f"{name}: binary {tool.binary!r} not found in {archive_path.name}")
            if len(candidates) > 1:
                raise ToolIntegrityError(f"{name}: ambiguous archive, several files named {tool.binary!r}")
            member = candidates[0]
            if not member.isfile():
                raise ToolIntegrityError(
                    f"{name}: {member.name!r} is not a regular file (symlinks are refused)"
                )
            handle = tar.extractfile(member)
            if handle is None:
                raise ToolIntegrityError(f"{name}: cannot read {member.name!r}")
            return handle.read()
    except (tarfile.TarError, OSError) as exc:
        raise ToolIntegrityError(f"{name}: unreadable archive {archive_path.name}: {exc}") from exc


def _expected_binary(name: str, tool: Tool, artifact: Artifact, cached: Path) -> bytes:
    if tool.archive == "none":
        return cached.read_bytes()
    return _binary_bytes_from_archive(name, tool, cached)


def _ensure_cached(name: str, tool: Tool, artifact: Artifact, cache_dir: Path, fetch: Fetcher) -> Path:
    cached = cache_dir / artifact.file_name
    if cached.is_file() and not cached.is_symlink() and sha256_file(cached) == artifact.sha256:
        return cached
    cache_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache_dir) as tmp:
        partial = Path(tmp) / artifact.file_name
        fetch(artifact.url, partial)
        actual = sha256_file(partial)
        if actual != artifact.sha256:
            raise ToolIntegrityError(
                f"{name} {tool.version}: hash mismatch for {artifact.file_name} "
                f"(expected {artifact.sha256}, got {actual}); nothing was installed"
            )
        os.replace(partial, cached)
    return cached


def install_tools(
    lock: ToolLock,
    dest: Path,
    *,
    platform: str | None = None,
    only: Iterable[str] | None = None,
    fetch: Fetcher = https_download,
) -> VerificationReport:
    """Download (if needed), verify and install each selected tool, then verify the whole selection."""
    platform = platform or detect_platform()
    selected = _select(lock, only)
    bin_dir = dest / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name, tool in selected:
        artifact = _artifact_for(name, tool, platform)
        cached = _ensure_cached(name, tool, artifact, dest / "cache", fetch)
        content = _expected_binary(name, tool, artifact, cached)
        target = bin_dir / tool.binary
        with tempfile.NamedTemporaryFile(dir=bin_dir, delete=False) as tmp:
            tmp.write(content)
        tmp_path = Path(tmp.name)
        tmp_path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        if target.is_symlink():
            target.unlink()
        os.replace(tmp_path, target)
    return verify_tools(lock, dest, platform=platform, only=[name for name, _ in selected])


def verify_tools(
    lock: ToolLock,
    dest: Path,
    *,
    platform: str | None = None,
    only: Iterable[str] | None = None,
) -> VerificationReport:
    """Check that every selected binary is exactly the one contained in its pinned artifact."""
    platform = platform or detect_platform()
    entries: list[VerifiedTool] = []
    for name, tool in _select(lock, only):
        artifact = _artifact_for(name, tool, platform)
        cached = dest / "cache" / artifact.file_name
        binary = dest / "bin" / tool.binary
        if binary.is_symlink():
            raise ToolIntegrityError(f"{name}: {binary} is a symlink; refusing to trust it")
        if not binary.is_file() or not cached.is_file():
            raise ToolIntegrityError(f"{name} {tool.version} is not installed (run `sentinel tools install`)")
        if cached.is_symlink() or sha256_file(cached) != artifact.sha256:
            raise ToolIntegrityError(
                f"{name}: cached archive {artifact.file_name} does not match tools.lock.toml"
            )
        expected = hashlib.sha256(_expected_binary(name, tool, artifact, cached)).hexdigest()
        actual = sha256_file(binary)
        if actual != expected:
            raise ToolIntegrityError(
                f"{name}: installed binary was modified (expected sha256 {expected}, got {actual})"
            )
        if not os.access(binary, os.X_OK):
            raise ToolIntegrityError(f"{name}: {binary} is not executable")
        entries.append(VerifiedTool(name, tool.version, artifact.sha256, actual, binary))
    return VerificationReport(platform=platform, entries=tuple(entries))
