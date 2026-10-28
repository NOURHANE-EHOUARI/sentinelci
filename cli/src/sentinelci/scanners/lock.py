"""The tool lock file (`tools.lock.toml`): every security tool pinned by version and SHA-256.

TOML is read with the standard library (`tomllib`) on purpose: the integrity layer adds no dependency.
"""

import re
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from sentinelci.scanners.errors import ToolIntegrityError

LOCK_FILE_NAME = "tools.lock.toml"
PLATFORMS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64")
Platform = Literal["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"]
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_BINARY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _require_github_release(url: str, field: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"{field} must use https: {url}")
    if parsed.hostname != "github.com":
        raise ValueError(f"{field} must point to a github.com release: {url}")
    if "/releases/download/" not in parsed.path:
        raise ValueError(f"{field} must be a GitHub release asset: {url}")
    return url


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Artifact(_Strict):
    url: str
    sha256: str
    checksums_url: str | None = None

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return _require_github_release(value, "url")

    @field_validator("checksums_url")
    @classmethod
    def _checksums(cls, value: str | None) -> str | None:
        return None if value is None else _require_github_release(value, "checksums_url")

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value

    @property
    def file_name(self) -> str:
        return urlparse(self.url).path.rsplit("/", 1)[-1]


class Tool(_Strict):
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    homepage: str
    binary: str
    archive: Literal["tar.gz", "none"]
    checksums_url: str | None = None
    artifacts: dict[Platform, Artifact] = Field(min_length=1)

    @field_validator("binary")
    @classmethod
    def _binary(cls, value: str) -> str:
        if not _BINARY.fullmatch(value):
            raise ValueError("binary must be a plain file name")
        return value

    @field_validator("checksums_url")
    @classmethod
    def _checksums(cls, value: str | None) -> str | None:
        return None if value is None else _require_github_release(value, "checksums_url")

    @model_validator(mode="after")
    def _consistent(self) -> "Tool":
        prefix = f"{self.homepage}/releases/download/v{self.version}/"
        for platform, artifact in self.artifacts.items():
            if not artifact.url.startswith(prefix):
                raise ValueError(
                    f"{platform}: url must start with {prefix} (version and homepage must match)"
                )
        if self.checksums_url is None and any(a.checksums_url is None for a in self.artifacts.values()):
            raise ValueError(
                "a checksums_url is required (tool-level or per artifact) so reviewers can check hashes"
            )
        return self


class ToolLock(_Strict):
    schema_version: Literal[1]
    tools: dict[str, Tool] = Field(min_length=1)


def load_lock(path: Path) -> ToolLock:
    """Parse and validate the lock file; any problem is a ToolIntegrityError (fail closed)."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ToolIntegrityError(f"cannot read {LOCK_FILE_NAME} at {path}: {exc}") from exc
    try:
        return ToolLock.model_validate(data)
    except ValidationError as exc:
        raise ToolIntegrityError(f"invalid {LOCK_FILE_NAME} at {path}:\n{exc}") from exc
