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
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


def _signer_identity(homepage: str, version: str) -> re.Pattern[str]:
    """The certificate identity of a release build: a workflow file of the tool's own repository (no
    sub-path), run at a branch or tag whose last part is this version (`v1.2.3`, `release-v1.2.3`,
    `release/1.2.3`). It is documentation for reviewers: `sentinel tools install`/`verify` check only the
    pinned sha256."""
    return re.compile(
        re.escape(homepage)
        + r"/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml@refs/(?:heads|tags)/"
        + r"(?:[A-Za-z0-9_][A-Za-z0-9._]*[/-])*v?"
        + re.escape(version)
    )


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
    # Keyless signature of the asset (Sigstore): what a reviewer checks when there is no checksum file.
    certificate_url: str | None = None
    signature_url: str | None = None

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return _require_github_release(value, "url")

    @field_validator("checksums_url", "certificate_url", "signature_url")
    @classmethod
    def _optional_asset(cls, value: str | None) -> str | None:
        return None if value is None else _require_github_release(value, "release asset url")

    @property
    def signed(self) -> bool:
        return self.certificate_url is not None and self.signature_url is not None

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
    # For a project that signs its assets keyless instead of publishing checksums: the release workflow's
    # identity (certificate SAN) and the OIDC issuer a reviewer verifies each signature against. They are
    # documentation: `sentinel tools install`/`verify` check only the pinned sha256 and never read them.
    signer_identity: str | None = None
    signer_issuer: Literal["https://token.actions.githubusercontent.com"] | None = None
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
        # Every URL must be an asset sitting directly in this tool's release for this version, so a reviewer
        # reading a lock diff can trust where each hash comes from (no `..`, sub-paths or query strings).
        prefix = f"{self.homepage}/releases/download/v{self.version}/"
        urls = [("checksums_url", self.checksums_url)]
        for platform, artifact in self.artifacts.items():
            urls += [
                (f"{platform}.url", artifact.url),
                (f"{platform}.checksums_url", artifact.checksums_url),
                (f"{platform}.certificate_url", artifact.certificate_url),
                (f"{platform}.signature_url", artifact.signature_url),
            ]
        for field, url in urls:
            if url is None:
                continue
            asset = url[len(prefix) :] if url.startswith(prefix) else ""
            if not _ASSET.fullmatch(asset):
                raise ValueError(f"{field} must be a release asset directly under {prefix}: {url}")
        signed = self.signer_identity is not None and self.signer_issuer is not None
        if (self.signer_identity is None) != (self.signer_issuer is None):
            raise ValueError("signer_identity and signer_issuer go together")
        if self.signer_identity is not None and not _signer_identity(self.homepage, self.version).fullmatch(
            self.signer_identity
        ):
            raise ValueError(
                f"signer_identity must be a workflow file of {self.homepage} run at a branch or tag named "
                f"after this version (.github/workflows/<name>.yml@refs/tags/v{self.version}, "
                f"...@refs/heads/release-v{self.version}): {self.signer_identity}"
            )
        for platform, artifact in self.artifacts.items():
            has_checksums = self.checksums_url is not None or artifact.checksums_url is not None
            if not has_checksums and not (signed and artifact.signed):
                raise ValueError(
                    f"{platform}: a checksums_url, or a certificate_url and signature_url with the tool's "
                    "signer_identity and signer_issuer, is required so reviewers can check the hash"
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
