"""Policy bundle: the Rego files and risk model a decision depends on, and their digest.

The digest is recorded in every decision (SPEC section 6.5). It covers every file of the bundle
except Rego unit tests (`*_test.rego`), which never change a verdict. Exactly the hashed Rego files
are passed to OPA, so the digest describes what was evaluated.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

RISK_MODEL_FILE = "risk-model.yaml"
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class BundleError(Exception):
    """The policy bundle is missing, empty or malformed."""


@dataclass(frozen=True)
class PolicyBundle:
    root: Path
    files: tuple[Path, ...]
    """Every bundle file, relative to `root`, sorted by POSIX path."""

    @classmethod
    def load(cls, root: Path) -> PolicyBundle:
        if not root.is_dir():
            raise BundleError(f"policy directory not found: {root}")
        files = tuple(
            sorted(
                (
                    p.relative_to(root)
                    for p in root.rglob("*")
                    if p.is_file() and not p.name.endswith("_test.rego")
                ),
                key=lambda p: p.as_posix(),
            )
        )
        bundle = cls(root=root, files=files)
        if not bundle.rego_files:
            raise BundleError(f"no Rego policy in {root}")
        return bundle

    @property
    def rego_files(self) -> tuple[Path, ...]:
        """Absolute paths of the policies to load into OPA."""
        return tuple(self.root / p for p in self.files if p.suffix == ".rego")

    @property
    def manifest(self) -> str:
        """sha256sum-style manifest: `<hex>  <posix path>` per file, sorted by path."""
        return "".join(
            f"{hashlib.sha256((self.root / p).read_bytes()).hexdigest()}  {p.as_posix()}\n"
            for p in self.files
        )

    @property
    def digest(self) -> str:
        """`sha256:` of the manifest."""
        return "sha256:" + hashlib.sha256(self.manifest.encode("utf-8")).hexdigest()

    @property
    def risk_model_version(self) -> str:
        path = self.root / RISK_MODEL_FILE
        if not path.is_file():
            raise BundleError(f"risk model not found: {path}")
        model = yaml.safe_load(path.read_text(encoding="utf-8"))
        version = model.get("version") if isinstance(model, dict) else None
        if not isinstance(version, str) or not _SEMVER.match(version):
            raise BundleError(f"{path}: 'version' must be a semantic version string, got {version!r}")
        return version
