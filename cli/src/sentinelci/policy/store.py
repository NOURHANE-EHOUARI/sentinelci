"""Content-addressed evidence store: what `sentinel replay` re-evaluates from (SPEC section 6.5).

Layout under the store root:
    sha256/<hex>           every input exactly as digested (findings, waivers, baseline, tool status,
                           enrichment snapshot, SBOM, each policy file) and each policy bundle manifest
    decisions/<uuid>.json  decisions, as written by `sentinel evaluate --store`

A policy bundle is stored as its sha256sum-style manifest, whose own digest is the bundle digest recorded in
the decision, plus one blob per file. Every read is checked against its digest, so a tampered store means no
replay rather than a different answer.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path, PurePosixPath

from sentinelci.policy.bundle import BundleError, PolicyBundle

# All checked with fullmatch: Python's `$` also matches before a final newline.
_DIGEST = re.compile(r"sha256:([a-f0-9]{64})")
_MANIFEST_LINE = re.compile(r"([a-f0-9]{64})  (.+)")
_DECISION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class StoreError(Exception):
    """The evidence store cannot provide what was asked, or provides something else (fail closed)."""


def _write_atomically(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _safe_relative(path: str) -> PurePosixPath:
    pure = PurePosixPath(path)
    if "\\" in path or pure.is_absolute() or not pure.parts or ".." in pure.parts or "." in pure.parts:
        raise StoreError(f"policy bundle manifest names an unsafe path: {path!r}")
    return pure


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _blob_path(self, digest: str) -> Path:
        match = _DIGEST.fullmatch(digest)
        if not match:
            raise StoreError(f"not a sha256:<64 lowercase hex> digest: {digest!r}")
        return self.root / "sha256" / match.group(1)

    def put(self, data: bytes) -> str:
        """Store `data` under its digest and return the digest. A corrupt copy already there is replaced."""
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        path = self._blob_path(digest)
        if not (path.is_file() and path.read_bytes() == data):
            _write_atomically(path, data)
        return digest

    def get(self, digest: str) -> bytes:
        path = self._blob_path(digest)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise StoreError(f"{digest} is not in the evidence store {self.root}") from exc
        except OSError as exc:
            raise StoreError(f"cannot read {digest} from the evidence store: {exc}") from exc
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise StoreError(f"integrity check failed: the stored content of {digest} has another digest")
        return data

    def put_bundle(self, bundle: PolicyBundle) -> str:
        """Store every bundle file and the manifest; return the manifest digest (the bundle digest)."""
        manifest = bundle.manifest
        for line in manifest.removesuffix("\n").split("\n"):
            hex_digest, _, path = line.partition("  ")
            if self.put((bundle.root / path).read_bytes()) != "sha256:" + hex_digest:
                raise StoreError(f"policy file {path} changed while the bundle was being stored")
        return self.put(manifest.encode("utf-8"))

    def extract_bundle(self, digest: str, dest: Path) -> PolicyBundle:
        """Write the bundle `digest` names into the empty directory `dest` and load it from there."""
        try:
            manifest = self.get(digest).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StoreError(f"{digest} is not a policy bundle manifest") from exc
        # Split on "\n" only, as the manifest is written: splitlines() would also split on \v, \x1c, U+2028...
        lines = manifest.removesuffix("\n").split("\n")
        if not manifest.endswith("\n") or manifest == "\n":
            raise StoreError(f"{digest} is not a policy bundle manifest")
        for line in lines:
            match = _MANIFEST_LINE.fullmatch(line)
            if not match:
                raise StoreError(f"{digest} is not a policy bundle manifest (line {line[:80]!r})")
            target = dest / _safe_relative(match.group(2))
            data = self.get("sha256:" + match.group(1))
            if target.exists():
                raise StoreError(f"policy bundle manifest names {match.group(2)!r} twice")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        try:
            bundle = PolicyBundle.load(dest)
        except BundleError as exc:
            raise StoreError(f"stored policy bundle {digest} is unusable: {exc}") from exc
        if bundle.digest != digest:
            # E.g. a manifest that is not sorted or names a Rego unit test: not what `evaluate` records.
            raise StoreError(f"stored policy bundle {digest} does not reproduce its own digest")
        return bundle

    def decision_path(self, decision_id: str) -> Path:
        if not _DECISION_ID.fullmatch(decision_id):
            raise StoreError(f"not a decision id (lowercase UUID): {decision_id!r}")
        return self.root / "decisions" / f"{decision_id}.json"

    def put_decision(self, decision_id: str, text: str) -> Path:
        path = self.decision_path(decision_id)
        _write_atomically(path, text.encode("utf-8"))
        return path
