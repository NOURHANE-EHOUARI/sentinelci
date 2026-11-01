"""Sign and verify release attestations with the pinned Cosign, key pair and no transparency log (ADR-0010).

Every call goes through `run_verified_tool`: the binary is checked against tools.lock.toml right before it
runs, and the process gets a minimal environment. When signing, only the key variable (for `env://VAR` keys)
and `COSIGN_PASSWORD` are added to it. When verifying, the bundle is copied to a private directory first, and
the statement is parsed from the very bytes Cosign verified: a file swapped in between cannot be trusted.
"""

import base64
import binascii
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.attestations import AttestationError, Image

STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"})
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"
MAX_BUNDLE_BYTES = 64 << 20
_ENV_KEY = re.compile(r"env://(?P<var>[A-Z_][A-Z0-9_]{0,63})")
_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----")
_TIMEOUT_S = 120


def check_public_key(path: Path) -> None:
    """A readable PEM public key, or AttestationError: a missing or garbled key means the verification could
    not run, which is not the same answer as "this image is not trusted". The key's content is never
    echoed."""
    try:
        text = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise AttestationError(f"the public key {path} cannot be read ({type(exc).__name__})") from exc
    if _PUBLIC_KEY.search(text) is None:
        raise AttestationError(f"{path} is not a PEM public key (-----BEGIN PUBLIC KEY-----)")


@dataclass(frozen=True)
class Signer:
    """The private key: a file, or `env://VAR` (only VAR and COSIGN_PASSWORD reach Cosign)."""

    key: str
    lock: ToolLock
    tools_dir: Path
    platform: str | None = None

    def _key_env(self, environ: Mapping[str, str]) -> tuple[str, dict[str, str]]:
        env = {"COSIGN_PASSWORD": environ.get("COSIGN_PASSWORD", "")}
        match = _ENV_KEY.fullmatch(self.key)
        if match is not None:
            value = environ.get(match["var"])
            if not value:
                raise AttestationError(f"the signing key variable {match['var']} is empty or not set")
            return self.key, env | {match["var"]: value}
        path = Path(self.key)
        if not path.is_file():
            raise AttestationError(f"signing key {self.key} is not a file (or env://VAR)")
        return str(path.resolve()), env

    def attest(
        self, image: Image, predicate_type: str, predicate: Any, out: Path, environ: Mapping[str, str]
    ) -> None:
        """Sign one in-toto statement about `image` and write it as a Sigstore bundle to `out`."""
        key, env = self._key_env(environ)
        with tempfile.TemporaryDirectory(prefix="sentinel-attest-") as private:
            work = Path(private)
            predicate_file = work / "predicate.json"
            predicate_file.write_text(json.dumps(predicate, sort_keys=True), encoding="utf-8")
            bundle = work / "bundle.json"
            run_verified_tool(
                "cosign",
                [
                    "attest-blob",
                    "--key",
                    key,
                    "--predicate",
                    str(predicate_file),
                    "--type",
                    predicate_type,
                    "--hash",
                    image.digest_hex,
                    "--bundle",
                    str(bundle),
                    "--tlog-upload=false",
                    "--use-signing-config=false",
                    "--yes",
                    image.name.rsplit("/", 1)[-1],  # the subject name; with --hash nothing is read from it
                ],
                lock=self.lock,
                tools_dir=self.tools_dir,
                cwd=work,
                platform=self.platform,
                timeout_s=_TIMEOUT_S,
                extra_env=env,
            )
            out.write_bytes(bundle.read_bytes())


@dataclass(frozen=True)
class Verified:
    """The outcome for one attestation: the predicate when everything held, otherwise why not."""

    predicate: Any | None
    problem: str | None


def statement_of(bundle_data: bytes) -> dict[str, Any]:
    """The in-toto statement inside a Sigstore bundle (DSSE envelope); AttestationError if malformed."""
    try:
        bundle = json.loads(bundle_data)
        envelope = bundle["dsseEnvelope"]
        if envelope["payloadType"] != IN_TOTO_PAYLOAD:
            raise AttestationError(
                f"the envelope holds {envelope['payloadType']!r}, not an in-toto statement"
            )
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise AttestationError(f"not a Sigstore bundle with a DSSE envelope: {exc}") from exc
    if not isinstance(statement, dict):
        raise AttestationError("the signed payload is not a JSON object")
    return statement


def check_statement(statement: dict[str, Any], image: Image, predicate_type: str) -> Any:
    """Re-check what Cosign checked, on the parsed statement: type, exactly one subject, this digest."""
    if statement.get("_type") not in STATEMENT_TYPES:
        raise AttestationError(f"unknown statement type {statement.get('_type')!r}")
    if statement.get("predicateType") != predicate_type:
        raise AttestationError(
            f"predicate type {statement.get('predicateType')!r}, expected {predicate_type}"
        )
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        raise AttestationError("the statement must have exactly one subject")
    if subjects[0].get("digest") != {"sha256": image.digest_hex}:
        raise AttestationError(f"the statement is about {subjects[0].get('digest')}, not {image.digest}")
    if "predicate" not in statement:
        raise AttestationError("the statement has no predicate")
    return statement["predicate"]


@dataclass(frozen=True)
class Verifier:
    """The public key that must have signed every attestation."""

    public_key: Path
    lock: ToolLock
    tools_dir: Path
    platform: str | None = None

    def verify(self, bundle_path: Path, image: Image, predicate_type: str) -> Verified:
        """Verify one bundle about `image` offline. A bad signature, subject or type is a problem (not
        trusted); a Cosign binary that does not match the lock raises (the verification could not run)."""
        if not bundle_path.is_file():
            return Verified(None, "missing (unsigned)")
        if bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
            return Verified(None, f"larger than {MAX_BUNDLE_BYTES >> 20} MiB")
        data = bundle_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix="sentinel-verify-") as private:
            work = Path(private)
            copy = work / "bundle.json"
            copy.write_bytes(data)
            run = run_verified_tool(
                "cosign",
                [
                    "verify-blob-attestation",
                    "--key",
                    str(self.public_key.resolve()),
                    "--bundle",
                    str(copy),
                    "--type",
                    predicate_type,
                    "--digest",
                    image.digest_hex,
                    "--digestAlg",
                    "sha256",
                    "--insecure-ignore-tlog=true",  # private mode: nothing was uploaded to a log
                ],
                lock=self.lock,
                tools_dir=self.tools_dir,
                cwd=work,
                platform=self.platform,
                timeout_s=_TIMEOUT_S,
                allowed_exit_codes=(0, 1),
            )
        if run.returncode != 0:
            reason = run.stderr.strip().splitlines()[-1:] or ["no reason given"]
            return Verified(None, f"signature check failed: {reason[0][:300]}")
        try:
            return Verified(check_statement(statement_of(data), image, predicate_type), None)
        except AttestationError as exc:
            return Verified(None, str(exc))


def default_environ() -> Mapping[str, str]:
    return os.environ
