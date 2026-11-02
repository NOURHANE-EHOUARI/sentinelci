"""Sign and verify release attestations with the pinned Cosign, key pair and no transparency log (ADR-0010).

Every call goes through `run_verified_tool`: the binary is checked against tools.lock.toml right before it
runs, and the process gets a minimal environment. When signing, only the key variable (for `env://VAR` keys)
and `COSIGN_PASSWORD` are added to it; in registry mode, also `DOCKER_CONFIG` when it is set (the registry
credentials). When verifying a bundle, it is copied to a private directory first, and the statement is parsed
from the very bytes Cosign verified: a file swapped in between cannot be trusted. In registry mode the
statements are parsed from what Cosign printed after verifying them, and re-checked (type, one subject, this
digest).

Registry mode (Cosign 3): `cosign sign` and `cosign attest` store a Sigstore bundle per statement as an OCI
referrer of the image (or, on a registry without the referrers API, in the `sha256-<hex>` tag index). The
image signature is itself a DSSE statement of type `https://sigstore.dev/cosign/sign/v1`, and `cosign verify`
accepts any statement the key signed about the digest as a signature, attestations included: so the image
signature check here requires a statement of that type.
"""

import base64
import binascii
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import ToolRun, run_verified_tool
from sentinelci.supplychain.attestations import AttestationError, Image

STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"})
SIGNATURE_TYPE = (
    "https://sigstore.dev/cosign/sign/v1"  # the statement `cosign sign` writes (Cosign 3 bundles)
)
NO_TRANSPARENCY_LOG = ("--tlog-upload=false", "--use-signing-config=false")  # private mode (ADR-0006)
# A registry verification that ran and failed: 1, or Cosign's codes for an image without signature (10), a
# non-existent tag (11), no matching signature (12), no certificate (13). Any other code: it could not run.
NOT_VERIFIED_EXIT_CODES = (1, 10, 11, 12, 13)
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"
MAX_BUNDLE_BYTES = 64 << 20
_ENV_KEY = re.compile(r"env://(?P<var>[A-Z_][A-Z0-9_]{0,63})")
_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----")
# What Cosign 3.1 says when the registry was read and holds nothing of a type; anything else (an HTTP error,
# a refused connection) means the registry could not be read, and the release check must not pass on it.
_NOTHING_ATTACHED = re.compile(
    r"no matching attestations|none of the attestations matched the predicate type"
)
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
class Registry:
    """How Cosign reaches the image's registry. Plain HTTP only when asked (a local registry, such as the
    kind cluster's: see `registry_for`); credentials only from `DOCKER_CONFIG` (the directory of a Docker
    config.json), if set."""

    allow_http: bool = False

    def flags(self) -> list[str]:
        return ["--allow-http-registry"] if self.allow_http else []

    @staticmethod
    def env(environ: Mapping[str, str]) -> dict[str, str]:
        config = environ.get("DOCKER_CONFIG")
        return {"DOCKER_CONFIG": config} if config else {}


def registry_for(image: Image, *, allow_http: bool) -> Registry:
    """The registry settings for `image`. Plain HTTP is for a local registry only (`check_local_registry`)."""
    if allow_http:
        check_local_registry(image.name)
    return Registry(allow_http=allow_http)


def check_local_registry(name: str) -> None:
    """AttestationError unless the registry of `name` (an image name, or a prefix of one) is local: a
    loopback host, or a single-label host with a port (kind's `kind-registry:5000`). Plain HTTP anywhere else
    would send the image and, with `DOCKER_CONFIG`, the registry credentials across the network in clear."""
    host = _registry_host(name)
    if host is None:
        raise AttestationError(
            f"{name} names no registry host: plain HTTP (--registry-http) needs a local one"
        )
    if not (_is_loopback(host) or "." not in host):  # a single label: localhost, or kind-registry:5000
        raise AttestationError(
            "plain HTTP (--registry-http) is for a local registry only (loopback, or a single-label "
            f"host with a port such as kind-registry:5000), not {host}"
        )


def _registry_host(name: str) -> str | None:
    """The host of the registry in an image name, without its port, or None when the name has none: its first
    part is a registry only with a dot, a port or as `localhost` (otherwise it is a Docker Hub repository)."""
    first, slash, _ = name.partition("/")
    if not slash or not ("." in first or ":" in first or first == "localhost"):
        return None
    return first.partition(":")[0]


def _repository(image: Image) -> str:
    """The image's repository, without a tag (`host:5000/demo-shop/api:v1` -> `host:5000/demo-shop/api`)."""
    head, slash, last = image.name.rpartition("/")
    return f"{head}{slash}{last.partition(':')[0]}"


def _is_loopback(name: str) -> bool:
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def _last_line(text: str) -> str:
    return (text.strip().splitlines()[-1:] or ["no reason given"])[0][:300]


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

    def public_key(self, environ: Mapping[str, str]) -> str:
        """The PEM public key of the signing key (`cosign public-key`): what the registry is checked with."""
        key, env = self._key_env(environ)
        with tempfile.TemporaryDirectory(prefix="sentinel-public-key-") as private:
            run = run_verified_tool(
                "cosign",
                ["public-key", "--key", key],
                lock=self.lock,
                tools_dir=self.tools_dir,
                cwd=Path(private),
                platform=self.platform,
                timeout_s=_TIMEOUT_S,
                extra_env=env,
            )
        match = _PUBLIC_KEY.search(run.stdout)
        if match is None:
            raise AttestationError("cosign public-key printed no PEM public key")
        return match.group(0) + "\n"

    def _push(
        self, args: list[str], image: Image, registry: Registry, environ: Mapping[str, str], work: Path
    ) -> None:
        run_verified_tool(
            "cosign",
            [*args, *NO_TRANSPARENCY_LOG, *registry.flags(), "--yes", image.reference],
            lock=self.lock,
            tools_dir=self.tools_dir,
            cwd=work,
            platform=self.platform,
            timeout_s=_TIMEOUT_S,
            extra_env=self._key_env(environ)[1] | Registry.env(environ),
        )

    def sign_image(self, image: Image, registry: Registry, environ: Mapping[str, str]) -> None:
        """Sign the image itself in its registry (`cosign sign`, by digest)."""
        key, _ = self._key_env(environ)
        with tempfile.TemporaryDirectory(prefix="sentinel-sign-") as private:
            self._push(["sign", "--key", key], image, registry, environ, Path(private))

    def attest_image(
        self,
        image: Image,
        predicate_type: str,
        predicate: Any,
        registry: Registry,
        environ: Mapping[str, str],
    ) -> None:
        """Attach one signed in-toto statement about `image` to it in its registry (`cosign attest`)."""
        key, _ = self._key_env(environ)
        with tempfile.TemporaryDirectory(prefix="sentinel-attest-") as private:
            work = Path(private)
            predicate_file = work / "predicate.json"
            predicate_file.write_text(json.dumps(predicate, sort_keys=True), encoding="utf-8")
            args = ["attest", "--key", key, "--type", predicate_type, "--predicate", str(predicate_file)]
            self._push(args, image, registry, environ, work)


@dataclass(frozen=True)
class Verified:
    """The outcome for one attestation: the predicate when everything held, otherwise why not."""

    predicate: Any | None
    problem: str | None


@dataclass(frozen=True)
class Attached:
    """What the key signed about an image in its registry, for one type: distinct predicates by canonical
    JSON, or why Cosign verified none (`reason`)."""

    predicates: dict[str, Any]
    reason: str | None


def canonical(predicate: Any) -> str:
    return json.dumps(predicate, sort_keys=True, separators=(",", ":"))


def statement_of(bundle_data: bytes) -> dict[str, Any]:
    """The in-toto statement inside a Sigstore bundle (DSSE envelope); AttestationError if malformed."""
    try:
        bundle = json.loads(bundle_data)
        envelope = bundle["dsseEnvelope"]
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationError(f"not a Sigstore bundle with a DSSE envelope: {exc}") from exc
    try:
        return statement_of_envelope(envelope)
    except AttestationError as exc:
        raise AttestationError(f"not a Sigstore bundle with a valid DSSE envelope: {exc}") from exc


def statement_of_envelope(envelope: Any) -> dict[str, Any]:
    """The in-toto statement of a DSSE envelope; AttestationError if malformed."""
    try:
        if envelope["payloadType"] != IN_TOTO_PAYLOAD:
            raise AttestationError(
                f"the envelope holds {envelope['payloadType']!r}, not an in-toto statement"
            )
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise AttestationError(f"malformed DSSE envelope: {exc}") from exc
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
            return Verified(None, f"signature check failed: {_last_line(run.stderr)}")
        try:
            return Verified(check_statement(statement_of(data), image, predicate_type), None)
        except AttestationError as exc:
            return Verified(None, str(exc))

    def _registry(
        self, args: list[str], image: Image, registry: Registry, environ: Mapping[str, str]
    ) -> ToolRun:
        with tempfile.TemporaryDirectory(prefix="sentinel-verify-") as private:
            return run_verified_tool(
                "cosign",
                [*args, "--key", str(self.public_key.resolve()), "--insecure-ignore-tlog=true",
                 *registry.flags(), image.reference],
                lock=self.lock,
                tools_dir=self.tools_dir,
                cwd=Path(private),
                platform=self.platform,
                timeout_s=_TIMEOUT_S,
                allowed_exit_codes=(0, *NOT_VERIFIED_EXIT_CODES),
                extra_env=Registry.env(environ),
            )  # fmt: skip

    def verify_signature(self, image: Image, registry: Registry, environ: Mapping[str, str]) -> Verified:
        """The image itself is signed by the key in its registry: a `cosign sign` statement about this digest.
        A signed attestation is not enough, although `cosign verify` accepts one (Cosign 3 bundles)."""
        run = self._registry(["verify", "--output", "json"], image, registry, environ)
        if run.returncode != 0:
            return Verified(None, f"signature check failed: {_last_line(run.stderr)}")
        try:
            entries = json.loads(run.stdout)
            critical = [entry["critical"] for entry in entries]
            signed = [
                c for c in critical
                if c["type"] == SIGNATURE_TYPE and c["image"]["docker-manifest-digest"] == image.digest
            ]  # fmt: skip
        except (KeyError, TypeError, ValueError) as exc:
            return Verified(None, f"unreadable Cosign output: {type(exc).__name__}")
        if not signed:
            types = sorted({str(c.get("type")) for c in critical if isinstance(c, dict)})
            return Verified(None, f"no image signature (cosign sign) about this digest; signed: {types}")
        return Verified(len(signed), None)

    def attached(
        self, image: Image, predicate_type: str, registry: Registry, environ: Mapping[str, str]
    ) -> Attached:
        """The distinct statements of `predicate_type` the key signed about the image in its registry, after
        Cosign's check and ours (type, one subject, this digest). AttestationError when one is malformed."""
        run = self._registry(["verify-attestation", "--type", predicate_type], image, registry, environ)
        if run.returncode != 0:
            return Attached({}, _last_line(run.stderr))
        predicates: dict[str, Any] = {}
        try:
            for line in (line for line in run.stdout.splitlines() if line.strip()):
                predicate = check_statement(statement_of_envelope(json.loads(line)), image, predicate_type)
                predicates[canonical(predicate)] = predicate
        except ValueError as exc:
            raise AttestationError(f"unreadable Cosign output: {exc}") from exc
        return Attached(predicates, None if predicates else "Cosign verified no statement")

    def verify_in_registry(
        self, image: Image, predicate_type: str, registry: Registry, environ: Mapping[str, str]
    ) -> Verified:
        """The attestation of `predicate_type` attached to the image, verified by Cosign then re-checked. A
        re-run of the attest job attaches the same statement again (the predicates read neither the clock nor
        the run attempt), which is one attestation; two different ones of the same type are ambiguous and
        trusted for neither."""
        try:
            found = self.attached(image, predicate_type, registry, environ)
        except AttestationError as exc:
            return Verified(None, str(exc)[:300])
        if found.reason is not None:
            return Verified(None, f"missing or not signed by the key: {found.reason}")
        if len(found.predicates) != 1:
            return Verified(None, f"{len(found.predicates)} different attestations of this type: ambiguous")
        return Verified(next(iter(found.predicates.values())), None)


def refuse_another_release(
    signer: Signer,
    image: Image,
    statements: Mapping[str, tuple[str, Any]],
    registry: Registry,
    environ: Mapping[str, str],
) -> None:
    """Before anything is signed: AttestationError when the registry already holds, for one of the release's
    types, a statement the same key signed about this digest that differs from the one about to be attached.

    A digest has one release per registry. A second, different one would make every later verification
    ambiguous (NOT TRUSTED), while Kyverno, which reads one statement per type, could still admit the image:
    the two verifiers would disagree. Attaching the same statements again (a re-run) is allowed. A registry
    that cannot be read (an HTTP error, a refused connection) stops the release too: only Cosign's own
    "nothing attached" answers count as an empty registry."""
    with tempfile.TemporaryDirectory(prefix="sentinel-release-check-") as private:
        public_key = Path(private) / "release.pub"
        public_key.write_text(signer.public_key(environ), encoding="ascii")
        verifier = Verifier(public_key, signer.lock, signer.tools_dir, signer.platform)
        for kind, (predicate_type, predicate) in statements.items():
            found = verifier.attached(image, predicate_type, registry, environ)
            if found.reason is not None and not _NOTHING_ATTACHED.search(found.reason):
                raise AttestationError(f"cannot read the {kind} attestations in the registry: {found.reason}")
            if set(found.predicates) - {canonical(predicate)}:
                raise AttestationError(
                    f"the registry already holds a different {kind} attestation of {image.digest}, signed by "
                    "this key: a digest has one release per registry. Remove the old release first (on a "
                    f"registry without the referrers API: crane delete {_repository(image)}:"
                    f"sha256-{image.digest_hex}), then attest again"
                )


def default_environ() -> Mapping[str, str]:
    return os.environ
