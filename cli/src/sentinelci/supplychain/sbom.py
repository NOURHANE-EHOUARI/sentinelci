"""SBOMs of a source tree or a built image with the pinned Syft, as CycloneDX and SPDX JSON (A4, SPEC §7).

Hardened like the scanners (SPEC §5): the binary is verified against tools.lock.toml right before it runs,
the process gets a minimal environment, and Syft never reads a configuration the scanned repository controls.
Syft loads `.syft.yaml` from its working directory and home, so it runs in private, empty ones, with
SentinelCI's own configuration passed explicitly (`configs/syft.yaml`: no network lookup, no tooling executed,
packages only). The proxy variables point at a closed local port, so nothing can leave the machine either.
Images are read from the OCI layout the build wrote (a directory, or a tar of one), never pulled from a
registry. A Docker archive is not accepted: Syft names it by a digest it computes over its own
reconstruction of the manifest, which no registry knows, so its SBOM would name an image that does not exist.

The output is checked before anyone uses it: a CycloneDX document with a `serialNumber` (what binds the signed
SBOM to the vulnerability attestation, ADR-0010) and an SPDX document. For an image, both must name the
manifest digest the build produced (`image_digest`): an SBOM of another image, or of an image Syft read
differently, never passes for this one. Anything else fails closed.
"""

import json
import re
import tempfile
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Literal

from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, run_verified_tool

SourceKind = Literal["dir", "oci-dir", "oci-archive"]
SOURCE_KINDS: tuple[SourceKind, ...] = ("dir", "oci-dir", "oci-archive")
IMAGE_KINDS: tuple[SourceKind, ...] = ("oci-dir", "oci-archive")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_SERIAL = re.compile(r"urn:uuid:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,127}")
_NO_NETWORK_PROXY = "http://127.0.0.1:9"
OFFLINE_ENV = {
    "HTTPS_PROXY": _NO_NETWORK_PROXY,
    "HTTP_PROXY": _NO_NETWORK_PROXY,
    "ALL_PROXY": _NO_NETWORK_PROXY,
    "https_proxy": _NO_NETWORK_PROXY,
    "http_proxy": _NO_NETWORK_PROXY,
    "all_proxy": _NO_NETWORK_PROXY,
    "NO_PROXY": "",
    "no_proxy": "",
    "GIT_ALLOW_PROTOCOL": "none",
}


@dataclass(frozen=True)
class Sbom:
    cyclonedx: bytes
    spdx: bytes
    serial_number: str
    packages: int
    run: ToolRun
    # Syft's own format, from the same run, when asked for: Grype's input for SCA (scanners/grype.py).
    syft_json: bytes | None = None


def _count_packages(components: list[object]) -> int:
    """Packages, without the operating-system component Syft adds for an image (it is not a package)."""
    return sum(1 for c in components if not (isinstance(c, dict) and c.get("type") == "operating-system"))


def _check_cyclonedx(data: bytes) -> tuple[str, int, object]:
    """(serialNumber, package count, the subject's version: the manifest digest for an image)."""
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"syft wrote an unreadable CycloneDX SBOM: {exc}") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ScannerError("syft's CycloneDX output is not a CycloneDX document")
    serial = document.get("serialNumber")
    if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
        raise ScannerError("syft's CycloneDX SBOM has no serialNumber (urn:uuid:...)")
    components = document.get("components", [])
    if not isinstance(components, list):
        raise ScannerError("syft's CycloneDX SBOM `components` is not a list")
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    version = component.get("version") if isinstance(component, dict) else None
    return serial, _count_packages(components), version


def _check_spdx(data: bytes) -> list[object]:
    """The versions of the packages the SPDX document DESCRIBES (for an image: its manifest digest)."""
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"syft wrote an unreadable SPDX SBOM: {exc}") from exc
    if not isinstance(document, dict) or not str(document.get("spdxVersion", "")).startswith("SPDX-"):
        raise ScannerError("syft's SPDX output is not an SPDX document")
    packages = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(packages, list) or not isinstance(relationships, list):
        return []
    versions = {p.get("SPDXID"): p.get("versionInfo") for p in packages if isinstance(p, dict)}
    return [
        versions.get(r.get("relatedSpdxElement"))
        for r in relationships
        if isinstance(r, dict)
        and r.get("relationshipType") == "DESCRIBES"
        and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
    ]


def _check_syft_json(data: bytes) -> None:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"syft wrote an unreadable syft-json SBOM: {exc}") from exc
    descriptor = document.get("descriptor") if isinstance(document, dict) else None
    if not isinstance(descriptor, dict) or descriptor.get("name") != "syft":
        raise ScannerError("syft's syft-json output is not a Syft document")
    if not isinstance(document.get("artifacts"), list):
        raise ScannerError("syft's syft-json SBOM `artifacts` is not a list")


def generate_sbom(
    target: Path,
    *,
    kind: SourceKind,
    name: str,
    lock: ToolLock,
    tools_dir: Path,
    image_digest: str | None = None,
    platform: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    syft_json: bool = False,
) -> Sbom:
    """Run Syft on `target` (a source tree, or the OCI layout of an image the build wrote) and return both
    SBOMs. An image needs `image_digest`, its manifest digest: both SBOMs must name it. With `syft_json`, the
    same run also writes Syft's own format (the input Grype matches best)."""
    if kind not in SOURCE_KINDS:
        raise ScannerError(f"unknown SBOM source kind {kind!r} (one of {', '.join(SOURCE_KINDS)})")
    if (kind in IMAGE_KINDS) != (image_digest is not None):
        raise ScannerError(
            "an image source needs its manifest digest (--image-digest), and only an image source takes one"
        )
    if image_digest is not None and not _DIGEST.fullmatch(image_digest):
        raise ScannerError(f"image digest {image_digest!r} is not sha256:<64 lowercase hex>")
    if not _NAME.fullmatch(name):
        raise ScannerError(f"SBOM name {name!r} is not a plain image or project name")
    source = target.resolve()
    if kind in ("dir", "oci-dir") and not source.is_dir():
        raise ScannerError(f"{target} is not a directory")
    if kind == "oci-archive" and not source.is_file():
        raise ScannerError(f"{target} is not a file")
    with tempfile.TemporaryDirectory(prefix="sentinel-syft-") as private:
        work = Path(private)
        cwd = work / "cwd"  # empty: Syft finds no .syft.yaml here
        cwd.mkdir()
        cyclonedx, spdx, native = work / "sbom.cdx.json", work / "sbom.spdx.json", work / "sbom.syft.json"
        with as_file(files("sentinelci.supplychain.configs").joinpath("syft.yaml")) as config:
            # No -q: Syft's error is the reason recorded for SC-010, and a run without a TTY is quiet.
            args = [
                f"{kind}:{source}",
                "-c", str(config),
                "--source-name", name,
                "-o", f"cyclonedx-json={cyclonedx}",
                "-o", f"spdx-json={spdx}",
            ]  # fmt: skip
            if syft_json:
                args += ["-o", f"syft-json={native}"]
            if kind == "dir":
                args += ["--base-path", str(source)]  # no link is followed above the tree
            run = run_verified_tool(
                "syft",
                args,
                lock=lock,
                tools_dir=tools_dir,
                cwd=cwd,
                platform=platform,
                timeout_s=timeout_s,
                extra_env=OFFLINE_ENV,
            )
        if not cyclonedx.is_file() or not spdx.is_file() or (syft_json and not native.is_file()):
            raise ScannerError("syft wrote no SBOM")
        cyclonedx_data, spdx_data = cyclonedx.read_bytes(), spdx.read_bytes()
        native_data = native.read_bytes() if syft_json else None
    serial, packages, subject = _check_cyclonedx(cyclonedx_data)
    described = _check_spdx(spdx_data)
    if native_data is not None:
        _check_syft_json(native_data)
    if image_digest is not None and (subject != image_digest or described != [image_digest]):
        raise ScannerError(
            f"syft describes the image as {subject!r} (CycloneDX) and {described!r} (SPDX), not "
            f"{image_digest}: the file is not an OCI layout of the image that was built"
        )
    return Sbom(
        cyclonedx=cyclonedx_data,
        spdx=spdx_data,
        serial_number=serial,
        packages=packages,
        run=run,
        syft_json=native_data,
    )
