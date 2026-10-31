"""SBOMs of a source tree or a built image with the pinned Syft, as CycloneDX and SPDX JSON (A4, SPEC §7).

Hardened like the scanners (SPEC §5): the binary is verified against tools.lock.toml right before it runs,
the process gets a minimal environment, and Syft never reads a configuration the scanned repository controls.
Syft loads `.syft.yaml` from its working directory and home, so it runs in private, empty ones, with
SentinelCI's own configuration passed explicitly (`configs/syft.yaml`: no network lookup, no tooling executed,
packages only). The proxy variables point at a closed local port, so nothing can leave the machine either.
Images are read from files the build wrote (an OCI layout or archive, a Docker archive), never pulled from a
registry.

The output is checked before anyone uses it: a CycloneDX document with a `serialNumber` (what binds the signed
SBOM to the vulnerability attestation, ADR-0010) and an SPDX document. Anything else fails closed.
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

SourceKind = Literal["dir", "oci-dir", "oci-archive", "docker-archive"]
SOURCE_KINDS: tuple[SourceKind, ...] = ("dir", "oci-dir", "oci-archive", "docker-archive")
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


def _check_cyclonedx(data: bytes) -> tuple[str, int]:
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
    return serial, len(components)


def _check_spdx(data: bytes) -> None:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"syft wrote an unreadable SPDX SBOM: {exc}") from exc
    if not isinstance(document, dict) or not str(document.get("spdxVersion", "")).startswith("SPDX-"):
        raise ScannerError("syft's SPDX output is not an SPDX document")


def generate_sbom(
    target: Path,
    *,
    kind: SourceKind,
    name: str,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> Sbom:
    """Run Syft on `target` (a source tree, or an image written by the build) and return both SBOMs."""
    if kind not in SOURCE_KINDS:
        raise ScannerError(f"unknown SBOM source kind {kind!r}")
    if not _NAME.fullmatch(name):
        raise ScannerError(f"SBOM name {name!r} is not a plain image or project name")
    source = target.resolve()
    if kind in ("dir", "oci-dir") and not source.is_dir():
        raise ScannerError(f"{target} is not a directory")
    if kind in ("oci-archive", "docker-archive") and not source.is_file():
        raise ScannerError(f"{target} is not a file")
    with tempfile.TemporaryDirectory(prefix="sentinel-syft-") as private:
        work = Path(private)
        cwd = work / "cwd"  # empty: Syft finds no .syft.yaml here
        cwd.mkdir()
        cyclonedx, spdx = work / "sbom.cdx.json", work / "sbom.spdx.json"
        with as_file(files("sentinelci.supplychain.configs").joinpath("syft.yaml")) as config:
            args = [
                f"{kind}:{source}",
                "-c", str(config),
                "--source-name", name,
                "-o", f"cyclonedx-json={cyclonedx}",
                "-o", f"spdx-json={spdx}",
                "-q",
            ]  # fmt: skip
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
        if not cyclonedx.is_file() or not spdx.is_file():
            raise ScannerError("syft wrote no SBOM")
        cyclonedx_data, spdx_data = cyclonedx.read_bytes(), spdx.read_bytes()
    serial, packages = _check_cyclonedx(cyclonedx_data)
    _check_spdx(spdx_data)
    return Sbom(cyclonedx=cyclonedx_data, spdx=spdx_data, serial_number=serial, packages=packages, run=run)
