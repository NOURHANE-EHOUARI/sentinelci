"""Software composition analysis of a source tree: the pinned Syft's SBOM, matched by the pinned Grype
(task A1, SPEC §5 stage 3).

Neither tool can be configured by the scanned repository:
- Syft runs exactly as for `sentinel sbom` (supplychain/sbom.py): verified binary, private working directory
  and home, SentinelCI's configuration passed explicitly, offline, no link followed above the tree. The same
  run writes Syft's own format, which Grype matches best (it keeps the Maven group of a pom dependency).
- Grype never sees the repository: it reads that SBOM, from a private working directory and home, with
  SentinelCI's configuration (`configs/grype.yaml`) passed explicitly. A `.grype.yaml` in the repository is
  never loaded and the GRYPE_* variables of the job are not inherited, so nothing the author of a change
  writes can add an ignore rule, a VEX document or `only-fixed`.
- The vulnerability database is a directory the pipeline prepared (`db_dir`, Grype's cache directory). The
  scan never downloads anything: auto-update is off and the network is closed (the proxy variables point at
  a closed port). Grype checks the database against its own hash before use, and refuses one built more than
  five days ago: a stale database misses recent vulnerabilities, so the scan fails closed (SC-010).
  `allow_stale_db` lifts the age check, for replays and tests only.
- That directory is filled by `update_database` (`sentinel tools grype-db`), with the same verified Grype and
  the same configuration: the latest database from the update URL pinned in `configs/grype.yaml`, or an
  archive the caller names (a local file, digested before import, or an https URL that names its sha256).
  Only this step uses the network, through the job's proxy if it has one. Whatever it exits with, the result
  counts only if Grype's own status check, run offline afterwards, calls the database valid.
- The report is checked before it is used: it must name the verified Grype version, and the normalizer
  refuses a report that shows a silenced match or an invalid database (normalize/grype.py). The database
  Grype used (schema, build time, checksum) comes back with the report: it is evidence of what Grype knew.

Grype's report holds no secret (package names, versions and advisories), but it is still kept in a private
temporary directory: only the parsed report leaves this module.
"""

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.grype import GrypeDatabase, check_grype_report, database_of_status
from sentinelci.scanners.errors import ScannerError, ToolIntegrityError
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, is_within, run_verified_tool
from sentinelci.supplychain.sbom import OFFLINE_ENV, Sbom, generate_sbom


class SbomScanFailure(Exception):
    """Which tool of a Syft-then-Grype scan failed (`syft`, or `grype` once the SBOM exists), and why: the
    tool status names each tool's own outcome, and Grype never runs when Syft failed."""

    def __init__(self, tool: str, error: Exception, sbom: Sbom | None = None) -> None:
        super().__init__(str(error))
        self.tool = tool
        self.error = error
        self.sbom = sbom


@dataclass(frozen=True)
class ImageScan:
    report: dict[str, Any]
    database: GrypeDatabase
    sbom: Sbom  # names the image's manifest digest (generate_sbom checks it)
    grype: ToolRun


@dataclass(frozen=True)
class ScaScan:
    report: dict[str, Any]
    database: GrypeDatabase
    sbom: Sbom
    grype: ToolRun
    # The scanned directory relative to the repository root: where the report's paths start.
    scan_root: str


def scan_root_of(target: Path, repo_root: Path) -> str:
    """`target` relative to `repo_root` (`.` for the root itself); a target outside the repository fails."""
    if not target.is_dir():
        raise ScannerError(f"{target} is not a directory")
    if not is_within(target, repo_root):
        raise ScannerError(f"scan target {target} is outside the repository root {repo_root}")
    return target.resolve().relative_to(repo_root.resolve()).as_posix() or "."


def grype_env(db_dir: Path, *, allow_stale_db: bool = False) -> dict[str, str]:
    """Grype's run-time settings: the prepared database, offline (the rest is in configs/grype.yaml)."""
    return {
        **OFFLINE_ENV,
        "GRYPE_DB_CACHE_DIR": str(db_dir.resolve()),
        "GRYPE_DB_VALIDATE_AGE": "false" if allow_stale_db else "true",
    }


# The only variables of the job the database download sees: how to reach the network from it. No token, key or
# GRYPE_* setting is passed (Grype's settings are SentinelCI's configuration file).
NETWORK_VARIABLES = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_CHUNK = 1 << 20
_SHA256 = re.compile(r"sha256:[a-f0-9]{64}")


@dataclass(frozen=True)
class PreparedDatabase:
    database: GrypeDatabase
    # The `grype db update` or `grype db import` run that filled the directory.
    grype: ToolRun
    # A local archive's digest, computed on the copy Grype imported (None for a download).
    archive_sha256: str | None = None


def network_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The job's proxy and CA settings, and nothing else of its environment."""
    return {name: environ[name] for name in NETWORK_VARIABLES if name in environ}


def check_archive_url(url: str) -> None:
    """A database fetched by URL is pinned: https, no credentials in the URL, and exactly one
    `checksum=sha256:<hex>` that Grype checks the download against."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ScannerError("a Grype database URL must be an https URL")
    if parts.username is not None or parts.password is not None:
        raise ScannerError("a Grype database URL must not carry credentials")
    if parts.fragment:
        raise ScannerError("a Grype database URL must not have a fragment")
    checksums = parse_qs(parts.query).get("checksum", [])
    if len(checksums) != 1 or not _SHA256.fullmatch(checksums[0]):
        raise ScannerError(
            "a Grype database URL must name the archive's digest once: ?checksum=sha256:<64 lowercase hex>"
        )


def _copy_archive(archive: Path, destination: Path) -> str:
    """Copy `archive` and digest the copy in the same pass: Grype imports exactly the bytes digested."""
    if not archive.is_file():
        raise ScannerError(f"Grype database archive {archive} is not a file")
    digest = hashlib.sha256()
    try:
        with archive.open("rb") as source, destination.open("xb") as copy:
            while chunk := source.read(_CHUNK):
                digest.update(chunk)
                copy.write(chunk)
    except OSError as exc:
        raise ScannerError(f"cannot read Grype database archive {archive}: {exc}") from exc
    return f"sha256:{digest.hexdigest()}"


def check_database(
    db_dir: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    allow_stale_db: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> GrypeDatabase:
    """Grype's own status check of the database in `db_dir`, offline, with the scan's settings: anything but a
    valid database fails closed, with Grype's reason."""
    with (
        tempfile.TemporaryDirectory(prefix="sentinel-grype-db-") as private,
        as_file(files("sentinelci.scanners.configs").joinpath("grype.yaml")) as config,
    ):
        status = run_verified_tool(
            "grype",
            ["db", "status", "-o", "json", "-c", str(config)],
            lock=lock,
            tools_dir=tools_dir,
            cwd=Path(private),  # empty: Grype finds no .grype.yaml here
            platform=platform,
            timeout_s=timeout_s,
            allowed_exit_codes=(0, 1),  # 1: an invalid database, whose reason is in the JSON
            extra_env=grype_env(db_dir, allow_stale_db=allow_stale_db),
        )
    try:
        database = database_of_status(json.loads(status.stdout))
    except json.JSONDecodeError as exc:
        raise ScannerError(f"grype db status printed no JSON: {exc}") from exc
    except NormalizationError as exc:
        raise ScannerError(str(exc)) from exc
    if status.returncode != 0:
        raise ScannerError(f"grype db status exited with code {status.returncode} for a valid database")
    return database


def update_database(
    db_dir: Path,
    *,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    archive: str | None = None,
    allow_stale_db: bool = False,
    environ: Mapping[str, str] | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> PreparedDatabase:
    """Fill `db_dir` with a vulnerability database, using the verified Grype and SentinelCI's configuration.

    Without `archive`, the latest database from the update URL pinned in configs/grype.yaml. With it, that
    archive: a local file, or an https URL that names its sha256 (`check_archive_url`). Fails closed unless
    the update succeeds and `check_database` then calls the database valid. `environ` (default: this
    process's) only provides the proxy and CA settings of a download.
    """
    if db_dir.exists() and not db_dir.is_dir():
        raise ScannerError(f"Grype database directory {db_dir} is not a directory")
    if archive is not None and "://" in archive:
        check_archive_url(archive)
    db_dir.mkdir(parents=True, exist_ok=True)
    network = network_env(os.environ if environ is None else environ)
    archive_sha256 = None
    with tempfile.TemporaryDirectory(prefix="sentinel-grype-db-") as private:
        work = Path(private)
        cwd = work / "cwd"  # empty: Grype finds no .grype.yaml here
        cwd.mkdir()
        if archive is None:
            args = ["db", "update"]
        elif "://" in archive:
            args = ["db", "import", archive]
        else:
            copy = work / "archive"
            archive_sha256 = _copy_archive(Path(archive), copy)
            args = ["db", "import", str(copy)]
            network = dict(OFFLINE_ENV)  # a local import has nothing to download
        with as_file(files("sentinelci.scanners.configs").joinpath("grype.yaml")) as config:
            # No -q: Grype's error is the reason recorded for SC-010.
            run = run_verified_tool(
                "grype",
                [*args, "-c", str(config)],
                lock=lock,
                tools_dir=tools_dir,
                cwd=cwd,
                platform=platform,
                timeout_s=timeout_s,
                extra_env={**network, "GRYPE_DB_CACHE_DIR": str(db_dir.resolve())},
            )
    try:
        database = check_database(
            db_dir,
            lock=lock,
            tools_dir=tools_dir,
            platform=platform,
            allow_stale_db=allow_stale_db,
            timeout_s=timeout_s,
        )
    except ScannerError as exc:
        raise ScannerError(f"grype {' '.join(args[:2])} left no usable database: {exc}") from exc
    return PreparedDatabase(database=database, grype=run, archive_sha256=archive_sha256)


def match_sbom(
    sbom: Path,
    *,
    db_dir: Path,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    allow_stale_db: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> tuple[dict[str, Any], GrypeDatabase, ToolRun]:
    """Run the verified Grype on a Syft SBOM, offline, against the database in `db_dir`."""
    if not db_dir.is_dir():
        raise ScannerError(
            f"Grype database directory {db_dir} does not exist (run `sentinel tools grype-db --db-dir` first)"
        )
    with tempfile.TemporaryDirectory(prefix="sentinel-grype-") as private:
        work = Path(private)
        cwd = work / "cwd"  # empty: Grype finds no .grype.yaml here
        cwd.mkdir()
        report = work / "grype.json"
        with as_file(files("sentinelci.scanners.configs").joinpath("grype.yaml")) as config:
            # No -q: Grype's error is the reason recorded for SC-010.
            run = run_verified_tool(
                "grype",
                [f"sbom:{sbom.resolve()}", "-c", str(config), "-o", f"json={report}"],
                lock=lock,
                tools_dir=tools_dir,
                cwd=cwd,
                platform=platform,
                timeout_s=timeout_s,
                extra_env=grype_env(db_dir, allow_stale_db=allow_stale_db),
            )
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScannerError(f"grype wrote no readable report: {exc}") from exc
    if not isinstance(data, dict):
        raise ScannerError("grype's report is not a JSON object")
    try:
        tool, database = check_grype_report(data)
    except NormalizationError as exc:
        raise ScannerError(f"grype's report cannot be trusted: {exc}") from exc
    if tool.version != run.version:
        raise ScannerError(f"the report names Grype {tool.version}, but the verified binary is {run.version}")
    return data, database, run


def scan_sca(
    target: Path,
    *,
    repo_root: Path,
    name: str,
    db_dir: Path,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    allow_stale_db: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ScaScan:
    """SBOM of `target` with the verified Syft, then the verified Grype on it. `name` names the SBOM's subject
    (the repository); `db_dir` is Grype's prepared database directory.

    A failure is an SbomScanFailure naming the tool that failed: a target that cannot be scanned counts as
    Syft's, and Grype never runs when Syft failed."""
    try:
        scan_root = scan_root_of(target, repo_root)
        sbom = generate_sbom(
            target,
            kind="dir",
            name=name,
            lock=lock,
            tools_dir=tools_dir,
            platform=platform,
            timeout_s=timeout_s,
            syft_json=True,
        )
        if sbom.syft_json is None:  # generate_sbom checked it; kept for the type checker
            raise ScannerError("syft wrote no syft-json SBOM")
    except (ToolIntegrityError, ScannerError) as exc:
        raise SbomScanFailure("syft", exc) from exc
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-sca-") as private:
            path = Path(private) / "sbom.syft.json"
            path.write_bytes(sbom.syft_json)
            report, database, run = match_sbom(
                path,
                db_dir=db_dir,
                lock=lock,
                tools_dir=tools_dir,
                platform=platform,
                allow_stale_db=allow_stale_db,
                timeout_s=timeout_s,
            )
    except (ToolIntegrityError, ScannerError) as exc:
        raise SbomScanFailure("grype", exc, sbom) from exc
    return ScaScan(report=report, database=database, sbom=sbom, grype=run, scan_root=scan_root)


def scan_image(
    archive: Path,
    *,
    image_digest: str,
    name: str,
    db_dir: Path,
    lock: ToolLock,
    tools_dir: Path,
    platform: str | None = None,
    allow_stale_db: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ImageScan:
    """Vulnerabilities of an image: the verified Syft's SBOM of its OCI layout archive (what
    `docker buildx build --output type=oci` writes), matched by the verified Grype, offline. `image_digest` is
    its manifest digest: Syft must find that image in the archive, and the report must be about it.

    A failure is an SbomScanFailure naming the tool that failed: Grype never runs when Syft failed."""
    try:
        sbom = generate_sbom(
            archive,
            kind="oci-archive",
            name=name,
            lock=lock,
            tools_dir=tools_dir,
            image_digest=image_digest,
            platform=platform,
            timeout_s=timeout_s,
            syft_json=True,
        )
        if sbom.syft_json is None:  # generate_sbom checked it; kept for the type checker
            raise ScannerError("syft wrote no syft-json SBOM")
    except (ToolIntegrityError, ScannerError) as exc:
        raise SbomScanFailure("syft", exc) from exc
    try:
        with tempfile.TemporaryDirectory(prefix="sentinel-image-") as private:
            path = Path(private) / "sbom.syft.json"
            path.write_bytes(sbom.syft_json)
            report, database, run = match_sbom(
                path,
                db_dir=db_dir,
                lock=lock,
                tools_dir=tools_dir,
                platform=platform,
                allow_stale_db=allow_stale_db,
                timeout_s=timeout_s,
            )
    except (ToolIntegrityError, ScannerError) as exc:
        raise SbomScanFailure("grype", exc, sbom) from exc
    return ImageScan(report=report, database=database, sbom=sbom, grype=run)
