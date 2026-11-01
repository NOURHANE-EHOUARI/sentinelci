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
- The report is checked before it is used: it must name the verified Grype version, and the normalizer
  refuses a report that shows a silenced match or an invalid database (normalize/grype.py). The database
  Grype used (schema, build time, checksum) comes back with the report: it is evidence of what Grype knew.

Grype's report holds no secret (package names, versions and advisories), but it is still kept in a private
temporary directory: only the parsed report leaves this module.
"""

import json
import tempfile
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.grype import GrypeDatabase, check_grype_report
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import ToolLock
from sentinelci.scanners.runner import DEFAULT_TIMEOUT_S, ToolRun, is_within, run_verified_tool
from sentinelci.supplychain.sbom import OFFLINE_ENV, Sbom, generate_sbom


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
            f"Grype database directory {db_dir} does not exist (run `grype db update` into it)"
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
    (the repository); `db_dir` is Grype's prepared database directory."""
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
    return ScaScan(report=report, database=database, sbom=sbom, grype=run, scan_root=scan_root)
