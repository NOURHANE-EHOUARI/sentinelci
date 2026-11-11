"""`sentinel scan sca`: the verified Syft's SBOM, matched offline by the verified Grype (task A1).

Unit tests pin a fake `syft` and a fake `grype` in one test lock. Integration tests use the real binaries
and run only when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory; the ones that match
need a Grype database too (SENTINEL_GRYPE_DB_DIR, a directory `sentinel tools grype-db` filled), which these
tests never download.
"""

import copy
import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Run
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.grype import load_grype_report, normalize_grype
from sentinelci.scanners import runner
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.grype import SbomScanFailure, grype_env, match_sbom, scan_sca
from sentinelci.scanners.installer import install_tools
from sentinelci.scanners.lock import ToolLock, load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.sbom import OFFLINE_ENV, generate_sbom

from .conftest import BASE, FakeReleases, raw_tool_lock, sha256
from .test_runner import PLATFORM

GOLDEN = Path(__file__).resolve().parents[1] / "normalize" / "fixtures" / "grype"
GOLDEN_REPORT = load_grype_report(GOLDEN / "grype-demo-shop.json")
GOLDEN_SBOM = (GOLDEN / "demo-shop.syft.json").read_text(encoding="utf-8")
CONFIG = files("sentinelci.scanners.configs").joinpath("grype.yaml").read_text(encoding="utf-8")
REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {"component": {"type": "file", "name": "NOURHANE-EHOUARI/sentinelci"}},
    "components": [{"type": "library", "name": "log4j-core"}],
}
SPDX = {"spdxVersion": "SPDX-2.3", "packages": [], "relationships": []}
REPO = "NOURHANE-EHOUARI/sentinelci"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _report(version: str = "1.0.0", **configuration: object) -> dict[str, Any]:
    """The golden report as the fake Grype (version 1.0.0 in the test lock) writes it."""
    report = copy.deepcopy(GOLDEN_REPORT)
    report["descriptor"]["version"] = version
    report["descriptor"]["configuration"].update(configuration)
    return report


class Fakes:
    def __init__(self, root: Path) -> None:
        self.record = root / "record"
        self.payloads = root / "payloads"
        self.record.mkdir()
        self.payloads.mkdir()

    def lines(self, name: str) -> list[str]:
        return (self.record / name).read_text().splitlines()

    def env(self, tool: str) -> dict[str, str]:
        return dict(line.split("=", 1) for line in self.lines(f"{tool}.env") if "=" in line)


def install_fakes(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    *,
    report: object = None,
    grype_exit: int = 0,
    grype_stderr: str = "",
    syft_json: object = GOLDEN_SBOM,
) -> tuple[ToolLock, Path, Fakes]:
    """A fake syft and a fake grype, pinned in one lock. Syft writes the given documents to its `-o fmt=path`
    outputs; Grype copies the SBOM it was given and writes `report` to its `-o json=path` output."""
    fakes = Fakes(tmp_path)
    documents = {"cyclonedx-json": CYCLONEDX, "spdx-json": SPDX, "syft-json": syft_json, "grype": report}
    for name, document in documents.items():
        if document is None:
            continue
        text = document if isinstance(document, str) else json.dumps(document)
        (fakes.payloads / name).write_text(text)
    record, payloads = fakes.record, fakes.payloads
    syft = f"""printf '%s\\n' "$@" > {record}/syft.argv
env > {record}/syft.env
while [ $# -gt 0 ]; do
  case "$1" in
    -o) fmt="${{2%%=*}}"; out="${{2#*=}}"; [ -f "{payloads}/$fmt" ] && cp "{payloads}/$fmt" "$out"; shift ;;
  esac
  shift
done
"""
    grype = f"""printf '%s\\n' "$@" > {record}/grype.argv
env > {record}/grype.env
pwd > {record}/grype.cwd
cp "${{1#sbom:}}" {record}/grype.sbom
while [ $# -gt 0 ]; do
  case "$1" in
    -c) cp "$2" {record}/grype.config; shift ;;
    -o) out="${{2#json=}}"; [ -f "{payloads}/grype" ] && cp "{payloads}/grype" "$out"; shift ;;
  esac
  shift
done
printf '%s' '{grype_stderr}' >&2
exit {grype_exit}
"""
    lock_text = "schema_version = 1\n"
    for tool, script in (("syft", syft), ("grype", grype)):
        content = ("#!/bin/sh\n" + script).encode()
        releases.files[BASE.format(tool=tool) + f"/{tool}-linux-amd64"] = content
        lock_text += raw_tool_lock(sha256(content), tool=tool).replace("schema_version = 1\n", "", 1)
    lock = load_lock(write_lock(lock_text))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)
    return lock, dest, fakes


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """(repository, scanned directory in it, database directory). The repository brings its own Grype
    configuration, which must never be loaded."""
    repo = tmp_path / "repo"
    target = repo / "demo-shop"
    target.mkdir(parents=True)
    (target / ".grype.yaml").write_text("only-fixed: true\nignore:\n  - vulnerability: GHSA-jfh8-c2jp-5v3q\n")
    db = tmp_path / "grype-db"
    db.mkdir()
    return repo, target, db


def _scan(lock: ToolLock, dest: Path, repo: Path, target: Path, db: Path, **options: Any):  # type: ignore[no-untyped-def]
    return scan_sca(
        target, repo_root=repo, name=REPO, db_dir=db, lock=lock, tools_dir=dest, platform=PLATFORM, **options
    )


def test_grype_matches_syfts_sbom_isolated_offline_with_sentinelcis_config(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("GRYPE_ONLY_FIXED", "true")  # a GRYPE_* variable of the job never reaches Grype
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "somewhere-else"))
    lock, dest, fakes = install_fakes(tmp_path, releases, write_lock, report=_report())
    repo, target, db = _tree(tmp_path)
    monkeypatch.chdir(target)  # the scanned directory as working directory: its .grype.yaml is still ignored

    scan = _scan(lock, dest, repo, target, db)

    argv = fakes.lines("grype.argv")
    sbom = Path(argv[0].removeprefix("sbom:"))
    assert argv[0].startswith("sbom:") and not sbom.is_relative_to(repo) and not sbom.exists()
    assert (fakes.record / "grype.sbom").read_text() == GOLDEN_SBOM, "Grype reads the SBOM Syft wrote"
    assert (fakes.record / "grype.config").read_text() == CONFIG, (
        "SentinelCI's configuration, passed explicitly"
    )
    assert not Path(argv[argv.index("-c") + 1]).is_relative_to(repo)
    assert argv[argv.index("-o") + 1].startswith("json=") and "-q" not in argv
    cwd = Path(fakes.lines("grype.cwd")[0])
    assert not cwd.is_relative_to(repo) and not cwd.exists(), (
        "a private working directory, gone after the run"
    )
    env = fakes.env("grype")
    assert "GITHUB_TOKEN" not in env and "GRYPE_ONLY_FIXED" not in env
    assert env["GRYPE_DB_CACHE_DIR"] == str(db.resolve())
    assert env["GRYPE_DB_VALIDATE_AGE"] == "true", "a stale database fails the scan by default"
    for key, value in OFFLINE_ENV.items():
        assert env.get(key) == value, key
    syft_argv = fakes.lines("syft.argv")
    outputs = [syft_argv[i + 1].split("=", 1)[0] for i, arg in enumerate(syft_argv) if arg == "-o"]
    assert outputs == ["cyclonedx-json", "spdx-json", "syft-json"], "one Syft run writes all three"
    assert syft_argv[0] == f"dir:{target.resolve()}"
    assert scan.report == _report() and scan.scan_root == "demo-shop"
    assert (scan.database.schema_version, scan.database.built) == ("v6.1.10", "2026-11-01T06:20:12Z")
    assert scan.grype.tool == "grype" and scan.sbom.syft_json == GOLDEN_SBOM.encode()


def test_the_age_check_is_lifted_only_on_request(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, fakes = install_fakes(tmp_path, releases, write_lock, report=_report())
    repo, target, db = _tree(tmp_path)
    _scan(lock, dest, repo, target, db, allow_stale_db=True)
    assert fakes.env("grype")["GRYPE_DB_VALIDATE_AGE"] == "false"
    assert grype_env(db)["GRYPE_DB_VALIDATE_AGE"] == "true"


def test_the_whole_repository_is_scan_root_dot(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    repo, _, db = _tree(tmp_path)
    assert _scan(lock, dest, repo, repo, db).scan_root == "."


@pytest.mark.parametrize("problem", ["no-database", "outside", "not-a-directory"])
def test_nothing_runs_on_a_bad_setup(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], problem: str
) -> None:
    lock, dest, fakes = install_fakes(tmp_path, releases, write_lock, report=_report())
    repo, target, db = _tree(tmp_path)
    if problem == "no-database":
        db.rmdir()
    elif problem == "outside":
        target = tmp_path / "elsewhere"
        target.mkdir()
    else:
        target = target / "file.txt"
        target.write_text("x")
    with pytest.raises(
        SbomScanFailure, match=r"does not exist|outside the repository|is not a directory"
    ) as raised:
        _scan(lock, dest, repo, target, db)
    assert isinstance(raised.value.error, ScannerError)
    # A target that cannot be scanned is Syft's failure; a missing database is Grype's, after Syft's SBOM.
    assert (raised.value.tool, raised.value.sbom is None) == (
        ("grype", False) if problem == "no-database" else ("syft", True)
    )
    assert not (fakes.record / "grype.argv").exists()
    if problem != "no-database":
        assert not (fakes.record / "syft.argv").exists()


@pytest.mark.parametrize(
    ("options", "message", "tool"),
    [
        ({"grype_exit": 1, "grype_stderr": "failed to load vulnerability db: database does not exist"},
         "grype exited with code 1: failed to load vulnerability db", "grype"),
        ({"report": None}, "grype wrote no readable report", "grype"),
        ({"report": "{not json"}, "grype wrote no readable report", "grype"),
        ({"report": []}, "not a JSON object", "grype"),
        ({"report": _report(**{"only-fixed": True})}, "cannot be trusted: .*only-fixed", "grype"),
        ({"report": _report(version="0.121.0")}, "names Grype 0.121.0, but the verified binary is 1.0.0",
         "grype"),
        ({"syft_json": None}, "syft wrote no SBOM", "syft"),
        ({"syft_json": {"descriptor": {"name": "trivy"}, "artifacts": []}}, "not a Syft document", "syft"),
        ({"syft_json": {"descriptor": {"name": "syft"}}}, "artifacts` is not a list", "syft"),
    ],
)  # fmt: skip
def test_anything_short_of_a_trusted_report_fails_closed(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    options: dict[str, Any],
    message: str,
    tool: str,
) -> None:
    lock, dest, _ = install_fakes(tmp_path, releases, write_lock, **{"report": _report(), **options})
    repo, target, db = _tree(tmp_path)
    with pytest.raises(SbomScanFailure, match=message) as raised:
        _scan(lock, dest, repo, target, db)
    assert isinstance(raised.value.error, ScannerError) and raised.value.tool == tool, (
        "names the tool that failed"
    )


def test_the_configuration_hides_nothing_and_stays_offline() -> None:
    for line in (
        "check-for-app-update: false",
        "only-fixed: false",
        "only-notfixed: false",
        'ignore-wontfix: ""',
        "ignore: []",
        "exclude: []",
        "vex-documents: []",
        "vex-add: []",
        'distro: ""',
        "by-cve: false",
        "timestamp: false",
        "  enable: false",
        "  auto-update: false",
        "  validate-by-hash-on-start: true",
        "  max-allowed-built-age: 120h",
        '  update-url: "https://grype.anchore.io/databases"',
        '  ca-cert: ""',
    ):
        assert line in CONFIG.splitlines(), line


def _cli(repo: Path, target: Path, db: Path, dest: Path, out: Path, *extra: str) -> Any:
    return CliRunner().invoke(
        app,
        [
            "scan", "sca", str(target), "--out", str(out), "--repo", REPO, "--commit", COMMIT,
            "--context", "pr", "--db-dir", str(db), "--repo-root", str(repo),
            "--lock", str(dest.parent / "tools.lock.toml"), "--tools-dir", str(dest), "--platform", PLATFORM,
            *extra,
        ],
    )  # fmt: skip


def test_cli_writes_sca_findings_with_repository_paths(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    repo, target, db = _tree(tmp_path)
    out = tmp_path / "out" / "sca.ndjson"
    result = _cli(repo, target, db, dest, out)
    assert result.exit_code == 0, result.output
    assert "grype 1.0.0 on the SBOM of syft 1.0.0 (1 package(s)), database v6.1.10" in result.output
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(findings) == 36 and {f["category"] for f in findings} == {"SCA"}
    assert {f["location"]["path"] for f in findings} == {
        "demo-shop/services/reports/pom.xml",
        "demo-shop/services/shop-api/requirements.txt",
        "demo-shop/services/web/package-lock.json",
    }


def test_cli_fails_closed_and_leaves_no_findings_file(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report(**{"by-cve": True}))
    repo, target, db = _tree(tmp_path)
    out = tmp_path / "sca.ndjson"
    out.write_text("stale\n")
    result = _cli(repo, target, db, dest, out)
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output and "by-cve" in result.output
    assert not out.exists()


# ---------------------------------------------------------------- the real Syft and Grype

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
# ---------------------------------------------------------------- tool status (the gate's SC-010, A3)


def _validator() -> Any:
    from jsonschema import Draft202012Validator

    root = Path(__file__).resolve().parents[3]
    return Draft202012Validator(json.loads((root / "schemas" / "tool-status.v1.json").read_text("utf-8")))


def _sca_status(tmp_path: Path, dest: Path, *extra: str) -> tuple[Any, Path, dict[str, Any] | None]:
    """Run the CLI over a stale findings file and a stale status; (result, findings path, status or None)."""
    repo, target, db = _tree(tmp_path)
    out, status = tmp_path / "sca.ndjson", tmp_path / "status.json"
    out.write_text("stale\n")
    status.write_text("stale")
    result = _cli(repo, target, db, dest, out, "--tool-status-out", str(status), *extra)
    if not status.exists():
        return result, out, None
    document = json.loads(status.read_text())
    assert not list(_validator().iter_errors(document)), document
    return result, out, document


def test_cli_records_syft_and_grype_ok_after_the_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    result, out, document = _sca_status(tmp_path, dest)
    assert result.exit_code == 0, result.output
    assert document is not None and len(out.read_text().splitlines()) == 36
    for tool in ("syft", "grype"):
        binary = hashlib.sha256((dest / "bin" / tool).read_bytes()).hexdigest()
        assert document["tools"][tool] == {
            "version": "1.0.0", "binary_sha256": binary, "artifact_sha256": binary, "status": "ok"
        }  # fmt: skip
    lock_bytes = (dest.parent / "tools.lock.toml").read_bytes()
    assert document["lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()


@pytest.mark.parametrize(
    ("options", "syft", "grype", "detail"),
    [
        ({"syft_json": None}, "failed", "not_run", "syft wrote no SBOM"),
        ({"grype_exit": 1, "grype_stderr": "failed to load vulnerability db"}, "ok", "failed",
         "grype exited with code 1"),
        ({"report": _report(**{"by-cve": True})}, "ok", "failed", "by-cve"),
    ],
    ids=["syft-fails", "grype-fails", "grype-report-untrusted"],
)  # fmt: skip
def test_cli_records_which_tool_failed_and_that_grype_never_ran_after_syft(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    options: dict[str, Any],
    syft: str,
    grype: str,
    detail: str,
) -> None:
    _, dest, fakes = install_fakes(tmp_path, releases, write_lock, **{"report": _report(), **options})
    result, out, document = _sca_status(tmp_path, dest)
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output, result.output
    assert not out.exists() and document is not None
    tools = document["tools"]
    assert (tools["syft"]["status"], tools["grype"]["status"]) == (syft, grype)
    failed = "syft" if syft != "ok" else "grype"
    assert detail in tools[failed]["detail"] and "binary_sha256" not in tools[failed]
    if grype == "not_run":
        assert tools["grype"] == {"version": "1.0.0", "status": "not_run",
                                  "detail": "not started: Syft produced no SBOM"}  # fmt: skip
        assert not (fakes.record / "grype.argv").exists()


def test_cli_a_finding_grype_reported_that_cannot_be_normalized_is_grypes_failure(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.cli as cli

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise NormalizationError("a match without a location")

    monkeypatch.setattr(cli, "normalize_grype", refuse)
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    result, out, document = _sca_status(tmp_path, dest)
    assert result.exit_code == 3 and not out.exists() and document is not None
    assert document["tools"]["syft"]["status"] == "ok"
    assert document["tools"]["grype"]["status"] == "failed"
    assert document["tools"]["grype"]["detail"] == "a match without a location"


@pytest.mark.parametrize("tool", ["syft", "grype"])
def test_cli_records_a_tampered_binary_that_never_ran(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], tool: str
) -> None:
    _, dest, fakes = install_fakes(tmp_path, releases, write_lock, report=_report())
    (dest / "bin" / tool).write_text(f"#!/bin/sh\ntouch {fakes.record}/tampered-ran\n")
    result, out, document = _sca_status(tmp_path, dest)
    assert result.exit_code == 3 and not out.exists() and document is not None
    assert not (fakes.record / "tampered-ran").exists()
    assert document["tools"][tool]["status"] == "integrity_mismatch"
    other = {"syft": "grype", "grype": "syft"}[tool]
    assert document["tools"][other]["status"] == ("not_run" if tool == "syft" else "ok")


def test_cli_records_a_timeout(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="syft", timeout=kwargs["timeout"])

    monkeypatch.setattr(runner.subprocess, "run", slow)
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    result, out, document = _sca_status(tmp_path, dest, "--timeout", "37")
    assert result.exit_code == 3 and not out.exists() and document is not None
    assert document["tools"]["syft"]["status"] == "timeout" and "37 s" in document["tools"]["syft"]["detail"]
    assert document["tools"]["grype"]["status"] == "not_run"


def test_cli_writes_no_status_without_a_lock(tmp_path: Path) -> None:
    # Nothing to vouch for: no status at all, which the gate reports as SC-010 "Tool status missing".
    dest = tmp_path / "tools"
    dest.mkdir()
    result, out, document = _sca_status(tmp_path, dest)
    assert result.exit_code == 3 and document is None and not out.exists()


def test_cli_passes_its_time_limit_to_both_tools(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[int] = []
    real = runner.subprocess.run

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs["timeout"])
        return real(*args, **kwargs)

    monkeypatch.setattr(runner.subprocess, "run", spy)
    _, dest, _ = install_fakes(tmp_path, releases, write_lock, report=_report())
    result, _, _ = _sca_status(tmp_path, dest, "--timeout", "1234")
    assert result.exit_code == 0, result.output
    assert seen and set(seen) == {1234}, "every Syft and Grype run gets the limit"


real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)
with_database = pytest.mark.skipif(
    not (TOOLS_DIR and GRYPE_DB), reason="set SENTINEL_GRYPE_DB_DIR to a `sentinel tools grype-db` directory"
)


@real
@pytest.mark.integration
def test_real_grype_without_a_database_fails_closed_offline(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(GOLDEN_SBOM)
    empty = tmp_path / "db"
    empty.mkdir()
    with pytest.raises(ScannerError, match=r"grype exited with code 1: .*database does not exist"):
        match_sbom(sbom, db_dir=empty, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    assert list(empty.iterdir()) == [], "nothing was downloaded"


@real
@pytest.mark.integration
def test_real_grype_loads_sentinelcis_configuration_over_a_local_one(tmp_path: Path) -> None:
    (tmp_path / ".grype.yaml").write_text(
        "only-fixed: true\nby-cve: true\nexclude: ['./x']\n"
        "db:\n  update-url: https://attacker.example/databases\n  max-allowed-built-age: 8760h\n"
    )
    with as_file(files("sentinelci.scanners.configs").joinpath("grype.yaml")) as config:
        run = run_verified_tool(
            "grype",
            ["-c", str(config), "config", "--load"],
            lock=load_lock(REPO_LOCK),
            tools_dir=Path(str(TOOLS_DIR)),
            cwd=tmp_path,  # where Grype would find the .grype.yaml
            extra_env=grype_env(tmp_path),
        )
    loaded = run.stdout.splitlines()
    for line in (
        "only-fixed: false",
        "by-cve: false",
        "exclude: []",
        "timestamp: false",
        "  auto-update: false",
        "  update-url: 'https://grype.anchore.io/databases'",
        "  max-allowed-built-age: 120h0m0s",
    ):
        assert line in loaded, line


@with_database
@pytest.mark.integration
def test_real_grype_reproduces_the_golden_report_with_its_database(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(GOLDEN_SBOM)
    report, database, _ = match_sbom(
        sbom,
        db_dir=Path(str(GRYPE_DB)),
        lock=load_lock(REPO_LOCK),
        tools_dir=Path(str(TOOLS_DIR)),
        allow_stale_db=True,
    )
    golden = GOLDEN_REPORT["descriptor"]["db"]["status"]["from"]
    if database.checksum is None or database.checksum not in golden.replace("%3A", ":"):
        pytest.skip(f"the golden report was made with another database ({database.checksum} here)")
    # descriptor.timestamp and descriptor.db differ on every run; the configuration is SentinelCI's here.
    for key in ("matches", "source", "distro"):
        assert report[key] == GOLDEN_REPORT[key], key
    run = Run(repo=REPO, commit=COMMIT, context="pr")
    assert len(normalize_grype(report, run=run)) == 36


@with_database
@pytest.mark.integration
def test_real_scan_finds_what_the_repository_tries_to_hide(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("pyyaml==5.3.1\n")
    (repo / ".grype.yaml").write_text("ignore:\n  - vulnerability: GHSA-8q59-q68h-6hv4\n")
    (repo / ".syft.yaml").write_text('exclude: ["./requirements.txt"]\n')
    scan = scan_sca(
        repo,
        repo_root=repo,
        name=REPO,
        db_dir=Path(str(GRYPE_DB)),
        lock=load_lock(REPO_LOCK),
        tools_dir=Path(str(TOOLS_DIR)),
        allow_stale_db=True,
    )
    findings = normalize_grype(scan.report, run=Run(repo=REPO, commit=COMMIT, context="pr"), scan_root=".")
    pyyaml = [f for f in findings if f.rule_id == "GHSA-8q59-q68h-6hv4"]
    assert len(pyyaml) == 1 and pyyaml[0].location is not None
    assert pyyaml[0].location.path == "requirements.txt"


@real
@pytest.mark.integration
def test_real_syft_names_files_from_the_scanned_directory_in_its_own_format(tmp_path: Path) -> None:
    """The path convention normalize/grype.py relies on: `/services/...`, from the scanned directory."""
    repo = tmp_path / "repo"
    (repo / "services" / "api").mkdir(parents=True)
    (repo / "services" / "api" / "requirements.txt").write_text("pyyaml==5.3.1\n")
    lock, tools = load_lock(REPO_LOCK), Path(str(TOOLS_DIR))
    sbom = generate_sbom(repo, kind="dir", name=REPO, lock=lock, tools_dir=tools, syft_json=True)
    assert sbom.syft_json is not None
    native = json.loads(sbom.syft_json)
    packages = [
        (a["name"], a["version"], [loc["path"] for loc in a["locations"]]) for a in native["artifacts"]
    ]
    assert packages == [("pyyaml", "5.3.1", ["/services/api/requirements.txt"])]
    assert (native["source"]["type"], native["source"]["name"]) == ("directory", REPO)
    assert [c["name"] for c in json.loads(sbom.cyclonedx)["components"]] == ["pyyaml"], "the same run"
