"""`sentinel tools grype-db`: the verified Grype fills the database directory a scan reads (task A1).

Unit tests pin a fake `grype` that records how each `grype db ...` command was run. Integration tests use the
real Grype (SENTINEL_TOOLS_DIR) and never reach the internet: downloads go to a closed port, or to an https
server on 127.0.0.1 with a throwaway certificate (needs openssl). The test that reads a real database needs
SENTINEL_GRYPE_DB_DIR as well.
"""

import copy
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.normalize.grype import GrypeDatabase, load_grype_report
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.grype import (
    NETWORK_VARIABLES,
    check_archive_url,
    check_database,
    update_database,
)
from sentinelci.scanners.installer import install_tools
from sentinelci.scanners.lock import ToolLock, load_lock
from sentinelci.supplychain.sbom import OFFLINE_ENV

from .conftest import BASE, FakeReleases, raw_tool_lock, sha256
from .test_grype_scan import CONFIG
from .test_runner import PLATFORM

GOLDEN = Path(__file__).resolve().parents[1] / "normalize" / "fixtures" / "grype" / "grype-demo-shop.json"
# A real `grype db status -o json` of a valid database is the status object a report carries.
STATUS: dict[str, Any] = load_grype_report(GOLDEN)["descriptor"]["db"]["status"]
CHECKSUM = "sha256:d0e1af9e6491440e1a671d0a0aafc32c5c7cb5cda787dcec3482799ef298f31c"
DATABASE = GrypeDatabase(schema_version="v6.1.10", built="2026-11-01T06:20:12Z", checksum=CHECKSUM)
DIGEST = "sha256:" + "0" * 64
URL = f"https://mirror.example/vulnerability-db_v6.1.10.tar.zst?checksum={DIGEST}"
REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
# What a CI job may hold: none of it but the network settings may reach Grype.
JOB_ENV = {
    "HTTPS_PROXY": "http://proxy.example:3128",
    "NO_PROXY": "localhost",
    "SSL_CERT_FILE": "/etc/ssl/corporate.pem",
    "GITHUB_TOKEN": "fake-not-a-token",
    "GRYPE_DB_UPDATE_URL": "https://attacker.example/databases",
    "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "false",
}


class FakeGrype:
    """Records argv, environment, working directory (and its content) of each `grype db <command>`."""

    def __init__(self, root: Path) -> None:
        self.record = root / "record"
        self.record.mkdir()

    def ran(self) -> list[str]:
        return sorted(path.stem for path in self.record.glob("*.argv"))

    def argv(self, command: str) -> list[str]:
        return (self.record / f"{command}.argv").read_text().splitlines()

    def env(self, command: str) -> dict[str, str]:
        lines = (self.record / f"{command}.env").read_text().splitlines()
        return dict(line.split("=", 1) for line in lines if "=" in line)

    def cwd(self, command: str) -> tuple[str, list[str]]:
        cwd, *content = (self.record / f"{command}.cwd").read_text().splitlines()
        return cwd, content


def install_grype(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    *,
    status: object = STATUS,
    update_exit: int = 0,
    status_exit: int = 0,
) -> tuple[ToolLock, Path, FakeGrype]:
    """A fake grype pinned in a test lock. `db update` and `db import` exit with `update_exit` (an import
    keeps a copy of the archive it was given); `db status` prints `status` and exits with `status_exit`."""
    fake = FakeGrype(tmp_path)
    record = fake.record
    payload = tmp_path / "status.json"
    payload.write_text(status if isinstance(status, str) else json.dumps(status))
    script = f"""#!/bin/sh
name="$1-$2"
printf '%s\\n' "$@" > {record}/$name.argv
env > {record}/$name.env
{{ pwd; ls -A; }} > {record}/$name.cwd
while [ $# -gt 0 ]; do
  case "$1" in
    -c) cp "$2" {record}/$name.config; shift ;;
  esac
  shift
done
case "$name" in
  db-import) arg=$(sed -n 3p {record}/$name.argv)
    [ -f "$arg" ] && cp "$arg" {record}/imported
    exit {update_exit} ;;
  db-update) exit {update_exit} ;;
  db-status) cat {payload}; exit {status_exit} ;;
esac
exit 64
"""
    content = script.encode()
    releases.files[BASE.format(tool="grype") + "/grype-linux-amd64"] = content
    lock = load_lock(write_lock(raw_tool_lock(sha256(content), tool="grype")))
    dest = tmp_path / "tools"
    install_tools(lock, dest, platform=PLATFORM, fetch=releases.fetch)
    return lock, dest, fake


@pytest.fixture
def grype(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> tuple[ToolLock, Path, FakeGrype]:
    return install_grype(tmp_path, releases, write_lock)


def _update(setup: tuple[ToolLock, Path, FakeGrype], db: Path, **options: Any) -> Any:
    lock, dest, _ = setup
    options.setdefault("environ", JOB_ENV)
    return update_database(db, lock=lock, tools_dir=dest, platform=PLATFORM, **options)


def test_a_download_runs_the_verified_grype_with_sentinelcis_configuration_and_only_the_network_settings(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = grype[2]
    db = tmp_path / "cache" / "grype-db"
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".grype.yaml").write_text("db:\n  update-url: https://attacker.example/databases\n")
    prepared = _update(grype, db)
    assert prepared.database == DATABASE and prepared.archive_sha256 is None
    assert prepared.grype.version == "1.0.0" and prepared.grype.args[:2] == ("db", "update")
    assert fake.ran() == ["db-status", "db-update"] and db.is_dir()
    argv = fake.argv("db-update")
    assert argv[:3] == ["db", "update", "-c"] and len(argv) == 4
    assert (fake.record / "db-update.config").read_text() == CONFIG
    env = fake.env("db-update")
    assert env["GRYPE_DB_CACHE_DIR"] == str(db.resolve())
    assert {name: env[name] for name in ("HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")} == {
        name: JOB_ENV[name] for name in ("HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")
    }
    for name in ("GITHUB_TOKEN", "GRYPE_DB_UPDATE_URL", "GRYPE_DB_VALIDATE_BY_HASH_ON_START", "HTTP_PROXY"):
        assert name not in env, name
    cwd, content = fake.cwd("db-update")
    assert cwd != str(tmp_path) and content == [], "Grype runs in an empty private directory"


def test_the_status_check_runs_offline_with_the_scans_settings(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]
) -> None:
    fake = grype[2]
    db = tmp_path / "db"
    _update(grype, db)
    argv = fake.argv("db-status")
    assert argv[:5] == ["db", "status", "-o", "json", "-c"] and len(argv) == 6
    assert (fake.record / "db-status.config").read_text() == CONFIG
    env = fake.env("db-status")
    assert {name: env.get(name) for name in OFFLINE_ENV} == OFFLINE_ENV, "no proxy of the job: offline"
    assert env["GRYPE_DB_CACHE_DIR"] == str(db.resolve()) and env["GRYPE_DB_VALIDATE_AGE"] == "true"
    assert "GITHUB_TOKEN" not in env
    assert fake.cwd("db-status")[1] == []


def test_the_age_check_is_lifted_only_on_request(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]
) -> None:
    _update(grype, tmp_path / "db", allow_stale_db=True)
    assert grype[2].env("db-status")["GRYPE_DB_VALIDATE_AGE"] == "false"


def test_the_network_settings_are_the_only_variables_passed() -> None:
    assert set(NETWORK_VARIABLES) == {
        "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR",
    }  # fmt: skip


def test_without_environ_the_processs_own_proxy_is_used(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("https_proxy", "http://laptop-proxy.example:8080")
    monkeypatch.setenv("GITHUB_TOKEN", "fake-not-a-token")
    lock, dest, fake = grype
    update_database(tmp_path / "db", lock=lock, tools_dir=dest, platform=PLATFORM)
    env = fake.env("db-update")
    assert env["https_proxy"] == "http://laptop-proxy.example:8080" and "GITHUB_TOKEN" not in env


def test_a_local_archive_is_imported_offline_from_the_copy_that_was_digested(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]
) -> None:
    fake = grype[2]
    archive = tmp_path / "vulnerability-db.tar.zst"
    archive.write_bytes(b"archive bytes" * 100_000)
    prepared = _update(grype, tmp_path / "db", archive=str(archive))
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    assert prepared.archive_sha256 == digest and prepared.database == DATABASE
    argv = fake.argv("db-import")
    assert argv[:2] == ["db", "import"] and argv[3] == "-c" and len(argv) == 5
    assert argv[2] != str(archive) and Path(argv[2]).name == "archive", "Grype imports the private copy"
    assert (fake.record / "imported").read_bytes() == archive.read_bytes()
    assert not Path(argv[2]).exists(), "the copy is gone afterwards"
    env = fake.env("db-import")
    assert {name: env.get(name) for name in OFFLINE_ENV} == OFFLINE_ENV, "a local import downloads nothing"
    assert "SSL_CERT_FILE" not in env


def test_a_pinned_url_is_imported_through_the_jobs_network(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]
) -> None:
    fake = grype[2]
    prepared = _update(grype, tmp_path / "db", archive=URL)
    assert prepared.archive_sha256 is None
    assert fake.argv("db-import")[:3] == ["db", "import", URL]
    assert fake.env("db-import")["HTTPS_PROXY"] == JOB_ENV["HTTPS_PROXY"]


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        (URL.replace("https://", "http://"), "https URL"),
        (URL.replace("https://", "file://"), "https URL"),
        ("https:///db.tar.zst?checksum=" + DIGEST, "https URL"),
        ("https://mirror.example/db.tar.zst", "name the archive's digest"),
        (f"{URL}&checksum={DIGEST}", "name the archive's digest once"),
        (URL.replace(DIGEST, "sha256:" + "A" * 64), "digest"),
        (URL.replace(DIGEST, "sha256:" + "0" * 63), "digest"),
        (URL.replace(DIGEST, "sha512:" + "0" * 64), "digest"),
        (URL.replace(DIGEST, "0" * 64), "digest"),
        (URL.replace("https://", "https://user:fake-password@"), "credentials"),
        (URL.replace("https://", "https://user@"), "credentials"),
        (URL + "#top", "fragment"),
    ],
)
def test_an_unpinned_url_is_refused_before_anything_runs(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype], url: str, reason: str
) -> None:
    with pytest.raises(ScannerError, match=reason):
        _update(grype, tmp_path / "db", archive=url)
    assert grype[2].ran() == [] and not (tmp_path / "db").exists()


def test_a_pinned_url_passes_the_check() -> None:
    check_archive_url(URL)
    check_archive_url(URL.replace(DIGEST, "sha256%3A" + "0" * 64))  # Grype's own spelling


@pytest.mark.parametrize("problem", ["db-is-a-file", "no-archive", "archive-is-a-directory"])
def test_nothing_runs_on_a_bad_setup(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype], problem: str
) -> None:
    db = tmp_path / "db"
    archive = tmp_path / "archive.tar.zst"
    if problem == "db-is-a-file":
        db.write_text("not a directory")
        archive.write_bytes(b"x")
        match = "is not a directory"
    elif problem == "no-archive":
        match = "is not a file"
    else:
        archive.mkdir()
        match = "is not a file"
    with pytest.raises(ScannerError, match=match):
        _update(grype, db, archive=str(archive))
    assert grype[2].ran() == []


# What the real Grype prints for an empty directory (and exits 1).
NO_DATABASE = {
    "schemaVersion": "",
    "path": "/db/6/vulnerability.db",
    "valid": False,
    "error": "database does not exist",
}


def _status(**changes: object) -> dict[str, Any]:
    status = copy.deepcopy(STATUS)
    for key, value in changes.items():
        if value is None:
            status.pop(key, None)
        else:
            status[key] = value
    return status


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ({"update_exit": 1}, "grype exited with code 1"),
        (
            {"status": NO_DATABASE, "status_exit": 1},
            "grype db update left no usable database: Grype's vulnerability database is not valid: "
            "database does not exist",
        ),
        ({"status": _status(valid=False), "status_exit": 0}, "is not valid"),
        ({"status": _status(valid="true")}, "is not valid"),
        ({"status": _status(valid=None)}, "is not valid"),
        ({"status": _status(built=None)}, "has no built"),
        ({"status": _status(schemaVersion="  ")}, "has no schemaVersion"),
        ({"status": _status(), "status_exit": 1}, "exited with code 1 for a valid database"),
        ({"status_exit": 2}, "grype exited with code 2"),
        ({"status": "database is fine"}, "printed no JSON"),
        ({"status": "[]"}, "Grype database status is not an object"),
    ],
)
def test_the_update_fails_closed_unless_grype_calls_the_database_valid(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    setup: dict[str, Any],
    message: str,
) -> None:
    installed = install_grype(tmp_path, releases, write_lock, **setup)
    with pytest.raises(ScannerError, match=message.replace("(", r"\(")):
        _update(installed, tmp_path / "db")


def test_a_database_with_no_checksum_is_valid_but_says_so(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    status = _status(**{"from": "/work/sentinel-grype-db-x/archive"})
    lock, dest, _ = install_grype(tmp_path, releases, write_lock, status=status)
    database = check_database(tmp_path / "db", lock=lock, tools_dir=dest, platform=PLATFORM)
    assert database == GrypeDatabase(schema_version="v6.1.10", built="2026-11-01T06:20:12Z", checksum=None)


def _cli(dest: Path, db: Path, *extra: str) -> Any:
    return CliRunner().invoke(
        app,
        [
            "tools", "grype-db", "--db-dir", str(db), "--lock", str(dest.parent / "tools.lock.toml"),
            "--tools-dir", str(dest), "--platform", PLATFORM, *extra,
        ],
    )  # fmt: skip


def test_cli_prepares_the_database_and_writes_its_evidence(
    tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]
) -> None:
    archive = tmp_path / "db.tar.zst"
    archive.write_bytes(b"fake archive")
    report = tmp_path / "evidence" / "grype-db.json"
    result = _cli(grype[1], tmp_path / "db", "--archive", str(archive), "--report", str(report))
    assert result.exit_code == 0, result.output
    assert f"grype 1.0.0: database v6.1.10 built 2026-11-01T06:20:12Z (checksum {CHECKSUM})" in result.output
    assert json.loads(report.read_text()) == {
        "schema_version": 1,
        "grype": {"version": "1.0.0", "binary_sha256": grype[0].tools["grype"].artifacts[PLATFORM].sha256},
        "database": {"schema_version": "v6.1.10", "built": "2026-11-01T06:20:12Z", "checksum": CHECKSUM},
        "archive_sha256": "sha256:" + hashlib.sha256(b"fake archive").hexdigest(),
    }


def test_cli_fails_closed_and_removes_an_older_report(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _ = install_grype(tmp_path, releases, write_lock, update_exit=1)
    report = tmp_path / "grype-db.json"
    report.write_text("{}\n")
    result = _cli(dest, tmp_path / "db", "--report", str(report))
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output, result.output
    assert not report.exists()


def test_cli_refuses_an_unpinned_url(tmp_path: Path, grype: tuple[ToolLock, Path, FakeGrype]) -> None:
    result = _cli(grype[1], tmp_path / "db", "--archive", "https://mirror.example/db.tar.zst")
    assert result.exit_code == 3 and "checksum=sha256" in result.output
    assert grype[2].ran() == []


# ---------------------------------------------------------------- the real Grype

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)
with_database = pytest.mark.skipif(
    not (TOOLS_DIR and GRYPE_DB), reason="set SENTINEL_GRYPE_DB_DIR to a `sentinel tools grype-db` directory"
)
# The download goes to a closed port, wherever the tests run: they never fetch a database.
NO_NETWORK = {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}


@real
@pytest.mark.integration
def test_real_grype_update_fails_closed_when_the_download_fails(tmp_path: Path) -> None:
    db = tmp_path / "db"
    # The listing comes from the update URL pinned in SentinelCI's configuration, through the given proxy.
    listing = re.escape('unable to download listing: Get "https://grype.anchore.io/databases/v6/latest.json"')
    listing += ": proxyconnect"
    with pytest.raises(ScannerError, match=rf"(?s)grype exited with code 1: .*{listing}"):
        update_database(db, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), environ=NO_NETWORK)
    assert not list(db.rglob("vulnerability.db"))


@real
@pytest.mark.integration
def test_real_grype_refuses_an_archive_that_is_not_a_database(tmp_path: Path) -> None:
    archive = tmp_path / "vulnerability-db.tar.zst"
    archive.write_bytes(b"not a database")
    db = tmp_path / "db"
    with pytest.raises(ScannerError, match=r"(?s)grype exited with code 1: .*unable to import"):
        update_database(db, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), archive=str(archive))
    assert not list(db.rglob("vulnerability.db"))


@real
@pytest.mark.integration
def test_real_grype_status_of_an_empty_directory_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="is not valid: database does not exist"):
        check_database(tmp_path, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))


@real
@pytest.mark.integration
def test_real_cli_fails_closed_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in NO_NETWORK.items():
        monkeypatch.setenv(name, value)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    result = CliRunner().invoke(
        app,
        ["tools", "grype-db", "--db-dir", str(tmp_path / "db"), "--lock", str(REPO_LOCK),
         "--tools-dir", str(TOOLS_DIR)],
    )  # fmt: skip
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output, result.output


ARCHIVE = b"not a database"


@pytest.fixture
def https_archive(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    """(URL, CA certificate) of ARCHIVE served over https on 127.0.0.1 with a throwaway certificate."""
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl to make a test certificate")
    key, cert = tmp_path / "server.key", tmp_path / "server.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )  # fmt: skip

    class Archive(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(ARCHIVE)))
            self.end_headers()

        def do_GET(self) -> None:
            self.do_HEAD()
            self.wfile.write(ARCHIVE)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Archive)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/vulnerability-db.tar.zst", cert
    finally:
        server.shutdown()
        server.server_close()


@real
@pytest.mark.integration
def test_real_grype_checks_the_digest_the_url_names_over_verified_tls(
    tmp_path: Path, https_archive: tuple[str, Path]
) -> None:
    url, cert = https_archive
    right = "sha256:" + hashlib.sha256(ARCHIVE).hexdigest()

    def refusal(digest: str, environ: dict[str, str]) -> str:
        with pytest.raises(ScannerError) as refused:
            update_database(
                tmp_path / "db",
                lock=load_lock(REPO_LOCK),
                tools_dir=Path(str(TOOLS_DIR)),
                archive=f"{url}?checksum={digest}",
                environ=environ,
            )
        return str(refused.value)

    with_ca = {"SSL_CERT_FILE": str(cert)}  # the job's CA variable reaches the download
    assert "Checksums did not match" in refusal("sha256:" + "1" * 64, with_ca)
    right_digest = refusal(right, with_ca)  # past the digest check: refused as an archive
    assert "Checksums did not match" not in right_digest and "unable to import" in right_digest
    assert "certificate signed by unknown authority" in refusal(right, {})
    assert not list((tmp_path / "db").rglob("vulnerability.db"))


@with_database
@pytest.mark.integration
def test_real_grype_status_of_a_prepared_database(tmp_path: Path) -> None:
    database = check_database(
        Path(str(GRYPE_DB)), lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), allow_stale_db=True
    )
    assert database.schema_version.startswith("v6.") and database.built
    assert database.checksum is None or database.checksum.startswith("sha256:")
