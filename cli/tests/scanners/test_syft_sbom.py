"""`sentinel sbom`: Syft hardened like the scanners, offline, never configured by the scanned repository (A4).

Unit tests use a fake `syft` pinned in a test lock. Integration tests use the real binary and run only when
SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import load_lock
from sentinelci.supplychain.sbom import OFFLINE_ENV, generate_sbom

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": SERIAL,
    "components": [{"name": "a"}],
}
SPDX = {"spdxVersion": "SPDX-2.3", "name": "demo-shop"}
REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
CONFIG = files("sentinelci.supplychain.configs").joinpath("syft.yaml").read_text(encoding="utf-8")


def fake_syft(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    cyclonedx: object = CYCLONEDX,
    spdx: object = SPDX,
    exit_code: int = 0,
) -> tuple[Path, Path]:
    """A fake syft that records its call and writes the given documents to its `-o fmt=path` outputs."""
    record = tmp_path / "record"
    record.mkdir()
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    for name, document in (("cyclonedx-json", cyclonedx), ("spdx-json", spdx)):
        text = document if isinstance(document, str) else json.dumps(document)
        (payloads / name).write_text(text)
    script = f"""printf '%s\\n' "$@" > {record}/argv
env > {record}/env
pwd > {record}/cwd
while [ $# -gt 0 ]; do
  case "$1" in
    -c) cp "$2" {record}/config; shift ;;
    -o) fmt="${{2%%=*}}"; out="${{2#*=}}"; [ -f "{payloads}/$fmt" ] && cp "{payloads}/$fmt" "$out"; shift ;;
  esac
  shift
done
exit {exit_code}
"""
    _, dest = install_script(tmp_path, releases, write_lock, script, tool="syft")
    return dest, record


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "requirements.txt").write_text("flask==3.1.0\n")
    (target / ".syft.yaml").write_text('exclude: ["**"]\n')  # the repository's own config: never loaded
    return target


def _generate(tmp_path: Path, dest: Path, target: Path, kind: str = "dir"):  # type: ignore[no-untyped-def]
    return generate_sbom(
        target,
        kind=kind,  # type: ignore[arg-type]
        name="demo-shop",
        lock=load_lock(tmp_path / "tools.lock.toml"),
        tools_dir=dest,
        platform=PLATFORM,
    )


def test_syft_runs_isolated_with_sentinelcis_config(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("SYFT_EXCLUDE", "**")  # a SYFT_* variable of the job never reaches Syft
    dest, record = fake_syft(tmp_path, releases, write_lock)
    target = _target(tmp_path)

    sbom = _generate(tmp_path, dest, target)

    argv = (record / "argv").read_text().splitlines()
    assert argv[0] == f"dir:{target.resolve()}"
    assert argv[argv.index("--source-name") + 1] == "demo-shop"
    assert argv[argv.index("--base-path") + 1] == str(target.resolve())
    assert "-q" in argv
    assert (record / "config").read_text() == CONFIG, "SentinelCI's configuration, passed explicitly"
    assert not Path(argv[argv.index("-c") + 1]).is_relative_to(target)
    cwd = Path((record / "cwd").read_text().strip())
    assert not cwd.is_relative_to(target) and not cwd.exists(), (
        "a private working directory, gone after the run"
    )
    env = dict(line.split("=", 1) for line in (record / "env").read_text().splitlines() if "=" in line)
    assert "GITHUB_TOKEN" not in env and "SYFT_EXCLUDE" not in env
    for key, value in OFFLINE_ENV.items():
        assert env.get(key) == value, key
    assert json.loads(sbom.cyclonedx) == CYCLONEDX and json.loads(sbom.spdx) == SPDX
    assert (sbom.serial_number, sbom.packages, sbom.run.tool) == (SERIAL, 1, "syft")


def test_the_configuration_keeps_syft_offline_and_reports_packages_only() -> None:
    for line in (
        "check-for-app-update: false",
        "enrich: []",
        "  search-remote-licenses: false",
        "  use-network: false",
        "  use-packages-lib: false",
        "  vcpkg-allow-git-clone: false",
        "    selection: none",
    ):
        assert line in CONFIG.splitlines(), line


@pytest.mark.parametrize("kind", ["oci-archive", "docker-archive"])
def test_images_are_read_from_the_file_the_build_wrote(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], kind: str
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    image = tmp_path / "image.tar"
    image.write_bytes(b"not really a tar")
    _generate(tmp_path, dest, image, kind=kind)
    argv = (record / "argv").read_text().splitlines()
    assert argv[0] == f"{kind}:{image.resolve()}" and "--base-path" not in argv


@pytest.mark.parametrize(
    ("cyclonedx", "spdx", "exit_code", "message"),
    [
        ({**CYCLONEDX, "serialNumber": None}, SPDX, 0, "no serialNumber"),
        ({**CYCLONEDX, "serialNumber": "3e671687-395b-41f5-a30f-a58921a69b79"}, SPDX, 0, "no serialNumber"),
        ({"bomFormat": "SPDX"}, SPDX, 0, "not a CycloneDX document"),
        ("{not json", SPDX, 0, "unreadable CycloneDX"),
        ({**CYCLONEDX, "components": {}}, SPDX, 0, "not a list"),
        (CYCLONEDX, {"spdxVersion": "2.3"}, 0, "not an SPDX document"),
        (CYCLONEDX, "[]", 0, "not an SPDX document"),
        (CYCLONEDX, SPDX, 1, "exited with code 1"),
    ],
    ids=["null-serial", "serial-not-urn", "not-cyclonedx", "unreadable", "components-not-list",
         "spdx-version", "spdx-not-object", "syft-fails"],
)  # fmt: skip
def test_unusable_output_fails_closed(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    cyclonedx: object,
    spdx: object,
    exit_code: int,
    message: str,
) -> None:
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx=cyclonedx, spdx=spdx, exit_code=exit_code)
    with pytest.raises(ScannerError, match=message):
        _generate(tmp_path, dest, _target(tmp_path))


def test_no_output_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _ = fake_syft(tmp_path, releases, write_lock)
    for payload in (tmp_path / "payloads").iterdir():
        payload.unlink()
    with pytest.raises(ScannerError, match="wrote no SBOM"):
        _generate(tmp_path, dest, _target(tmp_path))


@pytest.mark.parametrize(
    ("kind", "make", "name", "message"),
    [
        ("dir", lambda p: p.write_text("x"), "demo-shop", "is not a directory"),
        ("oci-archive", lambda p: p.mkdir(), "demo-shop", "is not a file"),
        ("dir", lambda p: p.mkdir(), "demo shop", "not a plain image or project name"),
        ("dir", lambda p: p.mkdir(), "-o", "not a plain image or project name"),
        ("registry", lambda p: p.mkdir(), "demo-shop", "unknown SBOM source kind"),
    ],
    ids=["dir-is-a-file", "archive-is-a-dir", "name-with-space", "name-like-an-option", "registry-pull"],
)
def test_bad_requests_never_run_syft(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    kind: str,
    make: Callable[[Path], object],
    name: str,
    message: str,
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    target = tmp_path / "target"
    make(target)
    with pytest.raises(ScannerError, match=message):
        generate_sbom(
            target, kind=kind, name=name, lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest,  # type: ignore[arg-type]
            platform=PLATFORM,
        )  # fmt: skip
    assert not (record / "argv").exists()


def _cli(tmp_path: Path, dest: Path, target: Path, cyclonedx: Path, spdx: Path) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "sbom", str(target), "--name", "demo-shop", "--cyclonedx", str(cyclonedx), "--spdx", str(spdx),
            "--lock", str(tmp_path / "tools.lock.toml"), "--tools-dir", str(dest), "--platform", PLATFORM,
        ],
    )  # fmt: skip
    return result.exit_code, result.output


def test_cli_writes_both_sboms(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _ = fake_syft(tmp_path, releases, write_lock)
    out = tmp_path / "out"
    code, output = _cli(tmp_path, dest, _target(tmp_path), out / "sbom.cdx.json", out / "sbom.spdx.json")
    assert code == 0, output
    assert (out / "sbom.cdx.json").read_bytes() == (tmp_path / "payloads" / "cyclonedx-json").read_bytes()
    assert (out / "sbom.spdx.json").read_bytes() == (tmp_path / "payloads" / "spdx-json").read_bytes()
    assert f"1 package(s), {SERIAL}" in output


def test_cli_failure_leaves_no_sbom(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx={"bomFormat": "CycloneDX"})
    out = tmp_path / "out"
    out.mkdir()
    for name in ("sbom.cdx.json", "sbom.spdx.json"):
        (out / name).write_text("stale")
    code, output = _cli(tmp_path, dest, _target(tmp_path), out / "sbom.cdx.json", out / "sbom.spdx.json")
    assert code == 3 and "FAIL CLOSED" in output
    assert list(out.iterdir()) == []


def test_cli_refuses_an_output_inside_the_target(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    target = _target(tmp_path)
    code, output = _cli(tmp_path, dest, target, target / "requirements.txt", tmp_path / "sbom.spdx.json")
    assert code == 3 and "is inside the target" in output
    assert (target / "requirements.txt").read_text() == "flask==3.1.0\n", (
        "a file of the target is never touched"
    )
    assert not (record / "argv").exists()


@pytest.mark.parametrize("same", [True, False], ids=["same-file", "a-directory"])
def test_cli_refuses_outputs_that_cannot_both_be_written(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], same: bool
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    out = tmp_path / "out"
    out.mkdir()
    spdx = out / "sbom.json" if same else out
    code, output = _cli(tmp_path, dest, _target(tmp_path), out / "sbom.json", spdx)
    assert code == 3 and ("same file" if same else "or a directory") in output
    assert not (record / "argv").exists()


# ---------------------------------------------------------------- the real Syft

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


@real
@pytest.mark.integration
def test_real_syft_ignores_the_repository_configuration_and_links_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    (target / "package-lock.json").write_text(
        json.dumps({
            "name": "web", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": {"name": "web", "version": "1.0.0"}, "node_modules/express": {"version": "4.21.2"},
            },
        })
    )  # fmt: skip
    (target / ".syft").mkdir()
    (target / ".syft" / "config.yaml").write_text('exclude: ["**"]\n')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("django==5.2\n")
    (target / "vendor").symlink_to(outside)
    monkeypatch.chdir(target)  # the repository as working directory, as in CI: its config is still ignored

    sbom = generate_sbom(
        target, kind="dir", name="demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR))
    )

    document = json.loads(sbom.cyclonedx)
    components = {(c["type"], c["name"], c.get("version")) for c in document["components"]}
    assert components == {
        ("library", "flask", "3.1.0"),
        ("library", "express", "4.21.2"),
        ("library", "web", "1.0.0"),
    }, "every package, none from the link out of the target, and no file component"
    assert document["metadata"]["component"]["name"] == "demo-shop"
    assert json.loads(sbom.spdx)["spdxVersion"].startswith("SPDX-2")
    assert sbom.serial_number == document["serialNumber"]
