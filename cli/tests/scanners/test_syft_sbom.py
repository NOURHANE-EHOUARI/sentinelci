"""`sentinel sbom`: Syft hardened like the scanners, offline, never configured by the scanned repository (A4).

Unit tests use a fake `syft` pinned in a test lock. Integration tests use the real binary and run only when
SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import hashlib
import io
import json
import os
import tarfile
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sentinelci.cli as cli_module
from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import load_lock
from sentinelci.supplychain.sbom import OFFLINE_ENV, generate_sbom

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
DIGEST = "sha256:" + "7" * 64
CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": SERIAL,
    "metadata": {"component": {"type": "container", "name": "demo-shop", "version": DIGEST}},
    "components": [{"type": "library", "name": "a"}],
}
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "name": "demo-shop",
    "packages": [{"SPDXID": "SPDXRef-DocumentRoot-Image-demo-shop", "versionInfo": DIGEST}],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-DocumentRoot-Image-demo-shop",
        }
    ],
}
REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
CONFIG = files("sentinelci.supplychain.configs").joinpath("syft.yaml").read_text(encoding="utf-8")


def fake_syft(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    cyclonedx: object = CYCLONEDX,
    spdx: object = SPDX,
    exit_code: int = 0,
    stderr: str = "",
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
printf '%s' '{stderr}' >&2
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


def _generate(  # type: ignore[no-untyped-def]
    tmp_path: Path, dest: Path, target: Path, kind: str = "dir", image_digest: str | None = None
):
    return generate_sbom(
        target,
        kind=kind,  # type: ignore[arg-type]
        name="demo-shop",
        lock=load_lock(tmp_path / "tools.lock.toml"),
        tools_dir=dest,
        image_digest=image_digest,
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
    assert "-q" not in argv, "Syft's error must reach the SC-010 reason (review of #36)"
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
        "  local-mod-cache-dir: /nonexistent/go/pkg/mod",
        "  maven-local-repository-dir: /nonexistent/.m2/repository",
        "  use-packages-lib: false",
        "  vcpkg-allow-git-clone: false",
        "    selection: none",
    ):
        assert line in CONFIG.splitlines(), line


@pytest.mark.parametrize("kind", ["oci-dir", "oci-archive"])
def test_images_are_read_from_the_file_the_build_wrote(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], kind: str
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    image = tmp_path / "image"
    if kind == "oci-dir":
        image.mkdir()
    else:
        image.write_bytes(b"not really a tar")
    _generate(tmp_path, dest, image, kind=kind, image_digest=DIGEST)
    argv = (record / "argv").read_text().splitlines()
    assert argv[0] == f"{kind}:{image.resolve()}" and "--base-path" not in argv


OTHER = "sha256:" + "8" * 64
ROOT: dict[str, str] = SPDX["relationships"][0]  # type: ignore[index]


@pytest.mark.parametrize(
    ("cyclonedx", "spdx"),
    [
        ({**CYCLONEDX, "metadata": {"component": {"version": OTHER}}}, SPDX),
        ({**CYCLONEDX, "metadata": {}}, SPDX),
        (CYCLONEDX, {**SPDX, "packages": [{**SPDX["packages"][0], "versionInfo": OTHER}]}),  # type: ignore[index]
        (CYCLONEDX, {**SPDX, "relationships": []}),
        (CYCLONEDX, {**SPDX, "relationships": SPDX["relationships"] * 2}),
        (CYCLONEDX, {**SPDX, "relationships": [{**ROOT, "relationshipType": "CONTAINS"}]}),
        (CYCLONEDX, {**SPDX, "relationships": [{**ROOT, "spdxElementId": "SPDXRef-Package-x"}]}),
    ],
    ids=["cyclonedx-other-digest", "cyclonedx-no-subject", "spdx-other-digest", "spdx-describes-nothing",
         "spdx-describes-twice", "spdx-contains-only", "spdx-a-package-describes"],
)  # fmt: skip
def test_an_image_sbom_must_name_the_image_that_was_built(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], cyclonedx: object, spdx: object
) -> None:
    """Review of #36, should fix 2: a Docker archive came out named by a digest no registry knows."""
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx=cyclonedx, spdx=spdx)
    image = tmp_path / "image.tar"
    image.write_bytes(b"not really a tar")
    with pytest.raises(ScannerError, match=f"not {DIGEST}: the file is not an OCI layout"):
        _generate(tmp_path, dest, image, kind="oci-archive", image_digest=DIGEST)


def test_the_package_count_leaves_out_the_operating_system(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    components = [{"type": "library", "name": "a"}, {"type": "operating-system", "name": "debian"}, "odd"]
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx={**CYCLONEDX, "components": components})
    assert _generate(tmp_path, dest, _target(tmp_path)).packages == 2


def test_syfts_error_is_the_reason(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    error = "ERROR could not determine source: no source providers were able to resolve the input"
    dest, _ = fake_syft(tmp_path, releases, write_lock, exit_code=1, stderr=error)
    with pytest.raises(ScannerError, match=f"exited with code 1: {error}"):
        _generate(tmp_path, dest, _target(tmp_path))


def test_a_serial_with_trailing_text_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # Review of #36, nit 1 (Hiba's test).
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx={**CYCLONEDX, "serialNumber": SERIAL + "x"})
    with pytest.raises(ScannerError, match="no serialNumber"):
        _generate(tmp_path, dest, _target(tmp_path))


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
        ("docker-archive", lambda p: p.write_text("x"), "demo-shop", "unknown SBOM source kind"),
        ("oci-dir", lambda p: p.mkdir(), "demo-shop", "needs its manifest digest"),
    ],
    ids=["dir-is-a-file", "archive-is-a-dir", "name-with-space", "name-like-an-option", "registry-pull",
         "docker-archive", "image-without-digest"],
)  # fmt: skip
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
    digest = DIGEST if kind == "oci-archive" else None
    with pytest.raises(ScannerError, match=message):
        generate_sbom(
            target, kind=kind, name=name, lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest,  # type: ignore[arg-type]
            image_digest=digest, platform=PLATFORM,
        )  # fmt: skip
    assert not (record / "argv").exists()


@pytest.mark.parametrize(
    ("kind", "digest", "message"),
    [
        ("dir", DIGEST, "only an image source takes one"),
        ("oci-dir", DIGEST.upper(), "is not sha256:<64 lowercase hex>"),
        ("oci-dir", DIGEST + "\n", "is not sha256:<64 lowercase hex>"),
        ("oci-dir", "sha512:" + "7" * 64, "is not sha256:<64 lowercase hex>"),
    ],
    ids=["dir-with-digest", "upper-case", "trailing-newline", "sha512"],
)
def test_the_image_digest_is_checked_before_syft_runs(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    kind: str,
    digest: str,
    message: str,
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    with pytest.raises(ScannerError, match=message):
        _generate(tmp_path, dest, _target(tmp_path), kind=kind, image_digest=digest)
    assert not (record / "argv").exists()


def _cli(
    tmp_path: Path, dest: Path, target: Path, cyclonedx: Path, spdx: Path, *extra: str
) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "sbom", str(target), "--name", "demo-shop", "--cyclonedx", str(cyclonedx), "--spdx", str(spdx),
            "--lock", str(tmp_path / "tools.lock.toml"), "--tools-dir", str(dest), "--platform", PLATFORM,
            *extra,
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


def test_cli_image_needs_its_digest(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, record = fake_syft(tmp_path, releases, write_lock)
    image = tmp_path / "image.tar"
    image.write_bytes(b"not really a tar")
    out = tmp_path / "out"
    code, output = _cli(tmp_path, dest, image, out / "c.json", out / "s.json", "--source", "oci-archive")
    assert code == 3 and "needs its manifest digest" in output and not (record / "argv").exists()
    code, output = _cli(
        tmp_path,
        dest,
        image,
        out / "c.json",
        out / "s.json",
        "--source",
        "oci-archive",
        "--image-digest",
        DIGEST,
    )
    assert code == 0, output


def test_a_failed_second_write_leaves_neither_sbom(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review of #36, nit 2 (Hiba's test).
    dest, _ = fake_syft(tmp_path, releases, write_lock, cyclonedx=CYCLONEDX, spdx=SPDX)
    real = cli_module._write_atomically

    def full_disk_on_spdx(path: Path, text: str) -> None:
        if path.name == "sbom.spdx.json":
            raise OSError(28, "No space left on device")
        real(path, text)

    monkeypatch.setattr(cli_module, "_write_atomically", full_disk_on_spdx)
    out = tmp_path / "out"
    code, output = _cli(tmp_path, dest, _target(tmp_path), out / "sbom.cdx.json", out / "sbom.spdx.json")
    assert code == 3 and "FAIL CLOSED" in output
    assert not (out / "sbom.cdx.json").exists()


def test_cli_an_output_under_a_file_is_refused_cleanly(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # Review of #36, nit 6: NotADirectoryError from the unlink, with a traceback, before the fix.
    dest, record = fake_syft(tmp_path, releases, write_lock)
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    code, output = _cli(tmp_path, dest, _target(tmp_path), blocker / "c.json", tmp_path / "s.json")
    assert code == 3 and "cannot use" in output and "nothing was written" in output
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


def _tar(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def oci_layout(root: Path) -> str:
    """A one-layer OCI image layout, written by hand (no registry, no Docker): one Python package and an
    os-release. Returns the manifest digest, the image's identity."""
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def blob(data: bytes) -> dict[str, object]:
        hexdigest = hashlib.sha256(data).hexdigest()
        (blobs / hexdigest).write_bytes(data)
        return {"digest": f"sha256:{hexdigest}", "size": len(data)}

    layer = blob(
        _tar([
            ("etc/os-release", b'ID=debian\nVERSION_ID="12"\nNAME="Debian GNU/Linux"\n'),
            ("usr/lib/python3.12/site-packages/tinypkg-1.0.dist-info/METADATA",
             b"Metadata-Version: 2.1\nName: tinypkg\nVersion: 1.0\n"),
        ])
    )  # fmt: skip
    config = blob(
        json.dumps(
            {"architecture": "amd64", "os": "linux", "config": {},
             "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]}}
        ).encode()
    )  # fmt: skip
    manifest = blob(
        json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
             "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
             "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", **layer}]}
        ).encode()
    )  # fmt: skip
    (root / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", **manifest}]})
    )  # fmt: skip
    return str(manifest["digest"])


@real
@pytest.mark.integration
@pytest.mark.parametrize("kind", ["oci-dir", "oci-archive"])
def test_real_syft_names_the_image_by_its_manifest_digest(tmp_path: Path, kind: str) -> None:
    """Review of #36, should fix 3: the image sources with the real Syft, offline, on a hand-made layout."""
    layout = tmp_path / "layout"
    digest = oci_layout(layout)
    target = layout
    if kind == "oci-archive":
        target = tmp_path / "image.tar"
        names = [
            "oci-layout",
            "index.json",
            *sorted(
                p.relative_to(layout).as_posix()
                for p in layout.rglob("*")
                if p.is_file() and p.parts[-3:-1] == ("blobs", "sha256")
            ),
        ]
        target.write_bytes(_tar([(name, (layout / name).read_bytes()) for name in names]))

    def generate(image_digest: str):  # type: ignore[no-untyped-def]
        return generate_sbom(
            target, kind=kind, name="demo-shop/shop-api", lock=load_lock(REPO_LOCK),  # type: ignore[arg-type]
            tools_dir=Path(str(TOOLS_DIR)), image_digest=image_digest,
        )  # fmt: skip

    sbom = generate(digest)
    document = json.loads(sbom.cyclonedx)
    assert document["metadata"]["component"]["version"] == digest
    types = {(c["type"], c["name"]) for c in document["components"]}
    assert ("library", "tinypkg") in types and ("operating-system", "debian") in types
    assert sbom.packages == len(document["components"]) - 1, "the operating system is not a package"
    with pytest.raises(ScannerError, match="not an OCI layout of the image that was built"):
        generate("sha256:" + "0" * 64)


@real
@pytest.mark.integration
def test_real_syft_writes_the_same_sbom_bytes_for_the_same_tree(tmp_path: Path) -> None:
    """Review of #80, should fix 1: Syft records its configuration in the syft-json SBOM, and two of its
    directories defaulted to the private home, a new one each run, so the SBOM's sha256 changed every time."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "requirements.txt").write_text("pyyaml==5.3.1\n")
    (tree / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.7\n")

    def native() -> bytes:
        sbom = generate_sbom(
            tree, kind="dir", name="demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)),
            syft_json=True,
        )  # fmt: skip
        assert sbom.syft_json is not None
        return sbom.syft_json

    first = native()
    assert first == native()
    packages = json.loads(first)["descriptor"]["configuration"]["packages"]
    assert packages["golang"]["local-mod-cache-dir"] == "/nonexistent/go/pkg/mod"
    assert packages["java-archive"]["maven-localrepository-dir"] == "/nonexistent/.m2/repository"
