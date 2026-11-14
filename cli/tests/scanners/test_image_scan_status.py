"""`sentinel scan image` with a fake Syft and a fake Grype: every outcome the gate reads, without real tools.

The real-tool tests of `test_image_scan.py` are skipped where the tools are not installed, as in CI, which
left the per-tool status untested there (review of #70, should fix 2: four mutants survived). The fakes are
the ones of `test_grype_scan.py`; their SBOMs name the digest of a real OCI layout (`test_syft_sbom.LAYOUT`),
so the layout check runs on real bytes before the fake Syft does.
"""

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner, Result

from sentinelci.cli import app
from sentinelci.normalize.grype import load_grype_report

from .conftest import FakeReleases
from .test_grype_scan import GOLDEN, Fakes, install_fakes
from .test_runner import PLATFORM
from .test_syft_sbom import CYCLONEDX, DIGEST, LAYOUT, SPDX, _tar, oci_archive

ROOT = Path(__file__).resolve().parents[3]
REF = "kind-registry:5000/demo-shop/shop-api"
OTHER = "sha256:" + "5c" * 32
MANIFEST = json.loads(LAYOUT["blobs/sha256/" + DIGEST.removeprefix("sha256:")])
LAYER = "blobs/sha256/" + MANIFEST["layers"][0]["digest"].removeprefix("sha256:")


def image_report(digest: str = DIGEST, **configuration: object) -> dict[str, Any]:
    """The golden report's matches as the fake Grype (1.0.0 in the test lock) reports an image SBOM."""
    report = copy.deepcopy(load_grype_report(GOLDEN / "grype-demo-shop.json"))
    report["descriptor"]["version"] = "1.0.0"
    report["descriptor"]["configuration"].update(configuration)
    report["source"] = {"type": "image", "target": {"manifestDigest": digest, "userInput": "image.oci.tar"}}
    for match in report["matches"]:
        artifact = match["artifact"]
        artifact["locations"] = [
            {"path": f"/app/{artifact['name']}/METADATA", "layerID": "sha256:" + "1b" * 32}
        ]
    return report


def fakes(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], report: object
) -> tuple[Path, Fakes]:
    """install_fakes, with Syft's CycloneDX and SPDX payloads describing the image of DIGEST."""
    _, dest, installed = install_fakes(tmp_path, releases, write_lock, report=report)
    for name, document in (("cyclonedx-json", CYCLONEDX), ("spdx-json", SPDX)):
        (installed.payloads / name).write_text(json.dumps(document))
    (tmp_path / "grype-db").mkdir()
    return dest, installed


def scan(tmp_path: Path, dest: Path, archive: Path, *extra: str, lock: Path | None = None) -> Result:
    return CliRunner().invoke(app, [
        "scan", "image", str(archive), "--image-digest", DIGEST, "--image-ref", REF,
        "--out", str(tmp_path / "out" / "container.ndjson"), "--repo", "NOURHANE-EHOUARI/sentinelci",
        "--commit", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "--context", "release",
        "--db-dir", str(tmp_path / "grype-db"), "--lock", str(lock or tmp_path / "tools.lock.toml"),
        "--tools-dir", str(dest), "--platform", PLATFORM,
        "--tool-status-out", str(tmp_path / "out" / "status.json"), *extra,
    ])  # fmt: skip


def status_of(tmp_path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((tmp_path / "out" / "status.json").read_text())
    schema = json.loads((ROOT / "schemas" / "tool-status.v1.json").read_text())
    assert not [error.message for error in Draft202012Validator(schema).iter_errors(document)]
    tools: dict[str, Any] = document["tools"]
    return tools


def stale_outputs(tmp_path: Path) -> None:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "container.ndjson").write_text("stale findings\n")
    (tmp_path / "out" / "status.json").write_text('{"stale": "status"}')


def test_a_scan_writes_its_findings_and_both_tools_ok_and_checks_the_database_age(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, installed = fakes(tmp_path, releases, write_lock, image_report())
    result = scan(tmp_path, dest, oci_archive(tmp_path / "image.oci.tar"))
    assert result.exit_code == 0, result.output
    findings = (tmp_path / "out" / "container.ndjson").read_text().splitlines()
    assert findings and {json.loads(f)["image"]["ref"] for f in findings} == {REF}, "a port is not a tag"
    assert {tool["status"] for tool in status_of(tmp_path).values()} == {"ok"}
    assert set(status_of(tmp_path)) == {"syft", "grype"}
    assert installed.env("grype")["GRYPE_DB_VALIDATE_AGE"] == "true", "a stale database fails by default"


def test_a_stale_database_is_accepted_only_on_request(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, installed = fakes(tmp_path, releases, write_lock, image_report())
    result = scan(tmp_path, dest, oci_archive(tmp_path / "image.oci.tar"), "--allow-stale-db")
    assert result.exit_code == 0, result.output
    assert installed.env("grype")["GRYPE_DB_VALIDATE_AGE"] == "false"


@pytest.mark.parametrize(
    ("report", "message"),
    [
        (image_report(OTHER), OTHER),
        (image_report(**{"only-fixed": True}), "only-fixed"),
    ],
    ids=["report-about-another-image", "report-made-with-only-fixed"],
)
def test_a_report_that_cannot_be_trusted_fails_grype_and_keeps_syft_ok(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    report: dict[str, Any],
    message: str,
) -> None:
    dest, _ = fakes(tmp_path, releases, write_lock, report)
    stale_outputs(tmp_path)
    result = scan(tmp_path, dest, oci_archive(tmp_path / "image.oci.tar"))
    assert result.exit_code == 3 and "FAIL CLOSED" in result.output, result.output
    assert not (tmp_path / "out" / "container.ndjson").exists(), "no findings file, not even the older one"
    tools = status_of(tmp_path)
    assert tools["syft"]["status"] == "ok"
    assert tools["grype"]["status"] == "failed" and message in tools["grype"]["detail"], tools["grype"]


def test_a_swapped_layer_fails_syft_and_grype_never_runs(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    """Review of #70, should fix 1: the fake Syft, like the real one, would describe the image as DIGEST."""
    dest, installed = fakes(tmp_path, releases, write_lock, image_report())
    swapped = {**LAYOUT, LAYER: _tar([("etc/os-release", b"ID=alpine\n")])}
    result = scan(tmp_path, dest, oci_archive(tmp_path / "image.oci.tar", swapped))
    assert result.exit_code == 3, result.output
    assert not (tmp_path / "out" / "container.ndjson").exists()
    tools = status_of(tmp_path)
    assert tools["syft"]["status"] == "failed"
    assert "does not hold the content its digest names" in tools["syft"]["detail"]
    assert tools["grype"]["status"] == "not_run"
    assert not (installed.record / "syft.argv").exists() and not (installed.record / "grype.argv").exists()


def test_an_unreadable_lock_leaves_neither_an_older_status_nor_older_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, installed = fakes(tmp_path, releases, write_lock, image_report())
    stale_outputs(tmp_path)
    broken = tmp_path / "broken.lock.toml"
    broken.write_text("schema_version = [")
    result = scan(tmp_path, dest, oci_archive(tmp_path / "image.oci.tar"), lock=broken)
    assert result.exit_code == 3, result.output
    assert not (tmp_path / "out" / "status.json").exists(), "no status to write, and the older one is gone"
    assert not (tmp_path / "out" / "container.ndjson").exists()
    assert not (installed.record / "syft.argv").exists()


@pytest.mark.parametrize(
    "ref",
    [REF + "@" + OTHER, REF + ":1.0.0", "shop-api:latest", ""],
    ids=["with-a-digest", "with-a-tag", "short-name-with-a-tag", "empty"],
)
def test_a_reference_with_its_own_tag_or_digest_is_never_scanned(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], ref: str
) -> None:
    """Review of #70, should fix 3: the finding's digest is the image's, and only that one."""
    dest, installed = fakes(tmp_path, releases, write_lock, image_report())
    stale_outputs(tmp_path)
    archive = oci_archive(tmp_path / "image.oci.tar")
    result = CliRunner().invoke(app, [
        "scan", "image", str(archive), "--image-digest", DIGEST, "--image-ref", ref,
        "--out", str(tmp_path / "out" / "container.ndjson"), "--repo", "NOURHANE-EHOUARI/sentinelci",
        "--commit", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "--context", "release",
        "--db-dir", str(tmp_path / "grype-db"), "--lock", str(tmp_path / "tools.lock.toml"),
        "--tools-dir", str(dest), "--platform", PLATFORM,
        "--tool-status-out", str(tmp_path / "out" / "status.json"),
    ])  # fmt: skip
    assert result.exit_code == 3 and "without tag or digest" in result.output, result.output
    assert not (installed.record / "syft.argv").exists(), "nothing ran"
    assert (
        not (tmp_path / "out" / "status.json").exists()
        and not (tmp_path / "out" / "container.ndjson").exists()
    )
