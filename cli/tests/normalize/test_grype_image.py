"""Grype JSON report of an image -> Finding v1, category CONTAINER (task A1, the image adapter).

No Grype database could be fetched where these tests were written, so the input is derived from the real
golden report of `test_grype.py` (Grype 0.121.0 on demo-shop's dependency seeds): its matches, moved into an
image the way Grype reports an image SBOM (`source.type` image, the manifest digest under `source.target`,
each package's in-image path and layer under `artifact.locations`). The real image scan is checked end to end
in `cli/tests/scanners/test_image_scan.py` when a database is available.
"""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sentinelci.contracts.finding import Run
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.normalize.grype import ImageSubject, load_grype_report, normalize_grype, normalize_grype_image

REPORT = Path(__file__).parent / "fixtures" / "grype" / "grype-demo-shop.json"
RUN = Run(
    repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="release"
)
DIGEST = "sha256:" + "4b" * 32
OTHER = "sha256:" + "5c" * 32
BASE_LAYER, APP_LAYER = "sha256:" + "0a" * 32, "sha256:" + "1b" * 32
IMAGE = ImageSubject(digest=DIGEST, ref="kind-registry:5000/demo-shop/shop-api")
PYYAML = "GHSA-8q59-q68h-6hv4"


def in_image(path: str, layer: str = APP_LAYER) -> dict[str, Any]:
    return {"path": path, "layerID": layer, "accessPath": path}


def image_report(digest: str = DIGEST) -> dict[str, Any]:
    """The golden report's matches, as Grype reports them for an image SBOM."""
    report = load_grype_report(REPORT)
    report["source"] = {
        "type": "image",
        "target": {
            "userInput": "image.oci.tar", "imageID": "sha256:" + "9f" * 32, "manifestDigest": digest,
            "mediaType": "application/vnd.oci.image.manifest.v1+json", "tags": [], "imageSize": 1,
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": BASE_LAYER,
                        "size": 1}],
            "repoDigests": [], "architecture": "amd64", "os": "linux",
        },
    }  # fmt: skip
    for match in report["matches"]:
        artifact = match["artifact"]
        artifact["locations"] = [in_image(f"/app/deps/{artifact['name']}-{artifact['version']}/METADATA")]
    return report


def pyyaml_finding(report: dict[str, Any]) -> Any:
    (finding,) = [f for f in normalize_grype_image(report, run=RUN, image=IMAGE) if f.rule_id == PYYAML]
    return finding


def test_every_match_is_a_container_finding_of_this_image(finding_validator: Draft202012Validator) -> None:
    report = image_report()
    findings = normalize_grype_image(report, run=RUN, image=IMAGE)
    directory = load_grype_report(REPORT)
    as_sca = normalize_grype(directory, run=RUN, scan_root="demo-shop")
    assert len(findings) == len(as_sca), "one finding per (vulnerability, purl base), as for a source tree"
    for finding in findings:
        assert (
            finding.category == "CONTAINER" and finding.location is None and finding.other_locations is None
        )
        assert finding.image is not None and finding.image.digest == DIGEST and finding.image.ref == IMAGE.ref
        assert finding.image.layer == APP_LAYER and finding.package is not None
        assert finding.id == package_fingerprint("CONTAINER", finding.rule_id, finding.package.purl)
        document = json.loads(finding.model_dump_json(exclude_none=True))
        assert not [e.message for e in finding_validator.iter_errors(document)], finding.rule_id
    assert {f.rule_id for f in findings} == {f.rule_id for f in as_sca}
    assert not {f.id for f in findings} & {f.id for f in as_sca}, "the category is part of the fingerprint"
    assert pyyaml_finding(report).package.purl == "pkg:pypi/pyyaml@5.3.1"  # type: ignore[union-attr]


def test_the_layer_is_the_first_place_of_the_package_by_path() -> None:
    report = image_report()
    (match,) = [m for m in report["matches"] if m["vulnerability"]["id"] == PYYAML]
    match["artifact"]["locations"] = [
        in_image("/usr/lib/z/METADATA", APP_LAYER),
        in_image("/opt/a/METADATA", BASE_LAYER),
    ]
    assert pyyaml_finding(report).image.layer == BASE_LAYER
    match["artifact"]["locations"] = [{"path": "/opt/a/METADATA"}]
    assert pyyaml_finding(report).image.layer is None, "no layer named: none claimed"


def test_the_same_package_found_twice_is_one_finding() -> None:
    report = image_report()
    (match,) = [m for m in report["matches"] if m["vulnerability"]["id"] == PYYAML]
    twin = copy.deepcopy(match)
    twin["artifact"]["locations"] = [in_image("/other/PyYAML-5.3.1/METADATA", BASE_LAYER)]
    twin["artifact"]["id"] = "another-artifact"
    report["matches"].append(twin)
    assert pyyaml_finding(report).image.layer == APP_LAYER, "/app/... sorts before /other/..."


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda r: r.update(source={"type": "directory", "target": "/src"}), "only an image report"),
        (lambda r: r["source"]["target"].update(manifestDigest=OTHER), "is about image"),
        (lambda r: r["source"]["target"].pop("manifestDigest"), "is about image None"),
        (lambda r: r["matches"][0]["artifact"]["locations"][0].update(layerID="l1"), "not a sha256 digest"),
        (lambda r: r["matches"][0]["artifact"].update(purl="not a purl"), "no usable purl"),
        (lambda r: r.pop("matches"), "no matches list"),
    ],
    ids=["a-directory-report", "another-image", "no-digest", "bad-layer", "bad-purl", "no-matches"],
)  # fmt: skip
def test_a_report_that_is_not_this_images_is_refused(change: Any, message: str) -> None:
    report = image_report()
    change(report)
    with pytest.raises(NormalizationError, match=message):
        normalize_grype_image(report, run=RUN, image=IMAGE)


def test_a_silenced_report_is_refused_like_a_source_tree_report() -> None:
    report = image_report()
    report["descriptor"]["configuration"]["ignore"].append({"vulnerability": PYYAML})
    with pytest.raises(NormalizationError):
        normalize_grype_image(report, run=RUN, image=IMAGE)


def test_an_image_needs_its_digest() -> None:
    with pytest.raises(NormalizationError, match="is not sha256"):
        normalize_grype_image(image_report(), run=RUN, image=ImageSubject(digest="latest"))


def test_the_source_tree_adapter_still_refuses_an_image_report() -> None:
    with pytest.raises(NormalizationError, match="image report needs the image adapter"):
        normalize_grype(image_report(), run=RUN)
