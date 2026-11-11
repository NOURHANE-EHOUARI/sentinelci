"""The CONTAINER seeds of the ground truth (task A9): vulnerable packages in an image built from demo-shop.

A CONTAINER seed names the image (a Dockerfile of demo-shop and its build arguments), the file where the
vulnerable version is pinned (`location`, where a developer would fix it), and the package and advisory
Grype reports for the built image (`sentinel scan image`, A1). Always checked: the pin, the build, the
advisory in the offline feed fixtures, and the gate rule the engine gives a CONTAINER finding of the seed.
The detection itself needs a built image and a Grype database: set SENTINEL_BLOCK_IMAGE_ARCHIVE to the BLOCK
image's OCI layout archive (`docker buildx build ... --output type=oci,dest=...`), SENTINEL_GRYPE_DB_DIR and
SENTINEL_TOOLS_DIR (README.md, "Container seeds").
"""

import json
import os
import re
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from sentinelci.contracts.finding import Run
from sentinelci.enrich import enrich_finding, load_snapshot
from sentinelci.enrich.reachability import Reachability
from sentinelci.normalize.fingerprint import package_fingerprint
from sentinelci.normalize.grype import ImageSubject, normalize_grype_image
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.decision import Subject, evaluate
from sentinelci.policy.opa import OpaError, OpaRunner
from sentinelci.risk.model import RiskModel, score_finding
from sentinelci.scanners.grype import scan_image
from sentinelci.scanners.lock import load_lock

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-shop"
FEEDS = ROOT / "eval" / "feeds"
TRUTH: dict[str, Any] = yaml.safe_load((DEMO / "ground-truth" / "findings.yaml").read_text(encoding="utf-8"))
SEEDS = [seed for seed in TRUTH["seeds"] if seed["category"] == "CONTAINER"]
SNAPSHOT = (FEEDS / "snapshot.json").read_bytes()
SNAPSHOT_VULNERABILITIES: dict[str, Any] = json.loads(SNAPSHOT)["vulnerabilities"]
FEED_FINDINGS = [json.loads(line) for line in (FEEDS / "findings.ndjson").read_text().splitlines()]
PYPI = re.compile(r"^pkg:pypi/(?P<name>[a-z0-9._-]+)@(?P<version>[^@?#]+)$")
# A pin of requirements.*.txt: `name==version \` (hashes on the following lines).
PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)\s*\\?\s*$")
IMAGE_DIGEST = "sha256:" + "4b" * 32  # any image: the gate does not read the digest
FINDING_SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas" / "finding.v1.json").read_text("utf-8")))


def _normalized(name: str) -> str:
    """PEP 503: the name a requirements file and a purl agree on."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _pypi(seed: dict[str, Any]) -> tuple[str, str]:
    match = PYPI.match(seed["package"])
    assert match, f"{seed['id']}: {seed['package']} is not a pypi purl with a version"
    return match["name"], match["version"]


def test_there_is_a_container_seed() -> None:
    assert [seed["id"] for seed in SEEDS] == ["GT-CONTAINER-001"]


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_requirements_file_pins_the_seeded_version_at_its_line(seed: dict[str, Any]) -> None:
    name, version = _pypi(seed)
    lines = (DEMO / seed["location"]["path"]).read_text(encoding="utf-8").splitlines()
    pinned = PIN.match(lines[seed["location"]["line"] - 1])
    assert pinned, f"{seed['id']}: line {seed['location']['line']} is not a pin"
    assert (_normalized(pinned["name"]), pinned["version"]) == (_normalized(name), version)
    # The pin is hash-checked like every other one (Dockerfile.release installs with --require-hashes).
    assert lines[seed["location"]["line"]].strip().startswith("--hash=sha256:")


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_image_installs_that_file_and_the_release_image_does_not_ship_the_seed(
    seed: dict[str, Any],
) -> None:
    """The build argument names the seed's requirements file, next to the Dockerfile; the release image (the
    Dockerfile's default) pins another version, so only the BLOCK image carries the seed."""
    dockerfile = DEMO / seed["image"]["dockerfile"]
    text = dockerfile.read_text(encoding="utf-8")
    (argument,) = seed["image"]["build_args"]
    default = re.search(rf"^ARG {argument}=(\S+)$", text, flags=re.MULTILINE)
    assert default, f"{seed['id']}: {dockerfile.name} has no ARG {argument} with a default"
    chosen = seed["image"]["build_args"][argument]
    assert dockerfile.parent / chosen == DEMO / seed["location"]["path"]
    assert chosen != default[1], "the seed is in the image built on purpose, not in the release image"
    name, version = _pypi(seed)
    released = {
        _normalized(pin["name"]): pin["version"]
        for line in (dockerfile.parent / default[1]).read_text(encoding="utf-8").splitlines()
        if (pin := PIN.match(line))
    }
    assert _normalized(name) in released and released[_normalized(name)] != version


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_feed_fixtures_know_the_advisory_offline(seed: dict[str, Any]) -> None:
    entry = SNAPSHOT_VULNERABILITIES[seed["cve"]]
    assert seed["vulnerability"] in entry.get("aliases", []), seed["id"]
    assert any(f["rule_id"] == seed["vulnerability"] for f in FEED_FINDINGS), seed["id"]
    enrichment = enrich_finding(_finding(seed), load_snapshot(SNAPSHOT), None)["enrichment"]
    assert enrichment["kev"]["listed"] is seed["kev"] and "cvss" in enrichment and "epss" in enrichment


def _image_report(seed: dict[str, Any]) -> dict[str, Any]:
    """Grype's report of an image holding the seed's package, from the feed fixture's match of that advisory
    (the same shape `test_grype_image.py` derives from the golden report)."""
    (match,) = [f for f in FEED_FINDINGS if f["rule_id"] == seed["vulnerability"]]
    golden = json.loads((ROOT / "cli/tests/normalize/fixtures/grype/grype-demo-shop.json").read_text("utf-8"))
    (raw,) = [
        m for m in golden["matches"]
        if m["vulnerability"]["id"] == match["rule_id"] and m["artifact"]["purl"] == seed["package"]
    ]  # fmt: skip
    name, version = _pypi(seed)
    path = f"/opt/venv/lib/python3.12/site-packages/{name}-{version}.dist-info/METADATA"
    raw["artifact"]["locations"] = [{"path": path, "layerID": "sha256:" + "1b" * 32, "accessPath": path}]
    golden["matches"] = [raw]
    golden["source"] = {
        "type": "image",
        "target": {"userInput": "block.oci.tar", "manifestDigest": IMAGE_DIGEST, "layers": []},
    }
    return golden


def _finding(seed: dict[str, Any]) -> dict[str, Any]:
    """The CONTAINER finding the image adapter gives for the seed (A1)."""
    run = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release")
    image = ImageSubject(digest=IMAGE_DIGEST, ref="kind-registry:5000/demo-shop/shop-api:block")
    (finding,) = normalize_grype_image(_image_report(seed), run=run, image=image)
    document: dict[str, Any] = json.loads(finding.model_dump_json(exclude_none=True))
    assert not [e.message for e in FINDING_SCHEMA.iter_errors(document)]
    assert document["id"] == package_fingerprint("CONTAINER", seed["vulnerability"], seed["package"])
    return document


@pytest.fixture
def opa_binary() -> Path:
    """The real OPA binary. Skips when absent, unless SENTINEL_REQUIRE_OPA is set (CI)."""
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")


def test_each_seeds_gate_rule_is_the_engines(opa_binary: Path) -> None:
    """Enrich (feed fixtures, demo-shop's reachability), score and evaluate the seeds' CONTAINER findings in
    release context: the rule that names each one is its `expected.gate`."""
    snapshot = load_snapshot(SNAPSHOT)
    model = RiskModel.load(ROOT / "policies" / "risk-model.yaml")
    reachability = Reachability.of_trees([DEMO])
    scored = [score_finding(enrich_finding(_finding(s), snapshot, None, reachability), model) for s in SEEDS]
    decision = evaluate(
        findings_data="".join(json.dumps(f, sort_keys=True) + "\n" for f in scored).encode(),
        subject=Subject(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release"),
        evaluated_at="2026-11-01T00:00:00Z",
        bundle=PolicyBundle.load(ROOT / "policies"),
        opa=OpaRunner.locate(opa_binary),
        enrichment_snapshot=SNAPSHOT,
    )
    rules: dict[str, set[str]] = {}
    for violation in decision["violations"]:
        for finding_id in violation["finding_ids"]:
            rules.setdefault(finding_id, set()).add(violation["rule"])
    for seed, finding in zip(SEEDS, scored, strict=True):
        expected = {seed["expected"]["gate"]} if "gate" in seed["expected"] else set()
        assert rules.get(finding["id"], set()) == expected, (seed["id"], finding["risk"]["priority"])


# ---------------------------------------------------------------- the built image (opt-in)

ARCHIVE = os.environ.get("SENTINEL_BLOCK_IMAGE_ARCHIVE")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")


def _manifest_digest(archive: Path) -> str:
    """The digest of the one image of an OCI layout archive (its index.json)."""
    with tarfile.open(archive) as tar:
        member = tar.extractfile("index.json")
        assert member is not None, "not an OCI layout archive"
        (manifest,) = json.load(member)["manifests"]
    return str(manifest["digest"])


@pytest.mark.skipif(
    not (ARCHIVE and GRYPE_DB and TOOLS_DIR),
    reason="set SENTINEL_BLOCK_IMAGE_ARCHIVE, SENTINEL_GRYPE_DB_DIR and SENTINEL_TOOLS_DIR (README.md)",
)
@pytest.mark.integration
@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_pinned_scanners_detect_the_seed_in_the_built_image(seed: dict[str, Any]) -> None:
    archive = Path(str(ARCHIVE))
    digest = _manifest_digest(archive)
    scan = scan_image(
        archive,
        image_digest=digest,
        name="demo-shop/shop-api:block",
        db_dir=Path(str(GRYPE_DB)),
        lock=load_lock(ROOT / "tools.lock.toml"),
        tools_dir=Path(str(TOOLS_DIR)),
    )
    run = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release")
    findings = normalize_grype_image(scan.report, run=run, image=ImageSubject(digest=digest, ref="block"))
    detected = {(f.tool.name, f.rule_id) for f in findings if f.package and f.package.purl == seed["package"]}
    expected = {(d["tool"], d["rule"]) for d in seed["expected"]["detections"]}
    assert expected <= detected, (seed["id"], sorted(detected))
