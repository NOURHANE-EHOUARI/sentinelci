"""The CONTAINER seeds of the ground truth (task A9): vulnerable packages in images built from demo-shop.

A CONTAINER seed names the image (`name`, a Dockerfile of demo-shop and its build arguments), the file where
the vulnerable version is pinned (`location`, where a developer would fix it), and the package and advisory
Grype reports for the built image (`sentinel scan image`, A1). Always checked: the pin, the Dockerfile and its
build in `make container-seed-images`, the advisory in the offline feed fixtures, and the gate rule the engine
gives a CONTAINER finding of the seed. The detection itself needs the built images and a Grype database: set
SENTINEL_CONTAINER_IMAGES to the directory `make container-seed-images` writes (`<name>.oci.tar`),
SENTINEL_GRYPE_DB_DIR and SENTINEL_TOOLS_DIR (README.md, "Container seeds").
"""

import json
import os
import re
import shlex
import tarfile
from functools import cache
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
PURL = re.compile(
    r"^pkg:(?P<type>pypi|npm|maven)/(?:(?P<namespace>[^/@]+)/)?(?P<name>[^/@]+)@(?P<version>[^@?#]+)$"
)
# A pin of requirements.*.txt: `name==version \` (hashes on the following lines).
PIN = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;\\]+)\s*\\?\s*$")
# A base image: a tag for people and the digest that decides.
PINNED_BASE = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")
JAR_PIN = re.compile(r"^(?P<sha256>[0-9a-f]{64})  lib/(?P<jar>[A-Za-z0-9._-]+\.jar)$")
IMAGE_DIGEST = "sha256:" + "4b" * 32  # any image: the gate does not read the digest
FINDING_SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas" / "finding.v1.json").read_text("utf-8")))


def _normalized(name: str) -> str:
    """PEP 503: the name a requirements file and a purl agree on."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _purl(seed: dict[str, Any]) -> dict[str, str]:
    match = PURL.match(seed["package"])
    assert match, f"{seed['id']}: {seed['package']} is not a pypi, npm or maven purl with a version"
    return {k: v or "" for k, v in match.groupdict().items()}


def _images() -> dict[str, dict[str, Any]]:
    """Each image the seeds name, by name: one Dockerfile and one set of build arguments per name."""
    images: dict[str, dict[str, Any]] = {}
    for seed in SEEDS:
        image = seed["image"]
        assert set(image) <= {"name", "dockerfile", "build_args"}, seed["id"]
        assert images.setdefault(image["name"], image) == image, f"{seed['id']}: another {image['name']}"
    return images


def _dockerfile(image: dict[str, Any]) -> tuple[dict[str, str], list[list[str]]]:
    """The ARG defaults of a Dockerfile (before its first FROM, or in a stage), and its stages as lists of
    instructions (continuations joined)."""
    text = (DEMO / image["dockerfile"]).read_text(encoding="utf-8").replace("\\\n", " ")
    arguments: dict[str, str] = {}
    stages: list[list[str]] = []
    for line in text.splitlines():
        instruction = line.strip()
        if not instruction or instruction.startswith("#"):
            continue
        if match := re.fullmatch(r"ARG (\w+)=(\S+)", instruction):
            assert match[1] not in arguments, f"{image['dockerfile']}: ARG {match[1]} twice"
            arguments[match[1]] = match[2]
        if instruction.startswith("FROM "):
            stages.append([])
        if stages:
            stages[-1].append(instruction)
    return arguments, stages


def test_the_benchmark_has_the_five_container_seeds_the_spec_asks_for() -> None:
    """SPEC section 17: container 5. Each is an SCA seed's pin as it ships in an image, so the offline feed
    fixtures cover it, and the two CISA KEV entries among them ship as jars."""
    assert [seed["id"] for seed in SEEDS] == [f"GT-CONTAINER-00{n}" for n in range(1, 6)]
    assert len({(seed["package"], seed["vulnerability"]) for seed in SEEDS}) == len(SEEDS)
    sca = {(s["package"], s["vulnerability"]) for s in TRUTH["seeds"] if s["category"] == "SCA"}
    assert {(seed["package"], seed["vulnerability"]) for seed in SEEDS} <= sca
    assert sorted(_images()) == ["reports", "shop-api-block", "web"]
    assert sum(seed["kev"] for seed in SEEDS) == 2


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_manifest_pins_the_seeded_version_at_its_line(seed: dict[str, Any]) -> None:
    purl = _purl(seed)
    path = DEMO / seed["location"]["path"]
    lines = path.read_text(encoding="utf-8").splitlines()
    number = seed["location"]["line"]
    if purl["type"] == "pypi":
        pinned = PIN.match(lines[number - 1])
        assert pinned, f"{seed['id']}: line {number} is not a pin"
        assert (_normalized(pinned["name"]), pinned["version"]) == (
            _normalized(purl["name"]),
            purl["version"],
        )
        # The pin is hash-checked like every other one (Dockerfile.release installs with --require-hashes).
        assert lines[number].strip().startswith("--hash=sha256:")
    elif purl["type"] == "npm":
        assert path.name == "package.json"
        assert lines[number - 1].strip().rstrip(",") == f'"{purl["name"]}": "{purl["version"]}"'
        lock = json.loads((path.parent / "package-lock.json").read_text(encoding="utf-8"))
        assert lock["packages"][f"node_modules/{purl['name']}"]["version"] == purl["version"]
        assert lock["packages"][f"node_modules/{purl['name']}"]["integrity"].startswith("sha512-")
    else:
        assert path.name == "pom.xml"
        assert lines[number - 2].strip() == f"<groupId>{purl['namespace']}</groupId>"
        assert lines[number - 1].strip() == f"<artifactId>{purl['name']}</artifactId>"
        assert lines[number].strip() == f"<version>{purl['version']}</version>"
        # The image's classpath is pinned jar by jar: the seed's jar is one of them.
        jars = (path.parent / "jars.sha256").read_text(encoding="utf-8").splitlines()
        assert f"{purl['name']}-{purl['version']}.jar" in {m["jar"] for j in jars if (m := JAR_PIN.match(j))}


@pytest.mark.parametrize("name", sorted(_images()))
def test_the_image_is_built_from_pinned_bases_and_runs_nothing_as_root_in_its_final_stage(name: str) -> None:
    image = _images()[name]
    arguments, stages = _dockerfile(image)
    assert stages, f"{image['dockerfile']} has no FROM"
    for stage in stages:
        base = stage[0].split()[1]
        if variable := re.fullmatch(r"\$\{(\w+)\}", base):
            base = arguments[variable[1]]
        assert PINNED_BASE.match(base), f"{image['dockerfile']}: {base} is not tag@sha256-pinned"
    final = stages[-1]
    assert not [i for i in final if i.startswith("RUN ")], (
        f"{image['dockerfile']}: the final stage runs a RUN"
    )
    users = [i.split()[1] for i in final if i.startswith("USER ")]
    assert users and users[-1] == "10001:10001", image["dockerfile"]
    text = (DEMO / image["dockerfile"]).read_text(encoding="utf-8")
    assert not re.search(r"^# *syntax=", text, flags=re.MULTILINE), "the builder's own frontend only"


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_build_uses_the_seeds_manifest(seed: dict[str, Any]) -> None:
    """The seed's manifest is in the image's build context, next to its Dockerfile, and reaches the build: as
    the build argument that chooses it (the BLOCK image), or copied in by name (web, reports)."""
    image = seed["image"]
    dockerfile = DEMO / image["dockerfile"]
    manifest = DEMO / seed["location"]["path"]
    assert manifest.parent == dockerfile.parent, seed["id"]
    allowed = (dockerfile.parent / f"{dockerfile.name}.dockerignore").read_text(encoding="utf-8").splitlines()
    assert "*" in allowed and f"!{manifest.name}" in allowed, (
        "the context is an allow-list naming the manifest"
    )
    secrets = {DEMO / s["location"]["path"] for s in TRUTH["seeds"] if s["category"] == "SECRET"}
    admitted = {dockerfile.parent / entry.removeprefix("!") for entry in allowed if entry.startswith("!")}
    assert not {path for path in secrets if any(path.is_relative_to(a) for a in admitted)}, "a fake secret"
    arguments, stages = _dockerfile(image)
    build_args = image.get("build_args", {})
    assert set(build_args) <= set(arguments), (
        f"{seed['id']}: a build argument the Dockerfile does not declare"
    )
    chosen = [argument for argument, value in build_args.items() if value == manifest.name]
    if chosen:
        assert arguments[chosen[0]] != manifest.name, (
            "the seed is in the image built on purpose, not by default"
        )
    else:
        copies = [i.split()[1:-1] for stage in stages for i in stage if i.startswith("COPY ")]
        assert any(manifest.name in sources for sources in copies), (
            f"{seed['id']}: {manifest.name} is not copied"
        )


@pytest.mark.parametrize("seed", [s for s in SEEDS if "build_args" in s["image"]], ids=lambda s: s["id"])
def test_the_release_image_does_not_ship_the_seed(seed: dict[str, Any]) -> None:
    """The release image (the Dockerfile's defaults) pins another version: only the BLOCK image carries it."""
    arguments, _ = _dockerfile(seed["image"])
    (argument,) = [
        a for a, v in seed["image"]["build_args"].items() if v == Path(seed["location"]["path"]).name
    ]
    purl = _purl(seed)
    released = {
        _normalized(pin["name"]): pin["version"]
        for line in (DEMO / seed["image"]["dockerfile"])
        .parent.joinpath(arguments[argument])
        .read_text()
        .splitlines()
        if (pin := PIN.match(line))
    }
    assert _normalized(purl["name"]) in released and released[_normalized(purl["name"])] != purl["version"]


def test_the_jar_pins_are_the_classpath_and_nothing_else() -> None:
    """jars.sha256 is what `sha256sum --check --strict` reads in the reports build: one well-formed line per
    jar, each jar once, and the build fails if Maven brings any other jar."""
    lines = (DEMO / "services" / "reports" / "jars.sha256").read_text(encoding="utf-8").splitlines()
    pins = [JAR_PIN.match(line) for line in lines]
    assert lines and all(pins), "every line is `<sha256>  lib/<jar>`"
    jars = [pin["jar"] for pin in pins if pin]
    assert len(set(jars)) == len(jars) and len({pin["sha256"] for pin in pins if pin}) == len(jars)
    text = (DEMO / "services" / "reports" / "Dockerfile").read_text(encoding="utf-8")
    assert "--strict-checksums" in text and "sha256sum --check --strict jars.sha256" in text
    assert 'test "$(find lib -type f | wc -l)" -eq "$(wc -l < jars.sha256)"' in text


def _make_builds() -> dict[str, list[str]]:
    """The `docker buildx build` commands of `make container-seed-images`, by the archive name they write."""
    text = (ROOT / "Makefile").read_text(encoding="utf-8").replace("\\\n", " ")
    (recipe,) = re.findall(r"^container-seed-images:.*\n((?:\t.*\n)+)", text, flags=re.MULTILINE)
    builds: dict[str, list[str]] = {}
    for line in recipe.splitlines():
        words = shlex.split(line.strip())
        if words[:3] != ["docker", "buildx", "build"]:
            continue
        (output,) = [w for w in words if w.startswith("type=oci,dest=$(SEED_IMAGES)/")]
        name = output.removeprefix("type=oci,dest=$(SEED_IMAGES)/").removesuffix(".oci.tar")
        assert name not in builds, f"{name} is built twice"
        builds[name] = words
    return builds


def test_make_builds_each_image_as_the_ground_truth_says() -> None:
    builds = _make_builds()
    assert sorted(builds) == sorted(_images())
    for name, image in _images().items():
        words = builds[name]
        dockerfile = f"demo-shop/{image['dockerfile']}"
        assert words[words.index("--file") + 1] == dockerfile, name
        assert words[-1] == str(Path(dockerfile).parent), f"{name}: the context is the Dockerfile's directory"
        given = {words[i + 1] for i, w in enumerate(words) if w == "--build-arg"}
        assert given == {f"{k}={v}" for k, v in image.get("build_args", {}).items()}, name
        assert {"--provenance=false", "--sbom=false"} <= set(words), name


@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_feed_fixtures_know_the_advisory_offline(seed: dict[str, Any]) -> None:
    entry = SNAPSHOT_VULNERABILITIES[seed["cve"]]
    assert seed["vulnerability"] in entry.get("aliases", []), seed["id"]
    assert any(f["rule_id"] == seed["vulnerability"] for f in FEED_FINDINGS), seed["id"]
    enrichment = enrich_finding(_finding(seed), load_snapshot(SNAPSHOT), None)["enrichment"]
    assert enrichment["kev"]["listed"] is seed["kev"] and "cvss" in enrichment and "epss" in enrichment


def _installed_at(seed: dict[str, Any]) -> str:
    """Where the image holds the seed's package: the file Syft reads it from."""
    purl = _purl(seed)
    name, version = purl["name"], purl["version"]
    if purl["type"] == "pypi":
        return f"/opt/venv/lib/python3.12/site-packages/{name}-{version}.dist-info/METADATA"
    if purl["type"] == "npm":
        return f"/app/node_modules/{name}/package.json"
    return f"/app/lib/{name}-{version}.jar"


def _image_report(seed: dict[str, Any]) -> dict[str, Any]:
    """Grype's report of an image holding the seed's package, from the golden report's match of that advisory
    on that package (the same shape `test_grype_image.py` derives from it)."""
    golden = json.loads((ROOT / "cli/tests/normalize/fixtures/grype/grype-demo-shop.json").read_text("utf-8"))
    (raw,) = [
        m for m in golden["matches"]
        if m["vulnerability"]["id"] == seed["vulnerability"] and m["artifact"]["purl"] == seed["package"]
    ]  # fmt: skip
    path = _installed_at(seed)
    raw["artifact"]["locations"] = [{"path": path, "layerID": "sha256:" + "1b" * 32, "accessPath": path}]
    golden["matches"] = [raw]
    golden["source"] = {
        "type": "image",
        "target": {
            "userInput": f"{seed['image']['name']}.oci.tar",
            "manifestDigest": IMAGE_DIGEST,
            "layers": [],
        },
    }
    return golden


def _finding(seed: dict[str, Any]) -> dict[str, Any]:
    """The CONTAINER finding the image adapter gives for the seed (A1)."""
    run = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release")
    image = ImageSubject(digest=IMAGE_DIGEST, ref=f"kind-registry:5000/demo-shop/{seed['image']['name']}")
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


# ---------------------------------------------------------------- the built images (opt-in)

IMAGES = os.environ.get("SENTINEL_CONTAINER_IMAGES")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")


def _manifest_digest(archive: Path) -> str:
    """The digest of the one image of an OCI layout archive (its index.json)."""
    with tarfile.open(archive) as tar:
        member = tar.extractfile("index.json")
        assert member is not None, "not an OCI layout archive"
        (manifest,) = json.load(member)["manifests"]
    return str(manifest["digest"])


@cache
def _detected(name: str) -> frozenset[tuple[str, str, str]]:
    """(tool, rule, purl) of each CONTAINER finding of the image `name`, scanned once by the pinned tools."""
    archive = Path(str(IMAGES)) / f"{name}.oci.tar"
    digest = _manifest_digest(archive)
    scan = scan_image(
        archive,
        image_digest=digest,
        name=f"kind-registry:5000/demo-shop/{name}",
        db_dir=Path(str(GRYPE_DB)),
        lock=load_lock(ROOT / "tools.lock.toml"),
        tools_dir=Path(str(TOOLS_DIR)),
    )
    run = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="0" * 40, context="release")
    findings = normalize_grype_image(scan.report, run=run, image=ImageSubject(digest=digest, ref=name))
    return frozenset(
        (f.tool.name, f.rule_id, f.package.purl) for f in findings if f.package and f.package.purl
    )


@pytest.mark.skipif(
    not (IMAGES and GRYPE_DB and TOOLS_DIR),
    reason="set SENTINEL_CONTAINER_IMAGES, SENTINEL_GRYPE_DB_DIR and SENTINEL_TOOLS_DIR (README.md)",
)
@pytest.mark.integration
@pytest.mark.parametrize("seed", SEEDS, ids=lambda s: s["id"])
def test_the_pinned_scanners_detect_the_seed_in_the_built_image(seed: dict[str, Any]) -> None:
    detected = {
        (tool, rule) for tool, rule, purl in _detected(seed["image"]["name"]) if purl == seed["package"]
    }
    expected = {(d["tool"], d["rule"]) for d in seed["expected"]["detections"]}
    assert expected <= detected, (seed["id"], sorted(detected))
