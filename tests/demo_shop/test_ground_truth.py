"""The demo-shop benchmark (SPEC section 17): every seed is documented, scanners find exactly the seeds.

- Structure tests always run: ids, paths, lines, fake secrets, and each seeded file names its ground-truth id.
- zizmor runs always (a dependency of the CLI, installed by `uv sync`).
- Gitleaks and Trivy run as integration tests when SENTINEL_TOOLS_DIR points to a `sentinel tools install`
  directory, through the verified runner, with SentinelCI's own scanner configuration.

The `detections` listed in the ground truth are the ones verified with the pinned tools, so these tests keep
the ground truth honest when a tool or a seed changes. A seed no pinned tool detects lists none and says
why in `known_miss` (ADR-0012); the Trivy test checks that it is still missed, so a tool upgrade that
starts detecting it shows up.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.scanners.gitleaks import scan_secrets
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.trivy import scan_iac_with_run

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-shop"
GROUND_TRUTH = DEMO / "ground-truth" / "findings.yaml"
CATEGORIES = {"SECRET", "SAST", "SCA", "CONTAINER", "IAC", "PIPELINE", "LICENSE"}
ID = re.compile(r"^GT-(SECRET|SAST|SCA|CONTAINER|IAC|PIPELINE|LICENSE|CANARY|CLEAN)-[0-9]{3}$")
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)

TRUTH: dict[str, Any] = yaml.safe_load(GROUND_TRUTH.read_text(encoding="utf-8"))
SEEDS: list[dict[str, Any]] = TRUTH["seeds"]
CONTROLS: list[dict[str, Any]] = TRUTH["controls"]
CANARIES: list[dict[str, Any]] = TRUTH.get("canaries", [])
TOKEN = re.compile(r"^CANARY-[A-Z0-9]+(?:-[A-Z0-9]+)+$")
SHOP_API = DEMO / "services" / "shop-api"
PIN = re.compile(r"^([a-z0-9][a-z0-9._-]*)==([^\s\\]+) \\$")


def _expected(tool: str) -> set[tuple[str, str]]:
    """(path, rule) pairs every listed detection of `tool` must produce."""
    return {
        (seed["location"]["path"], detection["rule"])
        for seed in SEEDS
        for detection in seed["expected"]["detections"]
        if detection["tool"] == tool
    }


def _controls(tool: str) -> set[str]:
    return {control["location"]["path"] for control in CONTROLS if tool in control["must_not_detect"]}


# ---------------------------------------------------------------- structure


def test_ground_truth_is_well_formed() -> None:
    assert TRUTH["version"] == 1
    ids = [entry["id"] for entry in [*SEEDS, *CONTROLS]]
    assert len(ids) == len(set(ids)), "ground-truth ids must be unique"
    for entry in [*SEEDS, *CONTROLS]:
        assert ID.match(entry["id"]), entry["id"]
        assert entry["owner"] in {"A9", "B9"}, entry["id"]
        assert entry["category"] in CATEGORIES, entry["id"]
        assert entry["title"].strip(), entry["id"]
        path = entry["location"]["path"]
        assert not path.startswith("/") and ".." not in Path(path).parts, path
        target = DEMO / path
        assert target.is_file(), f"{entry['id']}: {path} does not exist"
        if "line" in entry["location"]:
            lines = target.read_text(encoding="utf-8").splitlines()
            assert 1 <= entry["location"]["line"] <= len(lines), entry["id"]
    for seed in SEEDS:
        prefix = seed["id"].split("-")[1]
        assert prefix == seed["category"], f"{seed['id']} is filed under {seed['category']}"
        if seed["expected"]["detections"]:
            assert "known_miss" not in seed, f"{seed['id']} is detected: drop known_miss"
        else:
            assert str(seed.get("known_miss", "")).strip(), f"{seed['id']}: no detection, and no known_miss"
            # Only the Trivy test checks that a known miss is still missed: other categories get the same
            # check with their first known miss.
            assert seed["category"] == "IAC", f"{seed['id']}: known_miss is checked for IAC seeds only"
        for detection in seed["expected"]["detections"]:
            assert set(detection) == {"tool", "rule"} and all(detection.values()), seed["id"]
    for control in CONTROLS:
        assert control["id"].startswith("GT-CLEAN-")
        assert control["must_not_detect"], control["id"]
    assert set(TRUTH) <= {"version", "seeds", "canaries", "controls"}


# ---------------------------------------------------------------- prompt-injection canaries (B9)


def test_canaries_are_well_formed_and_planted_where_they_say() -> None:
    """Each canary is a token on its line, beside the seed an AI reads it with; no two share a token."""
    seed_ids = {seed["id"] for seed in SEEDS}
    tokens = [canary["token"] for canary in CANARIES]
    assert len(tokens) == len(set(tokens)) and CANARIES, "one unique token per canary"
    for canary in CANARIES:
        assert set(canary) == {"id", "owner", "title", "location", "near", "token"}, canary["id"]
        assert re.fullmatch(r"GT-CANARY-[0-9]{3}", canary["id"]) and canary["owner"] == "B9", canary["id"]
        assert TOKEN.fullmatch(canary["token"]), canary["id"]
        assert canary["near"] in seed_ids, canary["id"]
        lines = (DEMO / canary["location"]["path"]).read_text(encoding="utf-8").splitlines()
        assert canary["token"] in lines[canary["location"]["line"] - 1], f"{canary['id']}: not on its line"
        assert canary["id"] in "\n".join(lines), canary["id"]
        planted = [
            path
            for path in DEMO.rglob("*")
            if path.is_file()
            and GROUND_TRUTH.parent not in path.parents
            and canary["token"] in path.read_text("utf-8", "replace")
        ]
        assert planted == [DEMO / canary["location"]["path"]], f"{canary['token']} is planted once"


# ---------------------------------------------------------------- the release image's requirements (B9)


def _pins(name: str) -> dict[str, list[str]]:
    """package -> hashes of a hash-pinned requirements file; every requirement must have a hash."""
    pins: dict[str, list[str]] = {}
    current = None
    for line in (SHOP_API / name).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if match := PIN.match(line):
            current = match[1] + "==" + match[2]
            assert current not in pins, current
            pins[current] = []
        else:
            hashed = re.fullmatch(r"    --hash=sha256:([0-9a-f]{64})(?: \\)?", line)
            assert hashed is not None and current is not None, f"{name}: {line!r}"
            pins[current].append(hashed[1])
    assert pins and all(pins.values()), f"{name}: every requirement is pinned and hashed"
    return pins


def test_the_release_and_block_requirements_differ_only_in_the_seeded_pyyaml() -> None:
    """ADR-0011 decision 6: the BLOCK image is the release image with pyyaml 5.3.1 (GT-SCA-001), pinned by
    the hash of its sdist; the release image holds no seeded version."""
    release, block = _pins("requirements.release.txt"), _pins("requirements.block.txt")
    pyyaml = [pin for pin in release if pin.startswith("pyyaml==")]
    assert pyyaml and pyyaml[0] != "pyyaml==5.3.1"
    assert {k: v for k, v in release.items() if k not in pyyaml} == {
        k: v for k, v in block.items() if k != "pyyaml==5.3.1"
    }
    sdist = "b8eac752c5e14d3eca0e6dd9199cd627518cb5ec06add0de9d32baeee6fe645d"  # PyYAML-5.3.1.tar.gz
    assert block["pyyaml==5.3.1"] == [sdist]
    seeded = {
        line.split()[0]
        for line in (SHOP_API / "requirements.txt").read_text("utf-8").splitlines()
        if line and not line.startswith(("#", " "))
    }
    vulnerable = {"lxml==4.6.2", "pyyaml==5.3.1", "requests==2.30.0"} & seeded
    assert vulnerable == {"lxml==4.6.2", "pyyaml==5.3.1", "requests==2.30.0"}
    assert not vulnerable & set(release), "the release image installs no seeded version"


def test_the_application_imports_what_the_ground_truth_says() -> None:
    """Read, never run (demo-shop code runs only in its container): shop-api imports yaml and requests, which
    the SCA seeds mark imported, and never lxml (GT-SCA-003, declared and never imported)."""
    import ast

    imported: set[str] = set()
    for source in (SHOP_API / "app").glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
    module = {"pyyaml": "yaml", "requests": "requests", "lxml": "lxml"}
    for seed in SEEDS:
        name = seed.get("package", "").removeprefix("pkg:pypi/").split("@")[0]
        if name in module and "imported" in seed:
            assert (module[name] in imported) == seed["imported"], seed["id"]


@pytest.mark.parametrize("entry", [*SEEDS, *CONTROLS], ids=lambda e: e["id"])
def test_every_seeded_file_names_its_ground_truth_id(entry: dict[str, Any]) -> None:
    assert entry["id"] in (DEMO / entry["location"]["path"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("seed", [s for s in SEEDS if s["category"] == "SECRET"], ids=lambda s: s["id"])
def test_secrets_are_fake_and_say_so(seed: dict[str, Any]) -> None:
    assert seed.get("fake") is True
    assert "FAKE" in (DEMO / seed["location"]["path"]).read_text(encoding="utf-8")


def test_ci_examples_can_never_run() -> None:
    # GitHub only runs workflows from the repository root's .github/workflows.
    assert not list(DEMO.rglob(".github"))


# ---------------------------------------------------------------- zizmor (always available)


def test_zizmor_finds_every_pipeline_seed_and_nothing_in_controls() -> None:
    workflows = sorted(str(p.relative_to(DEMO)) for p in (DEMO / "examples").rglob("*.yml"))
    zizmor = Path(sys.executable).parent / "zizmor"
    result = subprocess.run(
        [str(zizmor), "--offline", "--format", "json", *workflows],
        cwd=DEMO,
        capture_output=True,
        text=True,
        check=False,
    )
    found = {
        (f["locations"][0]["symbolic"]["key"]["Local"]["verbatim_path"], f["ident"])
        for f in json.loads(result.stdout)
    }
    assert _expected("zizmor") <= found
    assert not {path for path, _ in found} & _controls("zizmor")


# ---------------------------------------------------------------- real scanners (integration)


@real
@pytest.mark.integration
def test_gitleaks_finds_exactly_the_secret_seeds() -> None:
    raw = scan_secrets(DEMO, lock=load_lock(ROOT / "tools.lock.toml"), tools_dir=Path(str(TOOLS_DIR)))
    found = {(item["File"], item["StartLine"], item["RuleID"]) for item in raw}
    expected = {
        (seed["location"]["path"], seed["location"]["line"], detection["rule"])
        for seed in SEEDS
        for detection in seed["expected"]["detections"]
        if detection["tool"] == "gitleaks"
    }
    assert found == expected, "recall must be 5/5 with no false positive, controls included"


@real
@pytest.mark.integration
def test_trivy_finds_every_iac_seed_and_nothing_in_controls() -> None:
    # The hardened adapter (`sentinel scan iac`): offline, no repository config, SentinelCI's check data.
    results, _ = scan_iac_with_run(
        DEMO, lock=load_lock(ROOT / "tools.lock.toml"), tools_dir=Path(str(TOOLS_DIR))
    )
    found = {
        (r["Target"], m["ID"])
        for r in results
        for m in r.get("Misconfigurations", [])
        if m.get("Status") == "FAIL"
    }
    assert _expected("trivy") <= found
    assert not {path for path, _ in found} & _controls("trivy")
    for seed in (s for s in SEEDS if "known_miss" in s and s["category"] == "IAC"):
        rules = sorted(rule for path, rule in found if path == seed["location"]["path"])
        assert not rules, (
            f"{seed['id']} is a known miss, but Trivy now reports {rules} in its file. If a rule flags "
            "the seed, list it in expected.detections and drop known_miss; never edit the seed to hide it"
        )
