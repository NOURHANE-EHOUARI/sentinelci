"""The demo-shop benchmark (SPEC section 17): every seed is documented, scanners find exactly the seeds.

- Structure tests always run: ids, paths, lines, fake secrets, and each seeded file names its ground-truth id.
- zizmor runs always (it is a dev dependency).
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
import tempfile
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.scanners.gitleaks import scan_secrets
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool

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
    with (
        tempfile.TemporaryDirectory(prefix="sentinel-trivy-") as work,
        as_file(files("sentinelci.scanners.configs").joinpath("trivy-data")) as config_data,
    ):
        report = Path(work) / "report.json"
        args = ["config", "--quiet", "--skip-check-update", "--cache-dir", str(Path(work) / "cache")]
        args += ["--config-data", str(config_data), "--format", "json", "--output", str(report), "."]
        run_verified_tool(
            "trivy",
            args,
            lock=load_lock(ROOT / "tools.lock.toml"),
            tools_dir=Path(str(TOOLS_DIR)),
            cwd=DEMO,
        )
        results = json.loads(report.read_text(encoding="utf-8")).get("Results", [])
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
