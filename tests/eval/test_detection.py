"""The detection report of the demo-shop benchmark (eval/detection, task B8): the ground truth's matching
rules, categories never scored when their tool did not run, and the same report for the same inputs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _load_run() -> ModuleType:
    path = ROOT / "eval" / "detection" / "run.py"
    spec = importlib.util.spec_from_file_location("sentinel_eval_detection_run", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


run_module = _load_run()
ToolRun = run_module.ToolRun
score = run_module.score
OK = [ToolRun(tool, "ok", version="1") for tool in ("gitleaks", "trivy", "grype", "opengrep", "zizmor")]


def seed(id_: str, category: str, path: str, tool: str, rule: str, **extra: Any) -> dict[str, Any]:
    return {"id": id_, "category": category, "location": {"path": path, **extra.pop("location", {})},
            "expected": {"detections": [{"tool": tool, "rule": rule}]}, **extra}  # fmt: skip


def finding(
    tool: str, rule: str, path: str, category: str, line: int | None = None, **extra: Any
) -> dict[str, Any]:
    location = {"path": f"demo-shop/{path}", **({"start_line": line} if line else {})}
    tool_of = {"name": tool, "version": "1"}
    return {"tool": tool_of, "rule_id": rule, "category": category, "location": location, **extra}


SECRET = seed(
    "GT-SECRET-001", "SECRET", "config/settings.yaml", "gitleaks", "github-pat", location={"line": 8}
)
IAC = seed("GT-IAC-001", "IAC", "infra/s3.tf", "trivy", "AWS-0086")
SCA = seed("GT-SCA-001", "SCA", "requirements.txt", "grype", "GHSA-x", package="pkg:pypi/pyyaml@5.3.1")
MISS = {
    "id": "GT-IAC-002", "category": "IAC", "location": {"path": "infra/iam.tf"},
    "known_miss": "Trivy misses it", "expected": {"detections": []},
}  # fmt: skip
CONTROL = {"id": "GT-CLEAN-001", "category": "SECRET", "location": {"path": "config/example.yaml"},
           "must_not_detect": ["gitleaks"]}  # fmt: skip


def truth(*seeds: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "seeds": list(seeds), "controls": [CONTROL], "canaries": [{"id": "GT-CANARY-001"}]}


def test_a_secret_is_detected_only_on_its_line() -> None:
    right = score(truth(SECRET), [finding("gitleaks", "github-pat", "config/settings.yaml", "SECRET", 8)], OK)
    wrong = score(truth(SECRET), [finding("gitleaks", "github-pat", "config/settings.yaml", "SECRET", 9)], OK)
    assert right["categories"]["SECRET"]["recall"] == 1.0
    assert wrong["categories"]["SECRET"] | {"tools": None} == {
        "seeds": 1, "tools": None, "measured": True, "detected": 0, "recall": 0.0,
        "missed": [{"id": "GT-SECRET-001"}],
    }  # fmt: skip


def test_a_seed_is_detected_in_any_of_the_findings_places_by_its_own_tool_and_rule() -> None:
    elsewhere = finding(
        "trivy", "AWS-0086", "infra/other.tf", "IAC", other_locations=[{"path": "demo-shop/infra/s3.tf"}]
    )
    assert score(truth(IAC), [elsewhere], OK)["categories"]["IAC"]["detected"] == 1
    for tool, rule in (("trivy", "AWS-0087"), ("checkov", "AWS-0086")):
        assert (
            score(truth(IAC), [finding(tool, rule, "infra/s3.tf", "IAC")], OK)["categories"]["IAC"][
                "detected"
            ]
            == 0
        )


def test_an_sca_seed_is_its_package_and_advisory_wherever_reported() -> None:
    lock = finding(
        "grype", "GHSA-x", "web/package-lock.json", "SCA", package={"purl": "pkg:pypi/pyyaml@5.3.1"}
    )
    other = finding("grype", "GHSA-x", "requirements.txt", "SCA", package={"purl": "pkg:pypi/pyyaml@6.0.3"})
    assert score(truth(SCA), [lock], OK)["categories"]["SCA"]["detected"] == 1
    assert score(truth(SCA), [other], OK)["categories"]["SCA"]["detected"] == 0


def test_a_known_miss_counts_as_a_miss_never_left_out() -> None:
    result = score(truth(IAC, MISS), [finding("trivy", "AWS-0086", "infra/s3.tf", "IAC")], OK)
    assert result["categories"]["IAC"]["recall"] == 0.5
    assert result["categories"]["IAC"]["missed"] == [{"id": "GT-IAC-002", "known_miss": True}]


def test_a_category_whose_tool_did_not_run_is_not_measured_never_zero() -> None:
    runs = [ToolRun("gitleaks", "ok", version="8"), ToolRun("grype", "skipped", reason="no Grype database")]
    result = score(
        truth(SECRET, SCA), [finding("gitleaks", "github-pat", "config/settings.yaml", "SECRET", 8)], runs
    )
    assert result["categories"]["SCA"] == {
        "seeds": 1,
        "tools": ["grype"],
        "measured": False,
        "reason": "not run: grype",
    }
    assert result["overall"] == {"seeds_measured": 1, "detected": 1, "categories_not_measured": ["SCA"]}
    assert result["tools"]["grype"] == {"status": "skipped", "reason": "no Grype database"}


def test_a_finding_in_a_control_by_a_listed_tool_is_a_false_positive_and_any_other_is_unlisted() -> None:
    fp = finding("gitleaks", "generic-api-key", "config/example.yaml", "SECRET", 3)
    other_tool = finding("trivy", "AWS-0001", "config/example.yaml", "IAC")
    in_seeded = finding("trivy", "AWS-0002", "infra/s3.tf", "IAC")
    result = score(truth(SECRET, IAC), [fp, other_tool, in_seeded], OK)
    assert result["controls"]["GT-CLEAN-001"] == {"must_not_detect": ["gitleaks"], "false_positives": 1}
    assert result["false_positives"] == [
        {"control": "GT-CLEAN-001", "tool": "gitleaks", "rule": "generic-api-key"}
    ]
    assert result["unlisted_findings"] == {"IAC": {"in_seeded_files": 1, "elsewhere": 1}}


def test_canaries_are_counted_and_said_not_measured() -> None:
    assert score(truth(SECRET), [], OK)["canaries"]["planted"] == 1
    assert score(truth(SECRET), [], OK)["canaries"]["measured"] is False


def test_the_report_on_the_real_ground_truth_is_the_same_for_the_same_findings(tmp_path: Path) -> None:
    """`--findings`: score recorded findings files. Only gitleaks here, so every other category says why it
    was not measured, and the same files give the same report, byte for byte."""
    truth_doc = run_module.yaml.safe_load(run_module.GROUND_TRUTH.read_text(encoding="utf-8"))
    secrets = [s for s in truth_doc["seeds"] if s["category"] == "SECRET"]
    findings = tmp_path / "in"
    findings.mkdir()
    rows = [finding("gitleaks", s["expected"]["detections"][0]["rule"], s["location"]["path"], "SECRET",
                    s["location"]["line"]) for s in secrets]  # fmt: skip
    (findings / "gitleaks.ndjson").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    for out in ("a", "b"):
        assert run_module.main(["--findings", str(findings), "--out", str(tmp_path / out)]) == 0
    first = (tmp_path / "a" / "detection.json").read_bytes()
    assert first == (tmp_path / "b" / "detection.json").read_bytes()
    report = json.loads(first)
    assert report["categories"]["SECRET"]["recall"] == 1.0
    assert all(not report["categories"][name]["measured"] for name in ("IAC", "SAST", "SCA", "PIPELINE"))
    assert report["tools"]["trivy"] == {"status": "skipped", "reason": "no trivy.ndjson in --findings"}
    assert (
        "| SAST | 10 | — | not measured | not run: opengrep |"
        in (tmp_path / "a" / "detection.md").read_text()
    )


def test_a_failed_scan_reports_the_clis_own_words() -> None:
    boxed = (
        "Usage: sentinel scan [OPTIONS]\nTry 'sentinel scan --help'.\n"
        "╭─ Error ─╮\n│ No such command 'sast'. │\n╰────╯\n"
    )
    assert run_module.reason(boxed) == "Error No such command 'sast'."


# ---------------------------------------------------------------- review of #77


CONTAINER_SEED = seed(
    "GT-CONTAINER-001", "CONTAINER", "services/shop-api/requirements.block.txt", "grype", "GHSA-x",
    package="pkg:pypi/pyyaml@5.3.1",
)  # fmt: skip
SCA_ON_THE_BLOCK_FILE = finding(
    "grype", "GHSA-x", "services/shop-api/requirements.block.txt", "SCA",
    package={"purl": "pkg:pypi/pyyaml@5.3.1"},
)  # fmt: skip


def test_a_finding_detects_only_seeds_of_its_own_category() -> None:
    """With the container seed, an SCA finding of the same package and advisory must not claim it: no image
    was scanned, so CONTAINER is not measured."""
    result = score(truth(SCA, CONTAINER_SEED), [SCA_ON_THE_BLOCK_FILE], OK)
    assert result["categories"]["SCA"]["detected"] == 1
    assert result["categories"]["CONTAINER"] == {
        "seeds": 1, "tools": ["grype"], "measured": False, "reason": "not run: grype did not scan CONTAINER",
    }  # fmt: skip


def test_a_container_scan_measures_container_with_its_own_findings() -> None:
    image_scan = ToolRun("grype", "ok", version="1", categories=("CONTAINER",))
    in_image = finding("grype", "GHSA-x", "usr/local/lib/python3.12/site-packages/PyYAML-5.3.1.dist-info",
                       "CONTAINER", package={"purl": "pkg:pypi/pyyaml@5.3.1"})  # fmt: skip
    measured = score(truth(CONTAINER_SEED), [SCA_ON_THE_BLOCK_FILE], [image_scan])["categories"]["CONTAINER"]
    assert (measured["measured"], measured["detected"]) == (True, 0), "the SCA finding still does not count"
    found = score(truth(CONTAINER_SEED), [in_image], [image_scan])["categories"]["CONTAINER"]
    assert (found["measured"], found["detected"], found["recall"]) == (True, 1, 1.0)


def test_a_category_of_known_misses_only_is_measured_at_zero() -> None:
    result = score(truth(SECRET, MISS | {"category": "PIPELINE"}), [], OK)
    assert result["categories"]["PIPELINE"] == {
        "seeds": 1, "tools": [], "measured": True, "detected": 0, "recall": 0.0,
        "missed": [{"id": "GT-IAC-002", "known_miss": True}],
    }  # fmt: skip


def test_recorded_findings_name_no_tree_and_their_files_digests(tmp_path: Path) -> None:
    findings = tmp_path / "in"
    findings.mkdir()
    body = (json.dumps(finding("gitleaks", "github-pat", "x.yaml", "SECRET", 1), indent=None) + "\n").encode()
    (findings / "gitleaks.ndjson").write_bytes(body.replace(b", ", b",  "))  # not how json.dumps writes it
    assert run_module.main(["--findings", str(findings), "--out", str(tmp_path / "out")]) == 0
    report = json.loads((tmp_path / "out" / "detection.json").read_bytes())
    assert report["inputs"]["demo_shop_tree"] is None and report["inputs"]["findings_recorded"] is True
    expected = hashlib.sha256((findings / "gitleaks.ndjson").read_bytes()).hexdigest()
    assert report["inputs"]["findings_sha256"] == {"gitleaks": expected}, "the file's own bytes"
    assert "recorded findings (`--findings`)" in (tmp_path / "out" / "detection.md").read_text()


def test_an_ignored_file_in_demo_shop_makes_the_tree_unclean(tmp_path: Path, monkeypatch: Any) -> None:
    """The scanners read ignored files too (a local `*.key`), so the report must not name a clean tree."""
    git = ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    (tmp_path / "demo-shop").mkdir()
    (tmp_path / "demo-shop" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.key\n", encoding="utf-8")
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
    monkeypatch.setattr(run_module, "ROOT", tmp_path)
    assert run_module.demo_shop_tree() is not None
    (tmp_path / "demo-shop" / "local.key").write_text("not a real key\n", encoding="utf-8")
    assert run_module.demo_shop_tree() is None
