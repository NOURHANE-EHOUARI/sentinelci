"""Dependabot's configuration (A10, #115 review, nit 2): nothing else reads .github/dependabot.yml, not even
zizmor, so these tests are the only check of its rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".github" / "dependabot.yml"


def updates() -> list[dict[str, Any]]:
    document: dict[str, Any] = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert document["version"] == 2
    entries: list[dict[str, Any]] = document["updates"]
    return entries


def entry(ecosystem: str) -> dict[str, Any]:
    (found,) = [u for u in updates() if u["package-ecosystem"] == ecosystem]
    return found


def test_every_entry_waits_a_week_before_adopting_a_release() -> None:
    for update in updates():
        assert update["cooldown"]["default-days"] >= 7, update["package-ecosystem"]


def test_the_intentionally_vulnerable_demo_is_never_updated() -> None:
    for update in updates():
        directories = [update.get("directory", ""), *update.get("directories", [])]
        demo = [d for d in directories if d.strip("/").startswith("demo-shop")]
        assert not demo, update["package-ecosystem"]


def test_a_major_version_never_comes_grouped_with_minor_and_patch_updates() -> None:
    for ecosystem in ("uv", "npm"):
        for group in entry(ecosystem)["groups"].values():
            assert sorted(group["update-types"]) == ["minor", "patch"], ecosystem


def test_typescript_majors_wait_while_the_client_generator_needs_typescript_5() -> None:
    package = json.loads((ROOT / "platform" / "web" / "package.json").read_text(encoding="utf-8"))
    declared = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    generator = declared["openapi-typescript"]
    ignored = {i["dependency-name"]: i["update-types"] for i in entry("npm").get("ignore", [])}
    if generator.split(".")[0] == "7":  # openapi-typescript 7 accepts TypeScript ^5 as a peer
        assert ignored.get("typescript") == ["version-update:semver-major"]


def test_uv_in_the_image_moves_only_with_the_version_ci_pins() -> None:
    """The workflows pin uv exactly and Dependabot does not update setup-uv's `version`: a uv bump of the
    image alone, even a patch, would split the image from CI (#115 review, nit 1)."""
    ignored = {i["dependency-name"]: set(i["update-types"]) for i in entry("docker")["ignore"]}
    assert ignored["astral-sh/uv"] == {
        "version-update:semver-major", "version-update:semver-minor", "version-update:semver-patch",
    }  # fmt: skip
    assert ignored["python"] == {"version-update:semver-major", "version-update:semver-minor"}
