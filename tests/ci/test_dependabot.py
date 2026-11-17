"""Dependabot's configuration (A10, #115 review, nit 2): nothing else reads .github/dependabot.yml, not even
zizmor, so these tests are the only check of its rules."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path, PurePosixPath
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


def test_uv_resolves_nothing_newer_than_dependabots_cooldown() -> None:
    """Dependabot's cooldown covers only the packages it names, and uv resolves the rest: uv waits the same
    week for every package it resolves (#135 review: grimp 3.20 came in under import-linter, 25 hours old)."""
    days = entry("uv")["cooldown"]["default-days"]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["tool"]["uv"]["exclude-newer"] == f"{days} days"
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    assert lock["options"]["exclude-newer-span"] == f"P{days}D", "the lock was not made with the window"


def test_the_intentionally_vulnerable_demo_is_never_updated() -> None:
    for update in updates():
        for directory in [update.get("directory", ""), *update.get("directories", [])]:
            assert not set(directory) & set("*?["), directory  # a glob such as /** reaches demo-shop/
            assert "demo-shop" not in PurePosixPath(directory).parts, directory  # ./demo-shop too


def test_a_major_version_never_comes_grouped_with_minor_and_patch_updates() -> None:
    """Every group, in every ecosystem: a grouped major is how #96 came (#130 review, nit 4)."""
    grouped = [update for update in updates() if "groups" in update]
    ecosystems = {"github-actions", "uv", "npm", "docker-compose", "docker"}
    assert {update["package-ecosystem"] for update in grouped} >= ecosystems
    for update in grouped:
        for group in update["groups"].values():
            assert sorted(group["update-types"]) == ["minor", "patch"], update["package-ecosystem"]


def test_typescript_majors_wait_while_the_client_generator_needs_typescript_5() -> None:
    """The reason is the generator's peer range, which the lockfile records: the check lasts as long as the
    reason does, and asks when the range changes (#130 review, nit 3)."""
    lock = json.loads((ROOT / "platform" / "web" / "package-lock.json").read_text(encoding="utf-8"))
    peer = lock["packages"]["node_modules/openapi-typescript"]["peerDependencies"]["typescript"]
    assert peer == "^5.x", f"the generator now accepts TypeScript {peer}: is the ignore still needed?"
    ignored = {i["dependency-name"]: i["update-types"] for i in entry("npm").get("ignore", [])}
    assert ignored.get("typescript") == ["version-update:semver-major"]


def test_uv_in_the_image_moves_only_with_the_version_ci_pins() -> None:
    """The workflows pin uv exactly and Dependabot does not update setup-uv's `version`: a uv bump of the
    image alone, even a patch, would split the image from CI (#115 review, nit 1)."""
    ignored = {i["dependency-name"]: set(i["update-types"]) for i in entry("docker")["ignore"]}
    assert ignored["astral-sh/uv"] == {
        "version-update:semver-major", "version-update:semver-minor", "version-update:semver-patch",
    }  # fmt: skip
    assert ignored["python"] == {"version-update:semver-major", "version-update:semver-minor"}


def test_the_image_and_every_workflow_use_one_uv() -> None:
    """What the ignore protects: the uv of platform/api's image is the one every workflow sets up. A person's
    PR can still split them, for example by bumping one workflow's UV_VERSION (#130 review, nit 1)."""
    dockerfile = (ROOT / "platform" / "api" / "Dockerfile").read_text(encoding="utf-8")
    versions = {"platform/api/Dockerfile": re.findall(r"astral-sh/uv:([0-9.]+)@", dockerfile)}
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        env = jobs.get("env", {})
        for job in jobs["jobs"].values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"):
                    version = str(step["with"]["version"])
                    version = version.replace("${{ env.UV_VERSION }}", str(env.get("UV_VERSION")))
                    versions.setdefault(workflow.name, []).append(version)
    assert versions["platform/api/Dockerfile"], "no uv image in platform/api/Dockerfile"
    assert len(versions) > 1, "no workflow sets up uv"
    assert len({v for vs in versions.values() for v in vs}) == 1, versions
