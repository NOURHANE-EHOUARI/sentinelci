"""Caching (task A10, ADR-0015): only what is verified after it is restored.

A workflow may keep the scanners' release archives between runs, nothing else: each archive is checked against
tools.lock.toml's sha256 before use, and the binary is extracted from it again
(cli/tests/scanners/test_install_verify.py: a corrupted cache is downloaded again instead of trusted). The
binaries and the package managers' caches are never kept: nothing checks them after a restore, and a pull
request's own run could have written them. The jobs that judge a change restore nothing in a pull request,
since the restore itself writes the whole entry before any check (#105 review).
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ARCHIVES = "${{ runner.temp }}/sentinel-tools/cache"
WRITES = ("write",)


def jobs(workflow: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    found: dict[str, Any] = loaded.get("jobs") or {}
    return found


def caches(job: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    return [
        (i, s) for i, s in enumerate(job.get("steps") or []) if s.get("uses", "").startswith("actions/cache")
    ]


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_only_the_verified_release_archives_are_cached(workflow: Path) -> None:
    for name, job in jobs(workflow).items():
        for index, cache in caches(job):
            assert cache["uses"].split("@")[0] == "actions/cache", f"{name}: restore and save, nothing else"
            assert cache["with"]["path"] == ARCHIVES, f"{name}: only the archives tools.lock.toml verifies"
            key = cache["with"]["key"]
            assert key.startswith(f"sentinel-tool-archives-{name}-") and "hashFiles('" in key, key
            assert "tools.lock.toml')" in key, f"{name}: a new lock is a new cache"
            # A prefix would restore another job's entry, which the per-job key keeps apart.
            assert "restore-keys" not in cache["with"], f"{name}: one exact key, no other job's entry"
            following = job["steps"][index + 1].get("run", "")
            assert "tools install" in following, f"{name}: the archives are verified right after the restore"


def test_a_job_that_judges_restores_no_cache_in_a_pull_request() -> None:
    """A pull request's own workflows can save any entry in its cache scope, under any key, and actions/cache
    extracts an entry with `tar -P -C $GITHUB_WORKSPACE` before anything checks it: the restore itself could
    overwrite the pipeline checkout or the CLI that judges the change (#105 review). The scan and the gate
    restore only outside pull requests, where only the base branch's runs wrote the entry."""
    judging = jobs(ROOT / ".github" / "workflows" / "sentinel-scan.yml")
    assert {"scan", "gate"} <= set(judging)
    for name, job in judging.items():
        for _, cache in caches(job):
            assert str(cache.get("if", "")).replace(" ", "") == "github.event_name!='pull_request'", name


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_package_manager_caches_are_explicit_and_kept_only_where_the_change_runs_anyway(
    workflow: Path,
) -> None:
    """setup-uv turns its cache on by default for hosted runners: every step says what it wants. Only ci.yml,
    whose jobs run the change's own code and hold no write token, keeps uv's cache; a job that judges a change
    (sentinel-scan, sentinel-remediate, the nightly replay) never reads a cache nothing verifies."""
    for name, job in jobs(workflow).items():
        for step in job.get("steps") or []:
            uses = step.get("uses", "")
            if uses.startswith("astral-sh/setup-uv@"):
                wanted = step["with"]["enable-cache"]
                assert isinstance(wanted, bool), f"{workflow.name} {name}: say whether uv's cache is kept"
                assert wanted is (workflow.name == "ci.yml"), f"{workflow.name} {name}: enable-cache {wanted}"
            if uses.startswith("actions/setup-node@"):
                assert step["with"]["package-manager-cache"] is False, f"{name}: npm's cache is never kept"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_job_that_holds_a_write_permission_restores_a_cache(workflow: Path) -> None:
    for name, job in jobs(workflow).items():
        if caches(job):
            permissions = job.get("permissions") or {}
            assert isinstance(permissions, dict), f"{name}: explicit permissions"
            assert not [p for p, level in permissions.items() if level in WRITES], (
                f"{name}: a job with a write token restores nothing another run wrote"
            )


def test_the_jobs_that_install_scanners_keep_their_archives() -> None:
    cached = {
        (workflow.name, name) for workflow in WORKFLOWS for name, job in jobs(workflow).items() if caches(job)
    }
    assert {("sentinel-scan.yml", "scan"), ("sentinel-scan.yml", "gate"), ("ci.yml", "checks")} <= cached
