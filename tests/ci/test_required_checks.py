"""The checks `main` requires (`CLAUDE.md`, "Repository status", ADR-0016) are `ci.yml`'s jobs, and `ci.yml`
reports each of them on every pull request (#160 review, nit 4). Branch protection names a check by its job's
`name:`: a renamed job, a path filter or a job-level `if:` would leave a required check that never reports,
and no pull request could be merged."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI: dict[Any, Any] = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))


def _required() -> list[str]:
    """The checks `CLAUDE.md`'s "Repository status" section requires, as it names them."""
    text = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    section = text.split("## Repository status", 1)[1].split("\n## ", 1)[0]
    (sentence,) = re.findall(r"The checks (.+?) are required", " ".join(section.split()))
    return re.findall(r"`([^`]+)`", sentence)


def test_the_required_checks_are_the_names_of_ci_jobs() -> None:
    required = _required()
    assert len(required) == len(set(required)) == 3
    assert set(required) == {job.get("name", key) for key, job in CI["jobs"].items()}


def test_ci_reports_every_job_on_every_pull_request() -> None:
    triggers = CI.get("on", CI.get(True))  # YAML 1.1 reads a bare `on` key as true
    pull_request = triggers["pull_request"] or {}
    assert not {"paths", "paths-ignore", "branches", "branches-ignore", "types"} & set(pull_request)
    assert not [key for key, job in CI["jobs"].items() if "if" in job]
