"""The OpenSSF Scorecard workflow (task A10): it runs only once the repository is public, holds only what
Scorecard needs, and keeps its result as an artifact (no code-scanning upload, ADR-0006)."""

from pathlib import Path
from typing import Any

import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scorecard.yml"


def workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return loaded


def test_it_runs_only_once_the_repository_is_public() -> None:
    (job,) = workflow()["jobs"].values()
    assert job["if"].replace(" ", "") == "${{github.event.repository.visibility=='public'}}"


def test_every_trigger_has_the_payload_its_condition_reads() -> None:
    # `github.event` is the webhook payload, and a scheduled run has none: there, both
    # `!github.event.repository.private` and `github.event.repository.private == false` are true
    # (#104 review).
    assert set(workflow()[True]) <= {"push", "workflow_dispatch"}


def test_it_holds_only_what_scorecard_needs() -> None:
    document = workflow()
    assert document["permissions"] == {}
    (job,) = document["jobs"].values()
    assert job["permissions"] == {"contents": "read", "actions": "read", "id-token": "write"}
    assert "security-events" not in job["permissions"], "no code-scanning upload in this project (ADR-0006)"


def test_it_scores_main_and_publishes_its_result() -> None:
    document = workflow()
    triggers = document[True]  # PyYAML reads the `on:` key as True
    assert triggers["push"] == {"branches": ["main"]}
    assert "pull_request" not in triggers and "pull_request_target" not in triggers
    (job,) = document["jobs"].values()
    (scorecard,) = [s for s in job["steps"] if s.get("uses", "").startswith("ossf/scorecard-action@")]
    assert scorecard["with"]["publish_results"] is True
    (keep,) = [s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert keep["with"]["path"] == scorecard["with"]["results_file"]
