"""`GET /api/v1/runs` (API 1.5.0, A8's pages): recorded runs, newest first, filtered and paginated, on a real
PostgreSQL."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

VALID = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "finding" / "valid"
NDJSON = {"Content-Type": "application/x-ndjson"}


def run(
    client: TestClient, headers: dict[str, str], repo: str, commit: str, context: str, **extra: str
) -> str:
    created = client.post(
        "/api/v1/runs", json={"repo": repo, "commit": commit, "context": context, **extra}, headers=headers
    )
    assert created.status_code == 201, created.text
    run_id: str = created.json()["id"]
    return run_id


def upload(client: TestClient, headers: dict[str, str], run_id: str, run_fields: dict[str, Any]) -> str:
    document = json.loads((VALID / "secret-in-config.json").read_text(encoding="utf-8")) | {"run": run_fields}
    body = (json.dumps(document) + "\n").encode()
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert uploaded.status_code == 201, uploaded.text
    return hashlib.sha256(body).hexdigest()


def ids(response: Any) -> list[str]:
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()["items"]]


def test_no_run_is_an_empty_page(client: TestClient) -> None:
    assert client.get("/api/v1/runs").json() == {"items": [], "total": 0, "limit": 100, "offset": 0}


def test_runs_are_listed_newest_first_and_filtered(client: TestClient, headers: dict[str, str]) -> None:
    main = {"ref": "refs/heads/main"}
    first = run(client, headers, "acme/shop", "a" * 40, "release", **main)
    second = run(client, headers, "acme/shop", "b" * 40, "pr", ref="refs/pull/7/merge", run_id="17/1")
    third = run(client, headers, "acme/billing", "c" * 40, "release", **main)
    digest = upload(
        client, headers, first, {"repo": "acme/shop", "commit": "a" * 40, "context": "release", **main}
    )

    assert ids(client.get("/api/v1/runs")) == [third, second, first]
    assert ids(client.get("/api/v1/runs", params={"repo": "acme/shop"})) == [second, first]
    assert ids(client.get("/api/v1/runs", params={"context": "release"})) == [third, first]
    assert ids(client.get("/api/v1/runs", params={"ref": "refs/heads/main", "repo": "acme/shop"})) == [first]
    assert ids(client.get("/api/v1/runs", params={"ref": "refs/heads"})) == [], "a ref is matched exactly"

    page = client.get("/api/v1/runs", params={"repo": "acme/shop"}).json()
    assert page["total"] == 2
    recorded, pending = page["items"][1], page["items"][0]
    assert (recorded["findings_sha256"], recorded["finding_count"]) == (digest, 1)
    assert (pending["findings_sha256"], pending["run_id"], pending["ref"]) == (
        None,
        "17/1",
        "refs/pull/7/merge",
    )


def test_pages_never_repeat_or_skip_a_run(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    """Runs created in the same instant: the run id decides, so walking the pages gives every run once."""
    made = [run(client, headers, "acme/shop", f"{n:x}" * 40, "pr") for n in range(1, 8)]
    with psycopg.connect(database_url, autocommit=True) as conn:  # none is recorded: the trigger allows it
        conn.execute("UPDATE runs SET created_at = '2026-11-01T00:00:00Z'")
    walked: list[str] = []
    for offset in range(0, 7, 3):
        page = client.get("/api/v1/runs", params={"limit": 3, "offset": offset}).json()
        assert (page["total"], page["limit"], page["offset"]) == (7, 3, offset)
        walked += [item["id"] for item in page["items"]]
    assert walked == sorted(made)


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 501},
        {"offset": -1},
        {"offset": 1_000_001},
        {"repo": "not a repo"},
        {"context": "nightly"},
        {"ref": "refs/heads/main\nx"},
        {"ref": ""},
    ],
    ids=[
        "limit-0",
        "limit-501",
        "negative-offset",
        "huge-offset",
        "bad-repo",
        "bad-context",
        "ref-newline",
        "empty-ref",
    ],
)
def test_bad_parameters_are_refused(client: TestClient, params: dict[str, Any]) -> None:
    assert client.get("/api/v1/runs", params=params).status_code == 422


def test_reading_runs_needs_no_token_like_the_other_reads(
    client: TestClient, headers: dict[str, str]
) -> None:
    made = run(client, headers, "acme/shop", "a" * 40, "local")
    assert ids(client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong"})) == [made]
