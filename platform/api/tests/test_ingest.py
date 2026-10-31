"""Ingestion and query API v1 (SPEC section 13.3) against a real PostgreSQL."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
RUN = {
    "repo": "NOURHANE-EHOUARI/sentinelci",
    "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "context": "pr",
}
NDJSON = {"Content-Type": "application/x-ndjson"}


def finding(name: str, **run: str) -> dict[str, Any]:
    """A valid Finding v1 fixture, moved to the run under test."""
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    document["run"] = {**RUN, **run}
    return document


def ndjson(*documents: dict[str, Any]) -> bytes:
    return "".join(json.dumps(d) + "\n" for d in documents).encode("utf-8")


SECRET = finding("secret-in-config.json")
SCA = finding("sca-enriched-and-scored.json")
CONTAINER = finding("container-os-package.json")


def create_run(client: TestClient, headers: dict[str, str], **fields: str) -> str:
    response = client.post("/api/v1/runs", json={**RUN, **fields}, headers=headers)
    assert response.status_code == 201, response.text
    run_id: str = response.json()["id"]
    return run_id


def upload(client: TestClient, headers: dict[str, str], run_id: str, body: bytes) -> Any:
    return client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})


# ---------------------------------------------------------------- authentication


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer wrong-token", "Basic dGVzdDp0ZXN0", "Bearer", "bearer  "],
    ids=["missing", "wrong-token", "other-scheme", "empty", "blank"],
)
def test_writes_need_a_valid_token(client: TestClient, authorization: str | None) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.post("/api/v1/runs", json=RUN, headers=headers)
    assert response.status_code == 401, response.text
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert client.get("/api/v1/findings").json()["items"] == []


def test_findings_upload_needs_a_valid_token(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    response = upload(client, {"Authorization": "Bearer wrong-token"}, run_id, ndjson(SECRET))
    assert response.status_code == 401
    assert client.get("/api/v1/findings").json()["items"] == []


def test_without_configured_tokens_every_write_is_refused(database_url: str) -> None:
    from sentinel_api.config import Settings
    from sentinel_api.main import create_app

    with TestClient(create_app(Settings(database_url=database_url, token_sha256=frozenset()))) as client:
        response = client.post("/api/v1/runs", json=RUN, headers={"Authorization": "Bearer anything"})
    assert response.status_code == 401, "no token configured must never mean an open API"


# ---------------------------------------------------------------- runs


def test_a_run_is_created_and_returned(client: TestClient, headers: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/runs", json={**RUN, "ref": "refs/pull/12/merge", "run_id": "11223344"}, headers=headers
    )
    assert response.status_code == 201, response.text
    run = response.json()
    assert {k: run[k] for k in ("repo", "commit", "context", "ref", "run_id")} == {
        **RUN, "ref": "refs/pull/12/merge", "run_id": "11223344",
    }  # fmt: skip
    assert run["finding_count"] == 0 and run["findings_sha256"] is None
    assert client.get(f"/api/v1/runs/{run['id']}").json() == run


@pytest.mark.parametrize(
    "fields",
    [
        {"repo": "not a repo"},
        {"repo": "owner/name\nx"},
        {"commit": "4b825dc"},
        {"commit": "4B825DC642CB6EB9A060E54BF8D69288FBEE4904"},
        {"context": "nightly"},
        {"ref": "refs/heads/a\u2028b"},
        {"run_id": "1\n2"},
        {"extra": "field"},
    ],
    ids=[
        "repo",
        "repo-newline",
        "short-commit",
        "uppercase-commit",
        "context",
        "ref-line-separator",
        "run-id-newline",
        "unknown-field",
    ],
)
def test_an_invalid_run_is_refused(
    client: TestClient, headers: dict[str, str], fields: dict[str, str]
) -> None:
    response = client.post("/api/v1/runs", json={**RUN, **fields}, headers=headers)
    assert response.status_code == 422, response.text


def test_an_unknown_run_is_not_found(client: TestClient, headers: dict[str, str]) -> None:
    missing = "00000000-0000-4000-8000-000000000000"
    assert client.get(f"/api/v1/runs/{missing}").status_code == 404
    assert upload(client, headers, missing, ndjson(SECRET)).status_code == 404


# ---------------------------------------------------------------- findings upload


def test_findings_are_stored_and_listed(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    body = ndjson(SECRET, SCA, CONTAINER)

    response = upload(client, headers, run_id, body)

    assert response.status_code == 201, response.text
    assert response.json() == {
        "run_id": run_id, "finding_count": 3, "findings_sha256": hashlib.sha256(body).hexdigest(),
    }  # fmt: skip
    run = client.get(f"/api/v1/runs/{run_id}").json()
    assert (run["finding_count"], run["findings_sha256"]) == (3, hashlib.sha256(body).hexdigest())
    listed = client.get("/api/v1/findings").json()
    assert listed["total"] == 3
    assert {item["finding"]["id"] for item in listed["items"]} == {SECRET["id"], SCA["id"], CONTAINER["id"]}
    stored = next(item["finding"] for item in listed["items"] if item["finding"]["id"] == SCA["id"])
    assert stored == SCA, "the document is kept exactly as uploaded"
    assert all(item["run_id"] == run_id for item in listed["items"])


def test_one_finding_is_returned_with_every_run_that_reported_it(
    client: TestClient, headers: dict[str, str]
) -> None:
    first = create_run(client, headers)
    upload(client, headers, first, ndjson(SECRET))
    second = create_run(client, headers, commit="a" * 40)
    upload(client, headers, second, ndjson(finding("secret-in-config.json", commit="a" * 40)))

    response = client.get(f"/api/v1/findings/{SECRET['id']}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding"]["run"]["commit"] == "a" * 40, "the latest occurrence"
    assert [o["run_id"] for o in body["occurrences"]] == [second, first]


def test_an_unknown_or_malformed_finding_id(client: TestClient) -> None:
    assert client.get(f"/api/v1/findings/{'0' * 64}").status_code == 404
    assert client.get("/api/v1/findings/not-a-fingerprint").status_code == 422


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (ndjson(SECRET) + b"{broken\n", "line 2: invalid JSON"),
        (ndjson(SECRET) + b"[1, 2]\n", "line 2: expected a JSON object"),
        (ndjson(SECRET, {**SCA, "category": "sca"}), "line 2: not a Finding v1"),
        (ndjson(SECRET, {**SCA, "id": "x"}), "line 2: 'id' must be a sha256 fingerprint"),
        (b"\xff\xfe", "not UTF-8"),
        (ndjson(SECRET, SECRET), "appears twice"),
    ],
    ids=["invalid-json", "not-an-object", "not-a-finding", "bad-id", "not-utf8", "duplicate"],
)
def test_a_bad_upload_stores_nothing(
    client: TestClient, headers: dict[str, str], body: bytes, expected: str
) -> None:
    run_id = create_run(client, headers)
    response = upload(client, headers, run_id, body)
    assert response.status_code == 422, response.text
    assert expected in response.json()["detail"]
    assert client.get("/api/v1/findings").json()["total"] == 0, "all or nothing"
    assert client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"] is None


@pytest.mark.parametrize(
    "run",
    [
        {"repo": "someone/else"},
        {"commit": "b" * 40},
        {"context": "release"},
        {"ref": "refs/heads/other"},
        {"run_id": "999"},
    ],
    ids=["repo", "commit", "context", "ref", "ci-run-id"],
)
def test_findings_of_another_run_are_refused(
    client: TestClient, headers: dict[str, str], run: dict[str, str]
) -> None:
    ci = {"ref": "refs/pull/12/merge", "run_id": "11223344"}
    run_id = create_run(client, headers, **ci)
    same = finding("sca-enriched-and-scored.json", **ci)
    other = finding("secret-in-config.json", **{**ci, **run})

    response = upload(client, headers, run_id, ndjson(same, other))

    assert response.status_code == 422, response.text
    assert "line 2: the finding belongs to another run" in response.json()["detail"]
    assert client.get("/api/v1/findings").json()["total"] == 0


def test_a_run_takes_one_upload_only(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    assert upload(client, headers, run_id, ndjson(SECRET)).status_code == 201

    again = upload(client, headers, run_id, ndjson(SCA))

    assert again.status_code == 409, again.text
    assert client.get("/api/v1/findings").json()["total"] == 1, "recorded evidence is never replaced"


def test_an_empty_upload_records_a_clean_run(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    response = upload(client, headers, run_id, b"")
    assert response.status_code == 201, response.text
    assert response.json()["finding_count"] == 0
    assert client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"] == hashlib.sha256(b"").hexdigest()


def test_an_oversized_upload_is_refused(database_url: str, headers: dict[str, str]) -> None:
    from sentinel_api.config import Settings
    from sentinel_api.main import create_app

    token_hash = hashlib.sha256(headers["Authorization"].removeprefix("Bearer ").encode()).hexdigest()
    settings = Settings(database_url=database_url, token_sha256=frozenset({token_hash}), max_upload_bytes=100)
    with TestClient(create_app(settings)) as client:
        run_id = create_run(client, headers)
        response = upload(client, headers, run_id, ndjson(SECRET))
        assert response.status_code == 413, response.text
        assert client.get("/api/v1/findings").json()["total"] == 0


def test_an_oversized_chunked_upload_is_refused(database_url: str, headers: dict[str, str]) -> None:
    """Without Content-Length, the limit applies to the bytes actually streamed."""
    from sentinel_api.config import Settings
    from sentinel_api.main import create_app

    token_hash = hashlib.sha256(headers["Authorization"].removeprefix("Bearer ").encode()).hexdigest()
    settings = Settings(database_url=database_url, token_sha256=frozenset({token_hash}), max_upload_bytes=100)
    body = ndjson(SECRET)
    with TestClient(create_app(settings)) as client:
        run_id = create_run(client, headers)
        response = client.post(
            f"/api/v1/runs/{run_id}/findings",
            content=iter([body[:60], body[60:]]),
            headers={**headers, **NDJSON},
        )
        assert "Content-Length" not in response.request.headers
        assert response.status_code == 413, response.text
        assert client.get("/api/v1/findings").json()["total"] == 0


def test_the_upload_must_be_ndjson(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    response = client.post(
        f"/api/v1/runs/{run_id}/findings", content=ndjson(SECRET),
        headers={**headers, "Content-Type": "application/json"},
    )  # fmt: skip
    assert response.status_code == 415, response.text


# ---------------------------------------------------------------- queries


def test_findings_can_be_filtered(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    upload(client, headers, run_id, ndjson(SECRET, SCA, CONTAINER))
    other = create_run(client, headers, repo="someone/else")
    upload(client, headers, other, ndjson(finding("sca-enriched-and-scored.json", repo="someone/else")))

    def ids(**params: str) -> set[str]:
        response = client.get("/api/v1/findings", params=params)
        assert response.status_code == 200, response.text
        return {item["finding"]["id"] + "@" + item["run_id"] for item in response.json()["items"]}

    assert ids(severity="CRITICAL") == {f"{SCA['id']}@{run_id}", f"{SCA['id']}@{other}"}
    assert ids(category="SECRET") == {f"{SECRET['id']}@{run_id}"}
    assert ids(repo="someone/else") == {f"{SCA['id']}@{other}"}
    assert ids(run_id=other) == {f"{SCA['id']}@{other}"}
    assert ids(tool="trivy") == {f"{CONTAINER['id']}@{run_id}"}


def test_findings_are_paginated_in_a_stable_order(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    upload(client, headers, run_id, ndjson(SECRET, SCA, CONTAINER))

    pages = [client.get("/api/v1/findings", params={"limit": 2, "offset": o}).json() for o in (0, 2)]

    assert [len(p["items"]) for p in pages] == [2, 1]
    assert all(p["total"] == 3 for p in pages)
    seen = [item["finding"]["id"] for p in pages for item in p["items"]]
    assert sorted(seen) == sorted({SECRET["id"], SCA["id"], CONTAINER["id"]})


@pytest.mark.parametrize(
    "params",
    [{"limit": "0"}, {"limit": "501"}, {"offset": "-1"}, {"severity": "critical"}, {"category": "sca"}],
)
def test_bad_query_parameters_are_refused(client: TestClient, params: dict[str, str]) -> None:
    assert client.get("/api/v1/findings", params=params).status_code == 422
