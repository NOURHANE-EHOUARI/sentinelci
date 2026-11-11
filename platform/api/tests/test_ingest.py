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


def message(response: Any) -> str:
    """The message of a 422, which has FastAPI's shape everywhere: `detail` is a list of errors."""
    detail = response.json()["detail"]
    assert isinstance(detail, list) and len(detail) == 1, detail
    msg: str = detail[0]["msg"]
    return msg


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


# ---------------------------------------------------------------- one run per CI run (#50 re-runs)

CI_RUN = {**RUN, "ref": "refs/pull/12/merge", "run_id": "11223344"}


def test_a_ci_run_recorded_again_is_answered_409_with_the_existing_run(
    client: TestClient, headers: dict[str, str]
) -> None:
    """A re-run of the upload step names the same CI run: it gets the run back, so it can resume it."""
    first = client.post("/api/v1/runs", json=CI_RUN, headers=headers)
    assert first.status_code == 201, first.text
    again = client.post("/api/v1/runs", json=CI_RUN, headers=headers)
    assert again.status_code == 409, again.text
    assert again.json()["run"] == first.json()
    assert "already recorded" in again.json()["detail"]


def test_the_409_shows_whether_the_findings_arrived(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers, **{"run_id": "11223344"})
    assert upload(client, headers, run_id, ndjson(SECRET)).status_code == 201
    run = client.post("/api/v1/runs", json={**RUN, "run_id": "11223344"}, headers=headers).json()["run"]
    assert (run["id"], run["finding_count"]) == (run_id, 1)
    assert run["findings_sha256"] == hashlib.sha256(ndjson(SECRET)).hexdigest()


def test_the_same_ci_run_with_another_ref_is_still_the_same_run(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id = create_run(client, headers, **{"run_id": "11223344", "ref": "refs/heads/a"})
    other_ref = {**RUN, "run_id": "11223344", "ref": "refs/heads/b"}
    again = client.post("/api/v1/runs", json=other_ref, headers=headers)
    assert again.status_code == 409 and again.json()["run"]["id"] == run_id
    assert again.json()["run"]["ref"] == "refs/heads/a"


@pytest.mark.parametrize(
    "other",
    [
        {"run_id": "11223345"},
        {"context": "release"},
        {"commit": "f" * 40},
        {"repo": "NOURHANE-EHOUARI/other"},
    ],
    ids=["another-ci-run", "another-context", "another-commit", "another-repo"],
)
def test_another_ci_run_is_another_run(
    client: TestClient, headers: dict[str, str], other: dict[str, str]
) -> None:
    first = create_run(client, headers, **{"run_id": "11223344"})
    assert create_run(client, headers, **{"run_id": "11223344", **other}) != first


def test_runs_without_a_ci_run_id_are_never_merged(client: TestClient, headers: dict[str, str]) -> None:
    """A local run names no CI run: each POST is a new run, as before."""
    assert create_run(client, headers) != create_run(client, headers)


def test_two_concurrent_creations_of_one_ci_run_record_one(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both requests pass the lookup before either commits: the unique index decides, the loser gets 409."""
    import threading

    from fastapi.responses import JSONResponse

    import sentinel_api.api as api

    real_lookup = api._existing_run
    barrier = threading.Barrier(2)
    looked = threading.local()

    def lookup_then_wait(session: Any, body: Any) -> Any:
        found = real_lookup(session, body)
        if not getattr(looked, "once", False):  # the first lookup of each request only
            looked.once = True
            barrier.wait(timeout=10)  # both have looked, neither has committed
        return found

    monkeypatch.setattr(api, "_existing_run", lookup_then_wait)
    factory = client.app.state.sessions  # type: ignore[attr-defined]
    outcomes: list[Any] = []

    def create() -> None:
        with factory() as session:
            outcomes.append(api.create_run(api.RunCreate(**CI_RUN), session))

    threads = [threading.Thread(target=create) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    created = [o for o in outcomes if isinstance(o, api.RunOut)]
    conflicts = [o for o in outcomes if isinstance(o, JSONResponse)]
    assert len(created) == len(conflicts) == 1, outcomes
    assert conflicts[0].status_code == 409
    assert json.loads(conflicts[0].body)["run"]["id"] == str(created[0].id)


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
    assert expected in message(response)
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
    assert "line 2: the finding belongs to another run" in message(response)
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


# ---------------------------------------------------------------- the exact upload (correlation, replay)


def test_the_exact_upload_is_served_back(client: TestClient, headers: dict[str, str]) -> None:
    """The bytes the run was recorded with, unchanged: a consumer that hashes them gets `findings_sha256`
    (the correlation document's `findings_sha256`, a replay). JSONB rows cannot give them back."""
    run_id = create_run(client, headers)
    body = (
        json.dumps(SECRET, ensure_ascii=False)
        + "\n\n"
        + json.dumps(SCA | {"message": "first\u2028second"}, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    assert upload(client, headers, run_id, body).status_code == 201
    response = client.get(f"/api/v1/runs/{run_id}/findings")
    assert response.status_code == 200, response.text
    assert response.content == body
    assert response.headers["content-type"].split(";")[0] == "application/x-ndjson"
    recorded = client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"]
    assert hashlib.sha256(response.content).hexdigest() == recorded
    assert response.headers["etag"] == f'"{recorded}"'


def test_a_clean_run_serves_an_empty_upload(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    assert upload(client, headers, run_id, b"").status_code == 201
    response = client.get(f"/api/v1/runs/{run_id}/findings")
    assert (response.status_code, response.content) == (200, b"")


def test_findings_not_uploaded_yet_are_not_found(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    response = client.get(f"/api/v1/runs/{run_id}/findings")
    assert response.status_code == 404 and "no findings recorded" in response.json()["detail"]
    missing = "00000000-0000-4000-8000-000000000000"
    assert client.get(f"/api/v1/runs/{missing}/findings").json()["detail"] == "no such run"


def test_a_run_recorded_before_the_bytes_were_kept_says_so(client: TestClient, database_url: str) -> None:
    import psycopg

    with psycopg.connect(database_url, autocommit=True) as conn:
        (run_id,) = conn.execute(
            "INSERT INTO runs (id, repo, commit, context, findings_sha256, findings_uploaded_at) VALUES "
            "(gen_random_uuid(), 'o/r', repeat('a', 40), 'pr', repeat('0', 64), now()) RETURNING id"
        ).fetchone()  # type: ignore[misc]
    response = client.get(f"/api/v1/runs/{run_id}/findings")
    assert response.status_code == 404 and "not kept" in response.json()["detail"]


KEPT_BYTES_REFUSED = {
    "another-digest": (
        "UPDATE runs SET findings_sha256 = repeat('0', 64), findings_uploaded_at = now(),"
        " findings_ndjson = 'x'::bytea WHERE id = %s"
    ),
    "no-digest": "UPDATE runs SET findings_ndjson = 'x'::bytea WHERE id = %s",
}


@pytest.mark.parametrize("case", KEPT_BYTES_REFUSED)
def test_the_database_keeps_only_bytes_that_hash_to_the_recorded_digest(
    client: TestClient, headers: dict[str, str], database_url: str, case: str
) -> None:
    import psycopg

    run_id = create_run(client, headers)
    with psycopg.connect(database_url, autocommit=True) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(KEPT_BYTES_REFUSED[case], (run_id,))


def test_recorded_bytes_cannot_change(client: TestClient, headers: dict[str, str], database_url: str) -> None:
    import psycopg

    run_id = create_run(client, headers)
    assert upload(client, headers, run_id, ndjson(SECRET)).status_code == 201
    with psycopg.connect(database_url, autocommit=True) as conn, pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE runs SET findings_ndjson = %s WHERE id = %s", (ndjson(SCA), run_id))
    assert client.get(f"/api/v1/runs/{run_id}/findings").content == ndjson(SECRET)


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


# ---------------------------------------------------------------- #38 review: contract


def test_writes_declare_the_bearer_scheme_and_reads_do_not(client: TestClient) -> None:
    document = client.app.openapi()  # type: ignore[attr-defined]
    assert document["components"]["securitySchemes"]["HTTPBearer"] == {"type": "http", "scheme": "bearer"}
    operations = {(m.upper(), p): op for p, item in document["paths"].items() for m, op in item.items()}
    for key in [("POST", "/api/v1/runs"), ("POST", "/api/v1/runs/{run_id}/findings")]:
        assert operations[key]["security"] == [{"HTTPBearer": []}], key
    for key, op in operations.items():
        if key[0] == "GET":
            assert "security" not in op, key


@pytest.mark.parametrize(
    ("method", "path", "codes"),
    [
        ("POST", "/api/v1/runs", {"201", "401", "409", "413", "422", "503"}),
        ("GET", "/api/v1/runs/{run_id}", {"200", "404", "413", "422", "503"}),
        ("GET", "/api/v1/runs/{run_id}/findings", {"200", "404", "413", "422", "503"}),
        ("POST", "/api/v1/runs/{run_id}/findings", {"201", "401", "404", "409", "413", "415", "422", "503"}),
        ("GET", "/api/v1/findings", {"200", "413", "422", "503"}),
        ("GET", "/api/v1/findings/{finding_id}", {"200", "404", "413", "422", "503"}),
    ],
)
def test_every_status_a_route_returns_is_in_the_contract(
    client: TestClient, method: str, path: str, codes: set[str]
) -> None:
    document = client.app.openapi()  # type: ignore[attr-defined]
    assert set(document["paths"][path][method.lower()]["responses"]) == codes


def test_every_error_body_has_the_documented_shape(client: TestClient, headers: dict[str, str]) -> None:
    """401, 404, 409, 413, 415 carry `{"detail": str}`; every 422 carries FastAPI's list of errors."""
    run_id = create_run(client, headers)
    upload(client, headers, run_id, ndjson(SECRET))
    plain = [
        client.post("/api/v1/runs", json=RUN),
        client.get(f"/api/v1/runs/{'0' * 8}-0000-4000-8000-{'0' * 12}"),
        upload(client, headers, run_id, ndjson(SCA)),
        client.post(f"/api/v1/runs/{run_id}/findings", content=b"x", headers={**headers}),
    ]
    assert [r.status_code for r in plain] == [401, 404, 409, 415]
    assert all(isinstance(r.json()["detail"], str) for r in plain)
    other = create_run(client, headers)
    invalid = [
        upload(client, headers, other, b"{broken\n"),
        client.post("/api/v1/runs", json={**RUN, "commit": "x"}, headers=headers),
        client.get("/api/v1/findings", params={"limit": 0}),
    ]
    assert [r.status_code for r in invalid] == [422, 422, 422]
    for response in invalid:
        detail = response.json()["detail"]
        assert isinstance(detail, list) and all({"loc", "msg", "type"} <= set(e) for e in detail), detail


def test_the_contract_version_is_the_apis_own(client: TestClient) -> None:
    from sentinel_api.main import API_VERSION
    from sentinelci import __version__ as engine_version

    document = client.app.openapi()  # type: ignore[attr-defined]
    assert document["info"]["version"] == API_VERSION == "1.7.0"
    assert client.get("/healthz").json() == {"status": "ok", "engine_version": engine_version}


# ---------------------------------------------------------------- #38 review: bodies before authentication


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_an_unauthenticated_large_body_is_refused_before_it_is_read(
    client: TestClient, chunked: bool
) -> None:
    body = b'{"repo": "' + b"x" * (1024 * 1024) + b'"}'
    content: Any = iter([body[: len(body) // 2], body[len(body) // 2 :]]) if chunked else body
    response = client.post("/api/v1/runs", content=content, headers={"Content-Type": "application/json"})
    assert response.status_code == 413, response.text
    small = client.post("/api/v1/runs", json=RUN)
    assert small.status_code == 401


def test_a_json_body_at_the_limit_is_still_read(database_url: str, headers: dict[str, str]) -> None:
    from sentinel_api.limits import MAX_JSON_BYTES

    assert MAX_JSON_BYTES == 64 * 1024, "the limit documented in deploy/compose/README.md"
    body = json.dumps({**RUN, "ref": "r" * 200}).encode()
    padded = body[:-1] + b" " * (MAX_JSON_BYTES - len(body)) + b"}"
    assert len(padded) == MAX_JSON_BYTES
    with _client(database_url, headers) as client:
        accepted = client.post(
            "/api/v1/runs", content=padded, headers={**headers, "Content-Type": "application/json"}
        )
        refused = client.post(
            "/api/v1/runs", content=padded + b" ", headers={**headers, "Content-Type": "application/json"}
        )
    assert (accepted.status_code, refused.status_code) == (201, 413)


# ---------------------------------------------------------------- #38 review: once per run


def _client(database_url: str, headers: dict[str, str], **settings: Any) -> TestClient:
    from sentinel_api.config import Settings
    from sentinel_api.main import create_app

    token_hash = hashlib.sha256(headers["Authorization"].removeprefix("Bearer ").encode()).hexdigest()
    return TestClient(
        create_app(Settings(database_url=database_url, token_sha256=frozenset({token_hash}), **settings))
    )


def test_two_concurrent_uploads_record_one(
    client: TestClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both requests pass the "not recorded yet" check before either commits; exactly one may win."""
    import threading
    import time

    from fastapi import HTTPException

    import sentinel_api.api as api

    run_id = create_run(client, headers)
    real_parse = api._parse

    def slow_parse(body: bytes, run: Any) -> list[dict[str, Any]]:
        time.sleep(0.5)
        return real_parse(body, run)

    monkeypatch.setattr(api, "_parse", slow_parse)
    factory = client.app.state.sessions  # type: ignore[attr-defined]
    outcomes: list[int] = []

    def store(body: bytes) -> None:
        with factory() as session:
            try:
                api._store(session, __import__("uuid").UUID(run_id), body)
                outcomes.append(201)
            except HTTPException as exc:
                outcomes.append(exc.status_code)

    threads = [threading.Thread(target=store, args=(ndjson(d),)) for d in (SECRET, SCA)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == [201, 409]
    run = client.get(f"/api/v1/runs/{run_id}").json()
    assert (
        client.get("/api/v1/findings", params={"run_id": run_id}).json()["total"] == run["finding_count"] == 1
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE runs SET findings_sha256 = repeat('0', 64) WHERE id = %s",
        "UPDATE runs SET finding_count = 99 WHERE id = %s",
        "UPDATE runs SET findings_sha256 = NULL, findings_uploaded_at = NULL WHERE id = %s",
        "UPDATE runs SET commit = repeat('b', 40) WHERE id = %s",
        "UPDATE runs SET repo = 'someone/else', context = 'release' WHERE id = %s",
        "UPDATE runs SET ref = 'refs/heads/other' WHERE id = %s",
        "DELETE FROM runs WHERE id = %s",
    ],
    ids=["hash", "count", "unrecord", "commit", "repo-context", "ref", "delete"],
)
def test_recorded_evidence_cannot_be_changed_in_the_database(
    client: TestClient, headers: dict[str, str], database_url: str, statement: str
) -> None:
    import psycopg

    run_id = create_run(client, headers)
    upload(client, headers, run_id, ndjson(SECRET))
    with (
        psycopg.connect(database_url) as conn,
        pytest.raises(psycopg.errors.RaiseException, match="recorded"),
    ):
        conn.execute(statement, (run_id,))


def test_findings_cannot_be_added_to_a_recorded_run_in_the_database(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    import psycopg

    run_id = create_run(client, headers)
    upload(client, headers, run_id, ndjson(SECRET))
    with (
        psycopg.connect(database_url) as conn,
        pytest.raises(psycopg.errors.RaiseException, match="recorded"),
    ):
        conn.execute(
            "INSERT INTO findings (run_id, finding_id, category, severity, tool, rule_id, document)"
            " VALUES (%s, %s, 'SCA', 'LOW', 'x', 'x', '{}')",
            (run_id, "f" * 64),
        )


# ---------------------------------------------------------------- #38 review: queries and boundaries


def test_a_huge_offset_is_refused_not_a_server_error(client: TestClient) -> None:
    assert client.get("/api/v1/findings", params={"offset": 2**63}).status_code == 422
    assert client.get("/api/v1/findings", params={"offset": 1_000_000}).status_code == 200


def test_findings_are_listed_newest_run_first(client: TestClient, headers: dict[str, str]) -> None:
    older = create_run(client, headers)
    upload(client, headers, older, ndjson(SECRET))
    newer = create_run(client, headers, commit="c" * 40)
    upload(client, headers, newer, ndjson(finding("secret-in-config.json", commit="c" * 40)))
    assert [i["run_id"] for i in client.get("/api/v1/findings").json()["items"]] == [newer, older]


def test_occurrences_are_bounded_and_counted(client: TestClient, headers: dict[str, str]) -> None:
    runs = []
    for n in range(3):
        commit = f"{n:x}" * 40
        runs.append(create_run(client, headers, commit=commit))
        upload(client, headers, runs[-1], ndjson(finding("secret-in-config.json", commit=commit)))
    body = client.get(f"/api/v1/findings/{SECRET['id']}", params={"limit": 2}).json()
    assert body["occurrence_count"] == 3
    assert [o["run_id"] for o in body["occurrences"]] == runs[::-1][:2]
    assert body["finding"]["run"]["commit"] == "2" * 40
    assert client.get(f"/api/v1/findings/{SECRET['id']}", params={"limit": 501}).status_code == 422


@pytest.mark.parametrize(
    ("authorization", "expected"),
    [("bearer {t}", 201), ("BEARER {t}", 201), ("Basic {t}", 401), ("{t}", 401), ("Bearer {t}x", 401)],
    ids=["lowercase", "uppercase", "other-scheme", "no-scheme", "longer"],
)
def test_the_scheme_is_case_insensitive_and_required(
    client: TestClient, headers: dict[str, str], authorization: str, expected: int
) -> None:
    token = headers["Authorization"].removeprefix("Bearer ")
    response = client.post("/api/v1/runs", json=RUN, headers={"Authorization": authorization.format(t=token)})
    assert response.status_code == expected, response.text


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_an_upload_exactly_at_the_limit_is_accepted(
    database_url: str, headers: dict[str, str], chunked: bool
) -> None:
    body = ndjson(SECRET)
    with _client(database_url, headers, max_upload_bytes=len(body)) as client:
        for extra, expected in [(b"\n", 413), (b"", 201)]:
            run_id = create_run(client, headers)
            data = body + extra
            content: Any = iter([data[:10], data[10:]]) if chunked else data
            response = client.post(
                f"/api/v1/runs/{run_id}/findings", content=content, headers={**headers, **NDJSON}
            )
            assert response.status_code == expected, (len(data), response.text)


@pytest.mark.parametrize("media_type", ["Application/X-NDJSON", "application/x-ndjson; charset=utf-8"])
def test_the_media_type_is_matched_as_http_says(
    client: TestClient, headers: dict[str, str], media_type: str
) -> None:
    run_id = create_run(client, headers)
    response = client.post(
        f"/api/v1/runs/{run_id}/findings",
        content=ndjson(SECRET),
        headers={**headers, "Content-Type": media_type},
    )
    assert response.status_code == 201, response.text


# ---------------------------------------------------------------- #38 review, round 2


def test_an_unrecorded_run_can_still_be_deleted(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    """Only recorded evidence is fixed: a run whose findings never arrived carries none."""
    import psycopg

    run_id = create_run(client, headers)
    with psycopg.connect(database_url) as conn:
        assert conn.execute("DELETE FROM runs WHERE id = %s", (run_id,)).rowcount == 1


def test_a_real_sized_upload_passes_the_body_limit(client: TestClient, headers: dict[str, str]) -> None:
    """Above the 64 KiB JSON cap: the upload route has its own limit (the middleware matches its path)."""
    from sentinel_api.limits import MAX_JSON_BYTES

    documents = []
    for n in range(200):
        document = finding("secret-in-config.json")
        document["id"] = hashlib.sha256(f"finding {n}".encode()).hexdigest()
        documents.append(document)
    body = ndjson(*documents)
    assert len(body) > MAX_JSON_BYTES
    run_id = create_run(client, headers)
    response = upload(client, headers, run_id, body)
    assert response.status_code == 201, response.text
    assert response.json()["finding_count"] == 200


def test_the_database_refusal_is_answered_409(
    client: TestClient, headers: dict[str, str], database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the lock is ever bypassed, a run recorded meanwhile makes the trigger refuse: 409, never a 500."""
    import uuid

    import psycopg
    from fastapi import HTTPException

    import sentinel_api.api as api

    run_id = create_run(client, headers)
    real_parse = api._parse

    def record_meanwhile(body: bytes, run: Any) -> list[dict[str, Any]]:
        with psycopg.connect(database_url, autocommit=True) as conn:
            conn.execute(
                "UPDATE runs SET findings_sha256 = repeat('0', 64), findings_uploaded_at = now()"
                " WHERE id = %s",
                (run_id,),
            )
        return real_parse(body, run)

    monkeypatch.setattr(api, "_parse", record_meanwhile)
    factory = client.app.state.sessions  # type: ignore[attr-defined]
    with factory() as session:
        # Without the row lock: the bypass this backstop exists for.
        monkeypatch.setattr(
            session, "get", lambda model, ident, **_: type(session).get(session, model, ident)
        )
        with pytest.raises(HTTPException) as caught:
            api._store(session, uuid.UUID(run_id), ndjson(SECRET))
    assert caught.value.status_code == 409


def test_runs_created_together_are_listed_in_a_stable_order(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    """Equal created_at: the run id, then the finding id, decide (pagination must never repeat or skip).

    The findings are inserted in descending id order, so an order left to the database would differ.
    """
    import psycopg

    names = ["secret-in-config.json", "sca-enriched-and-scored.json", "container-os-package.json"]
    runs = [create_run(client, headers, commit=c * 40) for c in "def"]
    for run_id, c in zip(runs, "def", strict=True):
        documents = sorted((finding(n, commit=c * 40) for n in names), key=lambda d: d["id"], reverse=True)
        assert upload(client, headers, run_id, ndjson(*documents)).status_code == 201
    with psycopg.connect(database_url) as conn:
        conn.execute("ALTER TABLE runs DISABLE TRIGGER runs_keep_recorded_evidence")
        conn.execute("UPDATE runs SET created_at = '2026-11-01T00:00:00Z'")
        conn.execute("ALTER TABLE runs ENABLE TRIGGER runs_keep_recorded_evidence")
    listed = [(i["run_id"], i["finding"]["id"]) for i in client.get("/api/v1/findings").json()["items"]]
    assert listed == sorted(listed)
