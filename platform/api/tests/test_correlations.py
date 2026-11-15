"""A run's correlations (`/api/v1/runs/{id}/correlations`, Correlation v1, task A7) against a real PostgreSQL.

Recorded only for the findings the run recorded, with each of them in exactly one group; kept and served byte
for byte, version by version; never changed, never deleted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

from sentinel_ai.correlate import correlate_run
from sentinel_ai.correlate.models import group_id

VALID = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "finding" / "valid"
RUN = {"repo": "acme/shop", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "context": "release"}
JSON = {"Content-Type": "application/json"}
NDJSON = {"Content-Type": "application/x-ndjson"}


def finding(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    return document | {"run": RUN}


SECRET = finding("secret-in-config.json")
SCA = finding("sca-enriched-and-scored.json")
CONTAINER = finding("container-os-package.json")
FINDINGS = (SECRET, SCA, CONTAINER)


def group(*finding_ids: str, stage: str = "dedup") -> dict[str, Any]:
    ids = sorted(finding_ids)
    return {
        "schema_version": "1.0",
        "group_id": group_id(ids),
        "finding_ids": ids,
        "stage": stage,
        "labelled_by": "template",
        "title": f"{len(ids)} finding(s)",
        "root_cause": "The same root cause.",
        "single_fix": None,
    }


def correlation(findings_sha256: str, *groups: dict[str, Any], version: str = "0.1.0") -> dict[str, Any]:
    stages = ["dedup", "structural"] if any(g["stage"] == "structural" for g in groups) else ["dedup"]
    return {
        "schema_version": "1.0",
        "findings_sha256": findings_sha256,
        "correlator": {"version": version, "stages": stages},
        "groups": sorted(groups, key=lambda g: str(g["group_id"])),
    }


def create_run(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post("/api/v1/runs", json=RUN, headers=headers)
    assert response.status_code == 201, response.text
    run_id: str = response.json()["id"]
    return run_id


def recorded_run(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    """A run with its findings recorded: (run id, findings_sha256)."""
    run_id = create_run(client, headers)
    body = "".join(json.dumps(f) + "\n" for f in FINDINGS).encode("utf-8")
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert uploaded.status_code == 201, uploaded.text
    return run_id, hashlib.sha256(body).hexdigest()


def message(response: Any) -> str:
    detail = response.json()["detail"]
    assert isinstance(detail, list) and len(detail) == 1, detail
    msg: str = detail[0]["msg"]
    return msg


def one_group_each(digest: str, **changes: Any) -> dict[str, Any]:
    return correlation(digest, *(group(f["id"]) for f in FINDINGS), **changes)


def post(client: TestClient, headers: dict[str, str], run_id: str, body: bytes, **extra: str) -> Any:
    return client.post(
        f"/api/v1/runs/{run_id}/correlations", content=body, headers={**headers, **JSON, **extra}
    )


def as_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=1).encode("utf-8")


# ---------------------------------------------------------------- recorded, then served byte for byte


def test_a_correlation_is_recorded_and_served_byte_for_byte(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(one_group_each(digest))
    created = post(client, headers, run_id, body)
    assert created.status_code == 201, created.text
    version = hashlib.sha256(body).hexdigest()
    assert created.json() | {"created_at": None} == {
        "run_id": run_id, "sha256": version, "correlator_version": "0.1.0", "group_count": 3,
        "created_at": None,
    }  # fmt: skip
    served = client.get(f"/api/v1/runs/{run_id}/correlations")
    assert served.status_code == 200
    assert served.content == body, "the exact bytes, whitespace and key order included"
    assert served.headers["content-type"] == "application/json"
    assert served.headers["ETag"] == f'"{version}"'
    # The run and its findings are untouched: a correlation is advisory.
    assert client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"] == digest


def test_the_same_bytes_again_get_their_version_and_a_new_document_is_a_new_version(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    first = as_bytes(one_group_each(digest))
    assert post(client, headers, run_id, first).status_code == 201
    again = post(client, headers, run_id, first)
    assert again.status_code == 409
    assert again.json()["correlation"]["sha256"] == hashlib.sha256(first).hexdigest()
    # Another correlator run (another version) is a new version, and the latest one.
    second = as_bytes(one_group_each(digest, version="0.2.0"))
    assert post(client, headers, run_id, second).status_code == 201
    assert client.get(f"/api/v1/runs/{run_id}/correlations").content == second
    old = client.get(
        f"/api/v1/runs/{run_id}/correlations", params={"sha256": hashlib.sha256(first).hexdigest()}
    )
    assert old.content == first
    versions = client.get(f"/api/v1/runs/{run_id}/correlations/versions").json()["items"]
    assert [(v["sha256"], v["group_count"]) for v in versions] == [
        (hashlib.sha256(second).hexdigest(), 3),
        (hashlib.sha256(first).hexdigest(), 3),
    ]


def test_a_document_larger_than_the_json_limit_is_accepted_up_to_the_upload_limit(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(one_group_each(digest)) + b" " * (70 * 1024)  # above the 64 KiB of small JSON bodies
    assert post(client, headers, run_id, body).status_code == 201
    assert client.get(f"/api/v1/runs/{run_id}/correlations").content == body


def test_the_correlators_own_output_on_the_served_bytes_is_recorded(
    client: TestClient, headers: dict[str, str]
) -> None:
    """The contract between A7 and B1, end to end: the correlator reads the exact upload the API serves and
    posts its document; the API records it as it was sent."""
    run_id, _ = recorded_run(client, headers)
    served = client.get(f"/api/v1/runs/{run_id}/findings").content
    body = json.dumps(correlate_run(served).document(), sort_keys=True).encode("utf-8")
    created = post(client, headers, run_id, body)
    assert created.status_code == 201, created.text
    assert client.get(f"/api/v1/runs/{run_id}/correlations").content == body


# ---------------------------------------------------------------- refused, nothing stored


def refused(client: TestClient, headers: dict[str, str], run_id: str, body: bytes) -> str:
    response = post(client, headers, run_id, body)
    assert response.status_code == 422, response.text
    assert client.get(f"/api/v1/runs/{run_id}/correlations").status_code == 404, "nothing was stored"
    return message(response)


def test_groups_of_other_findings_are_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    other = "0" * 64
    msg = refused(client, headers, run_id, as_bytes(one_group_each(other)))
    assert msg == f"computed from other findings: findings_sha256 is {other}, the run recorded {digest}"


@pytest.mark.parametrize(
    ("groups", "missing", "unknown"),
    [
        (lambda: [group(SECRET["id"]), group(SCA["id"])], 1, 0),
        (lambda: [group(f["id"]) for f in FINDINGS] + [group("e" * 64)], 0, 1),
    ],
    ids=["a-finding-left-out", "a-finding-not-the-runs"],
)
def test_the_groups_hold_each_of_the_runs_findings_exactly_once(
    client: TestClient, headers: dict[str, str], groups: Any, missing: int, unknown: int
) -> None:
    run_id, digest = recorded_run(client, headers)
    msg = refused(client, headers, run_id, as_bytes(correlation(digest, *groups())))
    assert msg == (
        f"the groups must hold each of the run's 3 findings exactly once: {missing} missing, "
        f"{unknown} not the run's"
    )


def test_a_finding_in_two_groups_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    document = correlation(
        digest, group(SECRET["id"]), group(SECRET["id"], SCA["id"]), group(CONTAINER["id"])
    )
    assert "a finding is in two groups" in refused(client, headers, run_id, as_bytes(document))


def test_a_group_across_two_categories_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    """The correlator groups within one category only, and the metrics give a group its first finding's."""
    run_id, digest = recorded_run(client, headers)
    mixed = group(SECRET["id"], SCA["id"])
    document = correlation(digest, mixed, group(CONTAINER["id"]))
    assert refused(client, headers, run_id, as_bytes(document)) == (
        f"group {mixed['group_id']} holds findings of 2 categories (SCA, SECRET): a group is one category"
    )


def test_a_group_of_one_category_is_recorded(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    other_sca = SCA | {"id": hashlib.sha256(b"another SCA finding").hexdigest()}
    findings = (SECRET, SCA, other_sca, CONTAINER)
    body = "".join(json.dumps(f) + "\n" for f in findings).encode("utf-8")
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert uploaded.status_code == 201, uploaded.text
    document = correlation(
        hashlib.sha256(body).hexdigest(),
        group(SECRET["id"]), group(SCA["id"], other_sca["id"]), group(CONTAINER["id"]),
    )  # fmt: skip
    response = post(client, headers, run_id, as_bytes(document))
    assert response.status_code == 201, response.text
    assert response.json()["group_count"] == 3


@pytest.mark.parametrize(
    "body",
    [
        lambda d: as_bytes(d | {"extra": 1}),
        lambda d: as_bytes(d | {"groups": [g | {"group_id": "f" * 64} for g in d["groups"]]}),
        lambda d: as_bytes(d | {"groups": list(reversed(d["groups"]))}),
        lambda d: as_bytes(d)[:-1] + b', "schema_version": "1.0"}',
        lambda d: as_bytes(d | {"correlator": {**d["correlator"], "threshold": 0.5}}).replace(b"0.5", b"NaN"),
        lambda d: as_bytes(d).replace(b'"0.1.0"', b'"\xff"'),
        lambda d: b"[" + as_bytes(d) + b"]",
    ],
    ids=[
        "extra-field",
        "wrong-group-id",
        "groups-unsorted",
        "repeated-key",
        "nan",
        "not-utf8",
        "not-an-object",
    ],
)
def test_anything_but_a_correlation_v1_document_is_refused(
    client: TestClient, headers: dict[str, str], body: Any
) -> None:
    run_id, digest = recorded_run(client, headers)
    assert refused(client, headers, run_id, body(one_group_each(digest))).startswith(
        "not a Correlation v1 document"
    )


def test_a_run_whose_findings_are_not_recorded_has_no_correlation_yet(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id = create_run(client, headers)
    response = post(client, headers, run_id, as_bytes(one_group_each("0" * 64)))
    assert response.status_code == 409
    assert response.json()["detail"].startswith("no findings recorded for this run yet")


def test_no_such_run_or_correlation_is_404(client: TestClient, headers: dict[str, str]) -> None:
    missing = "00000000-0000-4000-8000-000000000000"
    assert post(client, headers, missing, b"{}").status_code == 404
    assert client.get(f"/api/v1/runs/{missing}/correlations").status_code == 404
    assert client.get(f"/api/v1/runs/{missing}/correlations/versions").status_code == 404
    run_id, _ = recorded_run(client, headers)
    assert client.get(f"/api/v1/runs/{run_id}/correlations").status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}/correlations/versions").json() == {"items": []}
    unknown = client.get(f"/api/v1/runs/{run_id}/correlations", params={"sha256": "a" * 64})
    assert unknown.status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}/correlations", params={"sha256": "A" * 64}).status_code == 422


def test_recording_needs_a_token_and_json(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(one_group_each(digest))
    assert post(client, {"Authorization": "Bearer wrong-token"}, run_id, body).status_code == 401
    assert post(client, headers, run_id, body, **{"Content-Type": "text/plain"}).status_code == 415
    assert client.get(f"/api/v1/runs/{run_id}/correlations").status_code == 404


# ---------------------------------------------------------------- the database is the backstop


def test_the_database_keeps_a_version_as_recorded(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(one_group_each(digest))
    assert post(client, headers, run_id, body).status_code == 201
    with psycopg.connect(database_url, autocommit=True) as conn:
        for statement in (
            "UPDATE correlations SET group_count = 9",
            "DELETE FROM correlations",
        ):
            with pytest.raises(psycopg.errors.RaiseException, match="cannot change or be deleted"):
                conn.execute(statement)
        # Bytes that are not the version's name, or a document of other findings, are never added.
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO correlations (run_id, sha256, correlator_version, group_count, document) "
                "VALUES (%s, repeat('a', 64), 'x', 1, %s)",
                (run_id, body),
            )
        other = as_bytes(one_group_each("0" * 64))
        with pytest.raises(psycopg.errors.RaiseException, match="only for the findings the run recorded"):
            conn.execute(
                "INSERT INTO correlations (run_id, sha256, correlator_version, group_count, document) "
                "VALUES (%s, %s, 'x', 1, %s)",
                (run_id, hashlib.sha256(other).hexdigest(), other),
            )
        assert conn.execute("SELECT count(*), max(group_count) FROM correlations").fetchone() == (1, 3)


def test_the_409_is_documented_with_both_of_its_shapes(client: TestClient) -> None:
    """The same bytes again answer with `correlation`, a run without findings with `detail` only."""
    schema = client.get("/openapi.json").json()["paths"]["/api/v1/runs/{run_id}/correlations"]["post"][
        "responses"
    ]["409"]["content"]["application/json"]["schema"]
    assert sorted(option["$ref"].rsplit("/", 1)[1] for option in schema["anyOf"]) == [
        "CorrelationExists",
        "ErrorOut",
    ]
