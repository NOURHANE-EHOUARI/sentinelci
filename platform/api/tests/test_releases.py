"""Releases and their evidence (`/api/v1/releases`, Release evidence v1, tasks A4 and A8) against a real
PostgreSQL.

Recorded only when consistent (a release decision about an image, reports about that image, no trusted BLOCK);
once per decision; kept and served byte for byte; never changed, never deleted.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "release-evidence" / "valid"
JSON = {"Content-Type": "application/json"}


def fixture(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return document


WARN = fixture("warn-verified-in-the-registry-and-from-the-evidence.json")
BLOCK = fixture("block-without-a-trust-report.json")


def raw(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode()


def post(client: TestClient, headers: dict[str, str], body: bytes) -> Any:
    return client.post("/api/v1/releases", content=body, headers=headers | JSON)


def test_a_release_is_recorded_listed_and_served_byte_for_byte(
    client: TestClient, headers: dict[str, str]
) -> None:
    body = raw(WARN)
    created = post(client, headers, body)
    assert created.status_code == 201, created.text
    release = created.json()
    digest = WARN["decision"]["subject"]["image_digest"]
    assert release["decision_id"] == WARN["decision"]["decision_id"]
    assert (release["image_digest"], release["verdict"], release["trusted"]) == (digest, "WARN", True)
    assert release["sha256"] == hashlib.sha256(body).hexdigest()
    assert (release["repo"], release["ref"]) == ("NOURHANE-EHOUARI/sentinelci", "refs/heads/main")

    served = client.get(f"/api/v1/releases/{digest}/evidence")
    assert served.status_code == 200 and served.content == body
    assert served.headers["ETag"] == f'"{release["sha256"]}"'
    assert served.headers["Content-Type"] == "application/json"

    page = client.get("/api/v1/releases").json()
    assert page["total"] == 1 and page["items"] == [release]


def test_a_block_is_recorded_without_a_trust_report(client: TestClient, headers: dict[str, str]) -> None:
    created = post(client, headers, raw(BLOCK))
    assert created.status_code == 201, created.text
    assert (created.json()["verdict"], created.json()["trusted"]) == ("BLOCK", None)


def test_newest_first_and_filtered(client: TestClient, headers: dict[str, str]) -> None:
    assert post(client, headers, raw(WARN)).status_code == 201
    assert post(client, headers, raw(BLOCK)).status_code == 201
    items = client.get("/api/v1/releases").json()["items"]
    assert [item["verdict"] for item in items] == ["BLOCK", "WARN"]
    blocked = client.get("/api/v1/releases", params={"verdict": "BLOCK"}).json()
    assert blocked["total"] == 1 and blocked["items"][0]["verdict"] == "BLOCK"
    other = client.get("/api/v1/releases", params={"repo": "someone/else"}).json()
    assert other == {"items": [], "total": 0, "limit": 100, "offset": 0}
    paged = client.get("/api/v1/releases", params={"limit": 1, "offset": 1}).json()
    assert paged["total"] == 2 and [item["verdict"] for item in paged["items"]] == ["WARN"]


def test_a_decision_is_recorded_once(client: TestClient, headers: dict[str, str]) -> None:
    body = raw(WARN)
    first = post(client, headers, body).json()
    again = post(client, headers, body)
    assert again.status_code == 409 and again.json()["release"] == first
    assert again.json()["detail"].endswith("is recorded already")
    other = copy.deepcopy(WARN)
    other["trust_reports"] = other["trust_reports"][:1]
    changed = post(client, headers, raw(other))
    assert changed.status_code == 409 and changed.json()["release"]["sha256"] == first["sha256"]
    assert "with other evidence" in changed.json()["detail"]
    digest = WARN["decision"]["subject"]["image_digest"]
    assert client.get(f"/api/v1/releases/{digest}/evidence").content == body


def test_the_latest_release_of_an_image_or_the_one_named(client: TestClient, headers: dict[str, str]) -> None:
    """A rebuild with the same digest (a reproducible build) is a second release of the image."""
    second = copy.deepcopy(BLOCK)
    second["decision"]["subject"]["image_digest"] = WARN["decision"]["subject"]["image_digest"]
    assert post(client, headers, raw(WARN)).status_code == 201
    assert post(client, headers, raw(second)).status_code == 201
    digest = WARN["decision"]["subject"]["image_digest"]
    assert client.get(f"/api/v1/releases/{digest}/evidence").content == raw(second)
    named = client.get(
        f"/api/v1/releases/{digest}/evidence", params={"decision_id": WARN["decision"]["decision_id"]}
    )
    assert named.content == raw(WARN)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["decision"]["subject"].update(context="pr"), "a pr decision, not a release decision"),
        (lambda d: d["decision"]["subject"].pop("image_digest"), "names no image digest"),
        (lambda d: d["trust_reports"][0].update(repo="someone/fork"), "required someone/fork"),
        (lambda d: d["trust_reports"][0]["checks"][2].update(ok=False), "trusted is True, but 1 of 16"),
        (lambda d: d["trust_reports"][1].update(mode="registry"), "two trust reports of the same mode"),
        (lambda d: d.update(schema_version="2.0"), "schema_version"),
        (lambda d: d["decision"].pop("verdict"), "decision.verdict"),
    ],
)  # fmt: skip
def test_evidence_that_contradicts_itself_is_refused(
    client: TestClient, headers: dict[str, str], change: Any, message: str
) -> None:
    document = copy.deepcopy(WARN)
    change(document)
    refused = post(client, headers, raw(document))
    assert refused.status_code == 422, refused.text
    assert message in refused.json()["detail"][0]["msg"]
    assert client.get("/api/v1/releases").json()["total"] == 0


@pytest.mark.parametrize(
    "body",
    [
        b'{"schema_version": "1.0", "schema_version": "1.0"}',
        b'{"schema_version": NaN}',
        b"\xff\xfe",
        b"[]",
    ],
)
def test_bytes_that_mean_more_than_one_thing_are_refused(
    client: TestClient, headers: dict[str, str], body: bytes
) -> None:
    assert post(client, headers, body).status_code == 422


@pytest.mark.parametrize("trusted", [True, False], ids=["trusted", "not-trusted"])
def test_a_block_with_a_trust_report_is_refused(
    client: TestClient, headers: dict[str, str], trusted: bool
) -> None:
    """Review of #86, should fix 3: nothing is signed for a BLOCK, so it comes without a report; one that did
    not trust it was recorded and counted as a verification."""
    document = copy.deepcopy(WARN)
    document["decision"]["verdict"] = "BLOCK"
    document["decision"]["violations"] = [
        {"rule": "SC-002", "effect": "BLOCK", "finding_ids": ["b" * 64], "message": "P0 finding"}
    ]
    if not trusted:
        for report in document["trust_reports"]:
            report["checks"][0] = {**report["checks"][0], "ok": False, "detail": "no matching signature"}
            report["trusted"] = False
    refused = post(client, headers, raw(document))
    assert refused.status_code == 422 and "a BLOCK decision comes without a trust report" in refused.text
    assert client.get("/metrics").text.count("sentinel_attestation_verifications_total{") in (0, 2)
    assert 'not_trusted"} 1' not in client.get("/metrics").text


def test_recording_needs_the_token_and_json(client: TestClient, headers: dict[str, str]) -> None:
    assert client.post("/api/v1/releases", content=raw(WARN), headers=JSON).status_code == 401
    wrong = {"Authorization": "Bearer " + "y" * 43} | JSON
    assert client.post("/api/v1/releases", content=raw(WARN), headers=wrong).status_code == 401
    plain = headers | {"Content-Type": "text/plain"}
    assert client.post("/api/v1/releases", content=raw(WARN), headers=plain).status_code == 415


def test_an_unknown_image_or_a_malformed_digest(client: TestClient) -> None:
    assert client.get(f"/api/v1/releases/sha256:{'0' * 64}/evidence").status_code == 404
    assert client.get(f"/api/v1/releases/sha256:{'A' * 64}/evidence").status_code == 422
    assert client.get("/api/v1/releases/latest/evidence").status_code == 422


def test_a_recorded_release_never_changes(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    assert post(client, headers, raw(WARN)).status_code == 201
    decision_id = WARN["decision"]["decision_id"]
    with psycopg.connect(database_url, autocommit=True) as conn:
        for statement in (
            "UPDATE releases SET verdict = 'PASS' WHERE decision_id = %s",
            "DELETE FROM releases WHERE decision_id = %s",
        ):
            with pytest.raises(psycopg.errors.RaiseException, match="is kept as recorded"):
                conn.execute(statement, (decision_id,))


_COLUMNS = ("decision_id", "repo", "commit", "ref", "image_digest", "verdict", "trusted", "evaluated_at",
            "sha256", "document")  # fmt: skip
_INSERT = (
    'INSERT INTO releases (decision_id, repo, "commit", ref, image_digest, verdict, trusted, evaluated_at, \
sha256, document) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
)


def _insert(conn: Any, document: dict[str, Any], **columns: Any) -> None:
    """A direct insert of `document`'s bytes, with its own columns unless `columns` says otherwise."""
    body = raw(document)
    decision, subject = document["decision"], document["decision"]["subject"]
    reports = document["trust_reports"]
    values = {
        "decision_id": decision["decision_id"], "repo": subject["repo"], "commit": subject["commit"],
        "ref": subject.get("ref"), "image_digest": subject["image_digest"], "verdict": decision["verdict"],
        "trusted": all(r["trusted"] for r in reports) if reports else None,
        "evaluated_at": decision["evaluated_at"], "sha256": hashlib.sha256(body).hexdigest(),
        "document": body,
    } | columns  # fmt: skip
    conn.execute(_INSERT, [values[name] for name in _COLUMNS])


@pytest.mark.parametrize(
    ("document", "columns"),
    [
        (BLOCK, {"verdict": "PASS", "trusted": True}),
        (BLOCK, {"trusted": True}),
        (BLOCK, {"trusted": False}),
        (WARN, {"trusted": False}),
        (WARN, {"trusted": None}),
        (WARN, {"decision_id": "63f0ce64-0000-4000-8000-000000000000"}),
        (WARN, {"repo": "someone/else"}),
        (WARN, {"commit": "c" * 40}),
        (WARN, {"ref": "refs/heads/other"}),
        (WARN, {"image_digest": "sha256:" + "cd" * 32}),
        (WARN, {"verdict": "PASS"}),  # the verdict alone lies (#86 review, round 2)
    ],
    ids=["block-as-trusted-pass", "trusted-block", "verified-block", "warn-not-trusted", "warn-not-verified",
         "another-decision", "another-repo", "another-commit", "another-ref", "another-image",
         "warn-as-pass"],
)  # fmt: skip
def test_the_database_refuses_columns_that_are_not_the_document_s(
    client: TestClient, database_url: str, document: dict[str, Any], columns: dict[str, Any]
) -> None:
    """Review of #86: the listed and counted columns are checked against the bytes, as in 0006. A forged row
    was listed PASS and trusted while its document said BLOCK."""
    with psycopg.connect(database_url, autocommit=True) as conn:
        with pytest.raises((psycopg.errors.RaiseException, psycopg.errors.CheckViolation)):
            _insert(conn, document, **columns)
        assert conn.execute("SELECT count(*) FROM releases").fetchone() == (0,)
        _insert(conn, document)  # the same bytes with their own columns are kept
    assert client.get("/api/v1/releases").json()["total"] == 1


def test_the_database_refuses_a_block_that_carries_a_report(client: TestClient, database_url: str) -> None:
    """The API refuses this document; the check is the database's backstop, apart from the trigger (#86
    review, round 2: going back to `IS NOT TRUE` passed every other test)."""
    document = copy.deepcopy(BLOCK)
    report = copy.deepcopy(WARN["trust_reports"][0])
    report["image"]["digest"] = document["decision"]["subject"]["image_digest"]
    report["decision_id"] = document["decision"]["decision_id"]
    report["checks"][0] |= {"ok": False, "detail": "no signature"}
    report["trusted"] = False
    document["trust_reports"] = [report]
    with (
        psycopg.connect(database_url, autocommit=True) as conn,
        pytest.raises(psycopg.errors.CheckViolation, match="releases_block_never_trusted"),
    ):
        _insert(conn, document)  # its own columns: BLOCK, trusted false


def test_what_sentinel_upload_release_sends_is_recorded_as_sent(
    client: TestClient, headers: dict[str, str]
) -> None:
    """The CLI's document (sentinelci.report.release_upload) and the API's check are the same contract."""
    from sentinelci.report.release_upload import release_evidence

    reports = [json.dumps(report).encode() for report in WARN["trust_reports"]]
    data = release_evidence(json.dumps(WARN["decision"]).encode(), reports)
    created = post(client, headers, data)
    assert created.status_code == 201 and created.json()["sha256"] == hashlib.sha256(data).hexdigest()


def test_a_release_decision_naming_two_thousand_findings_is_recorded(
    client: TestClient, headers: dict[str, str]
) -> None:
    """Review of #86, should fix 1: above 64 KiB, a release was refused (413) before the route ran, as a run's
    decision was before 1.1.50. A violation can name every finding."""
    document = copy.deepcopy(WARN)
    named = [hashlib.sha256(str(n).encode()).hexdigest() for n in range(2000)]
    document["decision"]["violations"][0]["finding_ids"] = named
    body = raw(document)
    assert len(body) > 128 * 1024
    created = post(client, headers, body)
    assert created.status_code == 201, created.text
    digest = document["decision"]["subject"]["image_digest"]
    assert client.get(f"/api/v1/releases/{digest}/evidence").content == body


def test_a_release_one_report_does_not_trust_is_not_trusted(
    client: TestClient, headers: dict[str, str]
) -> None:
    """Review of #86 (Hiba's test): kills the stored `trusted` always True, `any` for `all`, and a
    `not_trusted` count that is always 0."""
    document = copy.deepcopy(WARN)
    offline = document["trust_reports"][1]
    offline["checks"][0] = {**offline["checks"][0], "ok": False, "detail": "no matching signature"}
    offline["trusted"] = False
    created = post(client, headers, raw(document))
    assert created.status_code == 201 and created.json()["trusted"] is False
    assert client.get("/api/v1/releases").json()["items"][0]["trusted"] is False
    metrics = client.get("/metrics").text
    assert 'sentinel_attestation_verifications_total{result="trusted"} 0' in metrics
    assert 'sentinel_attestation_verifications_total{result="not_trusted"} 1' in metrics


def test_a_named_decision_is_served_only_under_its_image(client: TestClient, headers: dict[str, str]) -> None:
    assert post(client, headers, raw(WARN)).status_code == 201
    decision_id = WARN["decision"]["decision_id"]
    named = client.get(f"/api/v1/releases/sha256:{'0' * 64}/evidence", params={"decision_id": decision_id})
    assert named.status_code == 404


def test_a_repeated_key_is_refused_even_in_valid_evidence(
    client: TestClient, headers: dict[str, str]
) -> None:
    body = raw(WARN).replace(b'"verdict": "WARN"', b'"verdict": "BLOCK", "verdict": "WARN"', 1)
    assert post(client, headers, body).status_code == 422
    assert client.get("/api/v1/releases").json()["total"] == 0


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["trust_reports"][0].update(decision_id="00000000-0000-4000-8000-000000000002"),
         "verified decision 00000000-0000-4000-8000-000000000002"),
        (lambda d: d["trust_reports"][0].update(decision_id=None), "names the decision it verified"),
    ],
    ids=["another-decision", "trusted-without-a-decision"],
)  # fmt: skip
def test_a_trust_report_of_another_decision_is_refused(
    client: TestClient, headers: dict[str, str], change: Any, message: str
) -> None:
    """Review of #86, should fix 4: a rebuild of the same digest is another release, and its report was listed
    next to this decision as trusted."""
    document = copy.deepcopy(WARN)
    change(document)
    refused = post(client, headers, raw(document))
    assert refused.status_code == 422 and message in refused.text, refused.text
    assert client.get("/api/v1/releases").json()["total"] == 0
