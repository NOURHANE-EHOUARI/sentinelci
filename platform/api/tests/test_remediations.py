"""Remediation attempts (`/api/v1/remediations`, Remediation attempt v1, tasks A6 and A8) against a real
PostgreSQL.

Recorded only when consistent (VERIFIED only through the verification gate, the result the proposal's), once
per proposal, kept and served byte for byte, never changed, never deleted; counted by strategy and outcome.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "remediation-attempt" / "valid"
JSON = {"Content-Type": "application/json"}
VERIFIED = json.loads((FIXTURES / "kubernetes-verified.json").read_text(encoding="utf-8"))
REJECTED = json.loads((FIXTURES / "llm-code-rejected-on-its-second-attempt.json").read_text(encoding="utf-8"))


def raw(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode()


def post(client: TestClient, headers: dict[str, str], body: bytes) -> Any:
    return client.post("/api/v1/remediations", content=body, headers=headers | JSON)


def test_an_attempt_is_recorded_listed_and_served_byte_for_byte(
    client: TestClient, headers: dict[str, str]
) -> None:
    body = raw(VERIFIED)
    created = post(client, headers, body)
    assert created.status_code == 201, created.text
    attempt = created.json()
    assert attempt["proposal_id"] == VERIFIED["proposal"]["proposal_id"]
    assert (attempt["strategy"], attempt["outcome"], attempt["pull_request"]) == (
        "deterministic:kubernetes", "VERIFIED", 81)  # fmt: skip
    assert (attempt["finding_count"], attempt["new_finding_count"]) == (2, 0)
    assert attempt["sha256"] == hashlib.sha256(body).hexdigest()
    served = client.get(f"/api/v1/remediations/{attempt['proposal_id']}")
    assert served.status_code == 200 and served.content == body
    assert served.headers["ETag"] == f'"{attempt["sha256"]}"'
    assert client.get("/api/v1/remediations").json()["items"] == [attempt]


def test_newest_first_and_filtered(client: TestClient, headers: dict[str, str]) -> None:
    assert post(client, headers, raw(VERIFIED)).status_code == 201
    assert post(client, headers, raw(REJECTED)).status_code == 201
    items = client.get("/api/v1/remediations").json()["items"]
    assert [item["outcome"] for item in items] == ["REJECTED", "VERIFIED"]
    llm = client.get("/api/v1/remediations", params={"strategy": "llm:code"}).json()
    assert llm["total"] == 1 and llm["items"][0]["attempt"] == 2
    verified = client.get("/api/v1/remediations", params={"outcome": "VERIFIED"}).json()
    assert [item["strategy"] for item in verified["items"]] == ["deterministic:kubernetes"]
    assert client.get("/api/v1/remediations", params={"repo": "o/r"}).json()["total"] == 0
    assert client.get("/api/v1/remediations", params={"outcome": "MERGED"}).status_code == 422


def test_an_attempt_is_recorded_once(client: TestClient, headers: dict[str, str]) -> None:
    first = post(client, headers, raw(VERIFIED)).json()
    again = post(client, headers, raw(VERIFIED))
    assert again.status_code == 409 and again.json()["remediation"] == first
    other = copy.deepcopy(VERIFIED)
    other["result"]["pull_request"] = 82
    changed = post(client, headers, raw(other))
    assert changed.status_code == 409 and "with another document" in changed.json()["detail"]
    assert client.get(f"/api/v1/remediations/{first['proposal_id']}").content == raw(VERIFIED)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["result"].update(tests_ok=False), "VERIFIED needs a build, passing tests"),
        (lambda d: d["result"].update(verdict="BLOCK"), "VERIFIED needs"),
        (lambda d: d["result"].update(proposal_id="0193f2c5-0000-7000-8000-00000000ffff"), "about proposal"),
        (lambda d: d["result"].update(verified_at="2026-11-11T08:00:00Z"), "verified before the proposal"),
        (lambda d: d["proposal"].update(strategy="manual"), "proposal.strategy"),
        (lambda d: d.pop("repo"), "repo"),
    ],
)  # fmt: skip
def test_an_attempt_that_contradicts_itself_or_the_gate_is_refused(
    client: TestClient, headers: dict[str, str], change: Any, message: str
) -> None:
    document = copy.deepcopy(VERIFIED)
    change(document)
    refused = post(client, headers, raw(document))
    assert refused.status_code == 422, refused.text
    assert message in refused.json()["detail"][0]["msg"]
    assert client.get("/api/v1/remediations").json()["total"] == 0


def test_recording_needs_the_token_and_json(client: TestClient, headers: dict[str, str]) -> None:
    assert client.post("/api/v1/remediations", content=raw(VERIFIED), headers=JSON).status_code == 401
    plain = headers | {"Content-Type": "text/plain"}
    assert client.post("/api/v1/remediations", content=raw(VERIFIED), headers=plain).status_code == 415
    assert client.get("/api/v1/remediations/0193f2c5-0000-7000-8000-00000000ffff").status_code == 404
    assert client.get("/api/v1/remediations/not-a-uuid").status_code == 422


def test_a_recorded_attempt_never_changes(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    assert post(client, headers, raw(VERIFIED)).status_code == 201
    with psycopg.connect(database_url, autocommit=True) as conn:
        for statement in (
            "UPDATE remediations SET outcome = 'FAILED' WHERE proposal_id = %s",
            "DELETE FROM remediations WHERE proposal_id = %s",
        ):
            with pytest.raises(psycopg.errors.RaiseException, match="is kept as recorded"):
                conn.execute(statement, (VERIFIED["proposal"]["proposal_id"],))


def test_the_database_holds_the_verification_gate_too(client: TestClient, database_url: str) -> None:
    body = raw(VERIFIED)
    with psycopg.connect(database_url, autocommit=True) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "INSERT INTO remediations (proposal_id, repo, strategy, attempt, finding_count, outcome, "
            "verdict, build_ok, tests_ok, target_resolved, new_finding_count, proposed_at, verified_at, "
            "sha256, "
            "document) VALUES (gen_random_uuid(), 'o/r', 'llm:code', 1, 1, 'VERIFIED', 'PASS', true, false, "
            "true, 0, now(), now(), %s, %s)",
            (hashlib.sha256(body).hexdigest(), body),
        )


def test_attempts_are_counted_by_strategy_and_outcome(client: TestClient, headers: dict[str, str]) -> None:
    assert "sentinel_remediation_attempts_total" not in client.get("/metrics").text, "absent before one"
    assert post(client, headers, raw(VERIFIED)).status_code == 201
    assert post(client, headers, raw(REJECTED)).status_code == 201
    body = client.get("/metrics").text
    samples = dict(re.findall(r"^sentinel_remediation_attempts_total\{(.*)\} (\d+)$", body, re.MULTILINE))
    assert len(samples) == 4 * 3, "every strategy and outcome, at 0 when there is none"
    assert samples['strategy="deterministic:kubernetes",outcome="VERIFIED"'] == "1"
    assert samples['strategy="llm:code",outcome="REJECTED"'] == "1"
    assert samples['strategy="llm:code",outcome="VERIFIED"'] == "0"


def test_what_sentinel_upload_remediation_sends_is_recorded_as_sent(
    client: TestClient, headers: dict[str, str]
) -> None:
    """The CLI's document (sentinelci.report.remediation_upload) and the API's check are the same contract."""
    from sentinelci.report.remediation_upload import remediation_attempt

    data = remediation_attempt(
        json.dumps(VERIFIED["proposal"]).encode(),
        json.dumps(VERIFIED["result"]).encode(),
        repo=VERIFIED["repo"],
    )
    created = post(client, headers, data)
    assert created.status_code == 201 and created.json()["sha256"] == hashlib.sha256(data).hexdigest()
