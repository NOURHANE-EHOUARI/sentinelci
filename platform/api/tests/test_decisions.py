"""A run's gate decision (`/api/v1/runs/{id}/decision`, Decision v1, API 1.6.0) against a real PostgreSQL.

One decision per run, made on exactly the findings the run recorded and about the run's subject; kept and
served byte for byte; never changed, never deleted. The run lists its verdict, and `/metrics` counts them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
DECISIONS = ROOT / "schemas" / "fixtures" / "decision"
RUN = {
    "repo": "acme/shop",
    "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "context": "release",
    "ref": "refs/heads/main",
}
JSON = {"Content-Type": "application/json"}
NDJSON = {"Content-Type": "application/x-ndjson"}


def finding(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    return document | {"run": RUN}


SECRET = finding("secret-in-config.json")
SCA = finding("sca-enriched-and-scored.json")


def run_fields(**changes: str | None) -> dict[str, str]:
    """RUN with these changes; a field changed to None is left out."""
    return {key: value for key, value in (RUN | changes).items() if value is not None}


def create_run(client: TestClient, headers: dict[str, str], **changes: str | None) -> str:
    response = client.post("/api/v1/runs", json=run_fields(**changes), headers=headers)
    assert response.status_code == 201, response.text
    run_id: str = response.json()["id"]
    return run_id


def recorded_run(client: TestClient, headers: dict[str, str], **changes: str | None) -> tuple[str, str]:
    """A run with its findings recorded: (run id, findings_sha256)."""
    run_id = create_run(client, headers, **changes)
    run = run_fields(**changes)
    body = "".join(json.dumps(f | {"run": run}) + "\n" for f in (SECRET, SCA)).encode("utf-8")
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert uploaded.status_code == 201, uploaded.text
    return run_id, hashlib.sha256(body).hexdigest()


def decision(findings_sha256: str, **changes: Any) -> dict[str, Any]:
    """The BLOCK fixture, made on these findings (`findings_digest`) about RUN, naming its findings."""
    document: dict[str, Any] = json.loads((DECISIONS / "valid" / "block-release.json").read_text("utf-8"))
    document["subject"] = {**document["subject"], **{k: RUN[k] for k in ("repo", "commit", "context", "ref")}}
    document["inputs"]["findings_digest"] = f"sha256:{findings_sha256}"
    document["violations"][0]["finding_ids"] = [SECRET["id"]]
    document["violations"][1]["finding_ids"] = [SCA["id"]]
    return document | changes


def as_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode("utf-8") + b"\n"  # as `sentinel evaluate` writes it


def post(client: TestClient, headers: dict[str, str], run_id: str, body: bytes, **extra: str) -> Any:
    return client.post(f"/api/v1/runs/{run_id}/decision", content=body, headers={**headers, **JSON, **extra})


def message(response: Any) -> str:
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, list) and len(detail) == 1, detail
    text: str = detail[0]["msg"]
    return text


# ---------------------------------------------------------------- recorded and served


def test_a_decision_is_recorded_and_served_byte_for_byte(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest))
    created = post(client, headers, run_id, body)
    assert created.status_code == 201, created.text
    out = created.json()
    sha256 = hashlib.sha256(body).hexdigest()
    assert {k: out[k] for k in ("run_id", "sha256", "decision_id", "verdict", "engine_version")} == {
        "run_id": run_id,
        "sha256": sha256,
        "decision_id": "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9e",
        "verdict": "BLOCK",
        "engine_version": "0.1.0",
    }
    assert out["evaluated_at"].startswith("2026-11-10T10:00:00")

    served = client.get(f"/api/v1/runs/{run_id}/decision")
    assert served.status_code == 200
    assert served.content == body, "the bytes that were sent, not a re-serialisation"
    assert served.headers["content-type"] == "application/json"
    assert served.headers["etag"] == f'"{sha256}"'


def test_a_decision_larger_than_the_json_limit_is_accepted_up_to_the_upload_limit(
    client: TestClient, headers: dict[str, str]
) -> None:
    """A violation can name every finding of a large run: a decision is an upload, not a small JSON body."""
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest)) + b" " * (70 * 1024)  # above the 64 KiB of small JSON bodies
    assert post(client, headers, run_id, body).status_code == 201
    assert client.get(f"/api/v1/runs/{run_id}/decision").content == body


def test_the_run_lists_its_verdict(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    other = create_run(client, headers, commit="a" * 40)
    assert client.get(f"/api/v1/runs/{run_id}").json()["verdict"] is None, "no decision yet"
    assert post(client, headers, run_id, as_bytes(decision(digest))).status_code == 201
    assert client.get(f"/api/v1/runs/{run_id}").json()["verdict"] == "BLOCK"
    listed = {item["id"]: item["verdict"] for item in client.get("/api/v1/runs").json()["items"]}
    assert listed == {run_id: "BLOCK", other: None}


def test_the_same_bytes_again_get_the_recorded_decision_and_another_one_is_refused(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest))
    first = post(client, headers, run_id, body).json()

    again = post(client, headers, run_id, body)
    assert again.status_code == 409
    assert again.json()["detail"] == f"decision {first['sha256']} is recorded already"
    assert again.json()["decision"] == first, "a re-run of the upload step finds what is recorded"

    # A run is one gate evaluation: a second, different decision for it is never recorded next to the first.
    second = as_bytes(decision(digest, decision_id="0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d00"))
    refused = post(client, headers, run_id, second)
    assert refused.status_code == 409
    assert refused.json()["detail"].startswith("this run's decision is recorded already")
    assert refused.json()["decision"] == first
    assert client.get(f"/api/v1/runs/{run_id}/decision").content == body


def test_a_decision_id_is_recorded_for_one_run_only(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    assert post(client, headers, run_id, as_bytes(decision(digest))).status_code == 201
    twin, twin_digest = recorded_run(client, headers, ref="refs/heads/next")
    copied = as_bytes(
        decision(twin_digest, subject={**decision(digest)["subject"], "ref": "refs/heads/next"})
    )
    refused = post(client, headers, twin, copied)
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"].startswith("decision 0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9e is recorded")
    assert client.get(f"/api/v1/runs/{twin}/decision").status_code == 404


def test_a_decision_without_a_ref_is_the_runs(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    document = decision(digest)
    del document["subject"]["ref"]
    assert post(client, headers, run_id, as_bytes(document)).status_code == 201


# ---------------------------------------------------------------- only the run's own decision


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (lambda d: d["inputs"].update(findings_digest="sha256:" + "0" * 64), "made on other findings"),
        (lambda d: d["subject"].update(repo="acme/billing"), "about another subject: repo"),
        (lambda d: d["subject"].update(commit="a" * 40), "about another subject: commit"),
        (lambda d: d["subject"].update(context="pr"), "about another subject: context"),
        (lambda d: d["subject"].update(ref="refs/heads/other"), "about another subject: ref"),
        (
            lambda d: d["violations"][0].update(finding_ids=["d" * 64]),
            "1 finding id(s) the run did not record",
        ),
        (
            lambda d: d.update(
                schema_version="1.4",
                vex_applied=["d" * 64],
                inputs=d["inputs"]
                | {"waivers_digest": "sha256:" + "5" * 64, "vex_digest": "sha256:" + "6" * 64},
            ),
            "1 finding id(s) the run did not record",
        ),
    ],
    ids=["other-findings", "repo", "commit", "context", "ref", "unknown-finding", "unknown-vex-finding"],
)
def test_a_decision_that_is_not_the_runs_is_refused(
    client: TestClient, headers: dict[str, str], change: Any, said: str
) -> None:
    run_id, digest = recorded_run(client, headers)
    document = decision(digest)
    change(document)
    assert said in message(post(client, headers, run_id, as_bytes(document)))
    assert client.get(f"/api/v1/runs/{run_id}/decision").status_code == 404


def test_a_ref_named_by_the_decision_must_be_the_runs(client: TestClient, headers: dict[str, str]) -> None:
    """A run recorded without a ref takes a decision that names none, never one that names a ref."""
    run_id, digest = recorded_run(client, headers, ref=None)
    named = decision(digest)
    assert "about another subject: ref" in message(post(client, headers, run_id, as_bytes(named)))
    del named["subject"]["ref"]
    assert post(client, headers, run_id, as_bytes(named)).status_code == 201


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (DECISIONS / "invalid").glob("*.json")), ids=lambda name: name[:-5]
)
def test_the_contracts_invalid_decisions_are_refused(
    client: TestClient, headers: dict[str, str], name: str
) -> None:
    run_id, _ = recorded_run(client, headers)
    body = (DECISIONS / "invalid" / name).read_bytes()
    assert message(post(client, headers, run_id, body)).startswith("not a Decision v1 document")


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"[]",
        b"not json",
        b"\xff\xfe{}",
        b'{"verdict": "PASS", "verdict": "BLOCK"}',
        b'{"risk": NaN}',
    ],
    ids=["empty", "array", "not-json", "not-utf8", "repeated-key", "nan"],
)
def test_anything_but_a_decision_v1_document_is_refused(
    client: TestClient, headers: dict[str, str], body: bytes
) -> None:
    run_id, _ = recorded_run(client, headers)
    assert message(post(client, headers, run_id, body)).startswith("not a Decision v1 document")


def test_a_repeated_key_inside_a_valid_decision_is_refused(
    client: TestClient, headers: dict[str, str]
) -> None:
    """Two readers could read two verdicts: the bytes must mean one thing."""
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest))
    twice = body.replace(b'"verdict": "BLOCK"', b'"verdict": "PASS", "verdict": "BLOCK"', 1)
    assert twice != body
    assert "repeats a key" in message(post(client, headers, run_id, twice))


def test_a_run_whose_findings_are_not_recorded_has_no_decision_yet(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id = create_run(client, headers)
    response = post(client, headers, run_id, as_bytes(decision("0" * 64)))
    assert response.status_code == 409
    assert response.json()["detail"].startswith("no findings recorded for this run yet")


def test_no_such_run_or_decision_is_404(client: TestClient, headers: dict[str, str]) -> None:
    missing = "00000000-0000-4000-8000-000000000000"
    assert post(client, headers, missing, b"{}").status_code == 404
    assert client.get(f"/api/v1/runs/{missing}/decision").status_code == 404
    run_id, _ = recorded_run(client, headers)
    response = client.get(f"/api/v1/runs/{run_id}/decision")
    assert response.status_code == 404 and response.json()["detail"] == "no decision recorded for this run"


def test_recording_needs_a_token_and_json_and_reading_needs_neither(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest))
    assert post(client, {"Authorization": "Bearer wrong-token"}, run_id, body).status_code == 401
    assert post(client, headers, run_id, body, **{"Content-Type": "text/plain"}).status_code == 415
    assert client.get(f"/api/v1/runs/{run_id}/decision").status_code == 404
    assert post(client, headers, run_id, body).status_code == 201
    assert client.get(f"/api/v1/runs/{run_id}/decision", headers={"Authorization": "x"}).status_code == 200


# ---------------------------------------------------------------- /metrics


def test_gate_decisions_are_counted_by_verdict_and_context(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id, digest = recorded_run(client, headers)
    assert "sentinel_gate_decisions_total" not in client.get("/metrics").text, "absent before any decision"
    assert post(client, headers, run_id, as_bytes(decision(digest))).status_code == 201
    pr_run, pr_digest = recorded_run(client, headers, context="pr", ref="refs/pull/7/head")
    passed = decision(
        pr_digest, verdict="PASS", violations=[], decision_id="0193f2c4-7a1e-7b3c-9d2e-000000000001"
    )
    passed["subject"] |= {"context": "pr", "ref": "refs/pull/7/head"}
    assert post(client, headers, pr_run, as_bytes(passed)).status_code == 201

    lines = [
        line for line in client.get("/metrics").text.splitlines() if "sentinel_gate_decisions_total" in line
    ]
    assert lines[:2] == [
        "# HELP sentinel_gate_decisions_total Gate decisions recorded, by verdict and context.",
        "# TYPE sentinel_gate_decisions_total counter",
    ]
    counts = {line.split(" ")[0]: line.split(" ")[1] for line in lines[2:]}
    assert len(counts) == 9, "every pair once a decision exists, so no series vanishes"
    non_zero = {key for key, value in counts.items() if value != "0"}
    assert non_zero == {
        'sentinel_gate_decisions_total{verdict="BLOCK",context="release"}',
        'sentinel_gate_decisions_total{verdict="PASS",context="pr"}',
    }
    for secret_of_a_run in (run_id, pr_run, RUN["repo"], RUN["commit"], digest):
        assert secret_of_a_run not in client.get("/metrics").text


# ---------------------------------------------------------------- the database is the backstop


def test_the_database_keeps_a_decision_as_recorded(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest))
    assert post(client, headers, run_id, body).status_code == 201

    def insert(conn: psycopg.Connection[Any], run: str, data: bytes, sha256: str | None = None) -> None:
        document = json.loads(data)
        conn.execute(
            "INSERT INTO decisions (run_id, sha256, decision_id, verdict, evaluated_at, engine_version, "
            "document) VALUES (%s, %s, %s, %s, now(), 'x', %s)",
            (
                run,
                sha256 or hashlib.sha256(data).hexdigest(),
                document["decision_id"],
                document["verdict"],
                data,
            ),
        )

    with psycopg.connect(database_url, autocommit=True) as conn:
        for statement in ("UPDATE decisions SET verdict = 'PASS'", "DELETE FROM decisions"):
            with pytest.raises(psycopg.errors.RaiseException, match="cannot change or be deleted"):
                conn.execute(statement)
        # Bytes that are not the decision's name are never added.
        with pytest.raises(psycopg.errors.CheckViolation):
            insert(conn, run_id, body, sha256="a" * 64)
        # A second decision for the run, a decision on other findings, or about another subject: never.
        second = as_bytes(decision(digest, decision_id="0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d00"))
        with pytest.raises(psycopg.errors.UniqueViolation):
            insert(conn, run_id, second)
        other_run, other_digest = recorded_run(client, headers, commit="f" * 40)
        for document, why in (
            (decision("0" * 64), "on the findings it recorded"),
            (decision(other_digest), "about the run's subject"),  # the commit is RUN's, not f...f
        ):
            document["decision_id"] = "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d01"
            with pytest.raises(psycopg.errors.RaiseException, match=why):
                insert(conn, other_run, as_bytes(document))
        # The columns are the document's: a verdict or an id other than the one it holds is refused.
        mislabelled = decision(other_digest, decision_id="0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d02")
        mislabelled["subject"]["commit"] = "f" * 40
        data = as_bytes(mislabelled)
        with pytest.raises(psycopg.errors.RaiseException, match="the columns are the document's"):
            conn.execute(
                "INSERT INTO decisions (run_id, sha256, decision_id, verdict, evaluated_at, engine_version, "
                "document) VALUES (%s, %s, %s, 'PASS', now(), 'x', %s)",
                (other_run, hashlib.sha256(data).hexdigest(), mislabelled["decision_id"], data),
            )
        assert conn.execute("SELECT count(*), max(verdict) FROM decisions").fetchone() == (1, "BLOCK")


def test_the_409_is_documented_with_both_of_its_shapes(client: TestClient, headers: dict[str, str]) -> None:
    """A recorded decision answers with `decision`, a run without findings with `detail` only: the contract
    says either, so a generated client never assumes `decision` is there (#79 review)."""
    from jsonschema import Draft202012Validator

    contract = client.get("/openapi.json").json()
    schema = contract["paths"]["/api/v1/runs/{run_id}/decision"]["post"]["responses"]["409"]["content"][
        "application/json"
    ]["schema"]
    refs = sorted(option["$ref"].rsplit("/", 1)[1] for option in schema["anyOf"])
    assert refs == ["DecisionExists", "ErrorOut"]
    validator = Draft202012Validator({**schema, "components": contract["components"]})
    run_id = create_run(client, headers)
    no_findings = post(client, headers, run_id, as_bytes(decision("0" * 64)))
    assert no_findings.status_code == 409 and list(validator.iter_errors(no_findings.json())) == []
    run_id, digest = recorded_run(client, headers, commit="b" * 40)
    document = decision(digest)
    document["subject"]["commit"] = "b" * 40
    assert post(client, headers, run_id, as_bytes(document)).status_code == 201
    again = post(client, headers, run_id, as_bytes(document))
    assert again.status_code == 409 and list(validator.iter_errors(again.json())) == []
