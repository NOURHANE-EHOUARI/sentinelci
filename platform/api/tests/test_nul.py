"""U+0000 anywhere in a request is a 422, never a 500 (B1, the #86 review).

PostgreSQL cannot store U+0000: not in a text column (psycopg refuses the parameter) and not in `jsonb`
("unsupported Unicode escape sequence"). Without a check at the boundary, a string holding it reached the
database and came back as a 500: nothing was recorded, so it failed closed, but the client was told the server
broke rather than that its document cannot be stored. Each test checks the 422 and that nothing was recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sentinel_ai.correlate.models import group_id

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
RUN = {
    "repo": "acme/shop",
    "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "context": "release",
    "ref": "refs/heads/main",
}
JSON = {"Content-Type": "application/json"}
NDJSON = {"Content-Type": "application/x-ndjson"}
NUL = "\u0000"


def finding(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    return document | {"run": RUN}


SECRET = finding("secret-in-config.json")
SCA = finding("sca-enriched-and-scored.json")


def create_run(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post("/api/v1/runs", json=RUN, headers=headers)
    assert response.status_code == 201, response.text
    run_id: str = response.json()["id"]
    return run_id


def recorded_run(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    """A run with its findings recorded: (run id, findings_sha256)."""
    run_id = create_run(client, headers)
    body = "".join(json.dumps(f) + "\n" for f in (SECRET, SCA)).encode("utf-8")
    uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert uploaded.status_code == 201, uploaded.text
    return run_id, hashlib.sha256(body).hexdigest()


def decision(findings_sha256: str) -> dict[str, Any]:
    """The BLOCK fixture, made on these findings about RUN, naming its findings (as test_decisions.py)."""
    path = ROOT / "schemas" / "fixtures" / "decision" / "valid" / "block-release.json"
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    document["subject"] = {**document["subject"], **{k: RUN[k] for k in ("repo", "commit", "context", "ref")}}
    document["inputs"]["findings_digest"] = f"sha256:{findings_sha256}"
    document["violations"][0]["finding_ids"] = [SECRET["id"]]
    document["violations"][1]["finding_ids"] = [SCA["id"]]
    return document


def as_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode("utf-8") + b"\n"


def group(*finding_ids: str) -> dict[str, Any]:
    ids = sorted(finding_ids)
    return {
        "schema_version": "1.0",
        "group_id": group_id(ids),
        "finding_ids": ids,
        "stage": "dedup",
        "labelled_by": "template",
        "title": f"{len(ids)} finding(s)",
        "root_cause": "The same root cause.",
        "single_fix": None,
    }


def correlation(findings_sha256: str, *groups: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "findings_sha256": findings_sha256,
        "correlator": {"version": "0.1.0", "stages": ["dedup"]},
        "groups": sorted(groups, key=lambda g: str(g["group_id"])),
    }


def is_nul_refusal(response: Any) -> bool:
    return response.status_code == 422 and "U+0000" in response.text


@pytest.mark.parametrize("field", ["run_id", "ref"])
def test_a_run_with_u0000_in_a_field_is_refused(
    client: TestClient, headers: dict[str, str], field: str
) -> None:
    body = RUN | {field: f"ci{NUL}1"}
    response = client.post("/api/v1/runs", json=body, headers=headers)
    assert is_nul_refusal(response), response.text
    assert client.get("/api/v1/runs").json()["items"] == []


@pytest.mark.parametrize(
    "query",
    ["/api/v1/runs?ref=a%00b", "/api/v1/findings?tool=a%00b"],
    ids=["runs-ref", "findings-tool"],
)
def test_a_query_parameter_with_u0000_is_refused(client: TestClient, query: str) -> None:
    response = client.get(query)
    assert is_nul_refusal(response), response.text


@pytest.mark.parametrize(
    "title",
    [f"Hard-coded{NUL} API key", f"Hard-coded \\{NUL} API key"],
    ids=["u0000", "a-backslash-then-u0000-itself"],
)
def test_findings_with_u0000_in_a_string_are_refused(
    client: TestClient, headers: dict[str, str], title: str
) -> None:
    run_id = create_run(client, headers)
    bad = SECRET | {"title": title}
    body = "".join(json.dumps(f) + "\n" for f in (bad, SCA)).encode("utf-8")
    response = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert is_nul_refusal(response), response.text
    assert client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"] is None


def test_a_decision_with_u0000_in_a_string_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    document = decision(digest)
    document["violations"][0]["message"] = f"Hard-coded{NUL} secret"
    response = client.post(
        f"/api/v1/runs/{run_id}/decision", content=as_bytes(document), headers={**headers, **JSON}
    )
    assert is_nul_refusal(response), response.text
    assert client.get(f"/api/v1/runs/{run_id}/decision").status_code == 404


def test_a_decision_with_u0000_in_a_key_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    body = as_bytes(decision(digest)).replace(b'"verdict"', b'"verdict\\u0000"', 1)
    response = client.post(f"/api/v1/runs/{run_id}/decision", content=body, headers={**headers, **JSON})
    assert is_nul_refusal(response), response.text


def test_a_correlation_with_u0000_in_a_string_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_id, digest = recorded_run(client, headers)
    one = group(SECRET["id"]) | {"root_cause": f"The same{NUL} root cause."}
    body = json.dumps(correlation(digest, one, group(SCA["id"]))).encode("utf-8")
    response = client.post(f"/api/v1/runs/{run_id}/correlations", content=body, headers={**headers, **JSON})
    assert is_nul_refusal(response), response.text
    assert client.get(f"/api/v1/runs/{run_id}/correlations").status_code == 404


def test_release_evidence_with_u0000_in_a_check_is_refused(
    client: TestClient, headers: dict[str, str]
) -> None:
    """The case of the #86 review: the releases trigger casts the bytes to jsonb, which refused U+0000
    (a 500)."""
    path = ROOT / "schemas" / "fixtures" / "release-evidence" / "valid"
    document = json.loads(
        (path / "warn-verified-in-the-registry-and-from-the-evidence.json").read_text(encoding="utf-8")
    )
    document["trust_reports"][0]["checks"][0]["detail"] = f"signed{NUL} by the key"
    body = json.dumps(document, indent=2).encode("utf-8")
    response = client.post("/api/v1/releases", content=body, headers={**headers, **JSON})
    assert is_nul_refusal(response), response.text
    assert client.get("/api/v1/releases").json()["total"] == 0


def test_a_remediation_attempt_with_u0000_in_its_rationale_is_refused(
    client: TestClient, headers: dict[str, str]
) -> None:
    path = ROOT / "schemas" / "fixtures" / "remediation-attempt" / "valid" / "kubernetes-verified.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["proposal"]["rationale"] = f"Run shop-api{NUL} as a non-root user."
    body = json.dumps(document, indent=2).encode("utf-8")
    response = client.post("/api/v1/remediations", content=body, headers={**headers, **JSON})
    assert is_nul_refusal(response), response.text
    assert client.get("/api/v1/remediations").json()["total"] == 0


def test_a_raw_nul_byte_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    """Not valid JSON in a string either; the 422 names U+0000 rather than a parse error."""
    run_id = create_run(client, headers)
    body = json.dumps(SECRET).encode("utf-8").replace(b"Hard-coded", b"Hard-coded\x00", 1) + b"\n"
    response = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert is_nul_refusal(response), response.text


@pytest.mark.parametrize(
    "text",
    ["a \\u0000 b", "a \\\\u0000 b", "U+0000"],
    ids=["a-backslash-then-u0000", "two-backslashes-then-u0000", "the-words"],
)
def test_text_that_only_spells_u0000_is_kept(client: TestClient, headers: dict[str, str], text: str) -> None:
    """A backslash followed by `u0000`, as characters, is not U+0000: it is stored as it came."""
    run_id = create_run(client, headers)
    body = (json.dumps(SECRET | {"title": text}) + "\n").encode("utf-8")
    response = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert response.status_code == 201, response.text
    assert client.get(f"/api/v1/runs/{run_id}/findings").content == body


# A lone UTF-16 surrogate is the other string PostgreSQL cannot store (#126 review): JSON can spell one
# (`"\ud800"`), Python's json reads it, and it cannot be encoded as UTF-8.
@pytest.mark.parametrize("surrogate", ["\ud800", "\udc00"], ids=["high", "low"])
def test_findings_with_a_lone_surrogate_are_refused(
    client: TestClient, headers: dict[str, str], surrogate: str
) -> None:
    run_id = create_run(client, headers)
    bad = SECRET | {"title": f"Hard-coded{surrogate} API key"}
    body = "".join(json.dumps(f) + "\n" for f in (SCA, bad)).encode("utf-8")
    assert b"\\ud" in body or b"\\udc" in body  # the escape, as json.dumps writes it
    response = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert response.status_code == 422, response.text
    assert "surrogate" in response.text and response.json()["detail"][0]["loc"] == ["body", 2]
    assert client.get(f"/api/v1/runs/{run_id}").json()["findings_sha256"] is None


def test_a_valid_surrogate_pair_is_kept_byte_for_byte(client: TestClient, headers: dict[str, str]) -> None:
    run_id = create_run(client, headers)
    body = (json.dumps(SECRET | {"title": "Hard-coded API key \U0001f511"}) + "\n").encode("utf-8")
    assert b"\\ud83d\\udd11" in body  # one character, written as its surrogate pair
    response = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
    assert response.status_code == 201, response.text
    assert client.get(f"/api/v1/runs/{run_id}/findings").content == body


def test_a_run_with_a_lone_surrogate_gets_a_422_not_a_500(
    client: TestClient, headers: dict[str, str]
) -> None:
    """The model refuses the string, and the 422 must still render: it echoes the input it refused."""
    body = json.dumps(RUN | {"run_id": "ci\ud8001"}).encode("ascii")
    response = client.post("/api/v1/runs", content=body, headers={**headers, **JSON})
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body", "run_id"]


def test_a_refused_decision_says_it_is_a_decision(client: TestClient, headers: dict[str, str]) -> None:
    run_id, _ = recorded_run(client, headers)
    response = client.post(f"/api/v1/runs/{run_id}/decision", content=b"{}", headers={**headers, **JSON})
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["type"] == "decision_invalid"
