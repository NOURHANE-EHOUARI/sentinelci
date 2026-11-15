"""Waivers files and the waivers in force (`/api/v1/waivers`, API 1.9.0), and how often each rule fired
(`/api/v1/rules`), against a real PostgreSQL.

A waivers file is kept by its sha256, byte for byte, only when a recorded decision read it (its
`inputs.waivers_digest`): the platform shows the waivers a gate actually used, never a file nobody evaluated.
It never judges a waiver: whether one applied is the decision's `waivers_applied`, and why one is invalid is
the decision's SC-005 message.
"""

from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
FINDING = json.loads((ROOT / "schemas/fixtures/finding/valid/secret-in-config.json").read_text("utf-8"))
RELEASE = json.loads(
    (
        ROOT
        / "schemas/fixtures/release-evidence/valid/warn-verified-in-the-registry-and-from-the-evidence.json"
    ).read_text("utf-8")
)
BLOCK_RELEASE = json.loads(
    (ROOT / "schemas/fixtures/release-evidence/valid/block-without-a-trust-report.json").read_text("utf-8")
)
REPO = "acme/shop"
MAIN = "refs/heads/main"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
JSON = {"Content-Type": "application/json"}
YAML = {"Content-Type": "application/yaml"}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

WAIVERS = b"""version: 1
waivers:
  - id: waiver-2026-001
    finding_id: "%s"
    owner: hiba
    justification: |
      Test fixture key, never deployed.
    expires_at: "2026-12-31T00:00:00Z"
  - id: pyyaml-until-the-bump
    vulnerability: CVE-2020-14343
    purl: pkg:pypi/pyyaml
    owner: nourhane
    justification: The loader is never given user input.
    expires_at: "2026-12-01T00:00:00+01:00"
""" % FINDING["id"].encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_decision(
    client: TestClient,
    headers: dict[str, str],
    waivers_digest: str | None,
    *,
    repo: str = REPO,
    context: str = "release",
    ref: str | None = MAIN,
    evaluated_at: str = "2026-11-10T10:05:00+00:00",
    applied: tuple[str, ...] = ("waiver-2026-001",),
    violations: list[dict[str, Any]] | None = None,
    post: bool = True,
) -> dict[str, Any]:
    """A run with one finding and its recorded decision, which read the waivers file of this digest (None: a
    Decision 1.0, which does not record it). Returns the decision document. With post=False, the decision is
    built but not sent (a test records it another way)."""
    run = {"repo": repo, "commit": COMMIT, "context": context} | ({"ref": ref} if ref else {})
    created = client.post("/api/v1/runs", json=run, headers=headers)
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    body = (json.dumps(FINDING | {"run": run}) + "\n").encode()
    uploaded = client.post(
        f"/api/v1/runs/{run_id}/findings",
        content=body,
        headers=headers | {"Content-Type": "application/x-ndjson"},
    )
    assert uploaded.status_code == 201, uploaded.text
    document = copy.deepcopy(RELEASE["decision"])
    document["decision_id"] = str(uuid.uuid4())
    document["evaluated_at"] = evaluated_at
    document["subject"] = {**document["subject"], **run}
    if ref is None:
        document["subject"].pop("ref")
    if context != "release":
        document["subject"].pop("image_digest")
    document["inputs"]["findings_digest"] = f"sha256:{sha(body)}"
    document["vex_applied"] = []
    document["waivers_applied"] = list(applied)
    document["violations"] = (
        violations
        if violations is not None
        else [{"rule": "SC-006", "effect": "WARN", "finding_ids": [FINDING["id"]], "message": "P1 finding"}]
    )
    if document["violations"] and any(v["effect"] == "BLOCK" for v in document["violations"]):
        document["verdict"] = "BLOCK"
    elif not document["violations"]:
        document["verdict"] = "PASS"
    if waivers_digest is None:
        document["schema_version"] = "1.0"
        for key in ("waivers_digest", "tool_status_digest", "service_context_digest", "vex_digest"):
            document["inputs"].pop(key)
        document.pop("vex_applied")
    else:
        document["inputs"]["waivers_digest"] = waivers_digest
    if not post:
        return document | {"_run_id": run_id}
    recorded = client.post(
        f"/api/v1/runs/{run_id}/decision", content=json.dumps(document), headers=headers | JSON
    )
    assert recorded.status_code == 201, recorded.text
    return document | {"_run_id": run_id}


def release_decision(
    client: TestClient,
    headers: dict[str, str],
    waivers_digest: str,
    *,
    evaluated_at: str = "2026-11-11T09:00:00+00:00",
    ref: str = MAIN,
) -> dict[str, Any]:
    """A recorded release (the BLOCK fixture, no trust report) whose decision read this waivers file."""
    evidence = copy.deepcopy(BLOCK_RELEASE)
    decision = evidence["decision"]
    decision["decision_id"] = str(uuid.uuid4())
    decision["evaluated_at"] = evaluated_at
    decision["subject"]["repo"] = REPO
    decision["subject"]["ref"] = ref
    decision["inputs"]["waivers_digest"] = waivers_digest
    posted = client.post("/api/v1/releases", content=json.dumps(evidence), headers=headers | JSON)
    assert posted.status_code == 201, posted.text
    return dict(decision)


def put(client: TestClient, headers: dict[str, str], body: bytes, digest: str | None = None) -> Any:
    return client.put(f"/api/v1/waivers/{digest or sha(body)}", content=body, headers=headers | YAML)


def in_force(client: TestClient, **params: str) -> list[dict[str, Any]]:
    response = client.get("/api/v1/waivers", params=params)
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


# ---------------------------------------------------------------- a waivers file, kept by its digest


def test_a_file_a_decision_read_is_recorded_and_served_byte_for_byte(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    created = put(client, headers, WAIVERS)
    assert created.status_code == 201, created.text
    record = created.json()
    assert (record["sha256"], record["waiver_count"]) == (sha(WAIVERS), 2)
    served = client.get(f"/api/v1/waivers/{sha(WAIVERS)}")
    assert served.status_code == 200 and served.content == WAIVERS
    assert served.headers["ETag"] == f'"{sha(WAIVERS)}"'
    assert served.headers["Content-Type"].startswith("application/yaml")
    again = put(client, headers, WAIVERS)  # a re-run of the upload step: the same record, nothing new
    assert again.status_code == 200 and again.json() == record


def test_a_file_a_release_decision_read_is_recorded(client: TestClient, headers: dict[str, str]) -> None:
    release_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    assert put(client, headers, WAIVERS).status_code == 201


def test_a_file_no_recorded_decision_read_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{'5' * 64}")
    refused = put(client, headers, WAIVERS)
    assert refused.status_code == 409, refused.text
    assert "no recorded decision read" in refused.json()["detail"]
    assert client.get(f"/api/v1/waivers/{sha(WAIVERS)}").status_code == 404


def test_bytes_that_are_not_the_named_file_are_refused(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    refused = put(client, headers, WAIVERS + b"\n", digest=sha(WAIVERS))
    assert refused.status_code == 422, refused.text
    assert client.get(f"/api/v1/waivers/{sha(WAIVERS)}").status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        b"version: 1\nwaivers: [\n",  # not YAML
        b"version: 2\nwaivers: []\n",  # another version
        b"waivers: []\n",  # not the file's shape
        b"\xff\xfe",  # not UTF-8
    ],
)
def test_a_file_the_gate_could_not_have_read_is_refused(
    client: TestClient, headers: dict[str, str], body: bytes
) -> None:
    run_decision(client, headers, f"sha256:{sha(body)}")
    refused = put(client, headers, body)
    assert refused.status_code == 422, refused.text
    assert "not a waivers file" in json.dumps(refused.json())


ALIASES = b"""version: 1
waivers:
  - &a [x, x, x, x, x, x, x, x, x, x]
  - &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
"""


def test_a_file_with_a_yaml_alias_is_refused(client: TestClient, headers: dict[str, str]) -> None:
    """A few hundred bytes of aliases expand to millions of values (#110 review): the gate's own loader
    refuses them, so the gate fails closed and the platform answers 422."""
    run_decision(client, headers, f"sha256:{sha(ALIASES)}")
    refused = put(client, headers, ALIASES)
    assert refused.status_code == 422, refused.text
    assert "no YAML alias" in json.dumps(refused.json())


def test_a_file_no_decision_read_is_refused_before_it_is_parsed(
    client: TestClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The decision check comes first: a token holder cannot make the API parse a file no gate read."""

    def never(data: bytes) -> list[Any]:
        raise AssertionError("parsed a file no decision read")

    monkeypatch.setattr("sentinel_api.waivers.load_waivers", never)
    assert put(client, headers, ALIASES).status_code == 409


def test_the_waivers_in_force_are_read_from_what_the_put_parsed(
    client: TestClient, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file is parsed once, when it is recorded: listing the waivers in force never parses it again (a page
    view would otherwise cost the parse of every repository's file)."""
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    assert put(client, headers, WAIVERS).status_code == 201

    def never(data: bytes) -> list[Any]:
        raise AssertionError("parsed again")

    monkeypatch.setattr("sentinel_api.waivers.load_waivers", never)
    (item,) = in_force(client)
    assert [w["id"] for w in item["waivers"]] == ["waiver-2026-001", "pyyaml-until-the-bump"]
    assert put(client, headers, WAIVERS).json()["waiver_count"] == 2  # the same file again: no parse either


def test_the_decision_in_force_is_the_latest_by_its_document(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    """`evaluated_at` is copied for display only and the database does not check it: the latest decision is
    chosen by the document's own `evaluated_at` (#110 review)."""
    later = run_decision(
        client, headers, f"sha256:{EMPTY_SHA256}", evaluated_at="2026-11-10T00:00:00Z", applied=()
    )
    earlier = run_decision(
        client, headers, f"sha256:{EMPTY_SHA256}", evaluated_at="2026-11-01T00:00:00Z", applied=(), post=False
    )
    body = json.dumps({k: v for k, v in earlier.items() if not k.startswith("_")}).encode()
    with psycopg.connect(
        database_url, autocommit=True
    ) as connection:  # a column that disagrees with its document
        connection.execute(
            "INSERT INTO decisions (run_id, sha256, decision_id, verdict, evaluated_at, engine_version, "
            "document) "
            "VALUES (%s, encode(sha256(%s), 'hex'), %s, %s, '2026-12-31T00:00:00Z', '0.1.0', %s)",
            (earlier["_run_id"], body, earlier["decision_id"], earlier["verdict"], body),
        )
    (item,) = in_force(client)
    assert item["decision_id"] == later["decision_id"]
    assert item["evaluated_at"].startswith("2026-11-10")


def test_the_empty_file_is_no_waivers(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", applied=())
    created = put(client, headers, b"")
    assert created.status_code == 201 and created.json()["waiver_count"] == 0


def test_a_large_file_is_under_the_upload_limit_not_the_small_json_one(
    client: TestClient, headers: dict[str, str]
) -> None:
    entry = """  - id: w-%d
    vulnerability: CVE-2026-%05d
    purl: pkg:pypi/example
    owner: hiba
    justification: %s
    expires_at: "2026-12-31T00:00:00Z"
"""
    body = b"version: 1\nwaivers:\n" + b"".join((entry % (i, i, "x" * 200)).encode() for i in range(400))
    assert len(body) > 64 * 1024
    run_decision(client, headers, f"sha256:{sha(body)}", applied=())
    created = put(client, headers, body)
    assert created.status_code == 201, created.text
    assert created.json()["waiver_count"] == 400


def test_recording_needs_the_token_and_yaml(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    url = f"/api/v1/waivers/{sha(WAIVERS)}"
    assert client.put(url, content=WAIVERS, headers=YAML).status_code == 401
    assert (
        client.put(
            url, content=WAIVERS, headers=headers | {"Authorization": "Bearer nope"} | YAML
        ).status_code
        == 401
    )
    assert client.put(url, content=WAIVERS, headers=headers | JSON).status_code == 415
    assert client.get(url).status_code == 404


@pytest.mark.parametrize("digest", ["5" * 63, "5" * 65, "G" * 64, "A" * 64, f"sha256:{'5' * 64}"])
def test_a_malformed_digest_is_refused(client: TestClient, headers: dict[str, str], digest: str) -> None:
    assert client.put(f"/api/v1/waivers/{digest}", content=b"", headers=headers | YAML).status_code == 422
    assert client.get(f"/api/v1/waivers/{digest}").status_code == 422


def test_the_database_keeps_only_files_a_decision_read_and_never_changes_them(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    assert put(client, headers, WAIVERS).status_code == 201
    other = b"version: 1\nwaivers: []\n"
    with psycopg.connect(database_url, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException, match="no recorded decision read"):
            connection.execute(
                "INSERT INTO waivers_files (sha256, document, entries) VALUES (%s, %s, '[]')",
                (sha(other), other),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute(
                "INSERT INTO waivers_files (sha256, document, entries) VALUES (%s, %s, '[]')",
                (sha(WAIVERS), other),
            )
        with pytest.raises(psycopg.errors.RaiseException, match="kept as recorded"):
            connection.execute("UPDATE waivers_files SET created_at = now()")
        with pytest.raises(psycopg.errors.RaiseException, match="kept as recorded"):
            connection.execute("DELETE FROM waivers_files")


# ---------------------------------------------------------------- the waivers in force


def test_each_repositorys_latest_release_decision_with_its_waivers(
    client: TestClient, headers: dict[str, str]
) -> None:
    decision = run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    assert put(client, headers, WAIVERS).status_code == 201
    (item,) = in_force(client)
    assert item["repo"] == REPO and item["commit"] == COMMIT and item["ref"] == MAIN
    assert (item["source"], item["run_id"], item["image_digest"]) == ("run", decision["_run_id"], None)
    assert (item["decision_id"], item["verdict"]) == (decision["decision_id"], "WARN")
    assert item["evaluated_at"].startswith("2026-11-10T10:05:00")
    assert item["engine_version"] == "0.1.0"
    assert item["policy_bundle_digest"] == decision["inputs"]["policy_bundle_digest"]
    assert item["waivers_digest"] == f"sha256:{sha(WAIVERS)}"
    assert item["applied"] == ["waiver-2026-001"] and item["invalid_waivers"] == []
    assert item["waivers"] == [
        {
            "index": 0,
            "id": "waiver-2026-001",
            "finding_id": FINDING["id"],
            "vulnerability": None,
            "purl": None,
            "owner": "hiba",
            "justification": "Test fixture key, never deployed.\n",
            "expires_at": "2026-12-31T00:00:00Z",
            "applied": True,
        },
        {
            "index": 1,
            "id": "pyyaml-until-the-bump",
            "finding_id": None,
            "vulnerability": "CVE-2020-14343",
            "purl": "pkg:pypi/pyyaml",
            "owner": "nourhane",
            "justification": "The loader is never given user input.",
            "expires_at": "2026-12-01T00:00:00+01:00",  # as written: the reviewer's text, never a parsed date
            "applied": False,
        },
    ]


def test_only_release_decisions_of_the_default_branch_and_the_latest_one(
    client: TestClient, headers: dict[str, str]
) -> None:
    older = b"version: 1\nwaivers: []\n"
    run_decision(client, headers, f"sha256:{sha(older)}", evaluated_at="2026-11-01T00:00:00Z", applied=())
    put(client, headers, older)
    latest = run_decision(client, headers, f"sha256:{sha(WAIVERS)}", evaluated_at="2026-11-02T00:00:00Z")
    put(client, headers, WAIVERS)
    # Later, but not the default branch's release: a pull request, another branch, a run without a ref.
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", context="pr", evaluated_at="2026-11-09T00:00:00Z")
    run_decision(
        client, headers, f"sha256:{EMPTY_SHA256}", ref="refs/heads/dev", evaluated_at="2026-11-09T00:00:00Z"
    )
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", ref=None, evaluated_at="2026-11-09T00:00:00Z")
    (item,) = in_force(client)
    assert item["decision_id"] == latest["decision_id"] and len(item["waivers"]) == 2


def test_a_later_release_from_the_laptop_is_the_one_in_force(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}", evaluated_at="2026-11-10T00:00:00Z")
    release = release_decision(client, headers, f"sha256:{sha(WAIVERS)}", evaluated_at="2026-11-11T00:00:00Z")
    release_decision(
        client, headers, f"sha256:{EMPTY_SHA256}", evaluated_at="2026-11-12T00:00:00Z", ref="refs/tags/v1"
    )
    put(client, headers, WAIVERS)
    (item,) = in_force(client)
    assert (item["source"], item["decision_id"], item["run_id"]) == ("release", release["decision_id"], None)
    assert item["image_digest"] == release["subject"]["image_digest"] and item["verdict"] == "BLOCK"
    assert [w["applied"] for w in item["waivers"]] == [
        True,
        False,
    ]  # the release decision applied waiver-2026-001


def test_one_item_per_repository_and_the_filter(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", applied=())
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", repo="acme/api", applied=())
    assert [item["repo"] for item in in_force(client)] == ["acme/api", "acme/shop"]
    assert [item["repo"] for item in in_force(client, repo="acme/api")] == ["acme/api"]
    assert in_force(client, repo="acme/none") == []
    assert client.get("/api/v1/waivers", params={"repo": "not a repo"}).status_code == 422


def test_a_file_not_uploaded_is_unknown_never_none(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{sha(WAIVERS)}")
    (item,) = in_force(client)
    assert item["waivers"] is None and item["applied"] == ["waiver-2026-001"]


def test_the_empty_file_is_known_without_an_upload(client: TestClient, headers: dict[str, str]) -> None:
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", applied=())
    (item,) = in_force(client)
    assert item["waivers"] == []


def test_a_decision_that_does_not_record_its_waivers_file(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_decision(client, headers, None, applied=())
    (item,) = in_force(client)
    assert item["waivers_digest"] is None and item["waivers"] is None


def test_an_invalid_waiver_is_shown_as_written_with_the_decisions_reason(
    client: TestClient, headers: dict[str, str]
) -> None:
    odd = b"""version: 1
waivers:
  - id: no-owner
    finding_id: "%s"
    owner: 5
    justification: [not, text]
    expires_at: 2026-12-31
  - just a string
  - [a, list]
""" % FINDING["id"].encode()
    reason = "Invalid waiver no-owner: owner must be a non-empty string"
    run_decision(
        client,
        headers,
        f"sha256:{sha(odd)}",
        applied=(),
        violations=[{"rule": "SC-005", "effect": "BLOCK", "finding_ids": [FINDING["id"]], "message": reason}],
    )
    assert put(client, headers, odd).status_code == 201
    (item,) = in_force(client)
    assert item["invalid_waivers"] == [reason]
    first, second, third = item["waivers"]
    assert (first["id"], first["owner"], first["justification"]) == ("no-owner", None, None)
    assert first["expires_at"] == "2026-12-31"  # kept as the text the reviewer wrote
    assert second == {
        "index": 1, "id": None, "finding_id": None, "vulnerability": None, "purl": None, "owner": None,
        "justification": None, "expires_at": None, "applied": False,
    }  # fmt: skip
    assert third == second | {"index": 2}


def test_no_decision_no_waivers_in_force(client: TestClient) -> None:
    assert in_force(client) == []


# ---------------------------------------------------------------- how often each rule fired


def test_how_often_each_rule_fired_by_effect_and_context(client: TestClient, headers: dict[str, str]) -> None:
    assert client.get("/api/v1/rules").json() == {"decisions": 0, "items": []}
    secret = {"rule": "SC-001", "effect": "BLOCK", "finding_ids": [FINDING["id"]], "message": "Secret"}
    p1 = {"rule": "SC-006", "effect": "WARN", "finding_ids": [FINDING["id"]], "message": "P1 finding"}
    run_decision(
        client,
        headers,
        f"sha256:{EMPTY_SHA256}",
        violations=[secret, p1],
        evaluated_at="2026-11-01T00:00:00Z",
    )
    run_decision(
        client,
        headers,
        f"sha256:{EMPTY_SHA256}",
        violations=[p1],
        context="pr",
        evaluated_at="2026-11-03T00:00:00Z",
    )
    run_decision(
        client,
        headers,
        f"sha256:{EMPTY_SHA256}",
        violations=[p1],
        context="pr",
        evaluated_at="2026-11-02T00:00:00Z",
    )
    run_decision(client, headers, f"sha256:{EMPTY_SHA256}", violations=[], context="pr", applied=())
    release_decision(client, headers, f"sha256:{EMPTY_SHA256}", evaluated_at="2026-11-04T00:00:00Z")  # SC-002
    rules = client.get("/api/v1/rules").json()
    assert rules["decisions"] == 5
    counted = [
        (i["rule"], i["effect"], i["context"], i["decisions"], i["last_evaluated_at"][:10])
        for i in rules["items"]
    ]
    assert counted == [
        ("SC-001", "BLOCK", "release", 1, "2026-11-01"),
        ("SC-002", "BLOCK", "release", 1, "2026-11-04"),
        ("SC-006", "WARN", "pr", 2, "2026-11-03"),
        ("SC-006", "WARN", "release", 1, "2026-11-01"),
    ]


def test_a_decision_recorded_as_a_run_and_as_a_release_counts_once(
    client: TestClient, headers: dict[str, str]
) -> None:
    decision = run_decision(client, headers, f"sha256:{EMPTY_SHA256}")
    evidence = copy.deepcopy(RELEASE)
    evidence["decision"] = {k: v for k, v in decision.items() if not k.startswith("_")}
    evidence["decision"]["subject"]["image_digest"] = RELEASE["decision"]["subject"]["image_digest"]
    evidence["trust_reports"] = []
    evidence["decision"]["verdict"] = "WARN"
    posted = client.post("/api/v1/releases", content=json.dumps(evidence), headers=headers | JSON)
    assert posted.status_code == 201, posted.text
    rules = client.get("/api/v1/rules").json()
    assert rules["decisions"] == 1
    assert [(i["rule"], i["decisions"]) for i in rules["items"]] == [("SC-006", 1)]


# ---------------------------------------------------------------- what PostgreSQL cannot store (#126)


# The raw body is checked for U+0000 before anything is parsed, but YAML decodes escapes: "\0", "\x00" and
# "\u0000" become U+0000, and "\ud800" a lone surrogate, once the file is read. The entries are kept as jsonb,
# which refuses both, so each was a 500 (UntranslatableCharacter) after #110 met #126.
@pytest.mark.parametrize(
    ("field", "escape", "problem"),
    [
        ("owner", "\\0", "U+0000"),
        ("owner", "\\x00", "U+0000"),
        ("justification", "\\u0000", "U+0000"),
        ("owner", "\\ud800", "surrogate"),
    ],
    ids=["nul-escape", "hex-escape", "unicode-escape", "lone-surrogate"],
)
def test_a_waiver_whose_yaml_decodes_to_what_postgresql_refuses_is_a_422(
    client: TestClient, headers: dict[str, str], field: str, escape: str, problem: str
) -> None:
    justification = b"justification: |\n      Test fixture key, never deployed."
    line = b"owner: hiba" if field == "owner" else justification
    value = f'{field}: "a{escape}b"'.encode()
    body = WAIVERS.replace(line, value)
    assert body != WAIVERS
    run_decision(client, headers, f"sha256:{sha(body)}")
    response = put(client, headers, body)
    assert response.status_code == 422, response.text
    assert problem in response.json()["detail"][0]["msg"]
    assert client.get(f"/api/v1/waivers/{sha(body)}").status_code == 404, "nothing is stored"


def test_a_waiver_with_other_text_outside_ascii_is_kept(client: TestClient, headers: dict[str, str]) -> None:
    body = WAIVERS.replace(b"owner: hiba", b'owner: "Hiba \\u00e9 \\U0001F511"')
    run_decision(client, headers, f"sha256:{sha(body)}")
    response = put(client, headers, body)
    assert response.status_code == 201, response.text
    assert client.get(f"/api/v1/waivers/{sha(body)}").content == body
