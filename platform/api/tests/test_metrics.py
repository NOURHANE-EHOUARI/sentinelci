"""Prometheus metrics (`GET /metrics`, SPEC section 10, task A8) against a real PostgreSQL.

Only SPEC §10 names with bounded labels; counts made by PostgreSQL in a read-only transaction; a metric whose
data is not stored is absent, never 0.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text

from sentinel_ai.correlate.models import group_id
from sentinel_api.config import Settings
from sentinel_api.main import create_app
from sentinel_api.metrics import (
    CATEGORIES,
    CONTENT_TYPE,
    PRIORITIES,
    SPEC_METRICS,
    SPEC_NAMES,
    UNSCORED,
    Family,
    render,
)

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
REPO_A, REPO_B = "acme/shop", "acme/billing"
COMMITS = [f"{n:x}" * 40 for n in range(1, 6)]
NDJSON = {"Content-Type": "application/x-ndjson"}
SAMPLE = re.compile(r"^(?P<name>[a-z_]+)\{(?P<labels>[^}]*)\} (?P<value>-?[0-9]+(?:\.[0-9]+)?)$")
LABEL = re.compile(r'^(?P<key>[a-z_]+)="(?P<value>[^"\\\n]*)"$')
ALLOWED = {
    "priority": {*PRIORITIES, UNSCORED},
    "category": set(CATEGORIES),
    "result": {"trusted", "not_trusted"},
}
RELEASES = ROOT / "schemas" / "fixtures" / "release-evidence" / "valid"


def finding(name: str, **changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
    return document | changes


SCA_P0 = finding("sca-enriched-and-scored.json")
SCA_P2 = finding(
    "sca-enriched-and-scored.json", id="b" * 64, risk={**SCA_P0["risk"], "score": 40.0, "priority": "P2"}
)
CONTAINER = finding("container-os-package.json")  # unscored
SECRET = finding("secret-in-config.json")  # unscored


def record(
    client: TestClient,
    headers: dict[str, str],
    repo: str,
    commit: str,
    context: str,
    *documents: dict[str, Any],
    ref: str = "refs/heads/main",
) -> str:
    """A run of `ref` (the default branch unless said) and, when given, its findings (moved to that run)."""
    run = {"repo": repo, "commit": commit, "context": context, "ref": ref}
    created = client.post("/api/v1/runs", json=run, headers=headers)
    assert created.status_code == 201, created.text
    run_id: str = created.json()["id"]
    if documents:
        body = "".join(json.dumps(d | {"run": run}) + "\n" for d in documents).encode()
        uploaded = client.post(f"/api/v1/runs/{run_id}/findings", content=body, headers={**headers, **NDJSON})
        assert uploaded.status_code == 201, uploaded.text
    return run_id


def samples(body: str) -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
    """Every sample by metric and labels; fails on any line that is not well-formed exposition text."""
    found: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
    declared: dict[str, str] = {}
    for line in body.splitlines():
        if line.startswith("# HELP "):
            assert re.fullmatch(r"# HELP [a-z_]+ [^\n]+", line), line
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in ("counter", "gauge") and name not in declared, line
            declared[name] = kind
            continue
        match = SAMPLE.fullmatch(line)
        assert match is not None, f"not a sample line: {line!r}"
        assert match["name"] in declared, f"{match['name']} has no TYPE line before its samples"
        labels = []
        for pair in match["labels"].split(","):
            label = LABEL.fullmatch(pair)
            assert label is not None, pair
            labels.append((label["key"], label["value"]))
        found.setdefault(match["name"], {})[tuple(labels)] = float(match["value"])
    return found


def open_findings(client: TestClient) -> dict[tuple[str, str], float]:
    response = client.get("/metrics")
    assert response.status_code == 200 and response.headers["content-type"] == CONTENT_TYPE
    family = samples(response.text).get("sentinel_findings_open", {})
    return {(dict(key)["priority"], dict(key)["category"]): value for key, value in family.items()}


# ---------------------------------------------------------------- what is counted


def test_nothing_is_said_before_a_release_run_is_recorded(
    client: TestClient, headers: dict[str, str]
) -> None:
    assert client.get("/metrics").text == ""
    record(client, headers, REPO_A, COMMITS[0], "pr", SECRET, SCA_P0)
    record(client, headers, REPO_A, COMMITS[1], "local", CONTAINER)
    record(client, headers, REPO_A, COMMITS[2], "release")  # no findings recorded yet
    response = client.get("/metrics")
    assert response.status_code == 200 and response.text == "", "absent, not 0: no release run is known"


def test_open_findings_are_those_of_each_repositorys_latest_release_run(
    client: TestClient, headers: dict[str, str]
) -> None:
    record(client, headers, REPO_A, COMMITS[0], "release", SECRET, SCA_P0, SCA_P2)  # older: fixed since
    record(client, headers, REPO_A, COMMITS[1], "release", SCA_P0, CONTAINER)  # latest of A
    record(client, headers, REPO_A, COMMITS[2], "release")  # newer, but its findings are not recorded
    record(client, headers, REPO_A, COMMITS[3], "pr", SECRET, SCA_P2)  # a pull request: not open on main
    record(client, headers, REPO_B, COMMITS[4], "release", SECRET, SCA_P2)  # latest of B
    counts = open_findings(client)
    assert len(counts) == len(ALLOWED["priority"]) * len(CATEGORIES), "every pair, so no series vanishes"
    non_zero = {key: value for key, value in counts.items() if value}
    assert non_zero == {
        ("P0", "SCA"): 1, ("P2", "SCA"): 1, (UNSCORED, "CONTAINER"): 1, (UNSCORED, "SECRET"): 1,
    }  # fmt: skip


def test_a_release_run_of_another_ref_is_not_the_default_branchs(
    client: TestClient, headers: dict[str, str]
) -> None:
    """A manual run on a feature branch is a release run too (workflow_dispatch): it must not replace the
    default branch's open findings (#67 review)."""
    record(client, headers, REPO_A, COMMITS[0], "release", SECRET, SCA_P0)
    before = open_findings(client)
    record(client, headers, REPO_A, COMMITS[1], "release", CONTAINER, ref="refs/heads/try-something")
    record(client, headers, REPO_B, COMMITS[2], "release", SCA_P2, ref="refs/heads/try-something")
    assert open_findings(client) == before
    assert {key: value for key, value in before.items() if value} == {
        ("P0", "SCA"): 1,
        (UNSCORED, "SECRET"): 1,
    }


def test_the_default_branch_is_a_setting(database_url: str, headers: dict[str, str]) -> None:
    settings = Settings(
        database_url=database_url,
        token_sha256=frozenset({hashlib.sha256(headers["Authorization"].split()[1].encode()).hexdigest()}),
        default_ref="refs/heads/trunk",
    )
    with TestClient(create_app(settings)) as client:
        record(client, headers, REPO_A, COMMITS[0], "release", SECRET)
        assert client.get("/metrics").text == "", "main is not the default branch here"
        record(client, headers, REPO_A, COMMITS[1], "release", SCA_P0, ref="refs/heads/trunk")
        assert {key for key, value in open_findings(client).items() if value} == {("P0", "SCA")}


# ---------------------------------------------------------------- what it may say


def test_only_spec_names_with_bounded_labels_and_nothing_that_names_a_run(
    client: TestClient, headers: dict[str, str]
) -> None:
    run_id = record(client, headers, REPO_A, COMMITS[0], "release", SECRET, SCA_P0)
    body = client.get("/metrics").text
    found = samples(body)
    assert found and set(found) <= SPEC_NAMES
    for family in found.values():
        for key in family:
            for label, value in key:
                assert value in ALLOWED[label], (label, value)
    for secret_of_a_run in (REPO_A, COMMITS[0], run_id, SECRET["id"], SCA_P0["id"], "acme"):
        assert secret_of_a_run not in body


def test_decision_and_remediation_metrics_are_absent_until_their_data_is_stored(
    client: TestClient, headers: dict[str, str]
) -> None:
    record(client, headers, REPO_A, COMMITS[0], "release", SECRET)
    body = client.get("/metrics").text
    assert "sentinel_findings_open" in body
    for name in SPEC_NAMES - {"sentinel_findings_open"}:
        assert name not in body, f"{name}: not stored yet, so absent rather than 0"


def release(name: str, **subject: Any) -> bytes:
    document: dict[str, Any] = json.loads((RELEASES / name).read_text(encoding="utf-8"))
    document["decision"]["subject"].update(subject)
    for report in document["trust_reports"]:
        report["image"]["digest"] = document["decision"]["subject"]["image_digest"]
    return json.dumps(document).encode()


def verifications(client: TestClient) -> dict[str, float]:
    family = samples(client.get("/metrics").text).get("sentinel_attestation_verifications_total", {})
    return {dict(key)["result"]: value for key, value in family.items()}


def test_attestation_verifications_count_the_releases_verify_checked(
    client: TestClient, headers: dict[str, str]
) -> None:
    post = {"Content-Type": "application/json"} | headers
    block = release("block-without-a-trust-report.json")
    assert client.post("/api/v1/releases", content=block, headers=post).status_code == 201
    assert verifications(client) == {}, "a BLOCK was never signed, so never verified: absent, not 0"
    warn = release("warn-verified-in-the-registry-and-from-the-evidence.json")
    assert client.post("/api/v1/releases", content=warn, headers=post).status_code == 201
    assert verifications(client) == {"trusted": 1, "not_trusted": 0}
    body = client.get("/metrics").text
    assert "# TYPE sentinel_attestation_verifications_total counter" in body
    assert "sha256:" not in body and "NOURHANE" not in body, "nothing that names a release"


def test_the_counts_are_made_by_postgresql_in_a_read_only_transaction(
    client: TestClient, headers: dict[str, str]
) -> None:
    record(client, headers, REPO_A, COMMITS[0], "release", SECRET, SCA_P0)
    engine = client.app.state.sessions.kw["bind"]  # type: ignore[attr-defined]
    statements: list[str] = []

    def seen(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        statements.append(" ".join(statement.split()))

    event.listen(engine, "before_cursor_execute", seen)
    try:
        assert client.get("/metrics").status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", seen)
    assert statements[0] == "SET TRANSACTION READ ONLY", statements
    selects = statements[1:]
    assert selects and all("count(" in statement for statement in selects), selects
    assert any("GROUP BY" in statement for statement in selects)
    for statement in selects:
        assert "findings_ndjson" not in statement
        assert not re.search(r"findings\.document\s*(,|FROM)", statement), "no document is loaded"


# ---------------------------------------------------------------- access


def test_it_needs_no_token_and_only_answers_get(client: TestClient) -> None:
    assert client.get("/metrics").status_code == 200
    for method in ("post", "put", "delete"):
        assert getattr(client, method)("/metrics").status_code == 405


def test_without_a_database_it_answers_503() -> None:
    app = create_app(Settings(database_url=None, token_sha256=frozenset()))
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 503 and response.json() == {"detail": "no database is configured"}


# ---------------------------------------------------------------- the text format


def test_render_writes_the_exposition_format() -> None:
    family = Family(
        name="sentinel_gate_decisions_total",
        kind="counter",
        help='Decisions, by "verdict" \\ context.',
        samples=[({"verdict": "PASS", "context": "pr"}, 3), ({"verdict": 'a"b\\c\nd', "context": "pr"}, 0.5)],
    )
    assert render([family]) == (
        '# HELP sentinel_gate_decisions_total Decisions, by "verdict" \\\\ context.\n'
        "# TYPE sentinel_gate_decisions_total counter\n"
        'sentinel_gate_decisions_total{verdict="PASS",context="pr"} 3\n'
        'sentinel_gate_decisions_total{verdict="a\\"b\\\\c\\nd",context="pr"} 0.5\n'
    )
    assert render([]) == ""


def test_render_refuses_a_name_spec_section_10_does_not_list() -> None:
    with pytest.raises(ValueError, match="not a metric of SPEC section 10"):
        render([Family(name="sentinel_runs_total", kind="counter", help="x", samples=[])])


def test_render_refuses_a_label_spec_section_10_does_not_list() -> None:
    family = Family(name="sentinel_findings_open", kind="gauge", help="x",
                    samples=[({"priority": "P0", "category": "SCA", "repo": "acme/shop"}, 1)])  # fmt: skip
    with pytest.raises(ValueError, match="takes the labels priority, category only"):
        render([family])


def test_the_names_and_labels_are_spec_section_10s() -> None:
    section = (ROOT / "docs" / "spec" / "SPEC.md").read_text(encoding="utf-8").split("## 10.", 1)[1]
    section = section.split("\n## ", 1)[0]
    listed = dict(re.findall(r"`(sentinel_[a-z_]+)\{([a-z_,]+)\}`", section))
    assert {name: tuple(labels.split(",")) for name, labels in listed.items()} == SPEC_METRICS


# ---------------------------------------------------------------- MTTR (fixes on the default branch)

DECISIONS = ROOT / "schemas" / "fixtures" / "decision" / "valid"


def ndjson(
    repo: str, commit: str, context: str, *documents: dict[str, Any], ref: str = "refs/heads/main"
) -> bytes:
    """The bytes `record` uploads for these findings."""
    run = {"repo": repo, "commit": commit, "context": context, "ref": ref}
    return "".join(json.dumps(d | {"run": run}) + "\n" for d in documents).encode()


def decide(
    client: TestClient, headers: dict[str, str], run_id: str, repo: str, commit: str,
    *documents: dict[str, Any], scanner_failed: bool = False,
) -> None:  # fmt: skip
    """Record the run's decision: PASS, or a BLOCK for a scanner failure (SC-010) that names no finding."""
    name = "block-release-v1.2-scanner-timeout.json" if scanner_failed else "pass-pr.json"
    document: dict[str, Any] = json.loads((DECISIONS / name).read_text(encoding="utf-8"))
    document["decision_id"] = str(uuid.uuid4())
    document["subject"] = {"repo": repo, "commit": commit, "context": "release", "ref": "refs/heads/main"}
    digest = hashlib.sha256(ndjson(repo, commit, "release", *documents)).hexdigest()
    document["inputs"]["findings_digest"] = f"sha256:{digest}"
    response = client.post(
        f"/api/v1/runs/{run_id}/decision", content=json.dumps(document).encode(),
        headers={**headers, "Content-Type": "application/json"},
    )  # fmt: skip
    assert response.status_code == 201, response.text


def evidence_run(
    client: TestClient, headers: dict[str, str], repo: str, commit: str, *documents: dict[str, Any],
    scanner_failed: bool = False,
) -> str:  # fmt: skip
    run_id = record(client, headers, repo, commit, "release", *documents)
    decide(client, headers, run_id, repo, commit, *documents, scanner_failed=scanner_failed)
    return run_id


def recorded_at(database_url: str, *run_ids: str) -> list[float]:
    engine = create_engine(database_url)
    with engine.connect() as connection:
        found = {
            str(run_id): at.timestamp()
            for run_id, at in connection.execute(text("SELECT id, findings_uploaded_at FROM runs"))
        }
    engine.dispose()
    return [found[run_id] for run_id in run_ids]


def fixes(client: TestClient) -> dict[str, tuple[float, float]]:
    found = samples(client.get("/metrics").text)
    fixed, seconds = found.get("sentinel_findings_fixed"), found.get("sentinel_findings_fix_seconds")
    if fixed is None or seconds is None:
        assert fixed is None and seconds is None, "both or neither"
        return {}
    return {dict(key)["priority"]: (value, seconds[key]) for key, value in fixed.items()}


def test_a_finding_is_fixed_when_the_next_evidence_run_no_longer_reports_it(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    first = evidence_run(client, headers, REPO_A, COMMITS[0], SCA_P0, SCA_P2)
    second = evidence_run(client, headers, REPO_A, COMMITS[1], SCA_P2)  # SCA_P0 is gone
    third = evidence_run(client, headers, REPO_A, COMMITS[2], SECRET)  # SCA_P2 is gone, SECRET is new
    t1, t2, t3 = recorded_at(database_url, first, second, third)
    found = fixes(client)
    assert set(found) == set(ALLOWED["priority"]), "every priority, so no series vanishes"
    assert found["P0"] == (1, pytest.approx(t2 - t1, abs=1e-3))
    assert found["P2"] == (1, pytest.approx(t3 - t1, abs=1e-3)), "from its first report, not its last"
    assert {level: value for level, value in found.items() if level not in ("P0", "P2")} == {
        level: (0, 0) for level in ALLOWED["priority"] - {"P0", "P2"}
    }, "SECRET is still reported: not fixed"


def test_a_run_whose_scanner_failed_is_no_evidence_that_a_finding_is_gone(
    client: TestClient, headers: dict[str, str], database_url: str
) -> None:
    first = evidence_run(client, headers, REPO_A, COMMITS[0], SCA_P0, SECRET)
    evidence_run(client, headers, REPO_A, COMMITS[1], SECRET, scanner_failed=True)  # SC-010: skipped
    assert fixes(client)["P0"] == (0, 0)
    third = evidence_run(client, headers, REPO_A, COMMITS[2], SECRET)
    t1, t3 = recorded_at(database_url, first, third)
    assert fixes(client)["P0"] == (1, pytest.approx(t3 - t1, abs=1e-3))


def test_a_finding_that_comes_back_is_fixed_twice(client: TestClient, headers: dict[str, str]) -> None:
    for n, documents in enumerate([(SCA_P0, SECRET), (SECRET,), (SCA_P0, SECRET), (SECRET,)]):
        evidence_run(client, headers, REPO_A, COMMITS[n], *documents)
    assert fixes(client)["P0"][0] == 2


def test_runs_without_a_decision_other_refs_and_other_repositories_streaks_do_not_mix(
    client: TestClient, headers: dict[str, str]
) -> None:
    record(client, headers, REPO_A, COMMITS[0], "release", SCA_P0)  # no decision: not evidence
    assert fixes(client) == {}, "absent, not 0: no evidence run"
    evidence_run(client, headers, REPO_A, COMMITS[1], SCA_P0)
    evidence_run(client, headers, REPO_B, COMMITS[2], SECRET)  # B never reported SCA_P0
    record(client, headers, REPO_A, COMMITS[3], "release", SECRET, ref="refs/heads/feature")
    assert all(value == (0, 0) for value in fixes(client).values()), "nothing is gone from A's main yet"


# ---------------------------------------------------------------- alert reduction (latest correlations)


def correlation_group(*members: dict[str, Any]) -> dict[str, Any]:
    ids = sorted(f["id"] for f in members)
    stage = {"stage": "structural", "key": "package:pkg:pypi/x"} if len(ids) > 1 else {"stage": "dedup"}
    return {
        "schema_version": "1.0", "group_id": group_id(ids), "finding_ids": ids, "labelled_by": "template",
        "title": "t", "root_cause": "r", "single_fix": None,
    } | stage  # fmt: skip


def correlate(
    client: TestClient, headers: dict[str, str], run_id: str, body: bytes, *groups: tuple[dict[str, Any], ...]
) -> None:
    document = {
        "schema_version": "1.0",
        "findings_sha256": hashlib.sha256(body).hexdigest(),
        "correlator": {"version": "0.1.0", "stages": ["dedup", "structural"]},
        "groups": sorted(
            (correlation_group(*members) for members in groups), key=lambda g: str(g["group_id"])
        ),
    }
    response = client.post(
        f"/api/v1/runs/{run_id}/correlations",
        content=json.dumps(document).encode(),
        headers={**headers, "Content-Type": "application/json"},
    )
    assert response.status_code == 201, response.text


def reduction(client: TestClient) -> dict[str, tuple[float, float]]:
    found = samples(client.get("/metrics").text)
    findings, groups = found.get("sentinel_correlated_findings"), found.get("sentinel_root_cause_groups")
    if findings is None or groups is None:
        assert findings is None and groups is None, "both or neither"
        return {}
    return {dict(key)["category"]: (value, groups[key]) for key, value in findings.items()}


def test_alert_reduction_counts_each_repositorys_latest_correlated_release_run(
    client: TestClient, headers: dict[str, str]
) -> None:
    older = record(client, headers, REPO_A, COMMITS[0], "release", SECRET)
    correlate(client, headers, older, ndjson(REPO_A, COMMITS[0], "release", SECRET), (SECRET,))
    assert reduction(client)["SECRET"] == (1, 1)
    latest = record(client, headers, REPO_A, COMMITS[1], "release", SCA_P0, SCA_P2, CONTAINER)
    body = ndjson(REPO_A, COMMITS[1], "release", SCA_P0, SCA_P2, CONTAINER)
    correlate(client, headers, latest, body, (SCA_P0,), (SCA_P2,), (CONTAINER,))
    correlate(client, headers, latest, body, (SCA_P0, SCA_P2), (CONTAINER,))  # a newer version: it counts
    record(client, headers, REPO_A, COMMITS[2], "release", SECRET)  # newer, not correlated yet: left out
    pr = record(client, headers, REPO_A, COMMITS[3], "pr", SECRET)
    correlate(client, headers, pr, ndjson(REPO_A, COMMITS[3], "pr", SECRET), (SECRET,))  # not main's
    found = reduction(client)
    assert set(found) == set(CATEGORIES), "every category, so no series vanishes"
    assert {c: v for c, v in found.items() if v != (0, 0)} == {"SCA": (2, 1), "CONTAINER": (1, 1)}


def test_alert_reduction_is_absent_until_a_release_run_is_correlated(
    client: TestClient, headers: dict[str, str]
) -> None:
    record(client, headers, REPO_A, COMMITS[0], "release", SECRET)
    assert reduction(client) == {}
