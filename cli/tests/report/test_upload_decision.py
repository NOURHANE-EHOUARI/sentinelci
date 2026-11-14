"""`sentinel upload --decision` (API 1.6.0): the run's gate decision, sent last, byte for byte.

The platform keeps one decision per run, made on exactly the findings it recorded. So the CLI checks the
decision first, against the findings file and the run, and sends nothing when the platform would refuse it.
The platform is the fake of test_upload.py, whose decision answers are validated against
`schemas/openapi.yaml`.
"""

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinelci.report.upload import Platform, RunInfo, UploadError, check_decision

from .test_upload import COMMIT, REPO, ROOT, TOKEN, Fake, _serve, findings, run_upload

DECISIONS = ROOT / "schemas" / "fixtures" / "decision" / "valid"
RUN = RunInfo(repo=REPO, commit=COMMIT, context="pr")


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def platform(fake: Fake) -> Iterator[str]:
    yield from _serve(fake)


def ids(data: bytes) -> list[str]:
    return [json.loads(line)["id"] for line in data.splitlines() if line.strip()]


def decision(data: bytes, **changes: Any) -> dict[str, Any]:
    """A WARN decision made on `data` (the findings bytes) about RUN, naming its first finding."""
    document: dict[str, Any] = json.loads((DECISIONS / "pass-pr.json").read_text(encoding="utf-8"))
    document["subject"] = {"repo": REPO, "commit": COMMIT, "context": "pr"}
    document["inputs"]["findings_digest"] = f"sha256:{hashlib.sha256(data).hexdigest()}"
    document["verdict"] = "WARN"
    document["violations"] = [
        {"rule": "SC-006", "effect": "WARN", "finding_ids": ids(data)[:1], "message": "High-priority finding"}
    ]
    return document | changes


def as_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, indent=2).encode("utf-8") + b"\n"  # as `sentinel evaluate` writes it


def upload_with(tmp_path: Path, url: str, data: bytes, record: bytes, *extra: str) -> Any:
    path = tmp_path / "decision.v1.json"
    path.write_bytes(record)
    return run_upload(tmp_path, url, data, "--decision", str(path), *extra)


# ---------------------------------------------------------------- sent, last, byte for byte


def test_the_run_its_findings_then_its_decision_exactly_as_written(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    data = findings()
    record = as_bytes(decision(data))
    result = upload_with(tmp_path, platform, data, record)
    assert result.exit_code == 0, result.output
    printed = json.loads(result.output)
    assert printed == {
        "run_id": printed["run_id"], "finding_count": 2, "findings_sha256": hashlib.sha256(data).hexdigest(),
        "already_recorded": False, "decision_sha256": hashlib.sha256(record).hexdigest(), "verdict": "WARN",
        "decision_already_recorded": False,
    }  # fmt: skip
    assert [(method, path) for method, path, _, _ in fake.requests] == [
        ("POST", "/api/v1/runs"),
        ("POST", f"/api/v1/runs/{printed['run_id']}/findings"),
        ("POST", f"/api/v1/runs/{printed['run_id']}/decision"),
    ]
    _, _, headers, body = fake.requests[-1]
    assert body == record and headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == f"Bearer {TOKEN}" and TOKEN not in result.output
    assert fake.contract_errors == []


def test_without_decision_nothing_about_one_is_sent_or_printed(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    result = run_upload(tmp_path, platform, findings())
    assert result.exit_code == 0, result.output
    assert set(json.loads(result.output)) == {
        "run_id",
        "finding_count",
        "findings_sha256",
        "already_recorded",
    }
    assert not [path for _, path, _, _ in fake.requests if path.endswith("/decision")]


# ---------------------------------------------------------------- checked first: nothing is sent


def test_a_decision_made_on_the_scans_findings_is_refused_before_anything_is_sent(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    """The gate evaluates the scored findings: a decision made on them, sent with the scan's file (other
    bytes), is not this run's. The platform would refuse it after the run and its findings were recorded."""
    scored, scanned = findings(), findings(count=3)
    result = upload_with(tmp_path, platform, scanned, as_bytes(decision(scored)))
    assert result.exit_code == 4
    assert "made on other findings than --findings" in result.output
    assert "the scored findings the gate evaluated" in result.output
    assert "the findings or the decision were not recorded (the verdict is unchanged)" in result.output
    assert fake.requests == [], "no run is left behind"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"subject": {"repo": "acme/other", "commit": COMMIT, "context": "pr"}}, "its repo is not --repo"),
        ({"subject": {"repo": REPO, "commit": "f" * 40, "context": "pr"}}, "its commit is not --commit"),
        ({"subject": {"repo": REPO, "commit": COMMIT, "context": "release"}}, "its context is not --context"),
        ({"subject": {"repo": REPO, "commit": COMMIT, "context": "pr", "ref": "refs/heads/x"}},
         "a ref that is not --ref"),
        ({"violations": [{"rule": "SC-006", "effect": "WARN", "finding_ids": ["a" * 64], "message": "m"}]},
         "names 1 finding id(s) that are not in --findings"),
        ({"vex_applied": ["b" * 64], "schema_version": "1.4"}, "--decision is not a Decision v1 document"),
        ({"verdict": "PASS"}, "--decision is not a Decision v1 document"),
    ],
    ids=["repo", "commit", "context", "ref", "unknown-finding", "vex-incomplete", "inconsistent-verdict"],
)  # fmt: skip
def test_a_decision_that_is_not_this_runs_is_refused_locally(change: dict[str, Any], message: str) -> None:
    data = findings()
    with pytest.raises(UploadError, match=re.escape(message)):
        check_decision(as_bytes(decision(data, **change)), data, RUN)


def test_a_ref_the_decision_names_must_be_the_runs_and_one_it_does_not_name_is_any() -> None:
    data = findings(ref="refs/pull/12/merge")
    named = as_bytes(decision(data, subject={"repo": REPO, "commit": COMMIT, "context": "pr",
                                             "ref": "refs/pull/12/merge"}))  # fmt: skip
    assert (
        check_decision(named, data, RunInfo(REPO, COMMIT, "pr", ref="refs/pull/12/merge")).verdict == "WARN"
    )
    with pytest.raises(UploadError, match="a ref that is not --ref"):
        check_decision(named, data, RunInfo(REPO, COMMIT, "pr"))  # no --ref: the platform's run has none
    unnamed = as_bytes(decision(data))
    assert (
        check_decision(unnamed, data, RunInfo(REPO, COMMIT, "pr", ref="refs/pull/12/merge")).verdict == "WARN"
    )


def test_a_vex_applied_finding_must_be_in_the_file() -> None:
    data = findings()
    document = json.loads((DECISIONS / "pass-pr-v1.4-with-vex.json").read_text(encoding="utf-8"))
    document["subject"] = {"repo": REPO, "commit": COMMIT, "context": "pr"}
    document["inputs"]["findings_digest"] = f"sha256:{hashlib.sha256(data).hexdigest()}"
    document["vex_applied"] = ids(data)[1:]
    assert check_decision(as_bytes(document), data, RUN).verdict == "PASS"
    document["vex_applied"] = ["c" * 64]
    with pytest.raises(UploadError, match=r"names 1 finding id\(s\) that are not in --findings"):
        check_decision(as_bytes(document), data, RUN)


@pytest.mark.parametrize(
    "record",
    [
        b'{"schema_version": "1.0", "schema_version": "1.0"}',
        b'{"verdict": NaN}',
        b"\xff\xfe",
        b"[]",
        b"",
    ],
    ids=["repeated-key", "nan", "not-utf8", "not-an-object", "empty"],
)
def test_anything_but_one_decision_v1_document_is_refused_locally(record: bytes) -> None:
    with pytest.raises(UploadError, match="--decision is not"):
        check_decision(record, findings(), RUN)


def test_a_repeated_key_inside_an_otherwise_valid_decision_is_refused() -> None:
    data = findings()
    record = as_bytes(decision(data))
    doubled = record.replace(b'"verdict": "WARN",', b'"verdict": "PASS", "verdict": "WARN",', 1)
    assert doubled != record
    with pytest.raises(UploadError, match="unique keys: a key is repeated"):
        check_decision(doubled, data, RUN)


# ---------------------------------------------------------------- once per run


def test_the_same_ci_run_again_finds_its_decision_recorded(tmp_path: Path, platform: str, fake: Fake) -> None:
    data = findings(run_id="7/1")
    record = as_bytes(decision(data))
    first = upload_with(tmp_path, platform, data, record, "--run-id", "7/1")
    again = upload_with(tmp_path, platform, data, record, "--run-id", "7/1")
    assert first.exit_code == again.exit_code == 0, again.output
    printed = json.loads(again.output)
    assert printed["already_recorded"] and printed["decision_already_recorded"]
    assert printed["run_id"] == json.loads(first.output)["run_id"] and len(fake.decisions) == 1
    assert fake.contract_errors == []


def test_another_decision_for_a_recorded_run_is_an_upload_failure(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    data = findings(run_id="7/1")
    assert upload_with(tmp_path, platform, data, as_bytes(decision(data)), "--run-id", "7/1").exit_code == 0
    other = as_bytes(decision(data, decision_id="0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d00"))
    result = upload_with(tmp_path, platform, data, other, "--run-id", "7/1")
    assert result.exit_code == 4
    assert "already holds another decision: a run has one decision" in result.output


def test_a_decision_id_recorded_for_another_run_is_an_upload_failure(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    data = findings()
    record = as_bytes(decision(data))
    assert upload_with(tmp_path, platform, data, record).exit_code == 0  # a local run: a re-run is a new run
    result = upload_with(tmp_path, platform, data, record)
    first, second = fake.runs
    assert result.exit_code == 4
    # The message names the run that holds the decision (review of #87), and says this run's findings are in.
    assert f"decision {decision(data)['decision_id']} is recorded for run {first}" in result.output
    assert f"the decision was not recorded (the findings are, in run {second})" in result.output


def test_the_platform_must_record_the_bytes_sent(tmp_path: Path, platform: str, fake: Fake) -> None:
    fake.lie_about_decision = True
    data = findings()
    result = upload_with(tmp_path, platform, data, as_bytes(decision(data)))
    assert result.exit_code == 4
    assert "recorded another decision than the one sent" in result.output


def test_a_failed_decision_names_the_run_and_resume_finishes_it(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    data = findings()
    record = as_bytes(decision(data))
    fake.decision_status = 503
    failed = upload_with(tmp_path, platform, data, record)
    assert failed.exit_code == 4
    (run_id,) = fake.runs
    assert f"recording the decision of run {run_id} failed: HTTP 503" in failed.output
    assert f"--resume {run_id}" in failed.output
    # The findings are recorded: only the decision is missing, and the message says so (review of #87).
    assert f"the decision was not recorded (the findings are, in run {run_id})" in failed.output
    assert "the findings or the decision" not in failed.output
    fake.decision_status = None
    resumed = upload_with(tmp_path, platform, data, record, "--resume", run_id)
    assert resumed.exit_code == 0, resumed.output
    printed = json.loads(resumed.output)
    assert printed["already_recorded"] and not printed["decision_already_recorded"]
    assert fake.decisions[run_id]["sha256"] == hashlib.sha256(record).hexdigest()


def test_a_409_that_holds_no_decision_records_nothing(tmp_path: Path, platform: str, fake: Fake) -> None:
    """API 1.6.1: the 409's other shape (ErrorOut, the run's findings not recorded yet) is not "recorded"."""
    fake.decision_status = 409
    data = findings()
    result = upload_with(tmp_path, platform, data, as_bytes(decision(data)))
    (run_id,) = fake.runs
    assert result.exit_code == 4
    assert f"recording the decision of run {run_id} failed: HTTP 409" in result.output
    assert f"--resume {run_id}" in result.output


def test_a_lost_answer_to_the_decision_names_the_run_and_the_same_command_confirms_it(
    tmp_path: Path, platform: str, fake: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = Platform.post_decision

    def lost(self: Platform, run_id: str, data: bytes) -> tuple[int, object]:
        sent(self, run_id, data)  # recorded, then the answer is lost
        raise UploadError("the platform could not be reached: ConnectionResetError: reset")

    monkeypatch.setattr(Platform, "post_decision", lost)
    data = findings(run_id="7/1")
    record = as_bytes(decision(data))
    failed = upload_with(tmp_path, platform, data, record, "--run-id", "7/1")
    (run_id,) = fake.runs
    assert failed.exit_code == 4 and f"--resume {run_id}" in failed.output
    # The platform may hold the decision (it does here): the CLI must not say it does not (#87 review).
    assert "the decision was not recorded" not in failed.output
    assert f"the decision may be recorded or not (the findings are, in run {run_id})" in failed.output
    monkeypatch.setattr(Platform, "post_decision", sent)
    again = upload_with(tmp_path, platform, data, record, "--run-id", "7/1")
    assert again.exit_code == 0, again.output
    assert json.loads(again.output)["decision_already_recorded"] is True


@pytest.mark.parametrize("status", [413, 422])
def test_a_decision_the_platform_refuses_is_not_said_to_be_resumable(
    status: int, tmp_path: Path, platform: str, fake: Fake
) -> None:
    fake.decision_status = status
    data = findings()
    result = upload_with(tmp_path, platform, data, as_bytes(decision(data)))
    assert result.exit_code == 4
    assert f"HTTP {status}" in result.output and "--resume" not in result.output
