"""`sentinel upload-release` (tasks A4 and A8): the release decision and its trust reports, as Release
evidence v1, to a fake platform that answers like `POST /api/v1/releases`."""

import copy
import hashlib
import json
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from sentinelci.cli import app
from sentinelci.contracts.release import ReleaseEvidence
from sentinelci.report.release_upload import release_evidence
from sentinelci.report.upload import UploadError

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "release-evidence" / "valid"
EVIDENCE = json.loads((VALID / "warn-verified-in-the-registry-and-from-the-evidence.json").read_text())
TOKEN = "fake-ingestion-token-for-tests-only"  # noqa: S105 (a fake, for the fake platform)


class Fake:
    """The platform's releases: one document per decision, by decision id."""

    def __init__(self) -> None:
        self.recorded: dict[str, bytes] = {}
        self.requests: list[tuple[str, dict[str, str], bytes]] = []
        self.answer: tuple[int, Any] | None = None  # forced answer

    def post(self, headers: dict[str, str], body: bytes) -> tuple[int, Any]:
        if self.answer is not None:
            return self.answer
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, {"detail": f"bad token {headers.get('Authorization')}"}
        if headers.get("Content-Type") != "application/json":
            return 415, {"detail": "not json"}
        evidence = ReleaseEvidence.model_validate_json(body)
        decision_id = str(evidence.decision.decision_id)
        release = {"decision_id": decision_id, "sha256": hashlib.sha256(body).hexdigest()}
        if decision_id in self.recorded:
            kept = {
                "decision_id": decision_id,
                "sha256": hashlib.sha256(self.recorded[decision_id]).hexdigest(),
            }
            return 409, {"detail": "recorded already", "release": kept}
        self.recorded[decision_id] = body
        return 201, release


def handler(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {key: value for key, value in self.headers.items()}
            fake.requests.append((self.path, headers, body))
            status, answer = fake.post(headers, body) if self.path == "/api/v1/releases" else (404, {})
            data = json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: Any) -> None:
            pass

    return Handler


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def platform(fake: Fake) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(fake))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def files(tmp_path: Path, evidence: dict[str, Any] = EVIDENCE) -> list[str]:
    (tmp_path / "decision.v1.json").write_text(json.dumps(evidence["decision"], indent=2))
    args = ["--decision", str(tmp_path / "decision.v1.json")]
    for report in evidence["trust_reports"]:
        path = tmp_path / f"trust-{report['mode']}.json"
        path.write_text(json.dumps(report, indent=2))
        args += ["--trust-report", str(path)]
    return args


def upload(args: list[str], url: str, token: str | None = TOKEN) -> Result:
    env = {"SENTINEL_API_TOKEN": token} if token is not None else {}
    return CliRunner(env=env).invoke(app, ["upload-release", *args, "--api-url", url])


def test_the_evidence_is_recorded_once_and_again_counts_as_uploaded(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    args = files(tmp_path)
    first = upload(args, platform)
    assert first.exit_code == 0, first.output
    said = json.loads(first.output)
    sent = fake.requests[0][2]
    assert said == {
        "decision_id": EVIDENCE["decision"]["decision_id"],
        "image_digest": EVIDENCE["decision"]["subject"]["image_digest"],
        "sha256": hashlib.sha256(sent).hexdigest(),
        "already_recorded": False,
    }
    again = upload(args, platform)
    assert again.exit_code == 0 and json.loads(again.output)["already_recorded"] is True
    assert fake.requests[1][2] == sent, "the same files give the same bytes"


def test_the_document_is_the_decision_and_the_reports_registry_first(tmp_path: Path) -> None:
    decision = json.dumps(EVIDENCE["decision"]).encode()
    registry, evidence = (json.dumps(report).encode() for report in EVIDENCE["trust_reports"])
    data = release_evidence(decision, [evidence, registry])
    assert data == release_evidence(decision, [registry, evidence])
    document = json.loads(data)
    assert document["decision"] == EVIDENCE["decision"]
    assert [report["mode"] for report in document["trust_reports"]] == ["registry", "evidence"]


def test_a_block_is_sent_without_a_report(tmp_path: Path, platform: str, fake: Fake) -> None:
    block = json.loads((VALID / "block-without-a-trust-report.json").read_text())
    result = upload(files(tmp_path, block), platform)
    assert result.exit_code == 0, result.output
    assert json.loads(fake.requests[0][2])["trust_reports"] == []


def test_other_evidence_for_a_recorded_decision_is_refused(tmp_path: Path, platform: str, fake: Fake) -> None:
    assert upload(files(tmp_path), platform).exit_code == 0
    fewer = copy.deepcopy(EVIDENCE)
    fewer["trust_reports"] = fewer["trust_reports"][:1]
    (tmp_path / "fewer").mkdir()
    result = upload(files(tmp_path / "fewer", fewer), platform)
    assert result.exit_code == 4
    assert "recorded already with other evidence: a release never changes" in result.output


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda d: d["trust_reports"][0]["image"].update(digest="sha256:" + "0" * 64),
            "is about sha256:0000",
        ),
        (lambda d: d["decision"]["subject"].update(context="pr"), "not a release decision"),
        (lambda d: d["trust_reports"][0].update(mode="cluster"), "not release evidence v1"),
    ],
)
def test_evidence_the_platform_would_refuse_is_never_sent(
    tmp_path: Path, platform: str, fake: Fake, change: Any, message: str
) -> None:
    evidence = copy.deepcopy(EVIDENCE)
    change(evidence)
    result = upload(files(tmp_path, evidence), platform)
    assert result.exit_code == 4 and message in result.output, result.output
    assert fake.requests == []


def test_without_the_token_nothing_is_sent(tmp_path: Path, platform: str, fake: Fake) -> None:
    result = upload(files(tmp_path), platform, token=None)
    assert result.exit_code == 4 and "SENTINEL_API_TOKEN" in result.output
    assert fake.requests == []


def test_a_refused_token_is_never_printed(tmp_path: Path, platform: str, fake: Fake) -> None:
    fake.answer = (401, {"detail": f"bad token Bearer {TOKEN}"})
    result = upload(files(tmp_path), platform)
    assert result.exit_code == 4 and "HTTP 401" in result.output
    assert TOKEN not in result.output and "<SENTINEL_API_TOKEN>" in result.output


def test_the_platform_must_record_the_bytes_sent(tmp_path: Path, platform: str, fake: Fake) -> None:
    fake.answer = (201, {"decision_id": EVIDENCE["decision"]["decision_id"], "sha256": "0" * 64})
    result = upload(files(tmp_path), platform)
    assert result.exit_code == 4 and "recorded other bytes than the ones sent" in result.output


def test_files_that_are_not_json_are_an_upload_failure(tmp_path: Path) -> None:
    with pytest.raises(UploadError, match="the decision is not JSON"):
        release_evidence(b"{broken", [])
