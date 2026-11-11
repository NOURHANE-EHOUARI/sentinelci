"""`sentinel upload-remediation` (tasks A6 and A8): a proposal and its verification result, as Remediation
attempt v1, to a fake platform that answers like `POST /api/v1/remediations`."""

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
from sentinelci.contracts.remediation import RemediationAttempt

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "remediation-attempt" / "valid"
ATTEMPT = json.loads((VALID / "kubernetes-verified.json").read_text())
TOKEN = "fake-ingestion-token-for-tests-only"  # noqa: S105 (a fake, for the fake platform)


class Fake:
    def __init__(self) -> None:
        self.recorded: dict[str, bytes] = {}
        self.bodies: list[bytes] = []

    def post(self, headers: dict[str, str], body: bytes) -> tuple[int, Any]:
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, {"detail": "bad token"}
        attempt = RemediationAttempt.model_validate_json(body)
        proposal_id = attempt.proposal.proposal_id
        if proposal_id in self.recorded:
            kept = hashlib.sha256(self.recorded[proposal_id]).hexdigest()
            return 409, {
                "detail": "recorded already",
                "remediation": {"proposal_id": proposal_id, "sha256": kept},
            }
        self.recorded[proposal_id] = body
        return 201, {"proposal_id": proposal_id, "sha256": hashlib.sha256(body).hexdigest()}


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def platform(fake: Fake) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            fake.bodies.append(body)
            status, answer = fake.post(dict(self.headers.items()), body)
            data = json.dumps(answer).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def upload(tmp_path: Path, url: str, attempt: dict[str, Any] = ATTEMPT) -> Result:
    (tmp_path / "proposal.json").write_text(json.dumps(attempt["proposal"]))
    (tmp_path / "result.json").write_text(json.dumps(attempt["result"]))
    return CliRunner(env={"SENTINEL_API_TOKEN": TOKEN}).invoke(app, [
        "upload-remediation", "--proposal", str(tmp_path / "proposal.json"), "--result",
        str(tmp_path / "result.json"), "--repo", attempt["repo"], "--api-url", url,
    ])  # fmt: skip


def test_the_attempt_is_recorded_once_and_again_counts_as_uploaded(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    first = upload(tmp_path, platform)
    assert first.exit_code == 0, first.output
    assert json.loads(first.output) == {
        "proposal_id": ATTEMPT["proposal"]["proposal_id"], "outcome": "VERIFIED",
        "sha256": hashlib.sha256(fake.bodies[0]).hexdigest(), "already_recorded": False,
    }  # fmt: skip
    again = upload(tmp_path, platform)
    assert again.exit_code == 0 and json.loads(again.output)["already_recorded"] is True
    assert fake.bodies[1] == fake.bodies[0], "the same files give the same bytes"


def test_another_document_for_a_recorded_proposal_is_refused(tmp_path: Path, platform: str) -> None:
    assert upload(tmp_path, platform).exit_code == 0
    other = copy.deepcopy(ATTEMPT)
    other["result"]["pull_request"] = 82
    result = upload(tmp_path, platform, other)
    assert result.exit_code == 4 and "recorded already with another document" in result.output


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["result"].update(tests_ok=False), "VERIFIED needs a build, passing tests"),
        (lambda d: d["result"].update(attempt=2), "about attempt 2, not 1"),
        (lambda d: d.update(repo="not a repo"), "repo"),
    ],
)
def test_an_attempt_the_platform_would_refuse_is_never_sent(
    tmp_path: Path, platform: str, fake: Fake, change: Any, message: str
) -> None:
    attempt = copy.deepcopy(ATTEMPT)
    change(attempt)
    result = upload(tmp_path, platform, attempt)
    assert result.exit_code == 4 and message in result.output, result.output
    assert fake.bodies == []
