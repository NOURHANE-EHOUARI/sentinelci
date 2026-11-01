"""`sentinel upload` (M1, the B1 ingestion API): what it sends, what it never sends, and when it says no.

The platform is a small fake on 127.0.0.1 that answers like `schemas/openapi.yaml` (the B1 contract): every
request body is validated against the contract's `RunCreate`, and the token is checked like `require_writer`.
"""

import hashlib
import json
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.report.upload import RunInfo, UploadError, check_api_url, check_findings

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = yaml.safe_load((ROOT / "schemas" / "openapi.yaml").read_text(encoding="utf-8"))
RUN_CREATE = Draft202012Validator(CONTRACT["components"]["schemas"]["RunCreate"])
TOKEN = "fake-ingestion-token-for-tests-only"  # noqa: S105 (a fake, for the fake platform)
REPO, COMMIT = "NOURHANE-EHOUARI/sentinelci", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
FINDING = json.loads(
    (ROOT / "schemas" / "fixtures" / "finding" / "valid" / "secret-in-config.json").read_text()
)


def findings(*, count: int = 2, **run: Any) -> bytes:
    lines = []
    for index in range(count):
        finding = dict(FINDING, id=hashlib.sha256(str(index).encode()).hexdigest())
        finding["run"] = {"repo": REPO, "commit": COMMIT, "context": "pr"} | run
        lines.append(json.dumps(finding, sort_keys=True))
    return "".join(line + "\n" for line in lines).encode()


class Fake:
    """The platform's state and the requests it saw."""

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.upload_status: int | None = None  # force an answer to the findings upload
        self.redirect_to: str | None = None
        self.lie_about_digest = False


def handler(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _answer(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            fake.requests.append((method, self.path, dict(self.headers), body))
            if fake.redirect_to is not None:
                return self._answer(307, {}, {"Location": fake.redirect_to + self.path})
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                return self._answer(401, {"detail": "a valid ingestion token is required"})
            parts = self.path.strip("/").split("/")
            if method == "POST" and parts == ["api", "v1", "runs"]:
                document = json.loads(body)
                errors = [e.message for e in RUN_CREATE.iter_errors(document)]
                if errors:
                    return self._answer(422, {"detail": [{"msg": errors[0]}]})
                run_id = str(uuid.uuid4())
                fake.runs[run_id] = {"id": run_id, "ref": None, "run_id": None, **document,
                                     "created_at": "2026-11-01T20:00:00Z", "finding_count": 0,
                                     "findings_sha256": None, "findings_uploaded_at": None}  # fmt: skip
                return self._answer(201, fake.runs[run_id])
            if len(parts) == 4 and parts[:3] == ["api", "v1", "runs"] and method == "GET":
                run = fake.runs.get(parts[3])
                return self._answer(200, run) if run else self._answer(404, {"detail": "no such run"})
            if len(parts) == 5 and parts[4] == "findings" and method == "POST":
                run = fake.runs.get(parts[3])
                if run is None:
                    return self._answer(404, {"detail": "no such run"})
                if self.headers.get("Content-Type") != "application/x-ndjson":
                    return self._answer(415, {"detail": "findings are uploaded as application/x-ndjson"})
                if fake.upload_status is not None:
                    return self._answer(fake.upload_status, {"detail": "forced"})
                if run["findings_sha256"] is not None:
                    return self._answer(409, {"detail": "this run's findings are already recorded"})
                digest = hashlib.sha256(body).hexdigest()
                count = len([line for line in body.split(b"\n") if line.strip()])
                run.update(
                    findings_sha256=digest, finding_count=count, findings_uploaded_at="2026-11-01T20:00:01Z"
                )
                reported = "0" * 64 if fake.lie_about_digest else digest
                return self._answer(
                    201, {"run_id": parts[3], "finding_count": count, "findings_sha256": reported}
                )
            return self._answer(404, {"detail": "not found"})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    return Handler


def _serve(fake: Fake) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(fake))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def platform(fake: Fake) -> Iterator[str]:
    yield from _serve(fake)


def run_upload(tmp_path: Path, url: str, data: bytes, *extra: str, token: str | None = TOKEN) -> Any:
    path = tmp_path / "findings.ndjson"
    path.write_bytes(data)
    env = {"SENTINEL_API_TOKEN": token} if token is not None else {}
    args = ["upload", "--findings", str(path), "--api-url", url, "--repo", REPO, "--commit", COMMIT,
            "--context", "pr", *extra]  # fmt: skip
    return CliRunner(env=env).invoke(app, args)


def test_the_run_then_its_findings_exactly_as_written(tmp_path: Path, platform: str, fake: Fake) -> None:
    data = findings()
    result = run_upload(tmp_path, platform, data)
    assert result.exit_code == 0, result.output
    printed = json.loads(result.output)
    assert printed == {"run_id": printed["run_id"], "finding_count": 2, "already_recorded": False,
                       "findings_sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip
    (create, create_path, create_headers, create_body), (post, path, headers, body) = fake.requests
    assert (create, create_path) == ("POST", "/api/v1/runs")
    assert json.loads(create_body) == {"repo": REPO, "commit": COMMIT, "context": "pr"}
    assert (post, path) == ("POST", f"/api/v1/runs/{printed['run_id']}/findings") and body == data
    assert headers["Content-Type"] == "application/x-ndjson"
    assert create_headers["Authorization"] == headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in result.output


def test_without_the_token_variable_nothing_is_sent(tmp_path: Path, platform: str, fake: Fake) -> None:
    result = run_upload(tmp_path, platform, findings(), token=None)
    assert result.exit_code == 4 and "SENTINEL_API_TOKEN is not set" in result.output
    assert "the verdict is unchanged" in result.output and not fake.requests


def test_a_rejected_token_is_an_upload_failure_and_is_never_printed(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    result = run_upload(tmp_path, platform, findings(), token="wrong-token-value")  # noqa: S106 (a fake)
    assert result.exit_code == 4 and "HTTP 401" in result.output
    assert "wrong-token-value" not in result.output and len(fake.requests) == 1


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://sentinel.example.org", True), ("https://sentinel.example.org/base/", True),
        ("http://localhost:8000", True), ("http://127.0.0.1:8000", True), ("http://[::1]:8000", True),
        ("http://sentinel.example.org", False), ("http://10.0.0.5:8000", False), ("ftp://localhost", False),
        ("file:///etc/passwd", False), ("https://user:pw@sentinel.example.org", False),
        ("https://sentinel.example.org/?token=x", False), ("https://sentinel.example.org/#x", False),
        ("sentinel.example.org", False),
    ],
)  # fmt: skip
def test_https_or_the_loopback_only(url: str, ok: bool) -> None:
    if ok:
        assert check_api_url(url) == url.rstrip("/")
    else:
        with pytest.raises(UploadError, match="--api-url"):
            check_api_url(url)


def test_a_redirect_is_refused_and_never_followed(tmp_path: Path, platform: str, fake: Fake) -> None:
    elsewhere = Fake()
    for target in _serve(elsewhere):
        fake.redirect_to = target
        result = run_upload(tmp_path, platform, findings())
        assert result.exit_code == 4 and "redirect" in result.output
        assert not elsewhere.requests, "the token never reaches the redirect target"


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (findings(context="release"), "belongs to another run"),
        (findings(ref="refs/heads/other"), "belongs to another run"),
        (findings(count=1) * 2, "listed twice"),
        (b"not json\n", "invalid JSON"),
        (b'{"id": "x"}\n', "sha256 fingerprint"),
    ],
    ids=["another-context", "another-ref", "duplicate", "not-json", "not-a-finding"],
)
def test_findings_the_platform_would_refuse_never_create_a_run(
    tmp_path: Path, platform: str, fake: Fake, data: bytes, reason: str
) -> None:
    result = run_upload(tmp_path, platform, data, "--ref", "refs/pull/1/head")
    assert result.exit_code == 4 and reason in result.output, result.output
    assert not fake.requests


def test_a_failed_upload_names_the_run_to_resume_and_resume_finishes_it(
    tmp_path: Path, platform: str, fake: Fake
) -> None:
    data = findings()
    fake.upload_status = 503
    failed = run_upload(tmp_path, platform, data)
    assert failed.exit_code == 4 and "HTTP 503" in failed.output
    (run_id,) = fake.runs
    assert run_id in failed.output
    fake.upload_status = None
    resumed = run_upload(tmp_path, platform, data, "--resume", run_id)
    assert resumed.exit_code == 0 and json.loads(resumed.output)["run_id"] == run_id
    assert len(fake.runs) == 1, "no second run"
    again = run_upload(tmp_path, platform, data, "--resume", run_id)
    assert again.exit_code == 0 and json.loads(again.output)["already_recorded"] is True
    other = run_upload(tmp_path, platform, findings(count=1), "--resume", run_id)
    assert other.exit_code == 4 and "already holds other findings" in other.output


def test_resume_refuses_another_run(tmp_path: Path, platform: str, fake: Fake) -> None:
    assert run_upload(tmp_path, platform, findings()).exit_code == 0
    (run_id,) = fake.runs
    result = run_upload(tmp_path, platform, findings(context="release"), "--context", "release")
    assert result.exit_code == 0
    result = run_upload(tmp_path, platform, findings(), "--resume", next(r for r in fake.runs if r != run_id))
    assert result.exit_code == 4 and "is not this run" in result.output
    assert run_upload(tmp_path, platform, findings(), "--resume", "not-a-uuid").exit_code == 4


def test_the_platform_must_record_the_bytes_sent(tmp_path: Path, platform: str, fake: Fake) -> None:
    fake.lie_about_digest = True
    result = run_upload(tmp_path, platform, findings())
    assert result.exit_code == 4 and "recorded other bytes" in result.output


def test_an_unreachable_platform_is_an_upload_failure(tmp_path: Path) -> None:
    result = run_upload(tmp_path, "http://127.0.0.1:9", findings())
    assert result.exit_code == 4 and "could not be reached" in result.output


def test_an_empty_run_is_uploaded_as_such() -> None:
    assert check_findings(b"", RunInfo(REPO, COMMIT, "pr")) == 0
