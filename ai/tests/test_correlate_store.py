"""Storing a run's correlation on the platform (`sentinel-ai correlate`, task A7, B1's API 1.3.0).

The platform is a small fake on 127.0.0.1 that answers as agreed with B1 (#47 review thread): it serves a
run's recorded findings byte for byte; it keeps a posted Correlation v1 document byte for byte, validated
against `schemas/correlation.v1.json`, as the version named by the sha256 of its bytes; the same bytes again
are answered 409 with that version; a document whose `findings_sha256` is not the run's is refused. It
checks the bearer token like `require_writer`.
"""

import hashlib
import json
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from typer.testing import CliRunner

from sentinel_ai.cli import app
from sentinel_ai.correlate import correlate_run
from sentinel_ai.correlate.store import StoreError, correlate_and_store, document_bytes, read_findings, store
from sentinelci.report.upload import Platform

from .test_correlate import FINDINGS

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = {
    name: json.loads((ROOT / "schemas" / name).read_text("utf-8"))
    for name in ("correlation.v1.json", "root-cause-group.v1.json")
}
CORRELATION = Draft202012Validator(
    CONTRACTS["correlation.v1.json"],
    registry=Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in CONTRACTS.values()),
)
TOKEN = "fake-correlator-token-for-tests-only"  # noqa: S105 (a fake, for the fake platform)
DATA = "".join(json.dumps(finding) + "\n" for finding in FINDINGS).encode()


@dataclass
class Fake:
    runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: dict[str, bytes] = field(default_factory=dict)
    versions: dict[str, list[tuple[str, bytes]]] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)
    serve_other_findings: bool = False
    answer_sha256: str | None = None  # a platform that names another version than the bytes' own
    refuse_409: str | None = None  # a 409 that names no version: B1's answer for a run without findings
    echo_token: bool = False

    def record(self, data: bytes | None = DATA) -> str:
        run_id = str(uuid.uuid4())
        self.runs[run_id] = {
            "id": run_id,
            "findings_sha256": hashlib.sha256(data).hexdigest() if data else None,
        }
        if data:
            self.findings[run_id] = data
        return run_id


def handler(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _answer(self, status: int, body: Any, content_type: str = "application/json") -> None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            fake.requests.append((method, self.path))
            authorization = self.headers.get("Authorization", "")
            if authorization != f"Bearer {TOKEN}":
                said = f"rejected {authorization}" if fake.echo_token else "a valid token is required"
                return self._answer(401, {"detail": said})
            parts = self.path.strip("/").split("/")
            run = fake.runs.get(parts[3]) if len(parts) >= 4 and parts[:3] == ["api", "v1", "runs"] else None
            if run is None:
                return self._answer(404, {"detail": "no such run"})
            if method == "GET" and len(parts) == 4:
                return self._answer(200, run)
            if method == "GET" and parts[4:] == ["findings"]:
                data = fake.findings[run["id"]] + (b"\n" if fake.serve_other_findings else b"")
                return self._answer(200, data, "application/x-ndjson")
            if method == "POST" and parts[4:] == ["correlations"]:
                if self.headers.get("Content-Type") != "application/json":
                    return self._answer(415, {"detail": "a correlation is application/json"})
                document = json.loads(body)
                errors = [e.message for e in CORRELATION.iter_errors(document)]
                if errors:
                    return self._answer(422, {"detail": [{"msg": errors[0]}]})
                if run["findings_sha256"] is None or document["findings_sha256"] != run["findings_sha256"]:
                    return self._answer(422, {"detail": "the correlation is not about this run's findings"})
                if fake.refuse_409:
                    return self._answer(409, {"detail": fake.refuse_409})
                version = hashlib.sha256(body).hexdigest()
                kept = fake.versions.setdefault(run["id"], [])
                if any(sha == version for sha, _ in kept):
                    return self._answer(
                        409, {"detail": "already recorded", "correlation": {"sha256": version}}
                    )
                kept.append((version, body))
                return self._answer(201, {"run_id": run["id"], "sha256": fake.answer_sha256 or version})
            return self._answer(404, {"detail": "not found"})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    return Handler


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def url(fake: Fake) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(fake))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def platform(url: str) -> Platform:
    return Platform(base_url=url, token=TOKEN)


# ---------------------------------------------------------------- the document


def test_the_document_is_canonical_bytes_of_a_valid_correlation() -> None:
    data = document_bytes(correlate_run(DATA))
    assert data == document_bytes(correlate_run(DATA)), "the same correlation, the same bytes"
    document = json.loads(data)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert data == canonical.encode("utf-8") + b"\n", "keys sorted, no white space, UTF-8, one line feed"
    assert not [e.message for e in CORRELATION.iter_errors(document)]
    assert document["findings_sha256"] == hashlib.sha256(DATA).hexdigest()


# ---------------------------------------------------------------- storing


def test_a_run_s_correlation_is_stored_once_and_confirmed_after(fake: Fake, url: str) -> None:
    run_id = fake.record()
    stored = correlate_and_store(platform(url), run_id)
    ((version, kept),) = fake.versions[run_id]
    assert kept == document_bytes(correlate_run(DATA)), "the platform holds the bytes sent"
    assert stored.sha256 == version == hashlib.sha256(kept).hexdigest() and not stored.already_recorded
    assert stored.stages == ("dedup", "structural") and stored.skipped == () and stored.groups > 0
    again = correlate_and_store(platform(url), run_id)
    assert again.already_recorded and again.sha256 == version, "stages 1 and 2: the same version"
    assert len(fake.versions[run_id]) == 1


def test_another_correlator_setting_is_another_version_never_an_overwrite(fake: Fake, url: str) -> None:
    run_id = fake.record()
    first = correlate_and_store(platform(url), run_id)
    second = correlate_and_store(platform(url), run_id, structural=False)
    assert first.sha256 != second.sha256 and second.stages == ("dedup",)
    assert [sha for sha, _ in fake.versions[run_id]] == [first.sha256, second.sha256]


def test_a_run_without_recorded_findings_is_not_correlated(fake: Fake, url: str) -> None:
    run_id = fake.record(None)
    with pytest.raises(StoreError, match="no findings recorded yet"):
        correlate_and_store(platform(url), run_id)
    assert fake.requests == [("GET", f"/api/v1/runs/{run_id}")], "nothing else asked, nothing posted"


def test_findings_other_than_the_recorded_ones_are_refused(fake: Fake, url: str) -> None:
    run_id = fake.record()
    fake.serve_other_findings = True
    with pytest.raises(StoreError, match=r"other findings .* than the ones it recorded"):
        read_findings(platform(url), run_id)
    assert not fake.versions


def test_a_correlation_of_other_findings_is_never_sent(fake: Fake, url: str) -> None:
    run_id = fake.record()
    other = correlate_run(DATA + DATA[: DATA.index(b"\n") + 1].replace(b"lodash", b"lodash2"))
    with pytest.raises(StoreError, match="not computed from this run's findings"):
        store(platform(url), run_id, other, findings=DATA)
    assert not any(method == "POST" for method, _ in fake.requests)


def test_a_platform_that_names_another_version_confirms_nothing(fake: Fake, url: str) -> None:
    run_id = fake.record()
    fake.answer_sha256 = "0" * 64
    with pytest.raises(StoreError, match="not the sha256 of the bytes sent"):
        correlate_and_store(platform(url), run_id)


def test_a_refusal_is_reported_with_the_platforms_words(fake: Fake, url: str) -> None:
    run_id = fake.record()
    fake.runs[run_id]["findings_sha256"] = "1" * 64  # the platform's record and the bytes disagree
    fake.findings[run_id] = DATA
    with pytest.raises(StoreError, match="other findings"):
        correlate_and_store(platform(url), run_id)
    correlation = correlate_run(DATA)
    fake.runs[run_id]["findings_sha256"] = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(StoreError, match='HTTP 422, the platform says "the correlation is not about'):
        store(platform(url), run_id, correlation, findings=DATA)


def test_a_409_that_names_no_version_is_a_refusal_in_the_platforms_words(fake: Fake, url: str) -> None:
    run_id = fake.record()
    fake.refuse_409 = "no findings recorded for this run yet: a correlation follows the upload"
    with pytest.raises(
        StoreError, match="HTTP 409, the platform says 'no findings recorded for this run yet"
    ):
        correlate_and_store(platform(url), run_id)


@pytest.mark.parametrize("run_id", ["latest", "../runs", "1" * 36])
def test_a_run_id_is_checked_before_any_request(fake: Fake, url: str, run_id: str) -> None:
    with pytest.raises(StoreError, match="is not a run id"):
        read_findings(platform(url), run_id)
    assert not fake.requests


# ---------------------------------------------------------------- the command


def invoke(url: str, run_id: str, *extra: str, token: str | None = TOKEN) -> Any:
    env = {"SENTINEL_API_TOKEN": token} if token is not None else {}
    return CliRunner(env=env).invoke(app, ["correlate", "--run", run_id, "--api-url", url, *extra])


def test_the_command_prints_the_version_and_exits_0(fake: Fake, url: str) -> None:
    run_id = fake.record()
    done = invoke(url, run_id)
    assert done.exit_code == 0, done.output
    printed = json.loads(done.stdout)
    assert printed == {
        "run_id": run_id, "sha256": fake.versions[run_id][0][0], "groups": printed["groups"],
        "stages": ["dedup", "structural"], "skipped": [], "already_recorded": False,
    }  # fmt: skip
    assert json.loads(invoke(url, run_id).stdout)["already_recorded"] is True


def test_the_command_exits_4_and_never_prints_the_token(fake: Fake, url: str) -> None:
    run_id = fake.record()
    fake.echo_token = True
    leaked = "fake-token-that-the-platform-echoes"
    done = invoke(url, run_id, token=leaked)
    assert done.exit_code == 4 and "was not stored" in done.output
    assert "fake-token-that" not in done.output and "<SENTINEL_API_TOKEN>" in done.output
    assert invoke(url, run_id, token=None).exit_code == 4, "no token, nothing sent"
    assert invoke("http://example.com", run_id).exit_code == 4, "plain http only on the loopback"
