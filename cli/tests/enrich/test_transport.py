"""How the fetchers reach the feeds (enrich/transport.py): HTTPS to three hosts, no redirect, bounded.

The live transport is tested with a fake opener (no network), except the redirect refusal, which runs against
a local HTTP server so urllib's own redirect machinery is exercised.
"""

import base64
import http.client
import http.server
import io
import json
import ssl
import threading
import time
import urllib.error
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.enrich import transport as tr
from sentinelci.enrich.transport import HttpTransport, RecordingTransport, ReplayTransport, TransportError

URL = "https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc"


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, chunk: int | None = None) -> None:
        self.stream, self.status, self.chunk = io.BytesIO(body), status, chunk

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(min(size, self.chunk) if self.chunk else size)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeOpener:
    """Answers each open() with the next item: a FakeResponse, or an exception to raise."""

    def __init__(self, *answers: Any) -> None:
        self.answers, self.calls = list(answers), []

    def open(self, request: Any, timeout: float) -> Any:
        self.calls.append((request.full_url, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def http_transport(*answers: Any, timeout: float = 30.0) -> tuple[HttpTransport, FakeOpener, list[float]]:
    sleeps: list[float] = []
    transport = HttpTransport(timeout=timeout, sleep=sleeps.append)
    opener = FakeOpener(*answers)
    transport._opener = opener  # type: ignore[assignment]
    return transport, opener, sleeps


# ---------------------------------------------------------------- where requests may go


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://api.osv.dev/v1/vulns/X", True),
        ("https://api.osv.dev:443/v1/vulns/X", True),
        ("https://api.osv.dev:8443/v1/vulns/X", False),
        ("https://api.osv.dev:99999/v1/vulns/X", False),
        ("http://api.osv.dev/v1/vulns/X", False),
        ("https://api.osv.dev.evil.example/x", False),
        ("https://user@evil.example/x", False),
        ("file:///etc/passwd", False),
    ],
)
def test_only_https_to_the_three_feeds(url: str, ok: bool) -> None:
    assert tr.allowed(url) is ok
    if not ok:
        with pytest.raises(TransportError, match="not an allowed feed"):
            HttpTransport().request("GET", url)


@pytest.fixture
def redirecting_server() -> Iterator[str]:
    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def test_a_redirect_is_never_followed(redirecting_server: str) -> None:
    # The allow-list checks the first URL; a redirect could leave it (or HTTPS). The opener refuses them all.
    with pytest.raises(TransportError, match="redirect"):
        HttpTransport()._opener.open(redirecting_server, timeout=5)


# ---------------------------------------------------------------- bounded: size, time, retries


def test_the_size_cap_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tr, "MAX_RESPONSE_BYTES", 100)
    transport, _, _ = http_transport(FakeResponse(b"x" * 100, chunk=7))
    assert transport.request("GET", URL) == (200, b"x" * 100)
    transport, _, _ = http_transport(FakeResponse(b"x" * 101, chunk=7), FakeResponse(b"x" * 101))
    with pytest.raises(TransportError, match="larger than 100 bytes"):
        transport.request("GET", URL)


def test_the_timeout_is_given_to_the_socket_and_bounds_the_whole_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, opener, _ = http_transport(FakeResponse(b"{}"), timeout=7.5)
    transport.request("GET", URL)
    assert opener.calls == [(URL, 7.5)]
    clock = iter(range(0, 1000, 4))  # each read takes 4 s: a slow drip
    monkeypatch.setattr(tr.time, "monotonic", lambda: next(clock))
    transport, opener, sleeps = http_transport(
        FakeResponse(b"x" * 64, chunk=8), FakeResponse(b"x" * 64, chunk=8), timeout=10
    )
    with pytest.raises(TransportError, match="time limit"):
        transport.request("GET", URL)
    assert len(opener.calls) == 2 and sleeps == [1.0], "a missed deadline is transient: retried once"


@pytest.fixture
def dripping_server() -> Iterator[str]:
    """Promises 10,000 bytes, then sends 8 every 0.5 s: never slow enough for one socket timeout."""

    class Drip(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "10000")
            self.end_headers()
            try:
                for _ in range(20):  # 10 s at most, so a regression fails in seconds, not minutes
                    self.wfile.write(b"x" * 8)
                    self.wfile.flush()
                    time.sleep(0.5)
            except OSError:
                pass

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def test_the_deadline_holds_on_a_real_socket(dripping_server: str) -> None:
    """#18 re-review: read(64 KiB) waited for 64 KiB, so a 2 s timeout failed only after 40 s."""
    start = time.monotonic()
    with pytest.raises(TransportError, match="time limit"):
        HttpTransport(timeout=2)._once("GET", dripping_server, None)
    assert time.monotonic() - start < 5


def test_the_whole_run_has_a_time_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """#18 nit: OSV is asked once per id; all requests together stop at the run budget."""
    now = [0.0]
    monkeypatch.setattr(tr.time, "monotonic", lambda: now[0])
    transport, opener, _ = http_transport(*(FakeResponse(b"{}") for _ in range(3)), timeout=30)
    transport.budget = 50
    transport.request("GET", URL)  # t = 0: the budget starts
    now[0] = 40.0
    transport.request("GET", URL)  # 10 s left: the socket gets 10, not 30
    assert [timeout for _, timeout in opener.calls] == [30, 10]
    now[0] = 50.0
    with pytest.raises(TransportError, match="budget is spent"):
        transport.request("GET", URL)
    assert len(opener.calls) == 2, "no request once the budget is spent, and no retry"


@pytest.mark.parametrize("budget", [0, -1, float("inf"), float("nan")])
def test_the_budget_must_be_sensible(budget: float) -> None:
    with pytest.raises(ValueError, match="budget"):
        HttpTransport(budget=budget)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), 301])
def test_the_timeout_must_be_sensible(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        HttpTransport(timeout=timeout)


@pytest.mark.parametrize(
    ("error", "retried"),
    [
        (http.client.IncompleteRead(b"partial"), True),
        (TimeoutError("timed out"), True),
        (ConnectionResetError("reset"), True),
        (urllib.error.URLError(TimeoutError("timed out")), True),
        (urllib.error.URLError(ConnectionResetError("reset")), True),
        (http.client.BadStatusLine("garbage"), False),
        (urllib.error.URLError("no route"), False),
        (urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed")), False),
        (ssl.SSLError("handshake failure"), False),
        (TransportError("answered a redirect (302): not followed"), False),
        (ValueError("bad url"), False),
    ],
    ids=lambda e: type(e).__name__ if isinstance(e, BaseException) else str(e),
)
def test_network_and_protocol_errors_are_transport_errors(error: BaseException, retried: bool) -> None:
    """Only what a second try may cure is retried (#18 nit): never a refused redirect or a TLS failure."""
    transport, _, sleeps = http_transport(error, error)
    with pytest.raises(TransportError):
        transport.request("GET", URL)
    assert sleeps == ([1.0] if retried else [])


def test_an_error_status_is_returned_with_its_body() -> None:
    error = urllib.error.HTTPError(
        URL, 404, "Not Found", http.client.HTTPMessage(), io.BytesIO(b'{"code":5}')
    )
    transport, _, sleeps = http_transport(error)
    assert transport.request("GET", URL) == (404, b'{"code":5}')
    assert sleeps == [], "a 404 is an answer, not a transient failure"


class BrokenBody(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        raise ConnectionResetError("reset while reading the error body")

    read1 = read


def test_an_error_status_whose_body_cannot_be_read_is_a_transport_error() -> None:
    def error() -> urllib.error.HTTPError:
        return urllib.error.HTTPError(URL, 503, "Unavailable", http.client.HTTPMessage(), BrokenBody())

    transport, _, sleeps = http_transport(error(), error())
    with pytest.raises(TransportError, match="reset while reading"):
        transport.request("GET", URL)
    assert sleeps == [1.0], "retried once, like any transport failure"


def test_one_transient_failure_is_retried() -> None:
    transport, opener, sleeps = http_transport(TimeoutError("flake"), FakeResponse(b"{}"))
    assert transport.request("GET", URL) == (200, b"{}")
    unavailable = urllib.error.HTTPError(URL, 503, "Busy", http.client.HTTPMessage(), io.BytesIO(b""))
    transport, opener, sleeps = http_transport(unavailable, FakeResponse(b"{}"))
    assert transport.request("GET", URL) == (200, b"{}")
    assert len(opener.calls) == 2 and sleeps == [1.0]
    transport, opener, _ = http_transport(unavailable, unavailable)
    assert transport.request("GET", URL)[0] == 503, "only once"


# ---------------------------------------------------------------- recordings


class Answers:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body, self.status = body, status

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        return self.status, self.body


def test_recordings_keep_the_exact_bytes(tmp_path: Path) -> None:
    raw = b'{"x": 1}\xff\xfe not UTF-8'
    RecordingTransport(Answers(raw), tmp_path).request("GET", URL)
    assert ReplayTransport(tmp_path).request("GET", URL) == (200, raw)


@pytest.mark.parametrize(
    "edit",
    [
        lambda r: r.update(response_base64=base64.b64encode(b"forged").decode()),
        lambda r: r.update(response_sha256="0" * 64),
        lambda r: r.update(url="https://api.osv.dev/v1/vulns/OTHER"),
        lambda r: r.update(status="200"),
        lambda r: r.pop("format"),
        lambda r: r.update(response_base64="not base64!"),
    ],
    ids=["forged-body", "wrong-digest", "another-request", "status-string", "no-format", "bad-base64"],
)
def test_an_altered_recording_is_an_outage(tmp_path: Path, edit: Any) -> None:
    RecordingTransport(Answers(b"{}"), tmp_path).request("GET", URL)
    [path] = tmp_path.glob("*.json")
    record = json.loads(path.read_text(encoding="utf-8"))
    edit(record)
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(TransportError):
        ReplayTransport(tmp_path).request("GET", URL)


def test_record_must_be_a_directory(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(TransportError, match="not a directory"):
        RecordingTransport(Answers(b"{}"), tmp_path / "file")


# ---------------------------------------------------------------- the command fails closed


def run_snapshot(tmp_path: Path, *extra: str) -> tuple[int, str]:
    findings = tmp_path / "findings.ndjson"
    findings.write_text("", encoding="utf-8")
    args = ["snapshot", "--findings", str(findings), "--out", str(tmp_path / "snapshot.json"), *extra]
    result = CliRunner().invoke(app, args)
    return result.exit_code, result.output


@pytest.mark.parametrize("timeout", ["0", "-1", "inf", "nan", "1000"])
def test_cli_refuses_a_senseless_timeout(tmp_path: Path, timeout: str) -> None:
    code, _ = run_snapshot(tmp_path, "--timeout", timeout)
    assert code == 2
    assert not (tmp_path / "snapshot.json").exists()


def test_cli_record_pointing_at_a_file_exits_3(tmp_path: Path) -> None:
    (tmp_path / "rec").write_text("x", encoding="utf-8")
    code, out = run_snapshot(tmp_path, "--record", str(tmp_path / "rec"))
    assert code == 3, out


def test_cli_exits_3_on_anything_unexpected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinelci.cli as cli

    def broken(*args: object) -> None:
        raise RuntimeError("a bug")

    monkeypatch.setattr(cli, "build_snapshot", broken)
    code, out = run_snapshot(tmp_path, "--offline", str(tmp_path))
    assert code == 3
    assert "unexpected RuntimeError" in out
    assert not (tmp_path / "snapshot.json").exists()
