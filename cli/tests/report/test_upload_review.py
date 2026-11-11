"""Review tests for `sentinel upload` (#50): hostile platforms. Raw sockets, 127.0.0.1 only."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from sentinelci.report import upload as up

from .test_upload import COMMIT, REPO, TOKEN, findings, run_upload

RUN = up.RunInfo(REPO, COMMIT, "pr")
Answer = Callable[[bytes], bytes | None]  # request -> raw response (None: never answer)


def _response(status: str, body: bytes) -> bytes:
    head = f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    return (head + "Connection: close\r\n\r\n").encode() + body


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and (chunk := conn.recv(65536)):
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = next(
        (int(x.split(b":")[1]) for x in head.split(b"\r\n") if x.lower().startswith(b"content-length")), 0
    )
    while len(body) < length and (chunk := conn.recv(65536)):
        body += chunk
    return head + b"\r\n\r\n" + body


@pytest.fixture
def raw() -> Iterator[Callable[[Answer], tuple[str, list[bytes]]]]:
    servers: list[socket.socket] = []

    def start(answer: Answer) -> tuple[str, list[bytes]]:
        seen: list[bytes] = []
        server = socket.create_server(("127.0.0.1", 0))
        servers.append(server)

        def serve() -> None:
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                request = _read_request(conn)
                seen.append(request)
                reply = answer(request)
                if reply is not None:
                    conn.sendall(reply)
                    conn.close()

        threading.Thread(target=serve, daemon=True).start()
        return f"http://127.0.0.1:{server.getsockname()[1]}", seen

    yield start
    for server in servers:
        server.close()


def _honest(lie_count: bool = False, pad: int = 0) -> Answer:
    run_id = str(uuid.uuid4())

    def answer(request: bytes) -> bytes:
        body = request.partition(b"\r\n\r\n")[2]
        if request.startswith(b"POST /api/v1/runs "):
            # Valid JSON even when cut at the limit: the padding is trailing white space.
            return _response("201 Created", json.dumps({"id": run_id}).encode() + b" " * pad)
        count = len([line for line in body.split(b"\n") if line.strip()]) + (1 if lie_count else 0)
        result = {
            "run_id": run_id,
            "finding_count": count,
            "findings_sha256": hashlib.sha256(body).hexdigest(),
        }
        return _response("201 Created", json.dumps(result).encode())

    return answer


# Pass on the head; each kills one mutant that survived the PR's tests.


def test_the_platform_must_record_the_number_of_findings_sent(
    raw: Callable[[Answer], tuple[str, list[bytes]]],
) -> None:
    url, _ = raw(_honest(lie_count=True))
    with pytest.raises(up.UploadError, match="other bytes"):
        up.upload(findings(), RUN, up.Platform(url, TOKEN))


def test_an_oversized_answer_is_not_parsed(raw: Callable[[Answer], tuple[str, list[bytes]]]) -> None:
    url, seen = raw(_honest(pad=up.MAX_RESPONSE_BYTES))
    with pytest.raises(up.UploadError, match="creating the run failed"):
        up.upload(findings(), RUN, up.Platform(url, TOKEN))
    assert len(seen) == 1, "no findings sent after an answer that was too large"


def test_a_platform_that_never_answers_times_out(
    raw: Callable[[Answer], tuple[str, list[bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(up, "TIMEOUT_S", 0.5)
    url, _ = raw(lambda request: None)
    outcome: list[str] = []

    def call() -> None:
        try:
            up.upload(findings(), RUN, up.Platform(url, TOKEN))
        except up.UploadError as exc:
            outcome.append(str(exc))

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(10)
    assert outcome and "could not be reached" in outcome[0]


# Fail on the head (exit 1, a traceback, the token in clear text); pass with the fixes I propose.


@pytest.mark.parametrize(
    "reply",
    [b"garbage\r\n\r\n", b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
     b"HTTP/1.1 201 Created\r\n" + b"".join(b"X-%d: y\r\n" % i for i in range(150)) + b"\r\n"],
    ids=["bad-status-line", "bad-chunk", "too-many-headers"],
)  # fmt: skip
def test_a_malformed_answer_is_exit_4(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], reply: bytes
) -> None:
    url, _ = raw(lambda request: reply)
    result = run_upload(tmp_path, url, findings())
    assert result.exit_code == 4 and "the verdict is unchanged" in result.output, result.output


@pytest.mark.parametrize("url", ["http://localhost:abc", "https://" + "a" * 70 + ".example.org"])
def test_an_unusable_url_is_exit_4(tmp_path: Path, url: str) -> None:
    assert run_upload(tmp_path, url, findings()).exit_code == 4


def test_a_token_a_header_cannot_carry_is_exit_4_and_not_printed(tmp_path: Path) -> None:
    token = "fake-token-part-one\nfake-token-part-two"  # noqa: S105 (a fake)
    result = run_upload(tmp_path, "http://127.0.0.1:9", findings(), token=token)
    assert result.exit_code == 4 and "fake-token-part" not in result.output, result.output


def test_a_loopback_platform_is_never_reached_through_a_proxy(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, _ = raw(_honest())
    proxy, through_proxy = raw(lambda request: _response("502 Bad Gateway", b"{}"))
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("http_proxy", proxy)
    result = run_upload(tmp_path, url.replace("127.0.0.1", "localhost"), findings())
    assert not through_proxy, "the bearer token went to the proxy in clear text"
    assert result.exit_code == 0, result.output


def test_a_slow_drip_answer_hits_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, "TIMEOUT_S", 1.0)
    monkeypatch.setattr(up, "DEADLINE_S", 2.0, raising=False)
    body = json.dumps({"id": str(uuid.uuid4())}).encode()
    server = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:  # the headers at once, then one byte every 0.25 s: 10 s in all
        conn, _ = server.accept()
        _read_request(conn)
        conn.sendall(_response("201 Created", body)[: -len(body)])
        for byte in body:
            time.sleep(0.25)
            conn.sendall(bytes([byte]))
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    start = time.monotonic()
    with pytest.raises(up.UploadError):
        up.Platform(f"http://127.0.0.1:{server.getsockname()[1]}", TOKEN).create_run(RUN)
    assert time.monotonic() - start < 4
    server.close()


# Added with the fixes.


def test_the_deadline_covers_slow_headers_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(up, "TIMEOUT_S", 1.0)
    monkeypatch.setattr(up, "DEADLINE_S", 2.0)
    server = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:  # a status line, then one header every 0.25 s: 10 s in all
        conn, _ = server.accept()
        _read_request(conn)
        try:
            conn.sendall(b"HTTP/1.1 201 Created\r\n")
            for index in range(40):
                time.sleep(0.25)
                conn.sendall(b"X-Drip-%d: y\r\n" % index)
        except OSError:
            pass
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    start = time.monotonic()
    with pytest.raises(up.UploadError, match="did not answer within 2 s"):
        up.Platform(f"http://127.0.0.1:{server.getsockname()[1]}", TOKEN).create_run(RUN)
    assert time.monotonic() - start < 4
    server.close()


@pytest.mark.parametrize(
    "url",
    ["http://local\nhost:8000", "http://localhost\t.evil.com", "http://localhost :8000", "https://x.org\x7f"],
)
def test_white_space_or_control_characters_in_the_url_are_refused(url: str) -> None:
    with pytest.raises(up.UploadError, match="white space or control characters"):
        up.check_api_url(url)


@pytest.mark.parametrize(
    "token",
    ["fake-token-" + chr(0xE9), "fake token", "fake-token" + chr(7), "fake-" + chr(0x442) + "oken"],
    ids=["latin-1", "space", "control", "cyrillic"],
)
def test_a_token_that_is_not_visible_ascii_is_refused_and_not_printed(tmp_path: Path, token: str) -> None:
    result = run_upload(tmp_path, "http://127.0.0.1:9", findings(), token=token)
    assert result.exit_code == 4 and "SENTINEL_API_TOKEN holds" in result.output, result.output
    assert token not in result.output and "fake" not in result.output


def test_the_platform_object_never_shows_the_token() -> None:
    assert TOKEN not in repr(up.Platform("https://platform.example.com", TOKEN))
    assert TOKEN not in str(up.Platform("https://platform.example.com", TOKEN))


def test_the_platforms_own_words_are_quoted_without_control_characters(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]]
) -> None:
    detail = 'fine\n{"run_id": "fake", "already_recorded": true}\x1b[32m'
    url, _ = raw(
        lambda request: _response("500 Internal Server Error", json.dumps({"detail": detail}).encode())
    )
    result = run_upload(tmp_path, url, findings())
    assert result.exit_code == 4 and "\x1b" not in result.output
    assert 'HTTP 500, the platform says \'fine{"run_id": "fake", "already_recorded": true}[32m\'' in (
        result.output
    )


def test_findings_over_the_upload_limit_say_resume_will_not_help(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]]
) -> None:
    run_id = str(uuid.uuid4())

    def answer(request: bytes) -> bytes:
        if request.startswith(b"POST /api/v1/runs "):
            return _response("201 Created", json.dumps({"id": run_id}).encode())
        return _response("413 Content Too Large", b'{"detail": "too large"}')

    url, _ = raw(answer)
    result = run_upload(tmp_path, url, findings())
    assert result.exit_code == 4 and f"run {run_id} stays empty" in result.output
    assert "--resume will not help" in result.output


@pytest.mark.parametrize("count", ["many", 3, None])
def test_an_already_recorded_run_must_hold_as_many_findings(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], count: object
) -> None:
    data = findings()  # two findings
    run_id = str(uuid.uuid4())
    recorded = {
        "repo": REPO,
        "commit": COMMIT,
        "context": "pr",
        "findings_sha256": hashlib.sha256(data).hexdigest(),
    }
    if count is not None:
        recorded["finding_count"] = count
    url, _ = raw(lambda request: _response("200 OK", json.dumps(recorded).encode()))
    result = run_upload(tmp_path, url, data, "--resume", run_id)
    assert result.exit_code == 4 and "count differs" in result.output, result.output


def test_https_still_goes_through_the_jobs_proxy_which_sees_only_a_connect(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy, seen = raw(lambda request: _response("502 Bad Gateway", b"{}"))
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("https_proxy", proxy)
    result = run_upload(tmp_path, "https://platform.example.com", findings())
    assert result.exit_code == 4
    assert seen and seen[0].startswith(b"CONNECT platform.example.com:443 ")
    assert b"Authorization" not in seen[0] and TOKEN.encode() not in b"".join(seen)


def test_an_unexpected_error_is_exit_4_with_its_type_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError(f"something went wrong with {TOKEN}")

    monkeypatch.setattr("sentinelci.cli.upload", broken)
    result = run_upload(tmp_path, "http://127.0.0.1:9", findings())
    assert result.exit_code == 4 and "unexpected RuntimeError" in result.output, result.output
    assert TOKEN not in result.output and "Traceback" not in result.output


@pytest.mark.parametrize(
    "url", ["http://localhost:abc", "http://localhost:99999", "https://" + "a" * 70 + ".example.org"]
)
def test_an_unusable_url_is_refused_by_the_check(url: str) -> None:
    with pytest.raises(up.UploadError, match="not a usable URL"):
        up.check_api_url(url)


@pytest.mark.parametrize(
    "reply",
    [b"garbage\r\n\r\n", b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
     b"HTTP/1.1 201 Created\r\n" + b"".join(b"X-%d: y\r\n" % i for i in range(150)) + b"\r\n"],
    ids=["bad-status-line", "bad-chunk", "too-many-headers"],
)  # fmt: skip
def test_a_malformed_answer_is_an_upload_error(
    raw: Callable[[Answer], tuple[str, list[bytes]]], reply: bytes
) -> None:
    url, _ = raw(lambda request: reply)
    with pytest.raises(up.UploadError, match="the platform sent a malformed answer"):
        up.Platform(url, TOKEN).create_run(RUN)


# ---------------------------------------------------------------- Hiba's re-review of 7493800 (her tests)


def test_the_command_exits_at_the_deadline_without_waiting_for_the_request(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]]
) -> None:
    url, _ = raw(lambda request: None)  # never answers: the worker stays blocked for TIMEOUT_S (60 s)
    path = tmp_path / "findings.ndjson"
    path.write_bytes(findings())
    code = "import sentinelci.report.upload as up; up.DEADLINE_S = 1.0; import sentinelci.cli as c; c.app()"
    args = ["upload", "--findings", str(path), "--api-url", url, "--repo", REPO, "--commit", COMMIT]
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", code, *args, "--context", "pr"],
        env=os.environ | {"SENTINEL_API_TOKEN": TOKEN},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 4 and "did not answer within 1 s" in result.stderr, result.stderr
    assert time.monotonic() - start < 15, "the process waited for the blocked request"


def test_the_platform_cannot_make_the_cli_print_the_token(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]]
) -> None:
    def answer(request: bytes) -> bytes:
        auth = next(x for x in request.split(b"\r\n") if x.lower().startswith(b"authorization:"))
        return _response("401 Unauthorized", json.dumps({"detail": f"bad {auth.decode()}"}).encode())

    url, _ = raw(answer)
    result = run_upload(tmp_path, url, findings())
    assert result.exit_code == 4 and TOKEN not in result.output, result.output
    assert "<SENTINEL_API_TOKEN>" in result.output


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",
        "https://" + chr(0x4F8B) + chr(0x3048) + ".jp",
        "https://" + chr(0x130) + "stanbul.example",
        "https://sentinel.example.org/" + chr(0xE9),
    ],
    ids=["unclosed-bracket", "japanese-host", "dotted-capital-i", "non-ascii-path"],
)
def test_a_url_urllib_cannot_send_is_refused_by_the_check(url: str) -> None:
    with pytest.raises(up.UploadError, match=r"usable URL|in ASCII"):
        up.check_api_url(url)


@pytest.mark.parametrize("reply", [b"garbage\r\n\r\n", b""], ids=["malformed", "cut-off"])
def test_a_failed_findings_upload_names_the_run_to_resume(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], reply: bytes
) -> None:
    run_id = str(uuid.uuid4())

    def answer(request: bytes) -> bytes:
        if request.startswith(b"POST /api/v1/runs "):
            return _response("201 Created", json.dumps({"id": run_id}).encode())
        return reply

    url, _ = raw(answer)
    result = run_upload(tmp_path, url, findings())
    assert result.exit_code == 4 and f"--resume {run_id}" in result.output, result.output


@pytest.mark.parametrize(
    "body",
    [{"detail": "exists"}, {"detail": "exists", "run": {"id": "not-a-uuid"}}, {"run": []}, ["x"]],
    ids=["no-run", "bad-id", "run-not-an-object", "not-an-object"],
)
def test_a_409_without_a_usable_run_is_an_upload_failure(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], body: object
) -> None:
    url, seen = raw(lambda request: _response("409 Conflict", json.dumps(body).encode()))
    result = run_upload(tmp_path, url, findings(run_id="1/1"), "--run-id", "1/1")
    assert result.exit_code == 4 and "creating the run failed: HTTP 409" in result.output, result.output
    assert len(seen) == 1


def test_findings_recorded_meanwhile_are_compared_not_refused(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]]
) -> None:
    """Another attempt recorded the findings between the run's creation and this POST: 409, then a read."""
    data, run_id = findings(), str(uuid.uuid4())
    recorded = {"id": run_id, "repo": REPO, "commit": COMMIT, "context": "pr", "ref": None, "run_id": None,
                "finding_count": 2, "findings_sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip

    def answer(request: bytes) -> bytes:
        if request.startswith(b"POST /api/v1/runs "):
            return _response("201 Created", json.dumps({"id": run_id}).encode())
        if request.startswith(b"POST "):
            return _response("409 Conflict", json.dumps({"detail": "already recorded"}).encode())
        return _response("200 OK", json.dumps(recorded).encode())

    url, seen = raw(answer)
    result = run_upload(tmp_path, url, data)
    assert result.exit_code == 0 and json.loads(result.output)["already_recorded"] is True, result.output
    assert [r.split(b" ")[0] for r in seen] == [b"POST", b"POST", b"GET"]


def test_every_field_that_differs_is_named_and_none_of_the_platforms_values() -> None:
    recorded = {"repo": REPO, "commit": "f" * 40, "context": "pr", "ref": "refs/heads/elsewhere"}
    run = up.RunInfo(REPO, COMMIT, "pr", ref="refs/heads/main")
    with pytest.raises(up.UploadError) as caught:
        up._same_run("r", recorded, run)
    assert str(caught.value) == "run r is not this run (commit, ref differ)"


@pytest.mark.parametrize(
    ("token", "pad"),
    [
        ("fake-token-with-a\\backslash", 0),
        ("fake-token-with-'and\"", 0),
        ("fake-token-cut-by-the-limit", 255),
    ],
    ids=["backslash", "both-quotes", "cut-at-300"],  # repr escapes \\ and ', the limit cuts the token
)
def test_the_token_is_masked_before_the_platforms_words_are_quoted_or_cut(
    tmp_path: Path, raw: Callable[[Answer], tuple[str, list[bytes]]], token: str, pad: int
) -> None:
    def answer(request: bytes) -> bytes:
        auth = next(x for x in request.split(b"\r\n") if x.lower().startswith(b"authorization:"))
        detail = "x" * pad + f"rejected {auth.decode()}"
        return _response("401 Unauthorized", json.dumps({"detail": detail}).encode())

    url, _ = raw(answer)
    result = run_upload(tmp_path, url, findings(), token=token)
    assert result.exit_code == 4 and "fake-token" not in result.output, result.output
