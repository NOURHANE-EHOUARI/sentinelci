"""The platform client's generic calls (`Platform.get_bytes`, `Platform.post_json`, `answer_summary`), used by
the correlator to read a run's recorded findings and store its correlation (task A7, B1's API 1.3.0).

The server is a raw fake on 127.0.0.1: it answers each path with the status, content type and bytes a test
gives it, and keeps every request it saw.
"""

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinelci.report.upload import TOKEN_VARIABLE, Platform, UploadError, answer_summary

TOKEN = "fake-platform-client-token-for-tests-only"  # noqa: S105 (a fake, for the fake platform)


@dataclass
class Fake:
    answers: dict[str, tuple[int, str, bytes]] = field(default_factory=dict)  # path -> status, type, body
    seen: list[tuple[str, str, dict[str, str], bytes]] = field(default_factory=list)


@pytest.fixture
def fake() -> Fake:
    return Fake()


@pytest.fixture
def platform(fake: Fake) -> Iterator[Platform]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _handle(self, method: str) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            fake.seen.append((method, self.path, dict(self.headers), body))
            status, content_type, data = fake.answers.get(self.path, (404, "application/json", b"{}"))
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if status in (301, 302, 307, 308):
                self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Platform(base_url=f"http://127.0.0.1:{server.server_address[1]}", token=TOKEN)
    finally:
        server.shutdown()
        server.server_close()


PATH = "/api/v1/runs/0b7c1f5e-0000-4000-8000-000000000001/findings"
# Not JSON, a trailing blank line and bytes that are not UTF-8: given back exactly as served.
RAW = b'{"id": "a"}\n{"id":"b"}\n\n\xff\n'


def test_get_bytes_gives_the_exact_bytes_served(fake: Fake, platform: Platform) -> None:
    fake.answers[PATH] = (200, "application/x-ndjson", RAW)
    assert platform.get_bytes(PATH, limit=len(RAW)) == RAW, "exactly the limit is allowed"
    ((method, path, headers, body),) = fake.seen
    assert (method, path, body) == ("GET", PATH, b"")
    assert headers["Authorization"] == f"Bearer {TOKEN}" and "Content-Type" not in headers


def test_get_bytes_refuses_one_byte_over_the_limit(fake: Fake, platform: Platform) -> None:
    fake.answers[PATH] = (200, "application/x-ndjson", RAW)
    with pytest.raises(UploadError, match=f"larger than {len(RAW) - 1} bytes: refused"):
        platform.get_bytes(PATH, limit=len(RAW) - 1)


@pytest.mark.parametrize(
    ("status", "body", "said"),
    [
        (
            404,
            b'{"detail": "no such run"}',
            f"reading {PATH} failed: HTTP 404, the platform says 'no such run'",
        ),
        (500, b"<html>oops</html>", f"reading {PATH} failed: HTTP 500"),
        (204, b"", f"reading {PATH} failed: HTTP 204"),  # no bytes given is not a success
        (307, b"", "the platform answered with a redirect: refused, the token would follow it"),
    ],
)
def test_get_bytes_is_a_failure_on_anything_but_a_200(
    fake: Fake, platform: Platform, status: int, body: bytes, said: str
) -> None:
    fake.answers[PATH] = (status, "application/json", body)
    with pytest.raises(UploadError) as raised:
        platform.get_bytes(PATH, limit=1024)
    assert str(raised.value) == said
    assert len(fake.seen) == 1, "one request: nothing followed, nothing retried"


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (201, {"sha256": "a" * 64}, {"sha256": "a" * 64}),
        (409, {"detail": "already recorded", "correlation": {"sha256": "b" * 64}}, None),
        (422, {"detail": [{"msg": "'groups' is a required property"}]}, None),
    ],
)
def test_post_json_sends_the_bytes_as_they_are_and_gives_the_answer(
    fake: Fake, platform: Platform, status: int, body: dict[str, object], expected: object
) -> None:
    path = "/api/v1/runs/0b7c1f5e-0000-4000-8000-000000000001/correlations"
    fake.answers[path] = (status, "application/json", json.dumps(body).encode())
    sent = b'{"b":1,"a":"\xc3\xa9"}\n'  # not re-encoded, not re-ordered, the final line feed kept
    answered = platform.post_json(path, sent)
    assert answered == (status, body)
    ((method, seen_path, headers, received),) = fake.seen
    assert (method, seen_path, received) == ("POST", path, sent)
    assert headers["Content-Type"] == "application/json" and headers["Authorization"] == f"Bearer {TOKEN}"
    if expected is not None:
        assert answered[1] == expected


def test_answer_summary_quotes_the_platform_and_masks_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TOKEN_VARIABLE, TOKEN)
    said = answer_summary(401, {"detail": f"token {TOKEN} rejected\n"})
    assert said == f"HTTP 401, the platform says 'token <{TOKEN_VARIABLE}> rejected'"
    assert answer_summary(422, {"detail": [{"msg": "one"}, {"msg": "two"}]}) == (
        "HTTP 422, the platform says 'one; two'"
    )
    assert answer_summary(502, None) == "HTTP 502"
