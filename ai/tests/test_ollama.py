"""The Ollama provider (task B5, ADR-0009) against a fake Ollama server on the loopback: what it sends, what
it trusts, and where it refuses to go. An opt-in test runs it against a real server (SENTINEL_OLLAMA_URL)."""

import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from sentinel_ai.providers import LLMProvider
from sentinel_ai.providers.ollama import (
    EMBEDDING,
    EMBEDDING_BATCH,
    GENERATION,
    MAX_RESPONSE_BYTES,
    NUM_CTX,
    SEED,
    OllamaProvider,
    PinnedModel,
    ProviderError,
    check_url,
)

TAGS = {"models": [{"name": GENERATION.name, "digest": GENERATION.digest.removeprefix("sha256:")},
                   {"name": EMBEDDING.name, "digest": EMBEDDING.digest.removeprefix("sha256:")}]}  # fmt: skip


class Label(BaseModel):
    title: str
    confidence: float


Reply = tuple[int, bytes | dict[str, Any]]


class FakeOllama:
    """Answers each path from `routes` (a reply, or a function of the request body); records every request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Any]] = []
        self.routes: dict[str, Reply | Callable[[Any], Reply]] = {"/api/tags": (200, TAGS)}
        self.drip: dict[str, float] = {}  # path -> seconds between two bytes of its body
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else None
                fake.requests.append((self.command, self.path, body))
                route = fake.routes.get(self.path, (404, {"error": "not found"}))
                status, answer = route(body) if callable(route) else route
                data = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
                self.send_response(status)
                if status in (301, 302, 307):
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                delay = fake.drip.get(self.path)
                try:
                    if delay is None:
                        self.wfile.write(data)
                    else:  # one byte at a time, slowly: each read is quick, the whole answer is not
                        for byte in data:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(delay)
                except OSError:  # the client gave up
                    pass

            do_GET = do_POST = _answer

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def paths(self) -> list[str]:
        return [path for _, path, _ in self.requests]


@pytest.fixture
def fake() -> Iterator[FakeOllama]:
    server = FakeOllama()
    yield server
    server.server.shutdown()
    server.server.server_close()


def chat_reply(content: str) -> Reply:
    return 200, {"model": GENERATION.name, "message": {"role": "assistant", "content": content}, "done": True}


def test_it_is_a_provider() -> None:
    assert isinstance(OllamaProvider(), LLMProvider)


# ---------------------------------------------------------------- complete


def test_complete_asks_for_json_of_the_schema_deterministically_and_validates_it(fake: FakeOllama) -> None:
    fake.routes["/api/chat"] = chat_reply('{"title": "SQL injection", "confidence": 0.9}')
    label = OllamaProvider(fake.url).complete("the system", "<finding>x</finding>", Label)
    assert label == Label(title="SQL injection", confidence=0.9)
    assert fake.paths() == ["/api/tags", "/api/chat"]
    method, _, body = fake.requests[1]
    assert method == "POST"
    assert body == {
        "model": GENERATION.name, "stream": False, "think": False, "format": Label.model_json_schema(),
        "options": {"temperature": 0, "seed": SEED, "num_ctx": NUM_CTX},
        "messages": [{"role": "system", "content": "the system"},
                     {"role": "user", "content": "<finding>x</finding>"}],
    }  # fmt: skip


def test_the_digest_is_checked_before_every_request(fake: FakeOllama) -> None:
    """A long-lived worker sees a tag moved by a later `ollama pull`: the next request is refused."""
    fake.routes["/api/chat"] = chat_reply('{"title": "t", "confidence": 1}')
    provider = OllamaProvider(fake.url)
    provider.complete("s", "u", Label)
    provider.complete("s", "u", Label)
    assert fake.paths() == ["/api/tags", "/api/chat", "/api/tags", "/api/chat"]
    fake.routes["/api/tags"] = (200, {"models": [{"name": GENERATION.name, "digest": "0" * 64}]})
    with pytest.raises(ProviderError, match="not the pinned"):
        provider.complete("s", "u", Label)
    assert fake.paths()[-1] == "/api/tags", "no prompt after the tag moved"


def test_a_400_that_is_not_about_thinking_is_an_error_and_not_retried(fake: FakeOllama) -> None:
    fake.routes["/api/chat"] = (400, {"error": "invalid format schema"})
    provider = OllamaProvider(fake.url)
    with pytest.raises(ProviderError, match="HTTP 400") as raised:
        provider.complete("s", "u", Label)
    assert "schema" not in str(raised.value), "the body is never repeated"
    assert fake.paths().count("/api/chat") == 1
    fake.routes["/api/chat"] = chat_reply('{"title": "t", "confidence": 1}')
    provider.complete("s", "u", Label)
    assert fake.requests[-1][2]["think"] is False, "thinking stays off as asked: the field is still sent"


def test_a_server_that_sends_slowly_is_cut_off_at_the_time_limit(fake: FakeOllama) -> None:
    fake.routes["/api/chat"] = chat_reply('{"title": "' + "t" * 200 + '", "confidence": 1}')
    fake.drip["/api/chat"] = 0.02  # about 6 s for the whole answer, each byte well within the limit
    started = time.monotonic()
    with pytest.raises(ProviderError, match="within its time limit"):
        OllamaProvider(fake.url, generation_timeout_s=0.5).complete("s", "u", Label)
    assert time.monotonic() - started < 2.0


def test_an_answer_that_does_not_fit_the_schema_is_a_validation_error_for_the_repair_retry(
    fake: FakeOllama,
) -> None:
    fake.routes["/api/chat"] = chat_reply('{"title": "t"}')
    with pytest.raises(ValidationError):
        OllamaProvider(fake.url).complete("s", "u", Label)
    fake.routes["/api/chat"] = chat_reply("not json")
    with pytest.raises(ValidationError):
        OllamaProvider(fake.url).complete("s", "u", Label)


def test_a_model_without_a_thinking_mode_is_asked_again_without_the_field(fake: FakeOllama) -> None:
    def chat(body: Any) -> Reply:
        if "think" in body:
            return 400, {"error": '"gemma" does not support thinking'}
        return chat_reply('{"title": "t", "confidence": 1}')

    fake.routes["/api/chat"] = chat
    provider = OllamaProvider(fake.url)
    provider.complete("s", "u", Label)
    provider.complete("s", "u", Label)
    chats = [body for _, path, body in fake.requests if path == "/api/chat"]
    assert ["think" in body for body in chats] == [True, False, False], "remembered after the first refusal"


@pytest.mark.parametrize(
    ("reply", "said"),
    [
        ((500, {"error": "boom: prompt was <finding>secret</finding>"}), "refused /api/chat: HTTP 500"),
        ((200, b"<html>proxy login</html>"), "answer to /api/chat is not JSON"),
        ((200, [1, 2]), "is not a JSON object"),
        ((200, {"message": {"content": 7}}), "has no message content"),
        ((302, {}), "redirect: refused"),
        ((200, b" " * (MAX_RESPONSE_BYTES + 1)), f"larger than {MAX_RESPONSE_BYTES} bytes"),
    ],
    ids=["server-error", "not-json", "not-an-object", "no-content", "redirect", "too-large"],
)
def test_a_failed_chat_is_a_provider_error_that_echoes_nothing(
    fake: FakeOllama, reply: Reply, said: str
) -> None:
    fake.routes["/api/chat"] = reply
    with pytest.raises(ProviderError, match=said) as raised:
        OllamaProvider(fake.url).complete("s", "the prompt <finding>secret</finding>", Label)
    assert "secret" not in str(raised.value) and "boom" not in str(raised.value)


def test_a_server_that_does_not_answer_in_time_is_a_provider_error(fake: FakeOllama) -> None:
    released = threading.Event()

    def slow(body: Any) -> Reply:
        released.wait(5)
        return chat_reply('{"title": "t", "confidence": 1}')

    fake.routes["/api/chat"] = slow
    try:
        with pytest.raises(ProviderError, match="did not answer /api/chat: TimeoutError"):
            OllamaProvider(fake.url, generation_timeout_s=0.3).complete("s", "u", Label)
    finally:
        released.set()


def test_an_unreachable_server_is_a_provider_error() -> None:
    with pytest.raises(ProviderError, match="did not answer /api/tags"):
        OllamaProvider("http://127.0.0.1:9").complete("s", "u", Label)


# ---------------------------------------------------------------- pinned models


@pytest.mark.parametrize(
    ("tags", "said"),
    [
        ({"models": []}, "does not have gemma4:12b-it-qat: pull it first"),
        ({"models": [{"name": GENERATION.name, "digest": "0" * 64}]}, "not the pinned sha256:38044be4f92"),
        ({"models": "gemma"}, "model list is not Ollama's"),
    ],
    ids=["missing", "other-digest", "not-a-list"],
)
def test_a_model_that_is_not_the_pinned_one_is_refused_before_anything_is_sent(
    fake: FakeOllama, tags: dict[str, Any], said: str
) -> None:
    fake.routes["/api/tags"] = (200, tags)
    with pytest.raises(ProviderError, match=said):
        OllamaProvider(fake.url).complete("s", "u", Label)
    assert fake.paths() == ["/api/tags"], "no prompt is sent to an unverified model"


def test_another_model_can_be_pinned() -> None:
    model = PinnedModel("other:7b", "a" * 64)
    assert model.digest == "sha256:" + "a" * 64
    for bad in ("", "sha256:" + "A" * 64, "a" * 63, "md5:" + "a" * 64):
        with pytest.raises(ValueError, match="needs a sha256 digest"):
            PinnedModel("other:7b", bad)


# ---------------------------------------------------------------- embed


def test_embeddings_go_in_batches_with_one_size_across_them(fake: FakeOllama) -> None:
    """A large run stays under the answer cap: 150 texts are 3 requests of at most EMBEDDING_BATCH."""
    fake.routes["/api/embed"] = lambda body: (200, {"embeddings": [[float(t), 1.0] for t in body["input"]]})
    texts = [str(n) for n in range(150)]
    assert OllamaProvider(fake.url).embed(texts) == [[float(n), 1.0] for n in range(150)]
    sizes = [len(body["input"]) for _, path, body in fake.requests if path == "/api/embed"]
    assert sizes == [EMBEDDING_BATCH, EMBEDDING_BATCH, 150 - 2 * EMBEDDING_BATCH]
    assert fake.paths().count("/api/tags") == 1, "checked once per call, not per batch"

    def other_size_later(body: Any) -> Reply:
        width = 2 if body["input"][0] == "0" else 3
        return 200, {"embeddings": [[1.0] * width for _ in body["input"]]}

    fake.routes["/api/embed"] = other_size_later
    with pytest.raises(ProviderError, match="one size"):
        OllamaProvider(fake.url).embed(texts)


def test_embed_returns_one_finite_vector_per_text(fake: FakeOllama) -> None:
    fake.routes["/api/embed"] = (200, {"model": EMBEDDING.name, "embeddings": [[0.1, 0.2], [1, -3]]})
    provider = OllamaProvider(fake.url)
    assert provider.embed(["a", "b"]) == [[0.1, 0.2], [1.0, -3.0]]
    assert fake.requests[-1][2] == {"model": EMBEDDING.name, "input": ["a", "b"]}
    assert provider.embed([]) == []
    assert fake.paths() == ["/api/tags", "/api/embed"], "nothing is asked for no text"


@pytest.mark.parametrize(
    "embeddings",
    [
        [[0.1, 0.2]],
        [[0.1, 0.2], [0.3]],
        [[], []],
        [[0.1, "x"], [0.1, 0.2]],
        [[0.1, True], [0.1, 0.2]],
        "vectors",
        [[1e999, 0.0], [0.1, 0.2]],
    ],
    ids=["one-missing", "two-sizes", "empty", "a-string", "a-bool", "not-a-list", "infinite"],
)
def test_embeddings_that_are_not_finite_vectors_of_one_size_are_refused(
    fake: FakeOllama, embeddings: Any
) -> None:
    raw = json.dumps({"embeddings": embeddings}).replace("Infinity", "1e999").encode()
    fake.routes["/api/embed"] = (200, raw)
    with pytest.raises(ProviderError):
        OllamaProvider(fake.url).embed(["a", "b"])


# ---------------------------------------------------------------- where it may go


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:11434", "http://localhost:11434/", "http://[::1]:11434", "http://ollama:11434",
     "https://127.0.0.2"],
)  # fmt: skip
def test_local_urls_are_accepted(url: str) -> None:
    assert check_url(url) == url.rstrip("/")


@pytest.mark.parametrize(
    ("url", "said"),
    [
        ("http://models.example.com:11434", "must be local"),
        ("http://10.0.0.5:11434", "must be local"),
        ("ftp://127.0.0.1", "http:// or https://"),
        ("http://user:pw@127.0.0.1:11434", "credentials"),
        ("http://127.0.0.1:11434/?x=1", "a query"),
        ("http://127.0.0.1:11434\n", "white space"),
        ("http://127.0.0.1:99999", "invalid port"),
    ],
    ids=["remote-name", "private-address", "ftp", "credentials", "query", "newline", "port"],
)
def test_other_urls_are_refused(url: str, said: str) -> None:
    with pytest.raises(ValueError, match=said):
        check_url(url)


def test_a_remote_server_needs_to_be_asked_for() -> None:
    assert OllamaProvider("https://gpu.example.com", allow_remote=True).url == "https://gpu.example.com"


def test_the_url_comes_from_the_environment() -> None:
    assert OllamaProvider.from_env({}).url == "http://127.0.0.1:11434"
    assert (
        OllamaProvider.from_env({"SENTINEL_OLLAMA_URL": "http://ollama:11434"}).url == "http://ollama:11434"
    )
    with pytest.raises(ValueError, match="must be local"):
        OllamaProvider.from_env({"SENTINEL_OLLAMA_URL": "http://203.0.113.9:11434"})


def test_no_proxy_is_ever_used(fake: FakeOllama, monkeypatch: pytest.MonkeyPatch) -> None:
    """The code of the scanned repository never goes through a proxy, even when the environment names one."""
    for variable in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(variable, "http://127.0.0.1:9")  # nothing listens there
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    fake.routes["/api/chat"] = chat_reply('{"title": "t", "confidence": 1}')
    assert OllamaProvider(fake.url).complete("s", "u", Label).title == "t"


# ---------------------------------------------------------------- a real server (opt-in)


@pytest.mark.skipif(
    not os.environ.get("SENTINEL_OLLAMA_URL"), reason="set SENTINEL_OLLAMA_URL to a real Ollama"
)
def test_a_real_server_with_the_pinned_models() -> (
    None
):  # pragma: no cover (needs the models, minutes on CPU)
    provider = OllamaProvider.from_env()
    label = provider.complete(
        "Answer with JSON only.", 'Give the title "ok" and the confidence 1 for this test.', Label
    )
    assert 0 <= label.confidence <= 1
    vectors = provider.embed(["SQL injection in app/db.py", "SQL built from strings in app/db.py"])
    assert len(vectors) == 2 and len(vectors[0]) == 1024
