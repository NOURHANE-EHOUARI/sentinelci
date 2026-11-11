"""The default model backend (task B5, ADR-0009): a local Ollama server, through its HTTP API.

The standard library only (`urllib`): no client library, so no new dependency in the supply chain.

What reaches the model is code and findings of the scanned repository, so the guardrails are about where it
goes and what is trusted:
- **Local only.** The URL is `http(s)://` on the loopback or the Compose service `ollama`, with no
  credentials, query or fragment; another host is refused unless the caller says so (`allow_remote=True`). No
  proxy is ever used (`HTTP_PROXY` and the like are ignored) and a redirect is refused, so a request never
  leaves for another place than the one named.
- **Pinned models.** Each model is named with its Ollama digest (ADR-0009, `PINNED`). Before every request
  the server's own digest of the model is checked (`/api/tags`); a model that is missing or has another digest
  is a `ProviderError`, like any integrity failure, and nothing is sent.
- **Bounded.** Every request has a time limit on the whole request, checked while the answer is read (a
  server that sends slowly cannot hold it), and an answer larger than `MAX_RESPONSE_BYTES` is refused.
  Embeddings go in batches of `EMBEDDING_BATCH` texts, so a large run stays under both.
- **Validated.** `complete` asks Ollama for JSON matching the schema (`format`), deterministic (temperature 0,
  a fixed seed), and validates the answer against the Pydantic model itself: a malformed answer raises
  `pydantic.ValidationError`, which callers answer with their one repair retry (SPEC section 8). `embed`
  returns one finite vector per text, all of one size, or raises. A 400 whose body is about `think` turns
  that field off for the provider; any other 400 is an error.
- **No echo.** A `ProviderError` says what failed, never what was sent or what the server answered.

Owner: Track B (B5).
"""

import ipaddress
import json
import math
import os
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel

SchemaT = TypeVar("SchemaT", bound=BaseModel)

URL_VARIABLE = "SENTINEL_OLLAMA_URL"
DEFAULT_URL = "http://127.0.0.1:11434"
COMPOSE_HOST = "ollama"  # the Compose service (deploy/compose, profile `ai`)
SEED = 42
NUM_CTX = 8192
GENERATION_TIMEOUT_S = 900.0  # an explanation takes about 2 minutes on a laptop CPU (ADR-0009)
EMBEDDING_TIMEOUT_S = 120.0
METADATA_TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
READ_CHUNK = 64 * 1024  # the body is read in chunks, the time limit checked after each
EMBEDDING_BATCH = 64  # texts per /api/embed request: about 0.8 MB of answer for 1024 dimensions
MAX_ERROR_BYTES = 4096  # of an error body, read only to tell a refused `think` from another 400


@dataclass(frozen=True)
class PinnedModel:
    """An Ollama model and the digest it must have (`sha256:` and 64 hex digits)."""

    name: str
    digest: str

    def __post_init__(self) -> None:
        hex_part = self.digest.removeprefix("sha256:")
        if not self.name or len(hex_part) != 64 or any(c not in "0123456789abcdef" for c in hex_part):
            raise ValueError(f"model {self.name!r} needs a sha256 digest, got {self.digest!r}")
        if not self.digest.startswith("sha256:"):
            object.__setattr__(self, "digest", f"sha256:{self.digest}")


# ADR-0009: what was measured in eval/model-selection, pinned by the digest Ollama reports.
GENERATION = PinnedModel(
    "gemma4:12b-it-qat", "sha256:38044be4f923e5a55264ed7df4eaac2676651a905f735197c504045140c02bd3"
)
EMBEDDING = PinnedModel(
    "qwen3-embedding:0.6b", "sha256:ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d"
)
PINNED: Mapping[str, PinnedModel] = {model.name: model for model in (GENERATION, EMBEDDING)}


class ProviderError(Exception):
    """The model could not answer: the server is unreachable, refused, timed out, answered something that is
    not Ollama's API, or serves a model that is not the pinned one. Never holds the prompt or the answer."""


class _ThinkRefused(ProviderError):
    """A 400 whose body is about `think`: the model has no thinking mode."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise ProviderError("the model server answered with a redirect: refused")


def _opener() -> urllib.request.OpenerDirector:
    """An opener with an empty proxy table (`ProxyHandler({})`): HTTP_PROXY, HTTPS_PROXY and ALL_PROXY are
    never read, whenever they are set, and a redirect is refused."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def check_url(url: str, *, allow_remote: bool = False) -> str:
    """The base URL without a trailing slash, or ValueError: http(s), the loopback or the Compose service
    unless `allow_remote`, and nothing but a scheme, a host, a port and an optional path."""
    if any(char.isspace() or not char.isprintable() for char in url):
        raise ValueError("the model server URL must not hold white space or control characters")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("the model server URL must be http:// or https:// with a host")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ValueError("the model server URL must not hold credentials, a query or a fragment")
    try:
        parts.port  # noqa: B018 (raises on a malformed port)
    except ValueError:
        raise ValueError("the model server URL has an invalid port") from None
    host = parts.hostname
    if not allow_remote and not _local(host):
        raise ValueError(
            f"the model server must be local (the loopback or the Compose service `{COMPOSE_HOST}`), "
            f"not {host}: code would leave the machine"
        )
    return url.rstrip("/")


def _local(host: str) -> bool:
    if host in ("localhost", COMPOSE_HOST):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class OllamaProvider:
    """`LLMProvider` for a local Ollama server, with pinned models (ADR-0009)."""

    name = "ollama"

    def __init__(
        self,
        url: str = DEFAULT_URL,
        *,
        generation: PinnedModel = GENERATION,
        embedding: PinnedModel = EMBEDDING,
        allow_remote: bool = False,
        generation_timeout_s: float = GENERATION_TIMEOUT_S,
    ) -> None:
        self.url = check_url(url, allow_remote=allow_remote)
        self.generation = generation
        self.embedding = embedding
        self.generation_timeout_s = generation_timeout_s
        self._think_supported = True

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "OllamaProvider":
        """The provider at `SENTINEL_OLLAMA_URL` (default the loopback), with the pinned models."""
        environ = os.environ if environ is None else environ
        return cls(environ.get(URL_VARIABLE) or DEFAULT_URL)

    # ---------------------------------------------------------------- HTTP

    def _request(self, path: str, payload: Mapping[str, Any] | None, timeout: float) -> dict[str, Any]:
        """One JSON request; the answer as a JSON object, or ProviderError (never with a body)."""
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 (the scheme is checked: http or https)
            self.url + path, data=data, headers={"Content-Type": "application/json"},
            method="GET" if payload is None else "POST",
        )  # fmt: skip
        deadline = time.monotonic() + timeout
        late = ProviderError(f"the model server did not answer {path} within its time limit ({timeout:g} s)")
        try:
            with _opener().open(request, timeout=timeout) as response:
                # Read in chunks and check the time limit after each one: a server that sends slowly, byte
                # by byte, cannot hold the request past it (each read is bounded by `timeout` on its own).
                chunks: list[bytes] = []
                size = 0
                while True:
                    if time.monotonic() > deadline:
                        raise late
                    chunk = response.read1(READ_CHUNK)  # what has arrived, not a full chunk
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ProviderError(
                            f"the model server's answer to {path} is larger than {MAX_RESPONSE_BYTES} bytes"
                        )
                body = b"".join(chunks)
        except ProviderError:
            raise
        except urllib.error.HTTPError as exc:
            refused = f"the model server refused {path}: HTTP {exc.code}"
            if exc.code == 400 and b"think" in (exc.read(MAX_ERROR_BYTES) or b""):
                raise _ThinkRefused(refused) from None  # the body is read, never repeated
            raise ProviderError(refused) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError(f"the model server did not answer {path}: {type(exc).__name__}") from None
        if time.monotonic() > deadline:
            raise late
        try:
            answer = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProviderError(f"the model server's answer to {path} is not JSON") from None
        if not isinstance(answer, dict):
            raise ProviderError(f"the model server's answer to {path} is not a JSON object")
        return answer

    def verify(self, model: PinnedModel) -> None:
        """ProviderError unless the server serves `model` with its pinned digest. Checked before every
        request, so a later `ollama pull` that moves the tag is caught in a long-lived worker too (a local
        round trip, next to minutes of generation)."""
        tags = self._request("/api/tags", None, METADATA_TIMEOUT_S).get("models")
        if not isinstance(tags, list):
            raise ProviderError("the model server's model list is not Ollama's")
        served = [entry for entry in tags if isinstance(entry, dict) and entry.get("name") == model.name]
        if not served:
            raise ProviderError(f"the model server does not have {model.name}: pull it first (ADR-0009)")
        digest = str(served[0].get("digest", ""))
        if f"sha256:{digest.removeprefix('sha256:')}" != model.digest:
            raise ProviderError(
                f"{model.name} has digest {digest[:19]}..., not the pinned {model.digest[:19]}... "
                "(ADR-0009): refused as an integrity failure"
            )

    # ---------------------------------------------------------------- LLMProvider

    def complete(self, system: str, user: str, schema: type[SchemaT]) -> SchemaT:
        """The model's answer, validated against `schema` (pydantic.ValidationError when it does not fit)."""
        self.verify(self.generation)
        payload: dict[str, Any] = {
            "model": self.generation.name,
            "stream": False,
            "think": False,  # thinking traces cost minutes on a laptop CPU and are not used
            "format": schema.model_json_schema(),
            "options": {"temperature": 0, "seed": SEED, "num_ctx": NUM_CTX},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if not self._think_supported:
            payload.pop("think")
        try:
            answer = self._request("/api/chat", payload, self.generation_timeout_s)
        except _ThinkRefused:
            # A model without a thinking mode refuses the field with a 400 that says so: asked again once
            # without it, and never sent again. Any other 400 is an error.
            if not self._think_supported:
                raise
            self._think_supported = False
            payload.pop("think")
            answer = self._request("/api/chat", payload, self.generation_timeout_s)
        message = answer.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ProviderError("the model server's chat answer has no message content")
        return schema.model_validate_json(content)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """One finite vector per text, all of one size, or ProviderError. The texts go in batches of
        EMBEDDING_BATCH, so a large run's answers stay under MAX_RESPONSE_BYTES and its time limit."""
        if not texts:
            return []
        self.verify(self.embedding)
        vectors: list[Any] = []
        for start in range(0, len(texts), EMBEDDING_BATCH):
            batch = list(texts[start : start + EMBEDDING_BATCH])
            answer = self._request(
                "/api/embed", {"model": self.embedding.name, "input": batch}, EMBEDDING_TIMEOUT_S
            )
            got = answer.get("embeddings")
            if not isinstance(got, list) or len(got) != len(batch):
                raise ProviderError("the model server did not return one embedding per text")
            vectors += got
        sizes = {len(vector) if isinstance(vector, list) else -1 for vector in vectors}
        if len(sizes) != 1 or sizes == {0} or sizes == {-1}:
            raise ProviderError("the embeddings are not vectors of one size")
        result: list[list[float]] = []
        for vector in vectors:
            if not all(
                isinstance(x, int | float) and not isinstance(x, bool) and math.isfinite(x) for x in vector
            ):
                raise ProviderError("an embedding holds a value that is not a finite number")
            result.append([float(x) for x in vector])
        return result
