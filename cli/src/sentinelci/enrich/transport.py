"""How the snapshot fetchers reach the feeds: live HTTPS, or recorded responses for offline runs.

`HttpTransport` talks only to the three feeds over HTTPS, never follows a redirect, needs no credentials (the
feeds are public), caps every response at 32 MB and every request at one overall deadline, and retries a
transient failure once. `RecordingTransport` saves every response it passes on (gzip, base64, with the sha256
of the raw bytes), and `ReplayTransport` answers from those files after checking the digest: the offline
fixtures (eval/feeds/), for demos, evaluation and tests. Recordings are evidence inputs: use them only from
the base commit or a trusted store, since a change that edits them could forge EPSS or KEV answers.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import http.client
import io
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

ALLOWED_HOSTS = frozenset({"api.first.org", "www.cisa.gov", "api.osv.dev"})
DEFAULT_TIMEOUT_S = 30.0
MAX_TIMEOUT_S = 300.0
MAX_RESPONSE_BYTES = 32 * 1024 * 1024  # the KEV catalogue is about 2 MB
RETRIES = 1
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_CHUNK = 64 * 1024
# Responses are stored gzip-compressed (mtime 0, so the same answer gives the same file): the KEV catalogue
# is 1.8 MB raw, a few hundred KB compressed. The sha256 is of the raw bytes.
_RECORDING_FORMAT = "sentinelci-feed-recording/2"
MAX_RECORDED_BYTES = MAX_RESPONSE_BYTES


class TransportError(Exception):
    """A request could not be completed (network, timeout, size, redirect, or no valid recording)."""


class Transport(Protocol):
    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        """Return (HTTP status, response body)."""
        ...


def allowed(url: str) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and parts.hostname in ALLOWED_HOSTS and port in (None, 443)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could leave the allow-list or HTTPS: never follow one."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise TransportError(f"{req.full_url} answered a redirect ({code}) to {newurl}: not followed")


class HttpTransport:
    def __init__(
        self, timeout: float = DEFAULT_TIMEOUT_S, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        if not 0 < timeout <= MAX_TIMEOUT_S:
            raise ValueError(f"timeout must be in (0, {MAX_TIMEOUT_S}] seconds, got {timeout}")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._sleep = sleep

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        if not allowed(url):
            raise TransportError(
                f"{url} is not an allowed feed (HTTPS to {', '.join(sorted(ALLOWED_HOSTS))})"
            )
        for attempt in range(RETRIES + 1):
            last = attempt == RETRIES
            try:
                status, data = self._once(method, url, body)
            except TransportError:
                if last:
                    raise
            else:
                if status not in RETRY_STATUSES or last:
                    return status, data
            self._sleep(1.0)
        raise AssertionError("unreachable")  # pragma: no cover

    def _once(self, method: str, url: str, body: bytes | None) -> tuple[int, bytes]:
        headers = {"Accept": "application/json", "User-Agent": "sentinelci-enrich"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310 - https only
        deadline = time.monotonic() + self.timeout
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                return int(response.status), _read(response, deadline, url)
        except urllib.error.HTTPError as exc:  # an answer with an error status: the caller decides
            try:
                return exc.code, _read(exc, deadline, url)
            except (OSError, http.client.HTTPException) as read_error:
                raise TransportError(f"{method} {url}: {read_error}") from read_error
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError, OverflowError) as exc:
            raise TransportError(f"{method} {url}: {exc}") from exc


def _read(response: Any, deadline: float, url: str) -> bytes:
    """The whole body, within the size cap and the overall deadline (a slow drip cannot hold a run)."""
    chunks: list[bytes] = []
    total = 0
    while chunk := response.read(_CHUNK):
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise TransportError(f"{url}: response larger than {MAX_RESPONSE_BYTES} bytes")
        if time.monotonic() > deadline:
            raise TransportError(f"{url}: no complete answer within the time limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _key(method: str, url: str, body: bytes | None) -> str:
    return hashlib.sha256(b"\n".join([method.encode(), url.encode(), body or b""])).hexdigest()


class RecordingTransport:
    """Pass requests on and save each response as `<sha256 of the request>.json` under `directory`."""

    def __init__(self, inner: Transport, directory: Path) -> None:
        if directory.exists() and not directory.is_dir():
            raise TransportError(f"--record {directory} is not a directory")
        self.inner = inner
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        status, data = self.inner.request(method, url, body)
        record = {
            "format": _RECORDING_FORMAT,
            "method": method,
            "url": url,
            "body_base64": None if body is None else base64.b64encode(body).decode("ascii"),
            "status": status,
            "response_gzip_base64": base64.b64encode(gzip.compress(data, mtime=0)).decode("ascii"),
            "response_sha256": hashlib.sha256(data).hexdigest(),
        }
        path = self.directory / f"{_key(method, url, body)}.json"
        try:
            path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            raise TransportError(f"cannot record {url} in {self.directory}: {exc}") from exc
        return status, data


class ReplayTransport:
    """Answer from a directory written by RecordingTransport; a missing or altered recording is an outage."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        path = self.directory / f"{_key(method, url, body)}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if record["format"] != _RECORDING_FORMAT or record["method"] != method or record["url"] != url:
                raise ValueError("recording of another request")
            data = _gunzip(base64.b64decode(record["response_gzip_base64"], validate=True))
            status = record["status"]
            if not isinstance(status, int) or isinstance(status, bool):
                raise ValueError("status is not a number")
        except FileNotFoundError as exc:
            raise TransportError(f"{method} {url}: no recorded response in {self.directory}") from exc
        except (OSError, ValueError, KeyError, TypeError, EOFError, binascii.Error) as exc:
            raise TransportError(f"{method} {url}: unreadable recording {path.name}: {exc}") from exc
        if hashlib.sha256(data).hexdigest() != record.get("response_sha256"):
            raise TransportError(f"{method} {url}: recording {path.name} does not match its sha256")
        return status, data


def _gunzip(data: bytes) -> bytes:
    """Decompress at most MAX_RECORDED_BYTES: a recording cannot be a decompression bomb."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        raw = stream.read(MAX_RECORDED_BYTES + 1)
    if len(raw) > MAX_RECORDED_BYTES:
        raise ValueError(f"recording expands beyond {MAX_RECORDED_BYTES} bytes")
    return raw
