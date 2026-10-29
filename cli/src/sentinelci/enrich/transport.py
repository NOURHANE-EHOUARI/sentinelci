"""How the snapshot fetchers reach the feeds: live HTTPS, or recorded responses for offline runs.

`HttpTransport` talks only to the three feeds over HTTPS, with a timeout and a size cap, and needs no
credentials (the feeds are public). `RecordingTransport` saves every response it passes on, and
`ReplayTransport` answers from those files: the SPEC's offline fixtures, for demos, evaluation and tests.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

ALLOWED_HOSTS = frozenset({"api.first.org", "www.cisa.gov", "api.osv.dev"})
DEFAULT_TIMEOUT_S = 30.0
MAX_RESPONSE_BYTES = 32 * 1024 * 1024  # the KEV catalogue is about 2 MB


class TransportError(Exception):
    """A request could not be completed (network, timeout, size, or no recording)."""


class Transport(Protocol):
    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        """Return (HTTP status, response body)."""
        ...


class HttpTransport:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.timeout = timeout

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443):
            raise TransportError(
                f"{url} is not an allowed feed (HTTPS to {', '.join(sorted(ALLOWED_HOSTS))})"
            )
        headers = {"Accept": "application/json", "User-Agent": "sentinelci-enrich"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310 - https only
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:  # noqa: S310 - https only
                data = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(MAX_RESPONSE_BYTES)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"{method} {url}: {exc}") from exc
        if len(data) > MAX_RESPONSE_BYTES:
            raise TransportError(f"{method} {url}: response larger than {MAX_RESPONSE_BYTES} bytes")
        return status, data


def _key(method: str, url: str, body: bytes | None) -> str:
    return hashlib.sha256(b"\n".join([method.encode(), url.encode(), body or b""])).hexdigest()


class RecordingTransport:
    """Pass requests on and save each response as `<sha256 of the request>.json` under `directory`."""

    def __init__(self, inner: Transport, directory: Path) -> None:
        self.inner = inner
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        status, data = self.inner.request(method, url, body)
        record = {
            "method": method,
            "url": url,
            "body": None if body is None else body.decode("utf-8"),
            "status": status,
            "response": data.decode("utf-8", errors="replace"),
        }
        path = self.directory / f"{_key(method, url, body)}.json"
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return status, data


class ReplayTransport:
    """Answer from a directory written by RecordingTransport; a request never recorded is an outage."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        path = self.directory / f"{_key(method, url, body)}.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            return int(record["status"]), str(record["response"]).encode("utf-8")
        except FileNotFoundError as exc:
            raise TransportError(f"{method} {url}: no recorded response in {self.directory}") from exc
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise TransportError(f"{method} {url}: unreadable recording {path.name}") from exc
