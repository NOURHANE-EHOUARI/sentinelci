"""Request body limits, enforced before any route code runs.

FastAPI reads and parses a JSON body before the route's dependencies run, so a body limit inside a route (or
behind authentication) comes too late: an unauthenticated client could make the server buffer any amount of
memory (#38 review). This ASGI middleware counts the bytes as they arrive and answers 413 above the limit of
the path, with or without Content-Length.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Small JSON bodies: a run is a few short strings.
MAX_JSON_BYTES = 64 * 1024
# Uploads that can be large: a run's findings, a correlation of them (one group per finding at most), its
# decision (a violation can name every finding), and a waivers file (the gate reads one of any size).
_FINDINGS_UPLOAD = re.compile(r"^/api/v1/(?:runs/[^/]+/(?:findings|correlations|decision)|waivers/[^/]+)$")


class _TooLarge(HTTPException):
    """Raised from `receive`. An HTTPException, so FastAPI re-raises it while reading a body (it turns any
    other exception into a 400), and its handler answers 413."""

    def __init__(self, limit: int) -> None:
        super().__init__(413, f"the request body is larger than {limit} bytes")


class BodyLimit:
    def __init__(self, app: ASGIApp, upload_limit: Callable[[], int]) -> None:
        self.app = app
        self.upload_limit = upload_limit

    def _limit(self, path: str) -> int:
        return self.upload_limit() if _FINDINGS_UPLOAD.match(path) else MAX_JSON_BYTES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope["path"])
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await _refuse(send, limit)
            return
        received = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if started:  # the route answered before reading everything; nothing more to say
                return
            await _refuse(send, limit)


async def _refuse(send: Send, limit: int) -> None:
    body = json.dumps({"detail": f"the request body is larger than {limit} bytes"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
