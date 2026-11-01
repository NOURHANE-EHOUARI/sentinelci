"""`sentinel upload`: send one run's findings to the SentinelCI platform (M1, the B1 ingestion API).

A report, never part of the decision: the verdict is made and written before, and an upload that fails changes
nothing about it (its own step, its own exit code). The rules agreed with Track B:

- the token comes only from `SENTINEL_API_TOKEN`: never an argument, never printed, never in an error;
- the platform URL is `https://`, or `http://` on the loopback only (a local platform), with no credentials,
  query or fragment in it; a redirect is refused, since it would carry the token elsewhere;
- in CI it runs in a job that never runs repository code.

The findings are checked locally first, as the API checks them (Finding v1, each listed once, each about this
run), so a bad file never leaves an empty run behind. Then `POST /api/v1/runs`, then the NDJSON as is, and the
platform's `findings_sha256` must be the sha256 of the bytes sent. `--resume <run id>` finishes an upload that
stopped after the run was created; a run whose findings are already recorded counts as uploaded only if the
platform recorded these same bytes.
"""

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from sentinelci.policy.decision import load_findings
from sentinelci.policy.errors import EvaluationError

TOKEN_VARIABLE = "SENTINEL_API_TOKEN"  # noqa: S105 (the variable's name, not a token)
NDJSON = "application/x-ndjson"
TIMEOUT_S = 60.0
MAX_RESPONSE_BYTES = 1024 * 1024
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class UploadError(Exception):
    """The findings were not recorded by the platform (the verdict is unaffected)."""


@dataclass(frozen=True)
class RunInfo:
    repo: str
    commit: str
    context: str
    ref: str | None = None
    run_id: str | None = None

    def body(self) -> dict[str, str]:
        fields = {"repo": self.repo, "commit": self.commit, "context": self.context}
        return fields | {k: v for k, v in (("ref", self.ref), ("run_id", self.run_id)) if v is not None}


@dataclass(frozen=True)
class Uploaded:
    run_id: str
    finding_count: int
    findings_sha256: str
    already_recorded: bool = False


def check_api_url(url: str) -> str:
    """The base URL without a trailing slash, or UploadError: https, or http on the loopback."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise UploadError("--api-url must be an https:// URL (or http:// on localhost)")
    if parts.scheme == "http" and host not in LOOPBACK:
        raise UploadError("--api-url over plain http is allowed on localhost only")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise UploadError("--api-url must not hold credentials, a query or a fragment")
    return url.rstrip("/")


def token_from(environ: Mapping[str, str]) -> str:
    token = environ.get(TOKEN_VARIABLE, "").strip()
    if not token:
        raise UploadError(f"{TOKEN_VARIABLE} is not set: the platform token comes only from the environment")
    return token


def check_findings(data: bytes, run: RunInfo) -> int:
    """The number of findings, or UploadError if the platform would refuse the file (nothing is sent)."""
    try:
        findings = load_findings(data)
    except EvaluationError as exc:
        raise UploadError(str(exc)) from exc
    seen: set[str] = set()
    for index, finding in enumerate(findings, start=1):
        if finding["id"] in seen:
            raise UploadError(f"finding {index}: {finding['id']} is listed twice")
        seen.add(finding["id"])
        reported = finding["run"]
        required = {"repo": run.repo, "commit": run.commit, "context": run.context}
        optional = {"ref": run.ref, "run_id": run.run_id}
        if any(reported.get(k) != v for k, v in required.items()) or any(
            k in reported and reported[k] != v for k, v in optional.items()
        ):
            raise UploadError(
                f"finding {index} belongs to another run than --repo/--commit/--context/--ref/--run-id"
            )
    return len(findings)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise UploadError("the platform answered with a redirect: refused, the token would follow it")


@dataclass(frozen=True)
class Platform:
    base_url: str
    token: str

    def _request(
        self, method: str, path: str, body: bytes | None, content_type: str | None
    ) -> tuple[int, Any]:
        # base_url passed check_api_url: https, or http on the loopback; never file: or a custom scheme.
        request = urllib.request.Request(self.base_url + path, data=body, method=method)  # noqa: S310
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Accept", "application/json")
        if content_type is not None:
            request.add_header("Content-Type", content_type)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_S) as response:
                return response.status, _json(response.read(MAX_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as exc:
            return exc.code, _json(exc.read(MAX_RESPONSE_BYTES + 1))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise UploadError(f"the platform could not be reached: {type(exc).__name__}: {reason}") from exc

    def create_run(self, run: RunInfo) -> str:
        status, body = self._request(
            "POST", "/api/v1/runs", json.dumps(run.body()).encode(), "application/json"
        )
        if status != 201 or not isinstance(body, dict) or not _UUID.fullmatch(str(body.get("id", ""))):
            raise UploadError(f"creating the run failed: {_why(status, body)}")
        return str(body["id"])

    def run(self, run_id: str) -> dict[str, Any]:
        status, body = self._request("GET", f"/api/v1/runs/{run_id}", None, None)
        if status != 200 or not isinstance(body, dict):
            raise UploadError(f"reading run {run_id} failed: {_why(status, body)}")
        return body

    def upload(self, run_id: str, data: bytes) -> tuple[int, Any]:
        return self._request("POST", f"/api/v1/runs/{run_id}/findings", data, NDJSON)


def _json(raw: bytes) -> Any:
    if len(raw) > MAX_RESPONSE_BYTES:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _why(status: int, body: Any) -> str:
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, list):  # 422: FastAPI's list of validation errors
        detail = "; ".join(str(item.get("msg")) for item in detail[:3] if isinstance(item, dict))
    return f"HTTP {status}" + (f": {str(detail)[:300]}" if detail else "")


def upload(data: bytes, run: RunInfo, platform: Platform, *, resume: str | None = None) -> Uploaded:
    """Record `data` (Finding v1 NDJSON of `run`) on the platform; UploadError when it was not recorded."""
    count = check_findings(data, run)
    digest = hashlib.sha256(data).hexdigest()
    if resume is not None:
        if not _UUID.fullmatch(resume):
            raise UploadError(f"--resume {resume!r} is not a run id")
        recorded = platform.run(resume)
        if any(recorded.get(k) != v for k, v in run.body().items()):
            raise UploadError(f"run {resume} is not this run (repo, commit, context, ref or run id differ)")
        if recorded.get("findings_sha256") is not None:
            return _already(resume, recorded, digest)
        run_id = resume
    else:
        run_id = platform.create_run(run)
    status, body = platform.upload(run_id, data)
    if status == 409:
        return _already(run_id, platform.run(run_id), digest)
    if status != 201 or not isinstance(body, dict):
        raise UploadError(f"uploading the findings of run {run_id} failed: {_why(status, body)}")
    if body.get("findings_sha256") != digest or body.get("finding_count") != count:
        raise UploadError(f"run {run_id}: the platform recorded other bytes than the ones sent")
    return Uploaded(run_id=run_id, finding_count=count, findings_sha256=digest)


def _already(run_id: str, recorded: Mapping[str, Any], digest: str) -> Uploaded:
    if recorded.get("findings_sha256") != digest:
        raise UploadError(f"run {run_id} already holds other findings (findings_sha256 differs)")
    return Uploaded(run_id, int(recorded.get("finding_count", 0)), digest, already_recorded=True)


def platform_from(api_url: str, environ: Mapping[str, str] = os.environ) -> Platform:
    return Platform(base_url=check_api_url(api_url), token=token_from(environ))
