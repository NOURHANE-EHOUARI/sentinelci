"""`sentinel upload`: send one run's findings to the SentinelCI platform (M1, the B1 ingestion API).

A report, never part of the decision: the verdict is made and written before, and an upload that fails changes
nothing about it (its own step, its own exit code). The rules agreed with Track B:

- the token comes only from `SENTINEL_API_TOKEN`: never an argument, never printed, never in an error. It
  must be visible ASCII, so it can only ever be a header value;
- the platform URL is `https://`, or `http://` on the loopback only (a local platform), with no credentials,
  query, fragment or white space in it; a redirect is refused, since it would carry the token elsewhere, and
  plain http never goes through a proxy (the token would leave the machine in clear text). An https URL goes
  through the job's `HTTPS_PROXY`, which only sees a CONNECT;
- whatever happens, an upload fails with its own exit code (4) and one line that names no secret: every
  request has an overall deadline, and a malformed answer is an upload failure like a refused one;
- in CI it runs in a job that never runs repository code.

The findings are checked locally first, as the API checks them (Finding v1, each listed once, each about this
run), so a bad file never leaves an empty run behind. Then `POST /api/v1/runs`, then the NDJSON as is, and the
platform's `findings_sha256` must be the sha256 of the bytes sent. `--resume <run id>` finishes an upload that
stopped after the run was created; a run whose findings are already recorded counts as uploaded only if the
platform recorded these same bytes. A CI run (`--run-id`) needs no `--resume`: the platform answers the same
CI run again with 409 and the run it has (API 1.1.0), which is resumed the same way. In GitHub Actions the run
id is `<run id>/<run attempt>`, so a re-run of the job is a new run, as it is a new scan and a new decision.
"""

import hashlib
import http.client
import json
import os
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, NoReturn
from urllib.parse import urlsplit

from sentinelci.policy.decision import load_findings
from sentinelci.policy.errors import EvaluationError

TOKEN_VARIABLE = "SENTINEL_API_TOKEN"  # noqa: S105 (the variable's name, not a token)
NDJSON = "application/x-ndjson"
TIMEOUT_S = 60.0  # each socket operation
DEADLINE_S = 120.0  # each request, from connecting to the last byte of the answer
MAX_RESPONSE_BYTES = 1024 * 1024
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TOKEN = re.compile(r"[\x21-\x7e]+")


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
    if any(char.isspace() or not char.isprintable() for char in url):
        # urlsplit drops tabs and line breaks, so the check would read another URL than the request.
        raise UploadError("--api-url must not hold white space or control characters")
    if not url.isascii():
        # http.client sends the host and the path as they are, in Latin-1 or ASCII: it would fail mid-request.
        raise UploadError("--api-url must be in ASCII (an international host name in its xn-- form)")
    try:
        parts = urlsplit(url)
    except ValueError as exc:  # an unclosed "[" around an IPv6 address
        raise UploadError(f"--api-url is not a usable URL: {type(exc).__name__}") from exc
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise UploadError("--api-url must be an https:// URL (or http:// on localhost)")
    if parts.scheme == "http" and host not in LOOPBACK:
        raise UploadError("--api-url over plain http is allowed on localhost only")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise UploadError("--api-url must not hold credentials, a query or a fragment")
    try:
        parts.port  # noqa: B018 (urlsplit checks the port only when it is read)
        host.encode("idna")
    except (ValueError, UnicodeError) as exc:
        raise UploadError(f"--api-url is not a usable URL: {type(exc).__name__}") from exc
    return url.rstrip("/")


def token_from(environ: Mapping[str, str]) -> str:
    token = environ.get(TOKEN_VARIABLE, "").strip()
    if not token:
        raise UploadError(f"{TOKEN_VARIABLE} is not set: the platform token comes only from the environment")
    if not _TOKEN.fullmatch(token):
        raise UploadError(
            f"{TOKEN_VARIABLE} holds white space, a line break or a non-ASCII character, which a token "
            "cannot have (it is not printed)"
        )
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


def _within_deadline[T](call: Callable[[], T]) -> T:
    """`call()`, or UploadError once DEADLINE_S has passed: TIMEOUT_S bounds each socket operation only, so a
    platform that sends one byte at a time could otherwise hold the step for as long as it likes. The worker
    is a daemon thread: the CLI exits without waiting for it."""
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # re-raised in the caller's thread
            outcome["error"] = exc

    worker = threading.Thread(target=run, name="sentinel-upload", daemon=True)
    worker.start()
    worker.join(DEADLINE_S)
    if worker.is_alive():
        raise UploadError(f"the platform did not answer within {DEADLINE_S:g} s")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]  # type: ignore[no-any-return]


@dataclass(frozen=True)
class Platform:
    base_url: str
    token: str = field(repr=False)

    def _request(
        self, method: str, path: str, body: bytes | None, content_type: str | None
    ) -> tuple[int, Any]:
        # base_url passed check_api_url: https, or http on the loopback; never file: or a custom scheme.
        request = urllib.request.Request(self.base_url + path, data=body, method=method)  # noqa: S310
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Accept", "application/json")
        if content_type is not None:
            request.add_header("Content-Type", content_type)
        # Plain http is loopback only: never through a proxy, which would see the token in clear text.
        proxies = urllib.request.ProxyHandler({} if request.type == "http" else None)
        opener = urllib.request.build_opener(proxies, _NoRedirect)

        def send() -> tuple[int, Any]:
            try:
                with opener.open(request, timeout=TIMEOUT_S) as response:
                    return response.status, _json(response.read(MAX_RESPONSE_BYTES + 1))
            except urllib.error.HTTPError as exc:
                return exc.code, _json(exc.read(MAX_RESPONSE_BYTES + 1))
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                raise UploadError(
                    f"the platform could not be reached: {type(exc).__name__}: {reason}"
                ) from exc
            except http.client.HTTPException as exc:
                raise UploadError(f"the platform sent a malformed answer: {type(exc).__name__}") from exc

        return _within_deadline(send)

    def create_run(self, run: RunInfo) -> tuple[str, dict[str, Any] | None]:
        """The new run's id, or the id and record of the run the platform already has for this CI run (409,
        API 1.1.0: the same repo, commit, context and run id)."""
        try:
            status, body = self._request(
                "POST", "/api/v1/runs", json.dumps(run.body()).encode(), "application/json"
            )
        except UploadError as exc:
            # The run may have been created before the answer was lost: for a CI run, the 409 finds it again.
            if run.run_id is None:
                raise
            hint = "if the platform created the run, the same command again resumes it"
            raise UploadError(f"{exc} ({hint})") from exc
        if status == 201 and isinstance(body, dict) and _UUID.fullmatch(str(body.get("id", ""))):
            return str(body["id"]), None
        existing = body.get("run") if status == 409 and isinstance(body, dict) else None
        if isinstance(existing, dict) and _UUID.fullmatch(str(existing.get("id", ""))):
            return str(existing["id"]), existing
        raise UploadError(f"creating the run failed: {_why(status, body)}")

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
    # The platform's own words, quoted and without control characters: they cannot pass for the CLI's. The
    # token is masked first: repr escapes a backslash or a quote, and the cut could split the token.
    said = "".join(char for char in str(detail) if char.isprintable()) if detail else ""
    token = os.environ.get(TOKEN_VARIABLE, "").strip()
    said = (said.replace(token, f"<{TOKEN_VARIABLE}>") if token else said)[:300]
    return f"HTTP {status}" + (f", the platform says {said!r}" if said else "")


def upload(data: bytes, run: RunInfo, platform: Platform, *, resume: str | None = None) -> Uploaded:
    """Record `data` (Finding v1 NDJSON of `run`) on the platform; UploadError when it was not recorded."""
    count = check_findings(data, run)
    digest = hashlib.sha256(data).hexdigest()
    recorded: dict[str, Any] | None
    if resume is not None:
        if not _UUID.fullmatch(resume):
            raise UploadError(f"--resume {resume!r} is not a run id")
        run_id, recorded = resume, platform.run(resume)
    else:
        run_id, recorded = platform.create_run(run)
    if recorded is not None:  # --resume, or a CI run the platform already has (409): it must be this run
        _same_run(run_id, recorded, run)
        if recorded.get("findings_sha256") is not None:
            return _already(run_id, recorded, digest, count)
    try:
        status, body = platform.upload(run_id, data)
        recorded = platform.run(run_id) if status == 409 else None
    except UploadError as exc:
        _name_the_run(run_id, exc)
    if recorded is not None:  # recorded meanwhile, by another attempt of this upload
        return _already(run_id, recorded, digest, count)
    if status == 413:
        raise UploadError(
            f"run {run_id} stays empty: the findings are larger than the platform's upload limit, so "
            f"--resume will not help ({_why(status, body)})"
        )
    if status != 201 or not isinstance(body, dict):
        why = f"{_why(status, body)} (--resume {run_id} finishes it)"
        raise UploadError(f"uploading the findings of run {run_id} failed: {why}")
    if body.get("findings_sha256") != digest or body.get("finding_count") != count:
        raise UploadError(f"run {run_id}: the platform recorded other bytes than the ones sent")
    return Uploaded(run_id=run_id, finding_count=count, findings_sha256=digest)


def _same_run(run_id: str, recorded: Mapping[str, Any], run: RunInfo) -> None:
    """The platform's run is about this run. The fields that differ are named, never the platform's values."""
    differ = [name.replace("_", " ") for name, value in run.body().items() if recorded.get(name) != value]
    if differ:
        verb = "differs" if len(differ) == 1 else "differ"
        raise UploadError(f"run {run_id} is not this run ({', '.join(differ)} {verb})")


def _name_the_run(run_id: str, exc: UploadError) -> NoReturn:
    """A failure once the run exists names it: after a lost answer it may even hold the findings already."""
    said = str(exc) if run_id in str(exc) else f"run {run_id}: {exc}"
    raise UploadError(f"{said} (--resume {run_id} finishes or confirms it)") from exc


def _already(run_id: str, recorded: Mapping[str, Any], digest: str, count: int) -> Uploaded:
    """The run already holds findings: uploaded only if they are these bytes and this many findings. The
    platform's data is compared, never converted."""
    if recorded.get("findings_sha256") != digest or recorded.get("finding_count") != count:
        raise UploadError(f"run {run_id} already holds other findings (findings_sha256 or count differs)")
    return Uploaded(run_id, count, digest, already_recorded=True)


def platform_from(api_url: str, environ: Mapping[str, str] = os.environ) -> Platform:
    return Platform(base_url=check_api_url(api_url), token=token_from(environ))
