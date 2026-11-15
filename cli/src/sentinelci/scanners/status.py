"""Tool status v1 (schemas/tool-status.v1.json): what happened to every scanner of a run.

The pipeline writes one for every scan, success or failure, so the gate can turn a failed, timed-out or
tampered scanner into SC-010 inside a recorded decision instead of a bare workflow failure. It is the
`sentinel tools verify --report` manifest plus `status` and `detail` per tool.

A failure's `detail` is the error message: one line, at most `MAX_DETAIL` characters. Scanner errors carry the
tail of the tool's stderr, never its report (which may hold secret values).
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from sentinelci.normalize.errors import NormalizationError
from sentinelci.scanners.errors import ScannerError, ScannerTimeout, ToolIntegrityError
from sentinelci.scanners.lock import PLATFORMS, ToolLock
from sentinelci.scanners.runner import ToolRun

SCHEMA_VERSION = 1
MAX_DETAIL = 500


def outcome_ok(
    tool: str, version: str, binary_sha256: str, *, lock: ToolLock, platform: str | None
) -> dict[str, Any]:
    """`ok`: the binary was verified against the lock right before it ran, and it completed. The artifact is
    the release archive of a `[tools]` entry on this platform, or the pinned wheel that carries the binary of
    a `[python_tools]` entry (zizmor)."""
    outcome: dict[str, Any] = {"version": version, "binary_sha256": binary_sha256, "status": "ok"}
    if tool in lock.tools:
        for key, artifact in lock.tools[tool].artifacts.items():
            if key == platform:
                outcome["artifact_sha256"] = artifact.sha256
    elif tool in lock.python_tools:
        wheels = sorted(w.sha256 for w in lock.python_tools[tool].wheels if w.binary_sha256 == binary_sha256)
        if wheels:
            outcome["artifact_sha256"] = wheels[0]
    return outcome


def outcome_from_run(run: ToolRun, *, lock: ToolLock, platform: str | None) -> dict[str, Any]:
    """`ok`: the binary was verified against the lock right before it ran, and it completed."""
    return outcome_ok(run.tool, run.version, run.binary_sha256, lock=lock, platform=platform)


def outcome_from_error(tool: str, error: Exception, *, lock: ToolLock) -> dict[str, Any]:
    """The failure kind the gate reports; the version is the pinned one, since the tool may never have run."""
    if isinstance(error, ToolIntegrityError):
        status = "integrity_mismatch"
    elif isinstance(error, ScannerTimeout):
        status = "timeout"
    elif isinstance(error, ScannerError | NormalizationError):
        status = "failed"
    else:
        raise TypeError(f"not a scanner failure: {type(error).__name__}")
    pinned = lock.tools.get(tool) or lock.python_tools.get(tool)
    detail = " ".join(str(error).split())[:MAX_DETAIL] or type(error).__name__
    return {"version": pinned.version if pinned else "unknown", "status": status, "detail": detail}


def outcome_not_run(tool: str, detail: str, *, lock: ToolLock) -> dict[str, Any]:
    """`not_run`: expected but never started, because a tool before it failed (Grype after Syft)."""
    pinned = lock.tools.get(tool) or lock.python_tools.get(tool)
    return {"version": pinned.version if pinned else "unknown", "status": "not_run", "detail": detail}


def tool_status_document(
    lock_bytes: bytes, platform: str | None, outcomes: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """`platform` is recorded only when it is a lock platform (a scan can fail before it is known)."""
    if not outcomes:
        raise ValueError("a tool status must name at least one tool")
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "tools": dict(sorted(outcomes.items())),
    }
    if platform in PLATFORMS:
        document["platform"] = platform
    return document


def write_tool_status(document: dict[str, Any], destination: Path) -> None:
    """Deterministic and atomic: a partial file must never be read as a status."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    tmp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(destination)
