"""Combine the outputs of several scanners into the single findings file and tool status the gate reads.

Each scanner command writes its own findings NDJSON and tool status. The gate takes one of each, so the scan
job merges them here, and refuses anything that does not add up (fail closed):

- every findings line must be a Finding v1, and an id may appear only once across all files (two scanners
  never share a fingerprint scheme, so a repeated id means the same output was combined twice);
- every tool status must be a valid tool-status v1, all must name the same lock (and platform, when given),
  and a tool may appear in only one of them.

A scanner whose status file is missing is simply absent from the combined status: the gate's required-tools
rule reports it (SC-010), so nothing here needs to guess.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinelci.contracts.finding import Finding
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.tool_status import load_tool_status
from sentinelci.scanners.status import SCHEMA_VERSION


class CombineError(Exception):
    """Scanner outputs that cannot be combined into trustworthy gate inputs."""


def combine_findings(paths: Sequence[Path]) -> list[Finding]:
    findings: dict[str, tuple[Finding, str]] = {}
    for path in paths:
        try:
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise CombineError(f"cannot read findings {path}: {exc}") from exc
        # Only "\n" separates records: JSON strings may hold raw U+2028/U+2029, which str.splitlines() splits.
        for lineno, line in enumerate(text.split("\n"), start=1):
            if not line.strip():
                continue
            try:
                finding = Finding.model_validate_json(line)
            except ValidationError as exc:
                raise CombineError(
                    f"{path} line {lineno} is not a Finding v1 ({exc.error_count()} error(s))"
                ) from exc
            where = f"{path} line {lineno}"
            if finding.id in findings:
                raise CombineError(
                    f"finding {finding.id[:12]} appears twice ({findings[finding.id][1]}, {where})"
                )
            findings[finding.id] = (finding, where)
    return [finding for finding, _ in findings.values()]


def combine_tool_statuses(paths: Sequence[Path]) -> dict[str, Any]:
    if not paths:
        raise CombineError("no tool status to combine")
    tools: dict[str, Any] = {}
    lock_sha256: str | None = None
    platforms: set[str] = set()
    for path in paths:
        try:
            document = load_tool_status(path.read_bytes())
        except (OSError, EvaluationError) as exc:
            raise CombineError(f"cannot use tool status {path}: {exc}") from exc
        if lock_sha256 not in (None, document["lock_sha256"]):
            raise CombineError(f"tool status {path} was verified against another lock")
        lock_sha256 = document["lock_sha256"]
        if "platform" in document:
            platforms.add(document["platform"])
        for name, entry in document["tools"].items():
            if name in tools:
                raise CombineError(f"tool {name!r} appears in more than one tool status")
            tools[name] = entry
    if len(platforms) > 1:
        raise CombineError(f"tool statuses come from different platforms: {', '.join(sorted(platforms))}")
    combined: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lock_sha256": lock_sha256,
        "tools": dict(sorted(tools.items())),
    }
    if platforms:
        combined["platform"] = platforms.pop()
    return combined
