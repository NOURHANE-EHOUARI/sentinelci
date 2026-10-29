"""`sentinel replay`: re-evaluate a recorded decision from its input digests and compare (SPEC section 6.5).

Every input comes from the evidence store by the digest the decision recorded, the policy bundle included, so
replay never reads live files or feeds. The replayed decision must be identical to the record, `decision_id`
included. Scanner versions cannot be re-derived (scanners do not run again), so the recorded ones are passed
back as evidence; the OPA version is the running binary's, so an OPA upgrade shows up as a difference.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelci.policy.decision import Subject, dumps_decision, engine_version, evaluate
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.opa import OpaRunner
from sentinelci.policy.store import EvidenceStore

_MAX_SHOWN = 120


class ReplayError(EvaluationError):
    """The record cannot be replayed (incomplete, malformed or older than this engine's inputs)."""


@dataclass(frozen=True)
class ReplayResult:
    recorded: dict[str, Any]
    replayed: dict[str, Any]
    differences: list[str]

    @property
    def identical(self) -> bool:
        return not self.differences


def _short(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return text if len(text) <= _MAX_SHOWN else text[: _MAX_SHOWN - 1] + "…"


def differences(recorded: Any, replayed: Any, path: str = "") -> list[str]:
    """Leaf-level differences as `path: recorded -> replayed`, in a stable order."""
    if isinstance(recorded, dict) and isinstance(replayed, dict):
        out: list[str] = []
        for key in sorted(recorded.keys() | replayed.keys()):
            where = f"{path}.{key}" if path else key
            if key not in replayed:
                out.append(f"{where}: {_short(recorded[key])} -> (absent)")
            elif key not in recorded:
                out.append(f"{where}: (absent) -> {_short(replayed[key])}")
            else:
                out += differences(recorded[key], replayed[key], where)
        return out
    if isinstance(recorded, list) and isinstance(replayed, list) and len(recorded) == len(replayed):
        return [
            d
            for i, (a, b) in enumerate(zip(recorded, replayed, strict=True))
            for d in differences(a, b, f"{path}[{i}]")
        ]
    # Types too: True == 1 and 1.0 == 1 in Python, but they are different JSON.
    same = type(recorded) is type(replayed) and recorded == replayed
    return [] if same else [f"{path}: {_short(recorded)} -> {_short(replayed)}"]


def skip_reason(recorded: Mapping[str, Any], opa_version: str) -> str | None:
    """Why `--all` leaves a record out: another engine or OPA version cannot reproduce it by design.

    Within one engine and OPA version a decision must replay identically; across versions it differs at least
    in `engine_version` or `tool_versions.opa` (and so in `decision_id`).
    """
    engine = recorded.get("engine_version")
    if engine != engine_version():
        return f"recorded with engine {engine}"
    inputs = recorded.get("inputs")
    versions = inputs.get("tool_versions") if isinstance(inputs, dict) else None
    opa = versions.get("opa") if isinstance(versions, dict) else None
    if opa != opa_version:
        return f"recorded with OPA {opa}"
    return None


def _string(document: Mapping[str, Any], key: str, where: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise ReplayError(f"recorded decision has no {where}{key}")
    return value


def _optional_string(document: Mapping[str, Any], key: str) -> str | None:
    value = document.get(key)
    if value is not None and not isinstance(value, str):
        raise ReplayError(f"recorded decision has a malformed subject.{key}")
    return value


def replay(
    recorded: Mapping[str, Any], *, store: EvidenceStore, opa: OpaRunner, work_dir: Path
) -> ReplayResult:
    """Re-evaluate `recorded`; `work_dir` must be an empty directory (the policy bundle is written there)."""
    inputs = recorded.get("inputs")
    subject = recorded.get("subject")
    if not isinstance(inputs, dict) or not isinstance(subject, dict):
        raise ReplayError("recorded decision has no inputs or subject object")
    if "waivers_digest" not in inputs:
        raise ReplayError(
            "recorded decision has no waivers_digest (Decision 1.0): this engine always reads a waivers "
            "file, so it cannot reproduce it"
        )
    tool_versions = inputs.get("tool_versions", {})
    if not isinstance(tool_versions, dict) or not all(isinstance(v, str) for v in tool_versions.values()):
        raise ReplayError("recorded decision has malformed tool_versions")

    def blob(key: str) -> bytes:
        return store.get(_string(inputs, key, "inputs."))

    def optional_blob(key: str) -> bytes | None:
        return blob(key) if key in inputs else None

    replayed = evaluate(
        findings_data=blob("findings_digest"),
        subject=Subject(
            repo=_string(subject, "repo", "subject."),
            commit=_string(subject, "commit", "subject."),
            context=_string(subject, "context", "subject."),
            ref=_optional_string(subject, "ref"),
            image_digest=_optional_string(subject, "image_digest"),
        ),
        evaluated_at=_string(recorded, "evaluated_at", ""),
        bundle=store.extract_bundle(_string(inputs, "policy_bundle_digest", "inputs."), work_dir),
        opa=opa,
        tool_versions=tool_versions,
        waivers_data=blob("waivers_digest"),
        baseline_data=optional_blob("baseline_digest"),
        tool_status_data=optional_blob("tool_status_digest"),
        enrichment_snapshot=blob("enrichment_snapshot_digest"),
        sbom=optional_blob("sbom_digest"),
        service_context=optional_blob("service_context_digest"),
        vex_data=optional_blob("vex_digest"),
    )
    canonical: dict[str, Any] = json.loads(dumps_decision(replayed))
    return ReplayResult(dict(recorded), canonical, differences(dict(recorded), canonical))
