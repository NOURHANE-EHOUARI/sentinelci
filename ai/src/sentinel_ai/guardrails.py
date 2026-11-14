"""Guardrails shared by the AI analyst's tasks (task B5, SPEC section 8): what may be sent about a finding,
how untrusted text is put in a prompt, and how an answer is asked for and checked.

- **Data blocks.** Untrusted text (findings come from scanners, code and comments from the scanned repository)
  goes as JSON lines with `<` and `>` escaped, so no text in it can close the block it is in; each task's
  system prompt names its blocks as data.
- **Nothing secret.** Every text is redacted before it is sent (`redact`, shared with A7), a secret's
  finding is never sent, and an answer that quotes something that looks like a secret is refused.
- **Bounded.** Each text field is clipped, and the code window is a few lines around the finding.
- **Schema, then one repair retry** (`ask`): an answer that does not validate, or that a task's own check
  refuses, is asked for again once with the reason; then the task is "unavailable", never a guess.

Owner: Track B (B5).
"""

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from sentinel_ai.correlate.labels import REDACTED, redact
from sentinel_ai.providers import LLMProvider
from sentinelci.contracts.finding import Finding

__all__ = ["REDACTED", "Refused", "code_window", "described", "json_line", "quotes_a_secret", "redact"]

MAX_FIELD = 300  # characters of each text field of a finding
WINDOW = 15  # lines of code before and after the finding's lines
MAX_LINE = 400  # characters of each line of code sent


class Refused(Exception):
    """An answer a task's own check refuses; the message is the reason given back to the model."""


@dataclass(frozen=True)
class ModelInfo:
    """The model a task asks, as recorded in its output (`model` of the contracts)."""

    name: str
    digest: str | None = None


def json_line(value: object) -> str:
    """One JSON line whose text cannot close a block: `<` and `>` are escaped, which JSON allows."""
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e")
    )


def clip(value: object, limit: int = MAX_FIELD) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def quotes_a_secret(text: str) -> bool:
    return REDACTED in text or redact(text) != text


def described(finding: Finding) -> dict[str, Any]:
    """What is sent of a finding: never its id, snippet, evidence or run; every text clipped and redacted."""
    location = finding.location
    package = finding.package
    fields: dict[str, Any] = {
        "category": finding.category,
        "rule": finding.rule_id,
        "tool": finding.tool.name,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "cwe": list(finding.cwe or [])[:5],
        "cve": list(finding.cve or [])[:5],
        "aliases": list(finding.aliases or [])[:5],
        "file": location.path if location else None,
        "start_line": location.start_line if location else None,
        "end_line": location.end_line if location else None,
        "package": f"{package.name} {package.version}" if package else None,
        "fixed_versions": list(package.fixed_versions or [])[:5] if package else None,
    }
    sent: dict[str, Any] = {}
    for key, value in fields.items():
        if value in (None, [], ""):
            continue
        if isinstance(value, str):
            sent[key] = clip(redact(value))  # redact first: a clipped token no longer matches
        elif isinstance(value, list):
            sent[key] = [clip(redact(item)) for item in value]
        else:
            sent[key] = value
    return sent


def code_window(
    finding: Finding, repo_root: Path | None, findings: Sequence[Finding]
) -> list[dict[str, Any]] | None:
    """The lines around the finding, redacted, as `{"n", "text"}` (`flagged` on its own lines); None when
    there is no code to show: no checkout, no line, not a regular UTF-8 file inside the repository, or a file
    in which one of the scan's `findings` is a secret. `redact` knows a dozen patterns and Gitleaks over a
    hundred rules, so no code is ever sent from a file where a secret was found (as in B6)."""
    location = finding.location
    if repo_root is None or location is None or location.start_line is None:
        return None
    if any(
        other.category == "SECRET"
        and any(p is not None and p.path == location.path for p in places_of(other))
        for other in findings
    ):
        return None
    file = repo_root / location.path
    # The resolved path must be the named one: no symbolic link anywhere on the path, even one inside the
    # repository.
    if not file.is_file() or file.resolve() != repo_root.resolve() / location.path:
        return None
    try:
        text = file.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    # Lines as the scanner and git count them: on line feeds only (`splitlines` also splits on a form feed and
    # U+2028, which would shift every later line).
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    start = location.start_line
    end = max(start, location.end_line or start)
    if start > len(lines):
        return None
    window = []
    for number in range(max(1, start - WINDOW), min(len(lines), end + WINDOW) + 1):
        entry: dict[str, Any] = {"n": number, "text": redact(lines[number - 1])[:MAX_LINE]}
        if start <= number <= end:
            entry["flagged"] = True
        window.append(entry)
    return window


def places_of(finding: Finding) -> list[Any]:
    return [finding.location, *(finding.other_locations or [])]


def model_record(provider: LLMProvider, model: ModelInfo, prompt_sha256: str, user: str) -> dict[str, Any]:
    """The contracts' `model` object: provider, model, digest when pinned, and the prompt and input hashes."""
    record: dict[str, Any] = {
        "provider": provider.name,
        "name": model.name,
        "prompt_sha256": prompt_sha256,
        "input_sha256": hashlib.sha256(user.encode("utf-8")).hexdigest(),
    }
    if model.digest is not None:
        record["digest"] = model.digest
    return record


def texts_of(answer: BaseModel) -> list[str]:
    """Every string of an answer, nested lists included."""
    found: list[str] = []
    for value in answer.model_dump().values():
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, list):
            found += [item for item in value if isinstance(item, str)]
    return found


def ask[AnswerT: BaseModel, ResultT](
    provider: LLMProvider,
    system: str,
    user: str,
    schema: type[AnswerT],
    check: Callable[[AnswerT], ResultT],
) -> tuple[ResultT | None, str]:
    """The model's answer, validated against `schema` and accepted by `check`, with one repair retry; (None,
    why) when it could not give one. A provider failure is not retried and its message is not repeated."""
    reason = ""
    for attempt in range(2):
        message = user if attempt == 0 else (
            f"{user}\n\nYour previous answer was refused ({reason}). Answer again with only the JSON object."
        )  # fmt: skip
        try:
            answer = provider.complete(system, message, schema)
            # Validated again here: the provider's own validation is not this module's guarantee.
            validated = schema.model_validate(answer.model_dump())
        except (ValidationError, ValueError, TypeError) as exc:
            reason = f"not a valid answer: {type(exc).__name__}"
            continue
        except Exception as exc:  # the provider is down or refused
            return None, f"the provider failed: {type(exc).__name__}"
        if any(quotes_a_secret(text) for text in texts_of(validated)):
            reason = "the answer quotes something that looks like a secret"
            continue
        try:
            return check(validated), ""
        except Refused as exc:
            reason = str(exc)
    return None, reason


def block(name: str, lines: list[Any] | Mapping[str, Any]) -> str:
    """A named data block: one JSON line per item (or one for a mapping)."""
    body = json_line(lines) if isinstance(lines, Mapping) else "\n".join(json_line(item) for item in lines)
    return f"<{name}>\n{body}\n</{name}>"
