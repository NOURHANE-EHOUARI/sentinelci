"""Load `.sentinel/waivers.yaml` (schemas/waivers.v1.json, SPEC section 6.4).

Only the file structure is checked here. Each entry goes to the policy unchanged, because judging a
waiver (owner, justification, expiry, target) is the policy's job: rule SC-005 blocks invalid ones
and reports why. A file that cannot be read at all fails the evaluation instead (fail closed).
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from sentinelci.policy.errors import EvaluationError

DEFAULT_WAIVERS_PATH = ".sentinel/waivers.yaml"
WAIVERS_FILE_VERSION = 1


class _Loader(yaml.SafeLoader):
    """Safe loader that keeps timestamps as strings, and refuses aliases.

    YAML would turn `2026-12-31` into a date and drop the offset of `2026-12-31T00:00:00+01:00`;
    the policy must see exactly what the reviewer approved. An alias (`*name`) is refused: a reviewed waivers
    file never needs one, and anchors of anchors let a few hundred bytes expand to millions of values when the
    entries are written out for the policy, so the gate would run until its time limit instead of failing
    closed with a reason (#110 review).
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise yaml.composer.ComposerError(
                None,
                None,
                "a waivers file uses no YAML alias",
                self.peek_event().start_mark,  # type: ignore[no-untyped-call]
            )
        return super().compose_node(parent, index)


_Loader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


_TOO_DEEP = "waivers file is nested too deeply to be read"


def load_waivers(data: bytes) -> list[Any]:
    """Return the waiver entries of a waivers file. An empty file means no waivers."""
    try:
        document = yaml.load(data.decode("utf-8"), Loader=_Loader)  # noqa: S506 - a SafeLoader subclass
    except UnicodeDecodeError as exc:
        raise EvaluationError("waivers file is not UTF-8") from exc
    except yaml.YAMLError as exc:
        raise EvaluationError(f"waivers file is not valid YAML: {exc}") from exc
    except RecursionError:  # a deeply nested document reaches Python's recursion limit (#126 review)
        raise EvaluationError(_TOO_DEEP) from None
    if document is None:
        return []
    if not isinstance(document, dict) or set(document) != {"version", "waivers"}:
        raise EvaluationError("waivers file must be a mapping with exactly 'version' and 'waivers'")
    if document["version"] != WAIVERS_FILE_VERSION or isinstance(document["version"], bool):
        raise EvaluationError(f"unsupported waivers file version {document['version']!r}, expected 1")
    waivers = document["waivers"]
    if waivers is None:
        return []
    if not isinstance(waivers, list):
        raise EvaluationError("'waivers' must be a list")
    try:
        # Rejects YAML-only values (binary, sets, NaN) and normalizes keys to what OPA will see.
        normalized: list[Any] = json.loads(json.dumps(waivers, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise EvaluationError(f"waivers file holds a value that is not plain JSON data: {exc}") from exc
    return normalized
