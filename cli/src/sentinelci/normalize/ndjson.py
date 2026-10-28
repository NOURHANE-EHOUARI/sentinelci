"""Deterministic NDJSON serialization of findings (same input -> byte-identical output)."""

import json
from collections.abc import Iterable
from pathlib import Path

from sentinelci.contracts.finding import Finding


def dumps_ndjson(findings: Iterable[Finding]) -> str:
    """One compact JSON object per line, keys sorted, findings sorted by fingerprint."""
    lines = [
        json.dumps(f.to_json_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for f in sorted(findings, key=lambda f: f.id)
    ]
    return "".join(f"{line}\n" for line in lines)


def write_ndjson(findings: Iterable[Finding], path: Path) -> None:
    """Write atomically: a partial file must never be mistaken for a complete scan."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(dumps_ndjson(findings), encoding="utf-8")
    tmp.replace(path)
