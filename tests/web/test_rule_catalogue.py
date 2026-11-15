"""The dashboard's rule catalogue (platform/web/src/api/rules.ts) is SPEC section 6.3's table, rule for rule.

Checked here rather than in vitest: the dashboard's Vite config only lets it read its own folder, and widening
that would widen what the dev server serves.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs" / "spec" / "SPEC.md"
RULES_TS = ROOT / "platform" / "web" / "src" / "api" / "rules.ts"
_STRING = r'"(?:[^"\\]|\\.)*"'
_ENTRY = re.compile(rf"\{{ rule: ({_STRING}), verdict: ({_STRING}), condition: ({_STRING}) \}},")


def spec_rules() -> list[tuple[str, str, str]]:
    text = SPEC.read_text(encoding="utf-8")
    section = text[text.index("### 6.3 Rule catalogue") : text.index("### 6.4")]
    rows = []
    for line in section.splitlines():
        if re.match(r"^\| SC-\d{3} \|", line):
            rule, verdict, *condition = (cell.strip() for cell in line.strip()[1:-1].split("|"))
            rows.append((rule, verdict, "|".join(condition).strip()))
    return rows


def dashboard_rules() -> list[tuple[str, str, str]]:
    text = RULES_TS.read_text(encoding="utf-8")
    start = text.index("export const RULE_CATALOGUE")
    catalogue = text[start : text.index("];", start)]
    rules = []
    for match in _ENTRY.finditer(catalogue):
        rule, verdict, condition = (json.loads(part) for part in match.groups())
        rules.append((rule, verdict, condition))
    return rules


def test_the_dashboards_catalogue_is_spec_6_3() -> None:
    spec = spec_rules()
    assert len(spec) >= 11
    assert dashboard_rules() == spec


def test_every_entry_of_the_catalogue_is_read() -> None:
    """An entry the pattern above does not match would be skipped silently: count the entries another way."""
    text = RULES_TS.read_text(encoding="utf-8")
    assert len(dashboard_rules()) == text.count("{ rule: ")
