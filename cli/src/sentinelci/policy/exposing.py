"""The Trivy rule ids SC-011 blocks (policies/exposing.rego), for the tests that pin them against Trivy.

The gate reads the list from the policy bundle; this reads the same file, one quoted id per line, so the
real-Trivy test (cli/tests/scanners/test_trivy_exposing.py) checks the list the gate uses rather than a copy.
A test compares the result with OPA's own evaluation of the file, so the two readings cannot drift.
"""

from __future__ import annotations

import re
from pathlib import Path

EXPOSING_FILE = "exposing.rego"
_ID_LINE = re.compile(r'^\s*"((?:KSV|AWS|GCP|AZU)-[0-9]{4})",\s*(?:#.*)?$', re.MULTILINE)


def exposing_rule_ids(policy_dir: Path) -> frozenset[str]:
    """The rule ids of `<policy_dir>/exposing.rego`."""
    text = (policy_dir / EXPOSING_FILE).read_text(encoding="utf-8")
    return frozenset(_ID_LINE.findall(text))
