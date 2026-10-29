"""Every schema `pattern` means the same thing in every JSON Schema validator, and none admits a line break.

Python's `re` (python-jsonschema, the CLI and the platform) lets `$` match before a final newline and `.`
match `\\r`, U+2028 and U+2029; ECMA-262 (ajv in the dashboard) does neither. So `"<64 hex>\\n"` passed
`^[a-f0-9]{64}$` in Python only. Every pattern therefore starts with LINE_BREAK_GUARD, which rejects any line
terminator anywhere, and the two engines are compared on real values taken from the valid fixtures.
"""

import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, validators

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
FIXTURES = SCHEMAS / "fixtures"
LINE_BREAK_GUARD = r"^(?![^\r\n\u2028\u2029]*[\r\n\u2028\u2029])"
BREAKS = ("\n", "\r", "\r\n", "\u2028", "\u2029")


def schema_files() -> list[Path]:
    return sorted(SCHEMAS.glob("*.json"))


def patterns_of(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                yield value
            elif key == "patternProperties" and isinstance(value, dict):
                yield from value
            yield from patterns_of(value)
    elif isinstance(node, list):
        for item in node:
            yield from patterns_of(item)


ALL_PATTERNS = sorted(
    {p for f in schema_files() for p in patterns_of(json.loads(f.read_text(encoding="utf-8")))}
)


@pytest.mark.parametrize("pattern", ALL_PATTERNS)
def test_every_pattern_starts_with_the_line_break_guard(pattern: str) -> None:
    assert pattern.startswith(LINE_BREAK_GUARD), f"add LINE_BREAK_GUARD after '^': {pattern}"


def matched_values() -> dict[str, set[str]]:
    """Each pattern with the values it accepted while validating the valid fixtures."""
    seen: dict[str, set[str]] = {}
    pattern_keyword = Draft202012Validator.VALIDATORS["pattern"]

    def recording(validator: Any, pattern: str, instance: Any, schema: Any) -> Iterator[Any]:
        errors = list(pattern_keyword(validator, pattern, instance, schema))
        if not errors and isinstance(instance, str):
            seen.setdefault(pattern, set()).add(instance)
        yield from errors

    recorder = validators.extend(Draft202012Validator, {"pattern": recording})
    for schema_file in schema_files():
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        fixtures = FIXTURES / schema_file.name.removesuffix(".v1.json") / "valid"
        for fixture in sorted(fixtures.glob("*.json")):
            instance = json.loads(fixture.read_text(encoding="utf-8"))
            assert not list(recorder(schema, format_checker=FormatChecker()).iter_errors(instance))
    return seen


MATCHED = matched_values()


def test_every_pattern_is_exercised_by_a_valid_fixture() -> None:
    assert set(ALL_PATTERNS) <= set(MATCHED)


def probes() -> list[tuple[str, str, bool]]:
    """(pattern, string, expected): each accepted value, and line-break variants that must be rejected."""
    cases = []
    for pattern, values in sorted(MATCHED.items()):
        value = sorted(values)[0]
        cases.append((pattern, value, True))
        for brk in BREAKS:
            cases += [(pattern, value + brk, False), (pattern, brk + value, False)]
            cases.append((pattern, value[: len(value) // 2] + brk + value[len(value) // 2 :], False))
    return cases


PROBES = probes()


@pytest.mark.parametrize(("pattern", "text", "expected"), PROBES)
def test_python_engine(pattern: str, text: str, expected: bool) -> None:
    # python-jsonschema evaluates `pattern` with re.search, like this.
    assert (re.search(pattern, text) is not None) is expected


def test_ecma_engine_agrees() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed: the ECMA-262 comparison needs it")
    script = (
        "const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "process.stdout.write(JSON.stringify(cases.map(([p, s]) => new RegExp(p, 'u').test(s))));"
    )
    result = subprocess.run(  # noqa: S603 - fixed arguments, node resolved from PATH, probes via stdin
        [node, "-e", script],
        input=json.dumps([[p, s] for p, s, _ in PROBES]),
        capture_output=True,
        text=True,
        check=True,
        encoding="utf-8",
    )
    ecma = json.loads(result.stdout)
    disagreements = [(p, s, e) for (p, s, e), got in zip(PROBES, ecma, strict=True) if got is not e]
    assert not disagreements
