"""VEX (SPEC 6.4): OpenVEX not_affected statements, read from the base branch, recorded and replayed."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.vex import load_vex

ROOT = Path(__file__).resolve().parents[2]
VEX_FIXTURES = ROOT / "schemas" / "fixtures" / "vex"
VALID = (VEX_FIXTURES / "valid" / "not-affected-and-affected.json").read_bytes()


@pytest.mark.parametrize("path", sorted((VEX_FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_valid_vex_documents_load(path: Path) -> None:
    assert load_vex(path.read_bytes())


@pytest.mark.parametrize("path", sorted((VEX_FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_invalid_vex_documents_are_refused(path: Path) -> None:
    with pytest.raises(EvaluationError):
        load_vex(path.read_bytes())


@pytest.mark.parametrize(
    "probe",
    [
        {"version": True},
        {"author": None},
        {"statements": [{"vulnerability": {"name": "CVE-2099-0001"}, "products": [{"@id": "pkg:pypi/x"}],
                         "status": "not_affected", "justification": "component_not_present",
                         "status_notes": None}]},
    ],
    ids=["boolean-version", "null-author", "null-in-statement"],
)  # fmt: skip
def test_the_model_and_the_schema_refuse_the_same_probes(probe: dict[str, object]) -> None:
    document = {**json.loads(VALID), **probe}
    schema = json.loads((ROOT / "schemas" / "vex.v1.json").read_text(encoding="utf-8"))
    assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
    with pytest.raises(EvaluationError):
        load_vex(json.dumps(document).encode())


def test_only_not_affected_statements_reach_the_gate_normalized() -> None:
    assert load_vex(VALID) == [
        {
            "vulnerabilities": ["CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"],
            "products": [{"base": "pkg:pypi/example-lib", "version": None}],
            "justification": "vulnerable_code_not_in_execute_path",
        },
        {
            "vulnerabilities": ["CVE-2099-0002"],
            "products": [{"base": "pkg:deb/debian/openssl", "version": "3.0.11-1~deb12u2"}],
            "justification": "component_not_present",
        },
    ]


def test_pypi_products_are_canonical() -> None:
    document = json.loads(VALID)
    document["statements"][0]["products"] = [{"@id": "pkg:pypi/Example_Lib@1.2.0"}]
    [first, _] = load_vex(json.dumps(document).encode())
    assert first["products"] == [{"base": "pkg:pypi/example-lib", "version": "1.2.0"}]


@pytest.mark.parametrize(
    "data", [b"", b"{", b"\xff", b"[" * 100_000], ids=["empty", "not-json", "not-utf8", "deep"]
)
def test_unreadable_vex_is_refused(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_vex(data)
