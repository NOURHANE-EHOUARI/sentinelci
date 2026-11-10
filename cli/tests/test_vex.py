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


def test_every_statement_reaches_the_gate_normalized() -> None:
    """Every status reaches the gate: a statement of another status disputes not_affected (review of #24)."""
    dated = {"made": "2026-11-10T10:00:00.000000Z", "document_updated": "2026-11-10T10:00:00.000000Z"}
    assert load_vex(VALID) == [
        {
            "status": "not_affected",
            "vulnerabilities": ["CVE-2099-0001", "GHSA-xxxx-yyyy-zzzz"],
            "products": [{"base": "pkg:pypi/example-lib", "version": None}],
            "justification": "vulnerable_code_not_in_execute_path",
            **dated,
        },
        {
            "status": "not_affected",
            "vulnerabilities": ["CVE-2099-0002"],
            "products": [{"base": "pkg:deb/debian/openssl", "version": "3.0.11-1~deb12u2"}],
            "justification": "component_not_present",
            **dated,
        },
        {
            "status": "affected",
            "vulnerabilities": ["CVE-2099-0003"],
            "products": [{"base": "pkg:npm/left-pad", "version": "1.3.0"}],
            "justification": None,
            **dated,
        },
    ]


@pytest.mark.parametrize(
    ("statement", "document", "made", "updated"),
    [
        ({}, {}, "2026-11-10T10:00:00.000000Z", "2026-11-10T10:00:00.000000Z"),
        (
            {"timestamp": "2026-06-01T12:00:00+02:00"},
            {},
            "2026-06-01T10:00:00.000000Z",
            "2026-11-10T10:00:00.000000Z",
        ),
        (
            {"timestamp": "2026-06-01T00:00:00Z", "last_updated": "2026-10-01T00:00:00Z"},
            {"last_updated": "2026-11-11T00:00:00Z"},
            "2026-10-01T00:00:00.000000Z",
            "2026-11-11T00:00:00.000000Z",
        ),
    ],
    ids=["document-time", "own-time-in-utc", "own-last-updated"],
)  # fmt: skip
def test_each_statement_says_when_it_was_made_in_utc(
    statement: dict[str, str], document: dict[str, str], made: str, updated: str
) -> None:
    """The gate lets not_affected apply for 90 days after `made`, and refuses either date after evaluation.
    The document's own last_updated never refreshes a statement: only the statement's own dates do."""
    parsed = json.loads(VALID)
    parsed.update(document)
    parsed["statements"][0].update(statement)
    first = load_vex(json.dumps(parsed).encode())[0]
    assert (first["made"], first["document_updated"]) == (made, updated)


def test_a_duplicate_key_is_refused() -> None:
    """A reviewer of the raw file may stop at the first `status`; JSON would keep the last one."""
    data = VALID.replace(b'"status": "affected"', b'"status": "affected", "status": "not_affected"')
    assert data != VALID
    with pytest.raises(EvaluationError, match="duplicate key 'status'"):
        load_vex(data)


def test_pypi_products_are_canonical() -> None:
    document = json.loads(VALID)
    document["statements"][0]["products"] = [{"@id": "pkg:pypi/Example_Lib@1.2.0"}]
    [first, *_] = load_vex(json.dumps(document).encode())
    assert first["products"] == [{"base": "pkg:pypi/example-lib", "version": "1.2.0"}]


@pytest.mark.parametrize(
    "data", [b"", b"{", b"\xff", b"[" * 100_000], ids=["empty", "not-json", "not-utf8", "deep"]
)
def test_unreadable_vex_is_refused(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_vex(data)


SCHEMA = json.loads((ROOT / "schemas" / "vex.v1.json").read_text(encoding="utf-8"))


def _statement_probe(**changes: object) -> dict[str, object]:
    document = json.loads(VALID)
    document["statements"][0].update(changes)
    return document


@pytest.mark.parametrize(
    "document",
    [
        _statement_probe(impact_statement="   "),
        _statement_probe(status_notes="a\nb"),
        _statement_probe(action_statement=""),
        _statement_probe(**{"@id": "x\u2028y"}),
        _statement_probe(vulnerability={"name": "CVE-2099-0001", "description": "a\r\nb"}),
        _statement_probe(vulnerability={"name": "CVE-2099-0001", "@id": " "}),
        _statement_probe(timestamp="2026-11-10 10:00:00Z"),
        _statement_probe(timestamp="2026-11-10T10:00Z"),
        _statement_probe(timestamp="1700000000"),
        {**json.loads(VALID), "timestamp": "2026-11-10_10:00:00Z"},
        _statement_probe(products=[{"@id": "pkg:oci/shop-api@sha256%3A" + "a" * 64}]),
    ],
    ids=["blank-impact", "notes-line-break", "empty-action", "id-u2028", "description-crlf", "vuln-id-blank",
         "space-separator", "no-seconds", "unix-seconds", "underscore-separator", "image-product"],
)  # fmt: skip
def test_the_model_refuses_what_the_schema_refuses(document: dict[str, object]) -> None:
    assert list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(document))
    with pytest.raises(EvaluationError):
        load_vex(json.dumps(document).encode())


OVERSIZED = VALID.replace(b'"version": 1', b'"version": 1' + b" " * (4 * 1024 * 1024))  # valid, but too large


@pytest.mark.parametrize(
    "data",
    [b"[" * 2_000 + b"]" * 2_000, b'{"a": ' * 2_000 + b"1" + b"}" * 2_000, OVERSIZED],
    ids=["deep-array", "deep-object", "oversized"],
)
def test_deep_or_oversized_vex_is_refused(data: bytes) -> None:
    with pytest.raises(EvaluationError):
        load_vex(data)
