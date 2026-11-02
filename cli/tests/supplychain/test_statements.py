"""The statement re-checked after Cosign: the parsed envelope must say what Cosign was asked to verify."""

import base64
import json
from typing import Any

import pytest

from sentinelci.supplychain.attestations import DECISION_TYPE, AttestationError, parse_image
from sentinelci.supplychain.cosign import check_statement, statement_of

from .conftest import IMAGE, IMAGE_HEX, OTHER_IMAGE_HEX


def bundle(statement: Any, payload_type: str = "application/vnd.in-toto+json") -> bytes:
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps(
        {"dsseEnvelope": {"payloadType": payload_type, "payload": payload, "signatures": []}}
    ).encode()


BAD_BASE64 = json.dumps(
    {"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "%%"}}
).encode()


def statement(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "shop-api", "digest": {"sha256": IMAGE_HEX}}],
        "predicateType": DECISION_TYPE,
        "predicate": {"verdict": "PASS"},
    }
    body.update(changes)
    return body


def test_a_statement_about_this_image() -> None:
    parsed = statement_of(bundle(statement()))
    assert check_statement(parsed, parse_image(IMAGE), DECISION_TYPE) == {"verdict": "PASS"}
    assert check_statement(
        statement(_type="https://in-toto.io/Statement/v1"), parse_image(IMAGE), DECISION_TYPE
    ) == {"verdict": "PASS"}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"not json", "not a Sigstore bundle"),
        (b"{}", "not a Sigstore bundle"),
        (bundle(statement(), payload_type="text/plain"), "not an in-toto statement"),
        (BAD_BASE64, "not a Sigstore bundle"),
        (bundle(["a", "list"]), "not a JSON object"),
    ],
    ids=["not-json", "no-envelope", "other-payload-type", "bad-base64", "not-an-object"],
)  # fmt: skip
def test_malformed_bundles(data: bytes, message: str) -> None:
    with pytest.raises(AttestationError, match=message):
        statement_of(data)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"_type": "https://example.invalid/Statement"}, "unknown statement type"),
        ({"predicateType": "https://slsa.dev/provenance/v1"}, "predicate type"),
        ({"subject": []}, "exactly one subject"),
        ({"subject": [statement()["subject"][0]] * 2}, "exactly one subject"),
        ({"subject": [{"name": "x", "digest": {"sha256": OTHER_IMAGE_HEX}}]}, "is about {'sha256': 'aaaa"),
        ({"subject": [{"name": "x", "digest": {"sha256": IMAGE_HEX, "sha512": "b" * 128}}]}, "'sha512'"),
        ({"subject": "shop-api"}, "exactly one subject"),
    ],
    ids=["unknown-type", "other-predicate", "no-subject", "two-subjects", "other-digest", "extra-digest",
         "subject-not-a-list"],
)  # fmt: skip
def test_the_statement_is_re_checked(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(AttestationError, match=message):
        check_statement(statement(**changes), parse_image(IMAGE), DECISION_TYPE)


def test_a_statement_without_predicate() -> None:
    body = statement()
    del body["predicate"]
    with pytest.raises(AttestationError, match="no predicate"):
        check_statement(body, parse_image(IMAGE), DECISION_TYPE)
