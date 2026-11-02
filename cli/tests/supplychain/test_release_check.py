"""The release check before signing passes only on a registry it could read (#44 re-review)."""

from pathlib import Path
from typing import Any

import pytest

from sentinelci.scanners.lock import load_lock
from sentinelci.supplychain.attestations import KINDS, AttestationError, parse_image
from sentinelci.supplychain.cosign import (
    Attached,
    Registry,
    Signer,
    Verifier,
    refuse_another_release,
)

from .conftest import IMAGE, ROOT

LOCK = load_lock(ROOT / "tools.lock.toml")
EMPTY = "error during command execution: no matching attestations: "
OTHER_TYPES = (
    "error during command execution: none of the attestations matched the predicate type: "
    "https://slsa.dev/provenance/v1, found: https://sigstore.dev/cosign/sign/v1"
)
HTTP_500 = (
    "error during command execution: GET http://127.0.0.1:5000/v2/demo-shop/api/manifests/sha256-ab.att: "
    "unexpected status code 500 Internal Server Error"
)
REFUSED = 'error during command execution: Get "https://127.0.0.1:5000/v2/": connect: connection refused'


def _check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    monkeypatch.setattr(Signer, "public_key", lambda *_: pem)

    def attached(*_: Any) -> Attached:
        return Attached({}, reason)

    monkeypatch.setattr(Verifier, "attached", attached)
    signer = Signer(str(tmp_path / "k.key"), LOCK, tmp_path)
    statements = {kind: (predicate_type, {"kind": kind}) for kind, predicate_type in KINDS.items()}
    refuse_another_release(signer, parse_image(IMAGE), statements, Registry(), {})


@pytest.mark.parametrize("reason", [EMPTY, OTHER_TYPES])
def test_a_registry_that_holds_nothing_of_a_type_lets_the_release_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    _check(tmp_path, monkeypatch, reason)


@pytest.mark.parametrize("reason", [HTTP_500, REFUSED])
def test_a_registry_that_could_not_be_read_stops_the_release_before_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    with pytest.raises(AttestationError, match="cannot read"):
        _check(tmp_path, monkeypatch, reason)
