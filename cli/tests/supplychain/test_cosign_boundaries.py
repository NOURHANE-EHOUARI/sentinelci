"""What reaches Cosign, and which bytes the statement is read from (ADR-0010, decision 5 and verify).

From the review of #35 (should fix 1): the two properties a refactor could break without anyone noticing.
"""

from pathlib import Path
from typing import Any

import pytest

import sentinelci.supplychain.cosign as cosign
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import ToolRun
from sentinelci.supplychain.attestations import DECISION_TYPE, KINDS, parse_image
from sentinelci.supplychain.cosign import Signer, Verifier

from .conftest import IMAGE, ROOT
from .test_statements import bundle, statement

LOCK = load_lock(ROOT / "tools.lock.toml")


def _ok(**_: Any) -> ToolRun:
    return ToolRun(tool="cosign", version="3.1.4", binary_sha256="0" * 64, args=(), returncode=0,
                   stdout="", stderr="", duration_s=0.0)  # fmt: skip


def test_only_the_key_variable_and_the_password_reach_cosign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake(name: str, args: list[str], **kwargs: Any) -> ToolRun:
        seen.update(args=args, env=kwargs["extra_env"])
        (Path(kwargs["cwd"]) / "bundle.json").write_text("{}", encoding="utf-8")
        return _ok()

    monkeypatch.setattr(cosign, "run_verified_tool", fake)
    environ = {"SIGNING_KEY": "fake key material", "COSIGN_PASSWORD": "pw",
               "GITHUB_TOKEN": "ghs_fake", "AWS_SECRET_ACCESS_KEY": "fake"}  # fmt: skip
    Signer("env://SIGNING_KEY", LOCK, tmp_path).attest(
        parse_image(IMAGE), KINDS["decision"], {}, tmp_path / "out.json", environ
    )
    assert seen["env"] == {"SIGNING_KEY": environ["SIGNING_KEY"], "COSIGN_PASSWORD": "pw"}
    assert not {"fake key material", "pw"} & set(seen["args"])


def test_the_statement_comes_from_the_bytes_cosign_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "decision.sigstore.json"
    path.write_bytes(bundle(statement(predicate={"verdict": "BLOCK"})))

    def swap_after_cosign(name: str, args: list[str], **kwargs: Any) -> ToolRun:
        path.write_bytes(bundle(statement(predicate={"verdict": "PASS"})))  # swapped in after the check
        return _ok()

    monkeypatch.setattr(cosign, "run_verified_tool", swap_after_cosign)
    outcome = Verifier(tmp_path / "k.pub", LOCK, tmp_path).verify(path, parse_image(IMAGE), DECISION_TYPE)
    assert outcome.predicate == {"verdict": "BLOCK"}
