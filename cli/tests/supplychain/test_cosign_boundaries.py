"""What reaches Cosign, and which bytes the statement is read from (ADR-0010, decision 5 and verify).

From the review of #35 (should fix 1): the two properties a refactor could break without anyone noticing.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import sentinelci.cli as cli
import sentinelci.supplychain.cosign as cosign
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import ToolRun
from sentinelci.supplychain.attestations import DECISION_TYPE, KINDS, parse_image
from sentinelci.supplychain.cosign import SIGNATURE_TYPE, Registry, Signer, Verifier

from .conftest import IMAGE, IMAGE_HEX, ROOT
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


# ---------------------------------------------------------------- registry mode (A4d)


def _capture(monkeypatch: pytest.MonkeyPatch, stdout: str = "") -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake(name: str, args: list[str], **kwargs: Any) -> ToolRun:
        calls.append({"args": args, "env": kwargs.get("extra_env") or {}})
        return ToolRun(tool="cosign", version="3.1.4", binary_sha256="0" * 64, args=tuple(args), returncode=0,
                       stdout=stdout, stderr="", duration_s=0.0)  # fmt: skip

    monkeypatch.setattr(cosign, "run_verified_tool", fake)
    return calls


ENVIRON = {"SIGNING_KEY": "fake key material", "COSIGN_PASSWORD": "pw", "GITHUB_TOKEN": "ghs_fake",
           "DOCKER_CONFIG": "/run/docker-config", "AWS_SECRET_ACCESS_KEY": "fake"}  # fmt: skip


@pytest.mark.parametrize("allow_http", [False, True])
def test_pushing_gets_the_key_the_password_and_the_registry_credentials_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, allow_http: bool
) -> None:
    calls = _capture(monkeypatch)
    signer, registry, image = (
        Signer("env://SIGNING_KEY", LOCK, tmp_path),
        Registry(allow_http),
        parse_image(IMAGE),
    )
    signer.sign_image(image, registry, ENVIRON)
    signer.attest_image(image, KINDS["decision"], {"verdict": "PASS"}, registry, ENVIRON)
    for call in calls:
        assert call["env"] == {"SIGNING_KEY": "fake key material", "COSIGN_PASSWORD": "pw",
                               "DOCKER_CONFIG": "/run/docker-config"}  # fmt: skip
        assert call["args"][-1] == IMAGE, "always by digest, never a tag"
        assert {"--tlog-upload=false", "--use-signing-config=false", "--yes"} <= set(call["args"])
        assert ("--allow-http-registry" in call["args"]) is allow_http
        assert not {"fake key material", "pw"} & set(call["args"])
    assert [call["args"][0] for call in calls] == ["sign", "attest"]
    assert calls[1]["args"][calls[1]["args"].index("--type") + 1] == KINDS["decision"]


def test_without_docker_config_no_credentials_reach_cosign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture(monkeypatch)
    environ = {k: v for k, v in ENVIRON.items() if k != "DOCKER_CONFIG"}
    Verifier(tmp_path / "k.pub", LOCK, tmp_path).verify_signature(parse_image(IMAGE), Registry(), environ)
    assert calls[0]["env"] == {}
    assert (
        "--insecure-ignore-tlog=true" in calls[0]["args"] and "--allow-http-registry" not in calls[0]["args"]
    )


def _envelope(predicate: Any, **changes: Any) -> str:
    return json.dumps(json.loads(bundle(statement(predicate=predicate, **changes)))["dsseEnvelope"])


def test_a_retried_attestation_is_one_and_two_different_ones_are_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier, image = Verifier(tmp_path / "k.pub", LOCK, tmp_path), parse_image(IMAGE)
    _capture(monkeypatch, "\n".join([_envelope({"verdict": "PASS"})] * 2) + "\n")
    assert verifier.verify_in_registry(image, DECISION_TYPE, Registry(), {}).predicate == {"verdict": "PASS"}
    _capture(monkeypatch, _envelope({"verdict": "PASS"}) + "\n" + _envelope({"verdict": "WARN"}) + "\n")
    outcome = verifier.verify_in_registry(image, DECISION_TYPE, Registry(), {})
    assert outcome.predicate is None and outcome.problem == "2 different attestations of this type: ambiguous"


@pytest.mark.parametrize(
    ("stdout", "problem"),
    [("", "Cosign verified no statement"), ("not json\n", "Expecting value"),
     ('{"payloadType": "text/plain", "payload": ""}\n', "not an in-toto statement")],
    ids=["nothing", "not-json", "other-payload"],
)  # fmt: skip
def test_what_cosign_printed_is_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str, problem: str
) -> None:
    _capture(monkeypatch, stdout)
    outcome = Verifier(tmp_path / "k.pub", LOCK, tmp_path).verify_in_registry(
        parse_image(IMAGE), DECISION_TYPE, Registry(), {}
    )
    assert outcome.predicate is None and problem in str(outcome.problem)


def test_a_statement_about_another_digest_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    other = [{"name": "shop-api", "digest": {"sha256": "a" * 64}}]
    _capture(monkeypatch, _envelope({"verdict": "PASS"}, subject=other) + "\n")
    outcome = Verifier(tmp_path / "k.pub", LOCK, tmp_path).verify_in_registry(
        parse_image(IMAGE), DECISION_TYPE, Registry(), {}
    )
    assert outcome.predicate is None and "not sha256:" in str(outcome.problem)


def _signatures(*entries: tuple[str, str]) -> str:
    return json.dumps([{"critical": {"type": kind, "image": {"docker-manifest-digest": digest}}}
                       for kind, digest in entries])  # fmt: skip


@pytest.mark.parametrize(
    ("entries", "signed"),
    [([(SIGNATURE_TYPE, f"sha256:{IMAGE_HEX}")], True),
     ([(DECISION_TYPE, f"sha256:{IMAGE_HEX}")], False),  # an attestation: cosign verify accepts it, not us
     ([(SIGNATURE_TYPE, "sha256:" + "a" * 64)], False),
     ([], False)],
    ids=["signed", "only-an-attestation", "another-digest", "none"],
)  # fmt: skip
def test_the_image_signature_is_a_cosign_sign_statement_about_this_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entries: list[tuple[str, str]], signed: bool
) -> None:
    _capture(monkeypatch, _signatures(*entries))
    outcome = Verifier(tmp_path / "k.pub", LOCK, tmp_path).verify_signature(
        parse_image(IMAGE), Registry(), {}
    )
    assert (outcome.problem is None) is signed


@pytest.mark.parametrize("flag", [[], ["--registry-http"]])
def test_verify_reads_the_registry_without_evidence_and_http_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: list[str]
) -> None:
    """The test registry is on 127.0.0.1, which Cosign reaches over HTTP anyway: the flag is checked here."""
    seen: dict[str, Any] = {}

    def fake(image: Any, verifier: Any, registry: Registry, environ: Any, **kwargs: Any) -> Any:
        seen["registry"] = registry
        raise cosign.AttestationError("stop here")

    monkeypatch.setattr(cli, "verify_registry", fake)
    public = tmp_path / "k.pub"
    public.write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", encoding="ascii")
    args = ["verify", IMAGE, "--key", str(public), "--repo", "o/r", "--builder-id", "b",
            "--lock", str(ROOT / "tools.lock.toml"), *flag]  # fmt: skip
    assert CliRunner().invoke(cli.app, args).exit_code == 3
    assert seen["registry"] == Registry(allow_http=bool(flag))
