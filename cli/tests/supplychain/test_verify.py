"""`sentinel attest` then `sentinel verify`, with the real Cosign and key pairs generated per test (ADR-0010).

SPEC section 7: verify must fail on unsigned, wrong key, modified image, missing or BLOCK decision. Each bad
case below changes one thing in an otherwise trusted release. The trust checks themselves are also tested
without Cosign, on verified predicates. Real-tool tests are opt-in: set SENTINEL_TOOLS_DIR.
"""

import base64
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from sentinelci.cli import app
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.attestations import KINDS, AttestationError, parse_image, release_predicates
from sentinelci.supplychain.cosign import Signer, Verified
from sentinelci.supplychain.verify import trust_checks

from .conftest import (
    BUILDER,
    GITHUB_ENV,
    IMAGE,
    IMAGE_HEX,
    OTHER_IMAGE_HEX,
    REPO,
    ROOT,
    decision_bytes,
    findings_bytes,
    sbom_bytes,
)

REPO_LOCK = ROOT / "tools.lock.toml"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


# ---------------------------------------------------------------- trust checks, without Cosign


def verified(**changes: Any) -> dict[str, Verified]:
    good = release_predicates(
        parse_image(IMAGE),
        decision_data=decision_bytes(),
        findings_data=findings_bytes(),
        sbom_data=sbom_bytes(),
        env=GITHUB_ENV,
    )
    outcomes = {kind: Verified(json.loads(json.dumps(predicate)), None) for kind, predicate in good.items()}
    outcomes.update(changes)
    return outcomes


def failed(outcomes: dict[str, Verified], *, builder: str = BUILDER, repo: str = REPO) -> list[str]:
    checks = trust_checks(parse_image(IMAGE), outcomes, repo=repo, builder_id=builder)
    assert len(checks) == 15, "every check is always reported"
    return [check.name for check in checks if not check.ok]


def test_a_complete_release_passes_every_check() -> None:
    assert failed(verified()) == []


def _with(kind: str, edit: Callable[[Any], None]) -> dict[str, Verified]:
    outcomes = verified()
    predicate = json.loads(json.dumps(outcomes[kind].predicate))
    edit(predicate)
    outcomes[kind] = Verified(predicate, None)
    return outcomes


def _set(path: str, value: Any) -> Callable[[Any], None]:
    def edit(node: Any) -> None:
        *parents, leaf = path.split(".")
        for parent in parents:
            node = node[int(parent)] if parent.isdigit() else node[parent]
        node[leaf] = value

    return edit


OTHER_SOURCE = "git+https://github.com/x/y@main"
DEPENDENCY = "buildDefinition.resolvedDependencies.0"
BLOCK = [{"rule": "SC-001", "effect": "BLOCK", "finding_ids": ["c" * 64], "message": "Hard-coded secret"}]
VULN_UNAVAILABLE = [
    "vulnerability scan: names this decision",
    "vulnerability scan: the decision's findings",
    "vulnerability scan: the decision's SBOM",
    "SBOM: the one the vulnerability scan names",
]


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        (lambda: _with("decision", lambda d: d.update(verdict="BLOCK", violations=BLOCK)),
         ["decision: verdict is not BLOCK"]),
        (lambda: _with("decision", _set("subject.context", "pr")), ["decision: release context"]),
        (lambda: _with("decision", _set("subject.image_digest", f"sha256:{OTHER_IMAGE_HEX}")),
         ["decision: about this image"]),
        (lambda: _with("decision", _set("subject.repo", "someone/else")),
         ["decision: from the expected repository"]),
        (lambda: _with("provenance", _set("runDetails.builder.id", BUILDER.replace("main", "dev"))),
         ["provenance: built by the expected workflow"]),
        (lambda: _with("provenance", _set(f"{DEPENDENCY}.digest.gitCommit", "0" * 40)),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("provenance", _set(f"{DEPENDENCY}.uri", OTHER_SOURCE)),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("provenance", _set(f"{DEPENDENCY}.uri", f"git+https://github.com/{REPO}-fork@main")),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("provenance", lambda p: p["buildDefinition"]["resolvedDependencies"].append(
            {"uri": f"git+https://github.com/{REPO}@refs/heads/dev", "digest": {"gitCommit": "0" * 40}})),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("provenance", _set(f"{DEPENDENCY}.digest", "sha1:" + "0" * 40)),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("provenance", _set("buildDefinition.resolvedDependencies", 3)),
         ["provenance: built from the decision's commit"]),
        (lambda: _with("vuln", _set("scanner.result.decision_id", "00000000-0000-0000-0000-000000000000")),
         ["vulnerability scan: names this decision"]),
        (lambda: _with("vuln", _set("scanner.result.findings_digest", "sha256:" + "9" * 64)),
         ["vulnerability scan: the decision's findings"]),
        (lambda: _with("vuln", _set("scanner.result.sbom.digest", "sha256:" + "9" * 64)),
         ["vulnerability scan: the decision's SBOM"]),
        (lambda: _with("sbom", _set("serialNumber", "urn:uuid:00000000-0000-0000-0000-000000000000")),
         ["SBOM: the one the vulnerability scan names"]),
        (lambda: _with("sbom", _set("bomFormat", "SPDX")), ["SBOM: the one the vulnerability scan names"]),
        (lambda: _with("vuln", _set("scanner.result.totals.findings", 4)), VULN_UNAVAILABLE),
        (lambda: _with("vuln", _set("scanner", ["x"])), VULN_UNAVAILABLE),
        (lambda: _with("vuln", _set("scanner.result.tools", {"Trivy": "0.76.1"})), VULN_UNAVAILABLE),
    ],
    ids=[
        "block", "pr-context", "another-image", "another-repository", "another-builder", "another-commit",
        "another-source", "a-fork", "a-second-source", "digest-not-an-object", "dependencies-not-a-list",
        "another-decision", "other-findings", "other-sbom-digest", "other-sbom", "not-cyclonedx",
        "totals-do-not-add-up", "scanner-not-an-object", "tool-name-not-lowercase",
    ],
)  # fmt: skip
def test_each_binding_is_checked(outcomes: Callable[[], dict[str, Verified]], expected: list[str]) -> None:
    assert failed(outcomes()) == expected


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (_set("scanner.result.totals.findings", 4), "scanner.result totals.by_severity adds up to 3, not"),
        (_set("scanner.result.tools", {"Trivy": "0.76.1"}), "tools.Trivy.[key]: String should match pattern"),
        (_set("scanner", ["x"]), "scanner.result is not a vuln-result v1: Input should be an object"),
    ],
    ids=["totals", "tool-name", "scanner-not-an-object"],
)
def test_a_malformed_vulnerability_result_says_why(edit: Callable[[Any], None], reason: str) -> None:
    """Review of #35, should fix 2 and nit 2: the reason names the problem, and nothing raises."""
    checks = trust_checks(parse_image(IMAGE), _with("vuln", edit), repo=REPO, builder_id=BUILDER)
    details = {check.detail for check in checks if check.name == VULN_UNAVAILABLE[0]}
    assert len(details) == 1 and reason in details.pop()


@pytest.mark.parametrize(
    "content",
    [
        None,
        "",
        "not a key\n",
        "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nAAAA\n"
        "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n",
    ],
    ids=["missing", "empty", "garbage", "a-private-key"],
)
def test_a_missing_or_unreadable_public_key_means_verify_could_not_run(
    tmp_path: Path, content: str | None
) -> None:
    """Review of #35, nit 1: exit 3 (could not run), not 1 (this image is not trusted). Cosign never
    starts."""
    key = tmp_path / "cosign.pub"
    if content is not None:
        key.write_text(content)
    result = verify(key, tmp_path / "evidence")
    assert result.exit_code == 3, result.output
    assert "FAIL CLOSED" in result.output and "AAAA" not in result.output
    assert f"{key} is not a PEM public key" in result.output or "cannot be read" in result.output


def test_a_missing_attestation_fails_closed() -> None:
    missing = {"decision": Verified(None, "missing (unsigned)")}
    assert failed(verified(**missing)) == [
        "signature: release decision",
        "decision: valid Decision v1",
        "decision: release context",
        "decision: verdict is not BLOCK",
        "decision: about this image",
        "decision: from the expected repository",
        "provenance: built from the decision's commit",
        "vulnerability scan: names this decision",
        "vulnerability scan: the decision's findings",
        "vulnerability scan: the decision's SBOM",
    ]
    for kind in KINDS:
        assert f"signature: {kind}" not in failed(verified())
        assert failed(verified(**{kind: Verified(None, "missing (unsigned)")}))


def test_the_options_name_what_is_expected() -> None:
    assert failed(verified(), repo="someone/else") == [
        "decision: from the expected repository",
        "provenance: built from the decision's commit",
    ]
    assert failed(verified(), builder=BUILDER + "x") == ["provenance: built by the expected workflow"]


# ---------------------------------------------------------------- the real Cosign


def _cosign(args: list[str], cwd: Path) -> None:
    run_verified_tool(
        "cosign", args, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=cwd,
        extra_env={"COSIGN_PASSWORD": ""},
    )  # fmt: skip


@pytest.fixture
def keys(tmp_path: Path) -> dict[str, Path]:
    """Two key pairs made by the pinned Cosign for this test only: never committed, never reused."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    for prefix in ("release", "other"):
        _cosign(["generate-key-pair", "--output-key-prefix", prefix], keys_dir)
    return {name: keys_dir / name for name in ("release.key", "release.pub", "other.key", "other.pub")}


@pytest.fixture
def release(tmp_path: Path) -> dict[str, Path]:
    files = {"decision": decision_bytes(), "findings": findings_bytes(), "sbom": sbom_bytes()}
    paths = {name: tmp_path / f"{name}.json" for name in files}
    for name, data in files.items():
        paths[name].write_bytes(data)
    return paths


def attest(release: dict[str, Path], key: str, out: Path, image: str = IMAGE) -> Result:
    return CliRunner().invoke(
        app,
        [
            "attest", image, "--decision", str(release["decision"]), "--findings", str(release["findings"]),
            "--sbom", str(release["sbom"]), "--key", key, "--out", str(out),
            "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR),
        ],
    )  # fmt: skip


def verify(public_key: Path, evidence: Path, image: str = IMAGE, builder: str = BUILDER) -> Result:
    return CliRunner().invoke(
        app,
        [
            "verify", image, "--key", str(public_key), "--repo", REPO, "--builder-id", builder,
            "--evidence", str(evidence), "--lock", str(REPO_LOCK), "--tools-dir", str(TOOLS_DIR),
        ],
    )  # fmt: skip


@pytest.fixture
def evidence(
    tmp_path: Path, keys: dict[str, Path], release: dict[str, Path], github_env: dict[str, str]
) -> Path:
    out = tmp_path / "evidence"
    result = attest(release, str(keys["release.key"]), out)
    assert result.exit_code == 0, result.output
    return out


@real
@pytest.mark.integration
def test_a_signed_release_is_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    assert sorted(p.name for p in (evidence / "attestations").iterdir()) == [
        "decision.sigstore.json", "provenance.sigstore.json", "sbom.sigstore.json", "vuln.sigstore.json",
    ]  # fmt: skip
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 0, result.output
    assert "TRUSTED: 15/15 checks passed" in result.output
    assert "[FAIL]" not in result.output


@real
@pytest.mark.integration
def test_unsigned_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    (evidence / "attestations" / "provenance.sigstore.json").unlink()
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 1
    assert "[FAIL] signature: provenance (SLSA v1): missing (unsigned)" in result.output


@real
@pytest.mark.integration
def test_the_wrong_key_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    result = verify(keys["other.pub"], evidence)
    assert result.exit_code == 1
    assert result.output.count("[FAIL] signature:") == 4, result.output


@real
@pytest.mark.integration
def test_a_modified_image_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    result = verify(keys["release.pub"], evidence, image=IMAGE.replace(IMAGE_HEX, OTHER_IMAGE_HEX))
    assert result.exit_code == 1
    assert result.output.count("[FAIL] signature:") == 4, result.output
    assert "does not match any digest in statement" in result.output


@real
@pytest.mark.integration
def test_a_missing_decision_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    (evidence / "attestations" / "decision.sigstore.json").unlink()
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 1
    assert "[FAIL] decision: verdict is not BLOCK: no verified decision attestation" in result.output


@real
@pytest.mark.integration
def test_a_tampered_bundle_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    # Rewrite the signed decision to say PASS: the signature no longer matches the payload.
    path = evidence / "attestations" / "decision.sigstore.json"
    bundle = json.loads(path.read_text())
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    statement["predicate"].update(verdict="PASS", violations=[])
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    path.write_text(json.dumps(bundle))
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 1
    assert "[FAIL] signature: release decision: signature check failed" in result.output


@real
@pytest.mark.integration
def test_a_bundle_of_another_kind_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    # A validly signed provenance put where the decision belongs: right key and digest, wrong predicate type.
    attestations = evidence / "attestations"
    shutil.copy(attestations / "provenance.sigstore.json", attestations / "decision.sigstore.json")
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 1
    assert "[FAIL] signature: release decision: signature check failed: " in result.output


@real
@pytest.mark.integration
def test_a_block_decision_is_never_signed_and_never_trusted(
    tmp_path: Path,
    keys: dict[str, Path],
    release: dict[str, Path],
    github_env: dict[str, str],
    evidence: Path,
) -> None:
    block = json.loads(decision_bytes())
    block.update(verdict="BLOCK", violations=BLOCK)
    release["decision"].write_text(json.dumps(block))
    out = tmp_path / "refused"
    result = attest(release, str(keys["release.key"]), out)
    assert result.exit_code == 3 and "never signed" in result.output
    assert not (out / "attestations").exists() or not any((out / "attestations").iterdir())

    # Signed anyway, with the right key, by something other than `sentinel attest`: still refused.
    signer = Signer(str(keys["release.key"]), load_lock(REPO_LOCK), Path(str(TOOLS_DIR)))
    signer.attest(
        parse_image(IMAGE), KINDS["decision"], block, evidence / "attestations" / "decision.sigstore.json",
        {"COSIGN_PASSWORD": ""},
    )  # fmt: skip
    result = verify(keys["release.pub"], evidence)
    assert result.exit_code == 1
    assert "[FAIL] decision: verdict is not BLOCK: verdict BLOCK" in result.output


@real
@pytest.mark.integration
def test_another_builder_is_not_trusted(evidence: Path, keys: dict[str, Path]) -> None:
    result = verify(keys["release.pub"], evidence, builder=BUILDER.replace("release.yml", "other.yml"))
    assert result.exit_code == 1
    assert "[FAIL] provenance: built by the expected workflow" in result.output


@real
@pytest.mark.integration
def test_the_key_can_come_from_an_environment_variable(
    tmp_path: Path, keys: dict[str, Path], release: dict[str, Path], github_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    monkeypatch.setenv("SENTINEL_TEST_SIGNING_KEY", keys["release.key"].read_text())
    out = tmp_path / "from-env"
    result = attest(release, "env://SENTINEL_TEST_SIGNING_KEY", out)
    assert result.exit_code == 0, result.output
    assert verify(keys["release.pub"], out).exit_code == 0
    monkeypatch.delenv("SENTINEL_TEST_SIGNING_KEY")
    result = attest(release, "env://SENTINEL_TEST_SIGNING_KEY", out)
    assert result.exit_code == 3 and "is empty or not set" in result.output
    assert not any((out / "attestations").iterdir()), "all four or none"


@real
@pytest.mark.integration
def test_a_cosign_binary_that_does_not_match_the_lock_cannot_verify(
    tmp_path: Path, evidence: Path, keys: dict[str, Path]
) -> None:
    tools = tmp_path / "tools"
    shutil.copytree(Path(str(TOOLS_DIR)), tools, symlinks=True)
    cosign = tools / "bin" / "cosign"
    cosign.unlink()
    cosign.write_text("#!/bin/sh\nexit 0\n")
    cosign.chmod(0o755)
    result = CliRunner().invoke(
        app,
        [
            "verify", IMAGE, "--key", str(keys["release.pub"]), "--repo", REPO, "--builder-id", BUILDER,
            "--evidence", str(evidence), "--lock", str(REPO_LOCK), "--tools-dir", str(tools),
        ],
    )  # fmt: skip
    assert result.exit_code == 3, result.output
    assert "FAIL CLOSED" in result.output


@pytest.mark.parametrize(
    "error",
    [AttestationError("the signing service went away"), RuntimeError("a bug")],
    ids=["expected", "bug"],
)
def test_a_failure_halfway_leaves_no_evidence(
    tmp_path: Path,
    release: dict[str, Path],
    github_env: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    """All four bundles or none: a signature that fails at the third attestation removes the first two, even
    when the failure is a bug, and a stale bundle from an earlier run never survives a failed attempt."""
    signed: list[str] = []

    def flaky(self: Signer, image: Any, predicate_type: str, predicate: Any, out: Path, environ: Any) -> None:
        if len(signed) == 2:
            raise error
        out.write_text("{}")
        signed.append(predicate_type)

    monkeypatch.setattr(Signer, "attest", flaky)
    out = tmp_path / "evidence"
    (out / "attestations").mkdir(parents=True)
    (out / "attestations" / "provenance.sigstore.json").write_text("stale")
    key = tmp_path / "release.key"
    key.write_text("not used by the fake signer")
    result = attest(release, str(key), out)
    if isinstance(error, AttestationError):
        assert result.exit_code == 3 and "nothing was signed" in result.output
    else:
        assert result.exception is error
    assert len(signed) == 2, "the first two were written before the failure"
    assert list((out / "attestations").iterdir()) == []
