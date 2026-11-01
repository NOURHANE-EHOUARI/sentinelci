"""The four release predicates and the bindings the signer checks before anything is signed (ADR-0010)."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinelci.supplychain.attestations import (
    GITHUB_ACTIONS_BUILD_TYPE,
    KINDS,
    AttestationError,
    VulnResult,
    parse_image,
    release_predicates,
)

from .conftest import (
    BUILDER,
    COMMIT,
    GITHUB_ENV,
    IMAGE,
    IMAGE_HEX,
    OTHER_IMAGE_HEX,
    REPO,
    ROOT,
    SERIAL,
    decision_bytes,
    findings_bytes,
    sbom_bytes,
    sha,
)

VULN_FIXTURES = ROOT / "schemas" / "fixtures" / "vuln-result"


def predicates(**overrides: Any) -> dict[str, Any]:
    inputs: dict[str, Any] = {
        "decision_data": decision_bytes(),
        "findings_data": findings_bytes(),
        "sbom_data": sbom_bytes(),
        "env": GITHUB_ENV,
    }
    inputs.update(overrides)
    return release_predicates(parse_image(IMAGE), **inputs)


def test_the_four_predicates_of_a_release() -> None:
    result = predicates()
    assert set(result) == set(KINDS) == {"decision", "sbom", "vuln", "provenance"}
    assert result["decision"] == json.loads(decision_bytes())
    assert result["sbom"] == json.loads(sbom_bytes())

    vuln = result["vuln"]
    assert vuln["metadata"] == {
        "scanStartedOn": "2026-11-10T10:00:00Z",
        "scanFinishedOn": "2026-11-10T10:00:00Z",
    }
    assert vuln["scanner"]["uri"] == "pkg:github/NOURHANE-EHOUARI/sentinelci@0.1.0"
    assert vuln["invocation"]["builder.id"] == BUILDER
    assert vuln["scanner"]["result"] == {
        "schema_version": "1.0",
        "decision_id": "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9f",
        "findings_digest": sha(findings_bytes()),
        "sbom": {"digest": sha(sbom_bytes()), "serial_number": SERIAL},
        "totals": {
            "findings": 3,
            "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
            "by_category": {"CONTAINER": 1, "SCA": 1, "SECRET": 1},
        },
        "tools": {"gitleaks": "8.30.1", "grype": "0.121.0", "trivy": "0.76.1"},
    }

    provenance = result["provenance"]
    assert provenance["buildDefinition"]["buildType"] == GITHUB_ACTIONS_BUILD_TYPE
    assert provenance["buildDefinition"]["resolvedDependencies"] == [
        {"uri": f"git+https://github.com/{REPO}@refs/heads/main", "digest": {"gitCommit": COMMIT}}
    ]
    assert provenance["runDetails"] == {
        "builder": {"id": BUILDER},
        "metadata": {"invocationId": f"https://github.com/{REPO}/actions/runs/1234567890/attempts/1"},
    }


def test_the_predicates_never_depend_on_the_clock() -> None:
    assert json.dumps(predicates(), sort_keys=True) == json.dumps(predicates(), sort_keys=True)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"decision_data": decision_bytes(verdict="BLOCK", violations=[
            {"rule": "SC-001", "effect": "BLOCK", "finding_ids": ["c" * 64], "message": "secret"}])},
         "BLOCK: a blocked image is never signed"),
        ({"decision_data": decision_bytes(subject__context="pr")}, "context 'pr', not 'release'"),
        ({"decision_data": decision_bytes(subject__image_digest=f"sha256:{OTHER_IMAGE_HEX}")},
         "is about image sha256:aaaa"),
        ({"decision_data": b"{}"}, "not a Decision v1"),
        ({"findings_data": findings_bytes() + b"\n"}, "findings file is not the one the decision recorded"),
        ({"sbom_data": sbom_bytes() + b" "}, "SBOM file is not the one the decision recorded"),
        ({"decision_data": decision_bytes(inputs__sbom_digest=sha(sbom_bytes(serial=None))),
          "sbom_data": sbom_bytes(serial=None)}, "no CycloneDX serialNumber"),
        ({"decision_data": decision_bytes(inputs__sbom_digest=sha(b'{"spdxVersion": "SPDX-2.3"}')),
          "sbom_data": b'{"spdxVersion": "SPDX-2.3"}'}, "not a CycloneDX JSON document"),
        ({"env": {**GITHUB_ENV, "GITHUB_ACTIONS": "false"}}, "GitHub Actions only"),
        ({"env": {**GITHUB_ENV, "GITHUB_SHA": "0" * 40}}, "but the decision is about"),
        ({"env": {**GITHUB_ENV, "GITHUB_REPOSITORY": "someone/else"}}, "but the decision is about"),
        ({"env": {**GITHUB_ENV, "GITHUB_WORKFLOW_REF": "release.yml"}}, "GITHUB_WORKFLOW_REF"),
        ({"env": {k: v for k, v in GITHUB_ENV.items() if k != "GITHUB_RUN_ID"}}, "GITHUB_RUN_ID"),
        ({"env": {**GITHUB_ENV, "GITHUB_REF": "refs/heads/main\nx"}}, "GITHUB_REF"),
        ({"env": {**GITHUB_ENV, "GITHUB_SERVER_URL": "https://ghe.example"}}, "github.com only"),
    ],
    ids=[
        "block", "pr-context", "another-image", "not-a-decision", "other-findings", "other-sbom",
        "sbom-without-serial", "spdx-sbom", "not-github-actions", "other-commit", "other-repository",
        "malformed-workflow-ref", "missing-run-id", "ref-with-line-break", "other-server",
    ],
)  # fmt: skip
def test_inputs_that_do_not_belong_together_are_never_signed(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(AttestationError, match=message):
        predicates(**overrides)


def test_a_release_needs_an_sbom() -> None:
    decision = json.loads(decision_bytes())
    del decision["inputs"]["sbom_digest"]
    with pytest.raises(AttestationError, match="records no SBOM"):
        predicates(decision_data=json.dumps(decision).encode())


@pytest.mark.parametrize(
    "reference",
    [
        "shop-api:1.0",  # a tag alone
        f"shop-api@sha256:{IMAGE_HEX.upper()}",
        f"shop-api@sha256:{IMAGE_HEX[:-1]}",
        f"shop-api@sha512:{IMAGE_HEX}",
        f"Shop-API@sha256:{IMAGE_HEX}",
        f"shop-api@sha256:{IMAGE_HEX}\n",
        f"@sha256:{IMAGE_HEX}",
    ],
)
def test_only_digest_references_are_images(reference: str) -> None:
    with pytest.raises(AttestationError, match="not <name>@sha256"):
        parse_image(reference)


def test_an_image_reference() -> None:
    image = parse_image(f"localhost:5001/demo-shop/shop-api:1.0@sha256:{IMAGE_HEX}")
    assert (image.name, image.digest) == ("localhost:5001/demo-shop/shop-api:1.0", f"sha256:{IMAGE_HEX}")


def _accepted(path: Path) -> bool:
    try:
        return VulnResult.model_validate_json(path.read_bytes()).problem() is None
    except ValidationError:
        return False


@pytest.mark.parametrize("path", sorted((VULN_FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_the_read_model_accepts_the_valid_contract_fixtures(path: Path) -> None:
    assert _accepted(path)


@pytest.mark.parametrize("path", sorted((VULN_FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_the_read_model_refuses_the_invalid_contract_fixtures(path: Path) -> None:
    assert not _accepted(path)


@pytest.mark.parametrize(
    "totals",
    [
        {"findings": 3, "by_severity": {"HIGH": 2}, "by_category": {"SCA": 3}},
        {"findings": 3, "by_severity": {"HIGH": 3}, "by_category": {"SCA": 2}},
    ],
)
def test_totals_must_add_up(totals: dict[str, Any]) -> None:
    document = json.loads((VULN_FIXTURES / "valid" / "release-with-findings.json").read_text())
    document["totals"] = totals
    problem = VulnResult.model_validate_json(json.dumps(document)).problem()
    assert problem is not None and "adds up to 2, not totals.findings (3)" in problem


@pytest.mark.parametrize(
    ("tool_versions", "message"),
    [
        (
            {"gitleaks": "8.30.1", "Trivy": "0.76.1"},
            r"contract refuses: tools\.Trivy\.\[key\]: String should match",
        ),
        ({"trivy": "0.76.1\n"}, r"contract refuses: tools\.trivy: Value error, must be a single line"),
        ({"trivy": "0.76\u2028.1"}, "must be a single line"),
    ],
    ids=["tool-name-not-lowercase", "version-with-a-newline", "version-with-a-line-separator"],
)
def test_the_signer_refuses_a_result_the_contract_or_verify_would_refuse(
    tool_versions: dict[str, str], message: str
) -> None:
    """Review of #35, should fix 2: a Decision v1 allows any tool name and version, the vuln-result does
    not."""
    with pytest.raises(AttestationError, match=message):
        predicates(decision_data=decision_bytes(inputs__tool_versions=tool_versions))


def test_the_signer_refuses_a_result_verify_would_find_inconsistent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Counting cannot give totals that do not add up today; the check keeps it so if the counting changes.
    monkeypatch.setattr(VulnResult, "problem", lambda self: "totals.by_severity adds up to 2")
    with pytest.raises(AttestationError, match=r"would be inconsistent: totals\.by_severity adds up to 2"):
        predicates()
