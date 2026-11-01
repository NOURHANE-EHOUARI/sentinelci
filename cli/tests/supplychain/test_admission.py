"""Kyverno admission of SentinelCI releases (A5, SPEC section 7): the release-evidence ImageValidatingPolicy,
rendered by `sentinel admission-policy`, applied by the real Kyverno CLI to Pods whose images are in a real
registry, attested by `sentinel attest --push` or, for the bad cases, by the release key directly.

`kyverno apply` evaluates the policy the way the admission controller does and reads the signatures and
attestations from the registry, so this is the admission decision without a cluster. Each bad case changes one
thing in an otherwise trusted release, as in the `sentinel verify` tests, and must be refused for that reason:
the two verifiers trust exactly the same images. Real-tool tests are opt-in: set SENTINEL_TOOLS_DIR (crane,
cosign and kyverno installed there).
"""

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.admission import POLICY_NAME, render_policy
from sentinelci.supplychain.attestations import KINDS, AttestationError, parse_image
from sentinelci.supplychain.cosign import SIGNATURE_TYPE

from .conftest import BUILDER, GITHUB_ENV, REPO, decision_bytes
from .oci import REPO_LOCK, TOOLS_DIR, attach, attest, make_keys, needs_tools, predicates, push_image

PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexample0000000000000000000000\n"
    "-----END PUBLIC KEY-----\n"
)


def _render(tmp_path: Path, **changes: Any) -> dict[str, Any]:
    key = tmp_path / "release.pub"
    key.write_text(PUBLIC_KEY, encoding="ascii")
    params: dict[str, Any] = {"public_key": key, "image_glob": "kind-registry:5000/demo-shop/*", "repo": REPO,
                              "builder_id": BUILDER, "allow_http": False} | changes  # fmt: skip
    rendered: dict[str, Any] = yaml.safe_load(render_policy(**params))
    return rendered


# ---------------------------------------------------------------- rendering, without tools


def test_the_policy_requires_the_signature_and_the_four_attestations(tmp_path: Path) -> None:
    policy = _render(tmp_path)
    spec = policy["spec"]
    assert policy["metadata"]["name"] == POLICY_NAME
    assert [a["intoto"]["type"] for a in spec["attestations"]] == [SIGNATURE_TYPE, *KINDS.values()]
    assert spec["attestors"][0]["cosign"]["key"]["data"] == PUBLIC_KEY
    assert spec["matchImageReferences"] == [{"glob": "kind-registry:5000/demo-shop/*"}]
    assert spec["validationActions"] == ["Deny"] and spec["failurePolicy"] == "Fail"
    assert spec["validationConfigurations"] == {"mutateDigest": True, "verifyDigest": True, "required": True}
    assert spec["credentials"] == {"allowInsecureRegistry": False}
    assert _render(tmp_path, allow_http=True)["spec"]["credentials"] == {"allowInsecureRegistry": True}
    expressions = " ".join(v["expression"] for v in spec["validations"])
    assert f"== '{REPO}'" in expressions and f"== '{BUILDER}'" in expressions
    assert f"startsWith('git+https://github.com/{REPO}@')" in expressions
    assert "$" not in yaml.safe_dump(policy), "every placeholder is filled"


def test_the_signatures_are_checked_before_any_payload_is_read(tmp_path: Path) -> None:
    """extractPayload reads only verified statements, and the first failing validation is the reason given."""
    validations = [v["expression"] for v in _render(tmp_path)["spec"]["validations"]]
    names = ["signature", "decision", "sbom", "vuln", "provenance"]
    assert [
        f"attestations.{name}, [attestors.release]" in e for e, name in zip(validations, names, strict=False)
    ] == [True] * 5
    assert not any("extractPayload" in e for e in validations[:5])


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"repo": "o/r' || true || '"}, "--repo"),
        ({"builder_id": BUILDER + "' || true"}, "--builder-id"),
        ({"builder_id": "https://example.com/workflow"}, "--builder-id"),
        ({"image_glob": "Kind-Registry/demo"}, "--image-glob"),
        ({"image_glob": "kind-registry:5000/demo' "}, "--image-glob"),
        ({"image_glob": "*"}, "--image-glob"),
    ],
    ids=[
        "quote-in-repo",
        "quote-in-builder",
        "not-a-workflow",
        "uppercase-glob",
        "quote-in-glob",
        "any-image",
    ],
)
def test_a_value_that_could_change_the_policy_is_refused(
    tmp_path: Path, changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(AttestationError, match=message):
        _render(tmp_path, **changes)


def test_a_file_that_is_not_a_public_key_is_refused(tmp_path: Path) -> None:
    key = tmp_path / "release.key"
    key.write_text("-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nAAAA\n-----END ...\n", encoding="ascii")
    with pytest.raises(AttestationError, match="not a PEM public key"):
        render_policy(public_key=key, image_glob="r/x/*", repo=REPO, builder_id=BUILDER, allow_http=False)


def test_the_cli_writes_the_policy_and_refuses_bad_values(tmp_path: Path) -> None:
    key, out = tmp_path / "release.pub", tmp_path / "deploy" / "policy.yaml"
    key.write_text(PUBLIC_KEY, encoding="ascii")
    args = ["admission-policy", "--key", str(key), "--repo", REPO, "--builder-id", BUILDER,
            "--image-glob", "kind-registry:5000/demo-shop/*", "--out", str(out)]  # fmt: skip
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["metadata"]["name"] == POLICY_NAME
    out.write_text("stale", encoding="utf-8")
    result = CliRunner().invoke(app, [*args[:-2], "--repo", "not a repo", "--out", str(out)])
    assert result.exit_code == 3 and not out.exists(), "a refused render leaves no policy behind"


# ---------------------------------------------------------------- the real Kyverno, Cosign and registry


def _pod(name: str, image: str, init: str | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [{"name": "app", "image": image}]}
    if init is not None:
        spec["initContainers"] = [{"name": "init", "image": init}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "shop"}, "spec": spec}


def admit(work: Path, policy: str, pods: list[dict[str, Any]]) -> dict[str, tuple[str, str]]:
    """Pod name -> (result, message) as `kyverno apply` reports them; a Pod the policy does not match has
    no result."""
    work.mkdir(parents=True, exist_ok=True)
    (work / "policy.yaml").write_text(policy, encoding="utf-8")
    (work / "pods.yaml").write_text(yaml.safe_dump_all(pods), encoding="utf-8")
    run = run_verified_tool(
        "kyverno",
        ["apply", "policy.yaml", "--resource", "pods.yaml", "--policy-report", "--output-format", "json",
         "--remove-color"],
        lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=work, allowed_exit_codes=(0, 1),
    )  # fmt: skip
    report = json.loads(run.stdout)
    return {
        r["resources"][0]["name"]: (r["result"], r.get("message", "")) for r in report.get("results") or []
    }


def _with(signed: dict[str, Any], kind: str, path: str, value: Any) -> dict[str, Any]:
    changed = copy.deepcopy(signed)
    node = changed[kind]
    *parents, leaf = path.split(".")
    for parent in parents:
        node = node[parent]
    node[leaf] = value
    return changed


@pytest.fixture(scope="module")
def release(crane: Path, registry: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """Every case pushed once for the module: the good release and one image per bad case."""
    if not TOOLS_DIR:
        pytest.skip("set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
    work = tmp_path_factory.mktemp("admission")
    with pytest.MonkeyPatch.context() as env:
        for name, value in GITHUB_ENV.items():
            env.setenv(name, value)
        env.setenv("COSIGN_PASSWORD", "")
        keys = make_keys(work / "keys")
        images: dict[str, str] = {}

        def image(name: str) -> str:
            images[name] = push_image(crane, registry, work)
            return images[name]

        good = image("good")
        (work / "good").mkdir()
        assert attest(work / "good", good, keys["release.key"]).exit_code == 0
        image("unsigned")
        attach(image("no-image-signature"), keys["release.key"],
               predicates(work, images["no-image-signature"]), sign=False)  # fmt: skip
        blocking = [{"rule": "SC-002", "effect": "BLOCK", "finding_ids": ["c" * 64], "message": "P0"}]
        bad: dict[str, tuple[str, str, Any]] = {
            "pr-decision": ("decision", "subject.context", "pr"),
            "another-repository": ("decision", "subject.repo", "someone/else"),
            "another-builder": ("provenance", "runDetails.builder.id", BUILDER.replace("main", "dev")),
            "another-commit": ("provenance", "buildDefinition.resolvedDependencies.0.digest.gitCommit",
                               "f" * 40),
            "vuln-another-decision": ("vuln", "scanner.result.decision_id",
                                      "00000000-0000-4000-8000-000000000000"),
            "vuln-other-findings": ("vuln", "scanner.result.findings_digest", "sha256:" + "0" * 64),
            "vuln-other-sbom": ("vuln", "scanner.result.sbom.digest", "sha256:" + "0" * 64),
            "sbom-other-serial": ("sbom", "serialNumber", "urn:uuid:00000000-0000-4000-8000-000000000000"),
        }  # fmt: skip
        for name, (kind, path, value) in bad.items():
            target = image(name)
            signed = predicates(work, target)
            if path.startswith("buildDefinition.resolvedDependencies.0."):
                signed = copy.deepcopy(signed)
                signed[kind]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = value
            else:
                signed = _with(signed, kind, path, value)
            attach(target, keys["release.key"], signed)
        two = image("a-second-source-commit")  # every source of the repository, not just one
        signed = copy.deepcopy(predicates(work, two))
        dependencies = signed["provenance"]["buildDefinition"]["resolvedDependencies"]
        dependencies.append({**dependencies[0], "digest": {"gitCommit": "e" * 40}})
        attach(two, keys["release.key"], signed)
        block = image("block")
        blocked = decision_bytes(
            subject__image_digest=parse_image(block).digest, verdict="BLOCK", violations=blocking
        )
        attach(block, keys["release.key"], predicates(work, block) | {"decision": json.loads(blocked)})
        no_sbom = image("no-sbom")
        attach(
            no_sbom, keys["release.key"], {k: v for k, v in predicates(work, no_sbom).items() if k != "sbom"}
        )
        other = image("decision-of-another-image")
        attach(other, keys["release.key"], predicates(work, good))
        yield {"keys": keys, "images": images, "registry": registry, "work": work}


def _policy(release: dict[str, Any], key: str = "release.pub", builder: str = BUILDER) -> str:
    return render_policy(
        public_key=release["keys"][key], image_glob=f"{release['registry']}/demo-shop/*", repo=REPO,
        builder_id=builder, allow_http=True,
    )  # fmt: skip


EXPECTED = {
    "good": ("pass", "success"),
    "unsigned": ("fail", "signature: the image itself is not signed by the release key"),
    "no-image-signature": ("fail", "signature: the image itself is not signed by the release key"),
    "no-sbom": ("fail", "signature: no SBOM (CycloneDX) signed by the release key"),
    "pr-decision": ("fail", "decision: not a release decision"),
    "block": ("fail", "decision: the verdict is BLOCK"),
    "decision-of-another-image": ("fail", "decision: about another image"),
    "another-repository": ("fail", "decision: from another repository"),
    "another-builder": ("fail", "provenance: not built by the release workflow"),
    "another-commit": ("fail", "provenance: not built from the decision's commit"),
    "a-second-source-commit": ("fail", "provenance: not built from the decision's commit"),
    "vuln-another-decision": ("fail", "vulnerability scan: does not name this decision"),
    "vuln-other-findings": ("fail", "vulnerability scan: not the decision's findings"),
    "vuln-other-sbom": ("fail", "vulnerability scan: not the decision's SBOM"),
    "sbom-other-serial": ("fail", "SBOM: not the one the vulnerability scan names"),
}


@needs_tools
@pytest.mark.integration
def test_only_a_complete_release_is_admitted_and_each_bad_case_for_its_own_reason(
    release: dict[str, Any],
) -> None:
    pods = [_pod(name, reference) for name, reference in release["images"].items()]
    results = admit(release["work"] / "all", _policy(release), pods)
    assert {name: (result, message.strip()) for name, (result, message) in results.items()} == EXPECTED


@needs_tools
@pytest.mark.integration
def test_every_container_is_checked_and_an_image_needs_a_digest(release: dict[str, Any]) -> None:
    good, unsigned = release["images"]["good"], release["images"]["unsigned"]
    pods = [
        _pod("unsigned-init", good, init=unsigned),
        _pod("by-tag", f"{release['registry']}/demo-shop/shop-api:candidate"),
        _pod("not-ours", f"{release['registry']}/elsewhere/tool@{parse_image(unsigned).digest}"),
    ]
    results = admit(release["work"] / "containers", _policy(release), pods)
    assert results["unsigned-init"] == (
        "fail",
        "signature: the image itself is not signed by the release key",
    )
    assert results["by-tag"][0] == "fail" and "does not have a digest" in results["by-tag"][1]
    assert results["not-ours"] == ("pass", "success"), "the glob decides what this policy checks"


@needs_tools
@pytest.mark.integration
def test_the_policy_trusts_only_its_own_key_and_workflow(release: dict[str, Any]) -> None:
    good = [_pod("good", release["images"]["good"])]
    other_key = admit(release["work"] / "key", _policy(release, key="other.pub"), good)
    assert other_key["good"] == ("fail", "signature: the image itself is not signed by the release key")
    other_builder = admit(release["work"] / "builder", _policy(release, builder=BUILDER + "x"), good)
    assert other_builder["good"] == ("fail", "provenance: not built by the release workflow")


@needs_tools
@pytest.mark.integration
def test_sentinel_verify_agrees_with_admission_on_every_case(release: dict[str, Any]) -> None:
    """The two verifiers are the same rules: every image admission refuses, `sentinel verify` refuses."""
    for name, reference in release["images"].items():
        result = CliRunner().invoke(
            app,
            ["verify", reference, "--key", str(release["keys"]["release.pub"]), "--repo", REPO,
             "--builder-id", BUILDER, "--registry-http", "--lock", str(REPO_LOCK),
             "--tools-dir", str(TOOLS_DIR)],
        )  # fmt: skip
        assert (result.exit_code == 0) is (EXPECTED[name][0] == "pass"), (name, result.output)
