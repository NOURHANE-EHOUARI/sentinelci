"""Kyverno admission of SentinelCI releases (A5, SPEC section 7): the release-evidence ImageValidatingPolicy,
rendered by `sentinel admission-policy`, applied by the real Kyverno CLI to Pods whose images are in a real
registry, attested by `sentinel attest --push` or, for the bad cases, by the release key directly.

`kyverno apply` evaluates the policy the way the admission controller does and reads the signatures and
attestations from the registry, so this is the admission decision without a cluster. Each bad case changes one
thing in an otherwise trusted release, as in the `sentinel verify` tests, and must be refused for that reason;
`sentinel verify` must refuse it too (the verdicts are compared, not the reasons). Real-tool tests are
opt-in: set SENTINEL_TOOLS_DIR (crane, cosign and kyverno installed there).
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
from sentinelci.supplychain.admission import DECISION_VERSIONS, POLICY_NAME, render_policy
from sentinelci.supplychain.attestations import KINDS, AttestationError, local_release_builder_id, parse_image
from sentinelci.supplychain.cosign import SIGNATURE_TYPE

from .conftest import BUILDER, GITHUB_ENV, REPO, ROOT, decision_bytes
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
    rendered: dict[str, Any] = next(yaml.safe_load_all(render_policy(**params)))
    return rendered


# ---------------------------------------------------------------- rendering, without tools


def test_the_policy_requires_the_signature_and_the_four_attestations(tmp_path: Path) -> None:
    policy = _render(tmp_path)
    spec = policy["spec"]
    assert policy["metadata"]["name"] == POLICY_NAME
    assert [a["intoto"]["type"] for a in spec["attestations"]] == [SIGNATURE_TYPE, *KINDS.values()]
    assert spec["attestors"][0]["cosign"]["key"]["data"] == PUBLIC_KEY
    assert spec["matchImageReferences"] == [
        {"expression": "ref.lowerAscii().startsWith('kind-registry:5000/demo-shop/')"}
    ]
    (rule,) = spec["matchConstraints"]["resourceRules"]
    assert rule["operations"] == ["CREATE", "UPDATE"]
    assert rule["resources"] == ["pods"], "the ephemeral containers have their own document"
    assert spec["validationActions"] == ["Deny"] and spec["failurePolicy"] == "Fail"
    assert spec["webhookConfiguration"] == {"timeoutSeconds": 30}
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
        (
            {"builder_id": f"https://github.com/{REPO}/deploy/release/release.py@refs/heads/dev"},
            "--builder-id",
        ),
        (
            {"builder_id": f"https://github.com/{REPO}/deploy/release/other.py@refs/heads/main"},
            "--builder-id",
        ),
        ({"image_glob": "Kind-Registry/demo"}, "--image-glob"),
        ({"image_glob": "kind-registry:5000/demo' "}, "--image-glob"),
        ({"image_glob": "*"}, "--image-glob"),
        ({"image_glob": "kind-registry:5000/*/api*"}, "--image-glob"),
        ({"image_glob": "kind-registry:5000/demo-shop/api"}, "--image-glob"),
        ({"image_glob": "registry.example.com/demo-shop/*", "allow_http": True}, "plain HTTP"),
        ({"image_glob": "demo-shop/api/*", "allow_http": True}, "names no registry host"),
    ],
    ids=[
        "quote-in-repo",
        "quote-in-builder",
        "not-a-workflow",
        "release-script-off-main",
        "another-script",
        "uppercase-glob",
        "quote-in-glob",
        "any-image",
        "inner-star",
        "no-star",
        "http-to-a-real-registry",
        "http-without-registry",
    ],
)
def test_a_value_that_could_change_the_policy_is_refused(
    tmp_path: Path, changes: dict[str, Any], message: str
) -> None:
    with pytest.raises(AttestationError, match=message):
        _render(tmp_path, **changes)


def test_the_laptop_release_script_is_a_builder_the_policy_can_require(tmp_path: Path) -> None:
    """ADR-0011: `make release` signs on the laptop, so the cluster requires the release script at main."""
    local = local_release_builder_id(REPO)
    expressions = " ".join(
        v["expression"] for v in _render(tmp_path, builder_id=local)["spec"]["validations"]
    )
    assert f"runDetails.builder.id == '{local}'" in expressions and BUILDER not in expressions


def test_the_decision_versions_are_the_contracts(tmp_path: Path) -> None:
    """#45 review, blocking 1: rendered from the Decision v1 contract, which mirrors the schema."""
    schema = json.loads((ROOT / "schemas" / "decision.v1.json").read_text(encoding="utf-8"))
    assert list(DECISION_VERSIONS) == schema["properties"]["schema_version"]["enum"]
    expressions = " ".join(v["expression"] for v in _render(tmp_path)["spec"]["validations"])
    assert "schema_version in [" + ", ".join(f"'{v}'" for v in DECISION_VERSIONS) + "]" in expressions
    assert "verdict in ['PASS', 'WARN']" in expressions and "v.effect != 'WARN'" in expressions


def test_a_key_file_with_anything_but_one_public_key_is_refused(tmp_path: Path) -> None:
    """#45 review, should fix 3: the policy is committed, so a private key next to the public one would be."""
    key = tmp_path / "bundle.pem"
    private = "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nAAAA\n-----END ...\n"
    for text in (private + PUBLIC_KEY, PUBLIC_KEY + private, PUBLIC_KEY + PUBLIC_KEY):
        key.write_text(text, encoding="ascii")
        with pytest.raises(AttestationError, match="exactly one PEM public key"):
            render_policy(public_key=key, image_glob="r/x/*", repo=REPO, builder_id=BUILDER, allow_http=False)
    key.write_text(PUBLIC_KEY.replace("\n", "\r\n"), encoding="ascii")
    assert "example0000" in render_policy(
        public_key=key, image_glob="r/x/*", repo=REPO, builder_id=BUILDER, allow_http=False
    )


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
    assert next(yaml.safe_load_all(out.read_text(encoding="utf-8")))["metadata"]["name"] == POLICY_NAME
    out.write_text("stale", encoding="utf-8")
    result = CliRunner().invoke(app, [*args[:-2], "--repo", "not a repo", "--out", str(out)])
    assert result.exit_code == 3 and not out.exists(), "a refused render leaves no policy behind"
    result = CliRunner().invoke(app, [*args[:-2], "--out", str(key)])
    assert result.exit_code == 3 and key.read_text(encoding="ascii") == PUBLIC_KEY, "--out is never the key"


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
        # Signed with the key but not a non-BLOCK Decision v1 (#45 review, blocking 1).
        for name, changes in {
            "verdict-in-lower-case": {"verdict": "block"},
            "pass-with-a-block-violation": {"verdict": "PASS", "violations": blocking},
            "unknown-decision-version": {"schema_version": "9.9"},
        }.items():
            target = image(name)
            decision = json.loads(decision_bytes(subject__image_digest=parse_image(target).digest, **changes))
            attach(target, keys["release.key"], predicates(work, target) | {"decision": decision})
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
    "block": ("fail", "decision: not a non-BLOCK Decision v1 verdict"),
    "verdict-in-lower-case": ("fail", "decision: not a non-BLOCK Decision v1 verdict"),
    "pass-with-a-block-violation": ("fail", "decision: not a non-BLOCK Decision v1 verdict"),
    "unknown-decision-version": ("fail", "decision: not a non-BLOCK Decision v1 verdict"),
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


@needs_tools
@pytest.mark.integration
def test_a_provenance_without_our_source_and_a_non_cyclonedx_sbom_are_refused(
    release: dict[str, Any], crane: Path
) -> None:
    """#45 review, nit 2: the source guard (`.exists`) and the CycloneDX check are pinned."""
    keys, registry, work = release["keys"], release["registry"], release["work"]
    elsewhere = push_image(crane, registry, work)
    signed = copy.deepcopy(predicates(work, elsewhere))
    (source,) = signed["provenance"]["buildDefinition"]["resolvedDependencies"]
    source["uri"] = "git+https://github.com/o/r@main"
    attach(elsewhere, keys["release.key"], signed)
    spdx = push_image(crane, registry, work)
    attach(spdx, keys["release.key"], _with(predicates(work, spdx), "sbom", "bomFormat", "SPDX"))
    results = admit(work / "more", _policy(release), [_pod("elsewhere", elsewhere), _pod("spdx", spdx)])
    assert {name: (result, message.strip()) for name, (result, message) in results.items()} == {
        "elsewhere": ("fail", "provenance: not built from the decision's commit"),
        "spdx": ("fail", "SBOM: not the one the vulnerability scan names"),
    }


@needs_tools
@pytest.mark.integration
def test_an_upper_case_registry_host_is_still_checked(release: dict[str, Any]) -> None:
    """#45 review, should fix 2: host names ignore case, so the policy's match must too. The same registry is
    named `localhost:<port>` here, so that the host has letters."""
    port = release["registry"].rpartition(":")[2]
    policy = render_policy(
        public_key=release["keys"]["release.pub"], image_glob=f"localhost:{port}/demo-shop/*", repo=REPO,
        builder_id=BUILDER, allow_http=True,
    )  # fmt: skip
    path = {name: release["images"][name].partition("/")[2] for name in ("good", "unsigned")}
    pods = [
        _pod("unsigned-upper", f"LOCALHOST:{port}/{path['unsigned']}"),
        _pod("good-lower", f"localhost:{port}/{path['good']}"),
        _pod("good-upper", f"LOCALHOST:{port}/{path['good']}"),
    ]
    results = admit(release["work"] / "case", policy, pods)
    assert results["unsigned-upper"][0] == "fail", "matched and refused, not left unchecked"
    assert results["good-lower"] == ("pass", "success")
    assert results["good-upper"][0] == "fail", "refused rather than unchecked: fails closed"


def test_ephemeral_containers_have_their_own_policy(tmp_path: Path) -> None:
    """kubectl debug adds a container through the `pods/ephemeralcontainers` subresource. In the same policy
    as `pods`, it would turn off Kyverno's autogen for Deployments, Jobs and CronJobs: a second document."""
    key = tmp_path / "release.pub"
    key.write_text(PUBLIC_KEY, encoding="ascii")
    pods, ephemeral = yaml.safe_load_all(
        render_policy(public_key=key, image_glob="kind-registry:5000/demo-shop/*", repo=REPO,
                      builder_id=BUILDER, allow_http=False)
    )  # fmt: skip
    assert ephemeral["metadata"]["name"] == f"{POLICY_NAME}-ephemeral-containers"
    (rule,) = ephemeral["spec"]["matchConstraints"]["resourceRules"]
    assert rule["resources"] == ["pods/ephemeralcontainers"]
    assert {k: v for k, v in ephemeral["spec"].items() if k != "matchConstraints"} == {
        k: v for k, v in pods["spec"].items() if k != "matchConstraints"
    }


@needs_tools
@pytest.mark.integration
def test_a_pod_controller_with_an_unsigned_image_is_refused_itself(release: dict[str, Any]) -> None:
    """Kyverno's autogen: a Deployment, a Job or a CronJob is refused when applied, not only its Pods."""
    unsigned = release["images"]["unsigned"]
    pod_spec: dict[str, Any] = {"containers": [{"name": "app", "image": unsigned}]}
    labels = {"metadata": {"labels": {"app": "shop"}}}
    job = {**labels, "spec": {**pod_spec, "restartPolicy": "Never"}}
    controllers = [
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": "deployment", "namespace": "shop"},
         "spec": {"selector": {"matchLabels": {"app": "shop"}}, "template": {**labels, "spec": pod_spec}}},
        {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "job", "namespace": "shop"},
         "spec": {"template": job}},
        {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "cronjob", "namespace": "shop"},
         "spec": {"schedule": "0 * * * *", "jobTemplate": {"spec": {"template": job}}}},
    ]  # fmt: skip
    refused = ("fail", "signature: the image itself is not signed by the release key")
    results = admit(release["work"] / "controllers", _policy(release), controllers)
    assert results == {"deployment": refused, "job": refused, "cronjob": refused}


@needs_tools
@pytest.mark.integration
def test_the_demo_shop_charts_deployment_is_admitted_for_a_release_only(release: dict[str, Any]) -> None:
    """The Deployment of deploy/helm/demo-shop, rendered as Helm renders it (tests/deploy/chart_render.py),
    for this registry: admitted with the release's digest, refused with an unsigned image's (task A5b)."""
    from .deploy_modules import chart_render

    if chart_render.GO is None:
        pytest.skip("renders the chart with Go's text/template: needs Go")
    deployments = []
    for case in ("good", "unsigned"):
        image = parse_image(release["images"][case])
        (deployment,) = [
            d
            for d in chart_render.render({"image": {"repository": image.name, "digest": image.digest}})
            if d["kind"] == "Deployment"
        ]
        deployment["metadata"] |= {"name": f"shop-api-{case}", "namespace": "demo-shop"}
        deployments.append(deployment)
    results = admit(release["work"] / "chart", _policy(release), deployments)
    assert results["shop-api-good"][0] == "pass", results
    assert results["shop-api-unsigned"] == (
        "fail",
        "signature: the image itself is not signed by the release key",
    )


# ---------------------------------------------------------------- the demo-shop namespace's image policy


def _workload(kind: str, name: str, image: str, init: str | None = None) -> dict[str, Any]:
    pod: dict[str, Any] = {"containers": [{"name": "app", "image": image}]}
    if init is not None:
        pod["initContainers"] = [{"name": "init", "image": init}]
    meta = {"name": name, "namespace": "demo-shop"}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": pod}
    template = {"metadata": {"labels": {"app": name}}, "spec": {**pod, "restartPolicy": "Never"}}
    if kind == "CronJob":
        spec: dict[str, Any] = {"schedule": "0 * * * *", "jobTemplate": {"spec": {"template": template}}}
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": meta, "spec": spec}
    template["spec"].pop("restartPolicy")
    spec = {"selector": {"matchLabels": {"app": name}}, "template": template}
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": spec}


@needs_tools
@pytest.mark.integration
def test_the_demo_shop_namespace_runs_images_of_the_release_repository_only(tmp_path: Path) -> None:
    """deploy/argocd/demo-shop-namespace.yaml's ValidatingAdmissionPolicy and its binding, evaluated by the
    Kyverno CLI as the API server evaluates them (task A5b): an image from anywhere else, which Kyverno's
    release policy would not even match, is refused in demo-shop, in any container of any Pod controller."""
    release = "kind-registry:5000/demo-shop/shop-api@sha256:" + "a" * 64
    resources = [
        _workload("Pod", "release", release),
        _workload("Deployment", "release-deployment", release),
        _workload("CronJob", "release-cronjob", release),
        _workload("Pod", "upper-case-host", release.replace("kind-registry", "KIND-REGISTRY")),
        _workload("Pod", "foreign", "quay.io/argoproj/argocd:v3.6.1"),
        _workload("Pod", "foreign-init-container", release, init="busybox:1.37"),
        _workload("Deployment", "foreign-deployment", "nginx:1.31"),
        _workload("StatefulSet", "foreign-statefulset", "nginx:1.31"),
        _workload("CronJob", "foreign-cronjob", "nginx:1.31"),
        _workload("Pod", "longer-repository", "kind-registry:5000/demo-shop-evil/x:1"),
        {
            **_workload("Pod", "elsewhere", "nginx:1.31"),
            "metadata": {"name": "elsewhere", "namespace": "other"},
        },
    ]
    (tmp_path / "resources.yaml").write_text(yaml.safe_dump_all(resources), encoding="utf-8")
    documents = list(
        yaml.safe_load_all((ROOT / "deploy" / "argocd" / "demo-shop-namespace.yaml").read_text("utf-8"))
    )
    policies = [d for d in documents if d["kind"] != "Namespace"]
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump_all(policies), encoding="utf-8")
    # The CLI has no API server to read the namespaces' labels from: the binding's selector reads them here.
    values = {
        "apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Value", "metadata": {"name": "namespaces"},
        "namespaceSelector": [
            {"name": n, "labels": {"kubernetes.io/metadata.name": n}} for n in ("demo-shop", "other")
        ],
    }  # fmt: skip
    (tmp_path / "values.yaml").write_text(yaml.safe_dump(values), encoding="utf-8")
    run = run_verified_tool(
        "kyverno",
        ["apply", "policy.yaml", "--resource", "resources.yaml", "--values-file", "values.yaml",
         "--policy-report", "--output-format", "json", "--remove-color"],
        lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=tmp_path, allowed_exit_codes=(0, 1),
    )  # fmt: skip
    report = json.loads(run.stdout)
    results = {
        r["resources"][0]["name"]: (r["result"], r.get("message", "")) for r in report.get("results") or []
    }
    passed = {"release", "release-deployment", "release-cronjob", "upper-case-host"}
    assert {name for name, (result, _) in results.items() if result == "pass"} == passed
    refused = {name: message for name, (result, message) in results.items() if result == "fail"}
    assert set(refused) == {
        "foreign", "foreign-init-container", "foreign-deployment", "foreign-statefulset", "foreign-cronjob",
        "longer-repository",
    }  # fmt: skip
    assert refused["foreign-init-container"] == (
        "demo-shop runs SentinelCI releases only, from kind-registry:5000/demo-shop/: not busybox:1.37"
    )
    assert "elsewhere" not in results, "the binding is for the demo-shop namespace only"
