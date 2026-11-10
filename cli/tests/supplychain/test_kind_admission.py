"""The release admission policy in a real cluster (task A5b, SPEC section 7): kind, its registry and
Kyverno, as `make kind-up` sets them up (deploy/kind/cluster.py).

The images are pushed from the host to the cluster's registry (127.0.0.1:5001) and named in the Pods by its
name inside the cluster (kind-registry:5000), as a release will be. The Kyverno admission controller judges
each Pod when the API server asks it: server-side dry runs, so nothing runs. A release `sentinel attest
--push` attested is admitted; an unsigned image, a BLOCK decision signed with the release key, and a
Deployment with an unsigned image are denied, each with the policy's own message.

Opt-in: SENTINEL_KIND_CONTEXT names the cluster's kubectl context (the sentinel-kind workflow sets it) and
SENTINEL_TOOLS_DIR the pinned tools (cosign and crane).
"""

import json
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.supplychain.admission import POLICY_NAME, render_policy
from sentinelci.supplychain.attestations import parse_image

from .conftest import BUILDER, GITHUB_ENV, REPO, decision_bytes
from .oci import TOOLS_DIR, attach, attest, make_keys, predicates, push_image

CONTEXT = os.environ.get("SENTINEL_KIND_CONTEXT")
HOST_REGISTRY = os.environ.get("SENTINEL_KIND_REGISTRY", "127.0.0.1:5001")
CLUSTER_REGISTRY = "kind-registry:5000"
NAMESPACE = "sentinel-admission-test"
READY_S = 240

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (CONTEXT and TOOLS_DIR),
        reason="set SENTINEL_KIND_CONTEXT (a `make kind-up` cluster) and SENTINEL_TOOLS_DIR",
    ),
]


def kubectl(*args: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", "--context", str(CONTEXT), *args],
        input=input, capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip


def in_cluster(reference: str) -> str:
    """The same image by digest, as the cluster names its registry."""
    assert reference.startswith(f"{HOST_REGISTRY}/"), reference
    return CLUSTER_REGISTRY + reference.removeprefix(HOST_REGISTRY)


def pod(name: str, image: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"containers": [{"name": "app", "image": image}]},
    }  # fmt: skip


def deployment(name: str, image: str) -> dict[str, Any]:
    template = {"metadata": {"labels": {"app": name}}, "spec": pod(name, image)["spec"]}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": template},
    }  # fmt: skip


def admit(resource: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    """A server-side dry run: every admission webhook answers, and nothing is stored or started."""
    return kubectl("create", "--dry-run=server", "-o", "name", "-f", "-", input=json.dumps(resource))


@pytest.fixture(scope="module")
def release(crane: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """A good release, an unsigned image and a BLOCK decision in the cluster's registry, and the policy,
    rendered from the test's release key for the cluster's registry, applied and enforcing."""
    work = tmp_path_factory.mktemp("kind-admission")
    with pytest.MonkeyPatch.context() as env:
        for name, value in GITHUB_ENV.items():
            env.setenv(name, value)
        env.setenv("COSIGN_PASSWORD", "")
        keys = make_keys(work / "keys")
        good = push_image(crane, HOST_REGISTRY, work)
        (work / "good").mkdir()
        attested = attest(work / "good", good, keys["release.key"])
        assert attested.exit_code == 0, attested.output
        unsigned = push_image(crane, HOST_REGISTRY, work)
        block = push_image(crane, HOST_REGISTRY, work)
        blocking = [{"rule": "SC-002", "effect": "BLOCK", "finding_ids": ["c" * 64], "message": "P0"}]
        decision = decision_bytes(subject__image_digest=parse_image(block).digest, verdict="BLOCK",
                                  violations=blocking)  # fmt: skip
        attach(block, keys["release.key"], predicates(work, block) | {"decision": json.loads(decision)})

    policy = render_policy(
        public_key=keys["release.pub"], image_glob=f"{CLUSTER_REGISTRY}/demo-shop/*", repo=REPO,
        builder_id=BUILDER, allow_http=True,
    )  # fmt: skip
    kubectl("create", "namespace", NAMESPACE)
    applied = kubectl("apply", "-f", "-", input=policy)
    assert applied.returncode == 0, applied.stderr
    try:
        images = {"good": in_cluster(good), "unsigned": in_cluster(unsigned), "block": in_cluster(block)}
        # The webhook is registered asynchronously: until the unsigned image is denied, nothing is enforced.
        deadline = time.monotonic() + READY_S
        while admit(pod("readiness", images["unsigned"])).returncode == 0:
            if time.monotonic() > deadline:
                status = kubectl("get", "imagevalidatingpolicies", "-o", "yaml").stdout
                pytest.fail(f"the policy did not start denying within {READY_S} s:\n{status}")
            time.sleep(5)
        yield images
    finally:
        kubectl("delete", "--wait=false", "-f", "-", input=policy)
        kubectl("delete", "namespace", NAMESPACE, "--wait=false")


def test_a_release_attested_by_sentinel_attest_is_admitted(release: dict[str, str]) -> None:
    result = admit(pod("good", release["good"]))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "pod/good"


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("unsigned", "signature: the image itself is not signed by the release key"),
        ("block", "decision: not a non-BLOCK Decision v1 verdict"),
    ],
)
def test_a_bad_image_is_denied_with_the_policys_reason(
    release: dict[str, str], case: str, message: str
) -> None:
    result = admit(pod(case, release[case]))
    assert result.returncode != 0 and message in result.stderr, result.stderr


def test_a_deployment_with_an_unsigned_image_is_denied_itself(release: dict[str, str]) -> None:
    """Kyverno's autogen: the controller is refused when it is applied, not only its Pods later."""
    result = admit(deployment("unsigned", release["unsigned"]))
    assert result.returncode != 0, result.stdout
    assert "not signed by the release key" in result.stderr
    good = admit(deployment("good", release["good"]))
    assert good.returncode == 0, good.stderr


def test_the_policy_rendered_for_the_cluster_matches_its_registry(release: dict[str, str]) -> None:
    applied = kubectl("get", "imagevalidatingpolicies", POLICY_NAME, "-o", "yaml")
    assert applied.returncode == 0, applied.stderr
    spec = yaml.safe_load(applied.stdout)["spec"]
    assert spec["matchImageReferences"] == [
        {"expression": f"ref.lowerAscii().startsWith('{CLUSTER_REGISTRY}/demo-shop/')"}
    ]
    assert spec["credentials"]["allowInsecureRegistry"] is True
