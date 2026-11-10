"""`make demo-release` and `make demo-attack` on the demo cluster (task A5b, SPEC section 7, ADR-0011 decision
5): a release goes from its bundle to a running Deployment, through the cluster's registry, the GitOps
repository, Argo CD and Kyverno; then every attack next to it is refused, and it keeps running.

The release is a real one for the test's key: an image that runs as the release image must (a static server on
8080 as UID 10001, built with Go), attested by `sentinel attest --push` in a throwaway registry and saved with
`cosign save`, as `make release` will. The admission policy is rendered from the test's key, so Kyverno and
`sentinel verify` trust the same key.

Opt-in like test_kind_admission.py: SENTINEL_KIND_CONTEXT (a `make kind-up` cluster) and SENTINEL_TOOLS_DIR.
It commits a test release to the cluster's GitOps repository (.sentinel/gitops/demo-shop.git), as
`make demo-release` would, and removes what Argo CD deployed at the end.
"""

import json
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.supplychain.admission import POLICY_NAME
from sentinelci.supplychain.attestations import parse_image

from .conftest import BUILDER, GITHUB_ENV, REPO
from .deploy_modules import cluster, demo
from .oci import REPO_LOCK, TOOLS_DIR, attest, make_keys, push_image, runnable_image

CONTEXT = os.environ.get("SENTINEL_KIND_CONTEXT")
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


def gitops_main() -> str:
    repository = cluster.GITOPS_DIR / cluster.GITOPS_REPOSITORY
    done = subprocess.run(["git", "-C", str(repository), "rev-parse", "main"], capture_output=True, text=True,
                          check=True)  # fmt: skip
    return done.stdout.strip()


def admitted(image: str) -> bool:
    """A server-side dry run of a Pod in demo-shop: Kyverno and Pod Security answer, nothing is created."""
    pod = {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "readiness", "namespace": demo.NAMESPACE},
        "spec": {
            "securityContext": {
                "runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{"name": "app", "image": image, "securityContext": {
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}],
        },
    }  # fmt: skip
    return kubectl("create", "--dry-run=server", "-f", "-", input=json.dumps(pod)).returncode == 0


@pytest.fixture(scope="module")
def released(
    crane: Path, registry: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[dict[str, Any]]:
    """A runnable release saved as a bundle, the policy from its key applied and enforcing, then
    `make demo-release`'s steps run on it."""
    work = tmp_path_factory.mktemp("kind-demo")
    pins = cluster.load_pins()
    host = f"127.0.0.1:{pins.registry_port}"
    with pytest.MonkeyPatch.context() as env:
        for name, value in GITHUB_ENV.items():
            env.setenv(name, value)
        env.setenv("COSIGN_PASSWORD", "")
        keys = make_keys(work / "keys")
        image = runnable_image(crane, registry, work / "image")
        (work / "attest").mkdir()
        attested = attest(work / "attest", image, keys["release.key"])
        assert attested.exit_code == 0, attested.output
        bundle = work / "bundle"
        run_verified_tool("cosign", ["save", "--allow-http-registry", "--dir", str(bundle), image],
                          lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=work)  # fmt: skip
        unsigned = push_image(crane, host, work)
        # The BLOCK image of `make release`: an OCI layout of an image nothing signed.
        block = work / "block-image"
        blocked = push_image(crane, registry, work)
        run_verified_tool("crane", ["pull", "--format=oci", "--insecure", blocked, str(block)],
                          lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=work)  # fmt: skip

    digest = parse_image(image).digest
    # Another module's policy of the same name may still be being deleted: applying it now would fail.
    for name in (POLICY_NAME, f"{POLICY_NAME}-ephemeral-containers"):
        kubectl("wait", "--for=delete", f"imagevalidatingpolicies/{name}", "--timeout=120s")
    cluster.policy(keys["release.pub"], work / "policy.yaml", builder_id=BUILDER)
    # Loaded once here so that the readiness check can admit it; `demo-release` loads it again (same digest).
    load = ["load", "--allow-http-registry", "--dir", str(bundle), f"{host}/{demo.IMAGE_PATH}"]
    run_verified_tool("cosign", load, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=work)
    in_cluster = f"{pins.registry_in_cluster}/{demo.IMAGE_PATH}@{digest}"
    unsigned_in_cluster = pins.registry_in_cluster + unsigned.removeprefix(host)
    try:
        # The webhook takes this key asynchronously, after another module's policy: until it admits this
        # release and denies the unsigned image, it is not this policy that answers.
        deadline = time.monotonic() + READY_S
        while not admitted(in_cluster) or admitted(unsigned_in_cluster):
            if time.monotonic() > deadline:
                pytest.fail(f"the policy for the test key did not take effect within {READY_S} s")
            time.sleep(5)
        deployed = demo.release(bundle, key=keys["release.pub"], repo=REPO, builder_id=BUILDER,
                                tools_dir=Path(str(TOOLS_DIR)))  # fmt: skip
        yield {"digest": digest, "deployed": deployed, "bundle": bundle, "keys": keys, "image": in_cluster,
               "block": block}  # fmt: skip
    finally:
        kubectl("--namespace", "argocd", "delete", "application", demo.APPLICATION, "--wait=false")
        kubectl("--namespace", demo.NAMESPACE, "delete", "deployment,service,serviceaccount",
                "--selector", "app.kubernetes.io/part-of=demo-shop", "--wait=false")  # fmt: skip
        kubectl("delete", "--wait=false", "-f", str(work / "policy.yaml"))


def test_the_release_runs_by_its_digest_after_argo_cd_synced_it(released: dict[str, Any]) -> None:
    assert released["deployed"] == released["digest"]
    deployment = json.loads(kubectl("--namespace", demo.NAMESPACE, "get", "deployment", demo.DEPLOYMENT,
                                    "-o", "json").stdout)  # fmt: skip
    assert deployment["spec"]["template"]["spec"]["containers"][0]["image"] == released["image"]
    assert deployment["status"].get("readyReplicas") == 1
    application = json.loads(kubectl("--namespace", "argocd", "get", "application", demo.APPLICATION,
                                     "-o", "json").stdout)  # fmt: skip
    sync = application["status"]["sync"]
    assert (sync["status"], sync["revision"]) == ("Synced", gitops_main())
    assert application["status"]["health"]["status"] == "Healthy"


def release_again(released: dict[str, Any], key: str = "release.pub") -> str:
    return str(
        demo.release(
            released["bundle"],
            key=released["keys"][key],
            repo=REPO,
            builder_id=BUILDER,
            tools_dir=Path(str(TOOLS_DIR)),
        )
    )


def test_releasing_it_again_changes_nothing(released: dict[str, Any]) -> None:
    before = gitops_main()
    assert release_again(released) == released["digest"]
    assert gitops_main() == before


def test_the_other_key_is_refused_before_anything_is_loaded(released: dict[str, Any]) -> None:
    """The cluster's policy is the test key's: a release with another key stops at the policy check."""
    with pytest.raises(cluster.ClusterError, match="make kind-policy"):
        release_again(released, key="other.pub")


def test_every_attack_is_refused_and_the_release_keeps_running(released: dict[str, Any]) -> None:
    """`make demo-attack`: each attack refused by the check that must refuse it, on the real cluster."""
    results = demo.attack(key=released["keys"]["release.pub"], repo=REPO, builder_id=BUILDER,
                          tools_dir=Path(str(TOOLS_DIR)), block=released["block"])  # fmt: skip
    assert [(r.refused, r.by) for r in results] == [
        (True, "sentinel verify"),
        (True, "Kyverno, during Argo CD's sync"),
        (True, "Kyverno"),
        (True, "the API server's image policy"),
        (True, "Kyverno"),
    ], results
    assert results[0].message.startswith("NOT TRUSTED")
    for result in (results[1], results[2], results[4]):
        assert "denied" in result.message and "not signed by the release key" in result.message, result
    assert "demo-shop runs SentinelCI releases only" in results[3].message, results[3]
    deployment = json.loads(kubectl("--namespace", demo.NAMESPACE, "get", "deployment", demo.DEPLOYMENT,
                                    "-o", "json").stdout)  # fmt: skip
    assert deployment["spec"]["template"]["spec"]["containers"][0]["image"] == released["image"]
    assert deployment["status"].get("readyReplicas") == 1
    attacks = kubectl("--namespace", demo.NAMESPACE, "get", "deployments", "--selector",
                      "app.kubernetes.io/part-of=demo-shop-attack", "-o", "name")  # fmt: skip
    assert attacks.stdout.strip() == "", "no attack Deployment exists"
    repository = cluster.GITOPS_DIR / cluster.GITOPS_REPOSITORY
    log = subprocess.run(["git", "-C", str(repository), "log", "-2", "--format=%s", "main"],
                         capture_output=True, text=True, check=True).stdout  # fmt: skip
    assert log.startswith(f"restore release {released['digest']}\nattack: deploy a tampered image ")
