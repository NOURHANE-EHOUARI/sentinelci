"""`make demo-release` on the demo cluster (task A5b, SPEC section 7, ADR-0011 decision 5): a release goes
from its bundle to a running Deployment, through the cluster's registry, the GitOps repository, Argo CD and
Kyverno.

The release is a real one for the test's key: an image that runs as the release image must (a static server on
8080 as UID 10001, built with Go), attested by `sentinel attest --push` in a throwaway registry and saved with
`cosign save`, as `make release` will. The admission policy is rendered from the test's key, so Kyverno and
`sentinel verify` trust the same key. The cluster's registry is reached over TLS, trusting its CA through
SSL_CERT_FILE (`cluster.trust_bundle`), as `make demo-release` does.

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

    trust = str(cluster.trust_bundle())  # the cluster's registry serves TLS with its own CA
    tls = pytest.MonkeyPatch()
    tls.setenv("SSL_CERT_FILE", trust)  # for `demo.release`'s cosign and `sentinel verify`
    digest = parse_image(image).digest
    # Another module's policy of the same name may still be being deleted: applying it now would fail.
    for name in (POLICY_NAME, f"{POLICY_NAME}-ephemeral-containers"):
        kubectl("wait", "--for=delete", f"imagevalidatingpolicies/{name}", "--timeout=120s")
    in_cluster = f"{pins.registry_in_cluster}/{demo.IMAGE_PATH}@{digest}"
    unsigned_in_cluster = pins.registry_in_cluster + unsigned.removeprefix(host)
    try:
        # Inside the try: a setup that fails leaves no policy behind for the next run to wait 120 s on.
        cluster.policy(keys["release.pub"], work / "policy.yaml", builder_id=BUILDER)
        # Loaded once here so that the readiness check can admit it; `demo-release` loads it again (same
        # digest). The tool runner's minimal environment drops SSL_CERT_FILE: it is passed explicitly.
        load = ["load", "--dir", str(bundle), f"{host}/{demo.IMAGE_PATH}"]
        run_verified_tool("cosign", load, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), cwd=work,
                          extra_env={"SSL_CERT_FILE": trust})  # fmt: skip
        # The webhook takes this key asynchronously, after another module's policy: until it admits this
        # release and denies the unsigned image, it is not this policy that answers.
        deadline = time.monotonic() + READY_S
        while not admitted(in_cluster) or admitted(unsigned_in_cluster):
            if time.monotonic() > deadline:
                pytest.fail(f"the policy for the test key did not take effect within {READY_S} s")
            time.sleep(5)
        deployed = demo.release(bundle, key=keys["release.pub"], repo=REPO, builder_id=BUILDER,
                                tools_dir=Path(str(TOOLS_DIR)))  # fmt: skip
        yield {"digest": digest, "deployed": deployed, "bundle": bundle, "keys": keys, "image": in_cluster}
    finally:
        kubectl("--namespace", "argocd", "delete", "application", demo.APPLICATION, "--wait=false")
        kubectl("--namespace", demo.NAMESPACE, "delete", "deployment,service,serviceaccount",
                "--selector", "app.kubernetes.io/part-of=demo-shop", "--wait=false")  # fmt: skip
        kubectl("delete", "--wait=false", "-f", str(work / "policy.yaml"))
        tls.undo()


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
