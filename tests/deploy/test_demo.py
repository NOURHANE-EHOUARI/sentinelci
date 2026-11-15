"""`make demo-release` (deploy/kind/demo.py, task A5b): the steps, their order, and what stops them.

The cluster, Cosign and `sentinel verify` are a recording fake that answers like them; git is real, on a
GitOps repository in a temporary directory. The real cluster runs it in
cli/tests/supplychain/test_kind_demo.py (sentinel-kind workflow), and the bundle's path through cosign load
and sentinel verify is tested with the pinned tools in cli/tests/supplychain/test_demo_bundle.py.
"""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from sentinelci.supplychain.attestations import local_release_builder_id

ROOT = Path(__file__).resolve().parents[2]
KIND_DIR = ROOT / "deploy" / "kind"
ARGOCD_DIR = ROOT / "deploy" / "argocd"
DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32
REPO = "NOURHANE-EHOUARI/sentinelci"
BUILDER = local_release_builder_id(REPO)  # a laptop release (ADR-0011), as `make release` records it
TEST_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO6hJTV7g+9HDqwapkmeWrwZLKCO0\n"
    "CXbM/ElQoClaQE7Ga/Wd1pC90tiggwgrTX9sJGGo7T0IWLSq6kCA1m8H7w==\n"
    "-----END PUBLIC KEY-----\n"
)


def _load(name: str) -> ModuleType:
    if name in sys.modules:  # cluster.py, already loaded by test_kind.py: one module, one ClusterError
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, KIND_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cluster = _load("cluster")
demo = _load("demo")


def rendered_policy(key: Path, repo: str = REPO) -> list[dict[str, Any]]:
    from sentinelci.supplychain.admission import render_policy

    text = render_policy(public_key=key, image_glob=cluster.IMAGE_GLOB, repo=repo, builder_id=BUILDER,
                         allow_http=False)  # fmt: skip
    return list(yaml.safe_load_all(text))


class Fake:
    """kubectl, Cosign and `sentinel verify` as a cluster answers; git runs for real."""

    def __init__(
        self,
        *,
        policies: list[dict[str, Any]] | None,
        verify: int = 0,
        statuses: Sequence[dict[str, Any]] = (),
        image: str | None = None,
    ) -> None:
        self.policies = {p["metadata"]["name"]: p for p in policies or []}
        self.verify, self.statuses, self.image = verify, list(statuses), image
        self.calls: list[list[str]] = []
        self.commit = ""

    def __call__(
        self, args: Sequence[str], *, input: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        if args[0] == "git":
            done = subprocess.run(args, input=input, capture_output=True, text=True, check=False)
            if check and done.returncode:
                raise cluster.ClusterError(f"git failed: {done.stderr}")
            if "push" in args:
                self.commit = subprocess.run(
                    [*args[: args.index("push")], "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
            self.calls.append(args)
            return done
        self.calls.append(args)
        out, code = "", 0
        if "imagevalidatingpolicies" in args:
            policy = self.policies.get(args[-3])
            if policy is None:
                code = 1
            else:  # the API server adds defaults: the check must accept them
                out = json.dumps({"spec": {**policy["spec"], "evaluation": {"mode": "Kubernetes"}}})
        elif args[1:3] == ["-m", "sentinelci.cli"]:
            out, code = "TRUSTED: 16/16 checks passed\n" if self.verify == 0 else "NOT TRUSTED\n", self.verify
        elif "application" in args and "get" in args:
            status = self.statuses.pop(0) if len(self.statuses) > 1 else (self.statuses or [{}])[0]
            out = json.dumps({"status": self._fill(status)})
        elif "jsonpath={.spec.template.spec.containers[0].image}" in args:
            out = self.image or f"kind-registry:5000/demo-shop/shop-api@{DIGEST}"
        return subprocess.CompletedProcess(args, code, out, "")

    def _fill(self, status: dict[str, Any]) -> dict[str, Any]:
        """`COMMIT` in a status is the commit this run pushed, or the one a test set."""
        return json.loads(json.dumps(status).replace("COMMIT", self.commit))

    def commands(self) -> list[str]:
        return [" ".join(args) for args in self.calls]


SYNCED = {"sync": {"status": "Synced", "revision": "COMMIT"}, "health": {"status": "Healthy"}}


def bundle(tmp_path: Path, *digests: str, blob: bytes = b'{"schemaVersion": 2}') -> Path:
    """A `cosign save` layout: index.json naming images, and each image's manifest as a blob."""
    directory = tmp_path / "bundle"
    (directory / "blobs" / "sha256").mkdir(parents=True)
    real = "sha256:" + hashlib.sha256(blob).hexdigest()
    manifests = []
    for digest in digests or (real,):
        manifests.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest,
                          "annotations": {"kind": "dev.cosignproject.cosign/image"}})  # fmt: skip
        (directory / "blobs" / "sha256" / digest.removeprefix("sha256:")).write_bytes(blob)
    (directory / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": manifests}), "utf-8")
    return directory


@pytest.fixture
def key(tmp_path: Path) -> Path:
    path = tmp_path / "release.pub"
    path.write_text(TEST_KEY, encoding="ascii")
    return path


@pytest.fixture
def release_bundle(tmp_path: Path) -> tuple[Path, str]:
    blob = b'{"schemaVersion": 2, "test": "release"}'
    return bundle(tmp_path, blob=blob), "sha256:" + hashlib.sha256(blob).hexdigest()


@pytest.fixture(autouse=True)
def pinned_cosign(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo, "verified_tool", lambda name, tools_dir: f"/tools/bin/{name}")


def deploy(fake: Fake, bundle_dir: Path, key: Path, gitops: Path) -> str:
    return str(
        demo.release(
            bundle_dir,
            key=key,
            repo=REPO,
            builder_id=BUILDER,
            tools_dir=Path("/tools"),
            gitops=gitops,
            run=fake,
            timeout_s=30,
            sleep=lambda _: None,
        )
    )


def gitops_tree(gitops: Path, tmp_path: Path) -> Path:
    clone = tmp_path / "check"
    subprocess.run(["git", "clone", "--quiet", str(gitops / "demo-shop.git"), str(clone)], check=True)
    return clone


# ---------------------------------------------------------------- the bundle


def test_the_bundle_names_its_image_by_digest(tmp_path: Path) -> None:
    blob = b'{"manifest": 1}'
    assert demo.bundle_digest(bundle(tmp_path, blob=blob)) == "sha256:" + hashlib.sha256(blob).hexdigest()


@pytest.mark.parametrize(
    ("digests", "message"),
    [
        ((), "exactly one image"),
        ((DIGEST, OTHER), "exactly one image"),
        (("sha256:ABC",), "exactly one image"),
        ((DIGEST,), "does not have that digest"),
    ],
    ids=["none", "two", "malformed", "manifest-is-not-that-digest"],
)
def test_a_bundle_that_is_not_one_release_is_refused(
    tmp_path: Path, digests: tuple[str, ...], message: str
) -> None:
    directory = bundle(tmp_path, *digests) if digests else bundle(tmp_path, "x")
    if not digests:
        index = json.loads((directory / "index.json").read_text("utf-8"))
        index["manifests"][0]["annotations"]["kind"] = "dev.cosignproject.cosign/sigs"
        (directory / "index.json").write_text(json.dumps(index), "utf-8")
    with pytest.raises(cluster.ClusterError, match=message):
        demo.bundle_digest(directory)


def test_a_directory_that_is_not_a_layout_is_refused(tmp_path: Path) -> None:
    with pytest.raises(cluster.ClusterError, match="not a release bundle"):
        demo.bundle_digest(tmp_path)


# ---------------------------------------------------------------- the cluster's policy


def test_contains_accepts_defaults_the_server_adds_and_nothing_else() -> None:
    expected = {"a": [{"b": 1}], "c": {"d": True}}
    assert demo.contains(expected, {"a": [{"b": 1, "x": 0}], "c": {"d": True, "y": 1}, "z": 2})
    assert not demo.contains(expected, {"a": [{"b": 2}], "c": {"d": True}})
    assert not demo.contains(expected, {"a": [{"b": 1}, {"b": 1}], "c": {"d": True}}), (
        "a list keeps its length"
    )
    assert not demo.contains(expected, {"a": [{"b": 1}]})
    assert not demo.contains(expected, None)


def test_the_policy_must_be_the_one_rendered_from_the_key(key: Path, tmp_path: Path) -> None:
    demo.check_policy(key, REPO, BUILDER, Fake(policies=rendered_policy(key)))
    with pytest.raises(cluster.ClusterError, match=r"make kind-policy KEY="):
        demo.check_policy(key, REPO, BUILDER, Fake(policies=None))
    with pytest.raises(cluster.ClusterError, match="is not the one rendered"):
        demo.check_policy(key, REPO, BUILDER, Fake(policies=rendered_policy(key, repo="someone/else")))
    with pytest.raises(cluster.ClusterError, match="ephemeral"):
        demo.check_policy(key, REPO, BUILDER, Fake(policies=rendered_policy(key)[:1]))


# ---------------------------------------------------------------- release


def test_a_release_is_loaded_verified_committed_synced_and_rolled_out(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path
) -> None:
    bundle_dir, digest = release_bundle
    gitops = tmp_path / "gitops"
    fake = Fake(policies=rendered_policy(key), statuses=[{}, {"sync": {"status": "OutOfSync"}}, SYNCED],
                image=f"kind-registry:5000/demo-shop/shop-api@{digest}")  # fmt: skip
    assert deploy(fake, bundle_dir, key, gitops) == digest
    commands = fake.commands()

    load = commands.index(f"/tools/bin/cosign load --dir {bundle_dir} 127.0.0.1:5001/demo-shop/shop-api")
    (verify,) = [i for i, c in enumerate(commands) if " -m sentinelci.cli verify " in c]
    assert commands[verify].endswith(
        f"verify 127.0.0.1:5001/demo-shop/shop-api@{digest} --key {key} --repo {REPO} --builder-id {BUILDER} "
        f"--lock {ROOT}/tools.lock.toml --tools-dir /tools"
    )
    policy = [i for i, c in enumerate(commands) if "imagevalidatingpolicies" in c]
    push = next(i for i, c in enumerate(commands) if c.startswith("git") and " push " in c)
    kubectl = "kubectl --context kind-sentinel"
    apply = commands.index(f"{kubectl} apply -f {ARGOCD_DIR}/project.yaml -f {ARGOCD_DIR}/application.yaml")
    refresh = commands.index(
        f"{kubectl} --namespace argocd annotate --overwrite application/demo-shop "
        "argocd.argoproj.io/refresh=normal"
    )
    rollout = commands.index(
        f"{kubectl} --namespace demo-shop rollout status deployment/shop-api --timeout=30s"
    )
    assert max(policy) < load < verify < push < apply < refresh < rollout, (
        "each step only after the one before"
    )

    tree = gitops_tree(gitops, tmp_path)
    values = yaml.safe_load((tree / "demo-shop" / "release.yaml").read_text("utf-8"))
    assert values == {"image": {"digest": digest}}
    chart = ROOT / "deploy" / "helm" / "demo-shop"
    for path in chart.rglob("*"):
        if path.is_file():
            assert (tree / "demo-shop" / path.relative_to(chart)).read_bytes() == path.read_bytes()
    log = subprocess.run(["git", "-C", str(tree), "log", "--format=%an <%ae>%n%B"], capture_output=True,
                         text=True, check=True).stdout  # fmt: skip
    assert log.startswith(f"SentinelCI demo release <demo-release@sentinelci.invalid>\nrelease {digest}\n")
    assert f"Sentinel-Image: {digest}" in log and "Sentinel-Source: " in log


def test_the_same_release_twice_makes_no_second_commit(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path
) -> None:
    bundle_dir, digest = release_bundle
    gitops = tmp_path / "gitops"
    image = f"kind-registry:5000/demo-shop/shop-api@{digest}"
    first = Fake(policies=rendered_policy(key), statuses=[SYNCED], image=image)
    deploy(first, bundle_dir, key, gitops)
    second = Fake(policies=rendered_policy(key), statuses=[SYNCED], image=image)
    second.commit = first.commit
    deploy(second, bundle_dir, key, gitops)
    assert not [c for c in second.commands() if c.startswith("git") and (" push " in c or " commit " in c)]
    count = subprocess.run(["git", "-C", str(gitops / "demo-shop.git"), "rev-list", "--count", "main"],
                           capture_output=True, text=True, check=True).stdout.strip()  # fmt: skip
    assert count == "1"


def test_a_release_sentinel_verify_does_not_trust_is_not_committed(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path
) -> None:
    bundle_dir, _ = release_bundle
    fake = Fake(policies=rendered_policy(key), verify=1)
    with pytest.raises(demo.NotTrusted, match="not deployed"):
        deploy(fake, bundle_dir, key, tmp_path / "gitops")
    assert not (tmp_path / "gitops").exists(), "the GitOps repository is not even created"
    assert not [c for c in fake.commands() if c.startswith("kubectl") and " apply " in c]


def test_a_cluster_without_the_keys_policy_gets_nothing(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path
) -> None:
    bundle_dir, _ = release_bundle
    fake = Fake(policies=None)
    with pytest.raises(cluster.ClusterError, match="make kind-policy"):
        deploy(fake, bundle_dir, key, tmp_path / "gitops")
    assert not [c for c in fake.commands() if " load " in c or " verify " in c]


@pytest.mark.parametrize(
    "operation",
    [{"phase": "Failed"}, {"phase": "Error"}, {"phase": "Running", "retryCount": 5}],
    ids=["failed", "error", "argo-cd-retrying"],
)
def test_a_sync_kyverno_denied_stops_the_release_with_its_message(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path, operation: dict[str, Any]
) -> None:
    """Argo CD 3.6 retries a refused automated sync by itself: the phase stays Running, "Retrying attempt #5"
    (Hiba's kind run on #60), and a wait for Failed would only time out."""
    bundle_dir, _ = release_bundle
    denied = {
        "sync": {"status": "OutOfSync", "revision": "COMMIT"},
        "operationState": operation | {"syncResult": {"revision": "COMMIT"},
                           "message": "admission webhook denied: signature: not signed by the release key"},
    }  # fmt: skip
    fake = Fake(policies=rendered_policy(key), statuses=[denied])
    with pytest.raises(cluster.ClusterError, match=r"could not sync .*not signed by the release key"):
        deploy(fake, bundle_dir, key, tmp_path / "gitops")
    assert not [c for c in fake.commands() if " rollout " in c]


@pytest.mark.parametrize("retries", [None, 0, "5"], ids=["no-retry-count", "zero", "not-a-number"])
def test_a_first_sync_still_running_is_waited_for(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path, retries: object
) -> None:
    bundle_dir, digest = release_bundle
    running = {"sync": {"status": "OutOfSync", "revision": "COMMIT"},
               "operationState": {"phase": "Running", "syncResult": {"revision": "COMMIT"}}}  # fmt: skip
    if retries is not None:
        running["operationState"]["retryCount"] = retries
    fake = Fake(policies=rendered_policy(key), statuses=[running, SYNCED],
                image=f"kind-registry:5000/demo-shop/shop-api@{digest}")  # fmt: skip
    assert deploy(fake, bundle_dir, key, tmp_path / "gitops") == digest


def test_a_retried_sync_of_another_commit_is_not_this_releases(key: Path) -> None:
    times = iter([0.0, 10.0, 40.0])
    other = {
        "sync": {"status": "OutOfSync", "revision": "0" * 40},
        "operationState": {"phase": "Running", "retryCount": 3, "syncResult": {"revision": "0" * 40}},
    }
    fake = Fake(policies=None, statuses=[other])
    with pytest.raises(cluster.ClusterError, match="within 30 s"):
        demo.wait_for_sync("1" * 40, fake, timeout_s=30, clock=lambda: next(times), sleep=lambda _: None)


def test_argo_cd_that_never_syncs_times_out_with_its_status(key: Path) -> None:
    times = iter([0.0, 10.0, 20.0, 40.0])
    stuck = {
        "sync": {"status": "OutOfSync", "revision": "0" * 40},
        "conditions": [{"message": "repository not accessible"}],
    }
    fake = Fake(policies=None, statuses=[stuck])
    with pytest.raises(
        cluster.ClusterError, match=r"within 30 s: sync OutOfSync .*repository not accessible"
    ):
        demo.wait_for_sync("1" * 40, fake, timeout_s=30, clock=lambda: next(times), sleep=lambda _: None)


def test_a_deployment_running_another_image_fails_the_release(
    release_bundle: tuple[Path, str], key: Path, tmp_path: Path
) -> None:
    bundle_dir, _ = release_bundle
    fake = Fake(
        policies=rendered_policy(key),
        statuses=[SYNCED],
        image=f"kind-registry:5000/demo-shop/shop-api@{OTHER}",
    )
    with pytest.raises(cluster.ClusterError, match="not the release"):
        deploy(fake, bundle_dir, key, tmp_path / "gitops")


@pytest.mark.parametrize(("error", "code"), [("NotTrusted", 1), ("ClusterError", 3)])
def test_the_exit_code_says_what_stopped_it(monkeypatch: pytest.MonkeyPatch, error: str, code: int) -> None:
    errors = {"NotTrusted": demo.NotTrusted, "ClusterError": cluster.ClusterError}

    def failing(*args: Any, **kwargs: Any) -> str:
        raise errors[error]("stopped")

    monkeypatch.setattr(demo, "release", failing)
    monkeypatch.setattr(cluster, "trust_bundle", lambda tls: Path("/tls/trust.pem"))
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")  # restored after the test
    assert demo.main(["release"]) == code


def test_cosign_and_sentinel_verify_trust_the_clusters_registry_by_its_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str | None] = []
    monkeypatch.setattr(demo, "release", lambda *args, **kwargs: seen.append(os.environ.get("SSL_CERT_FILE")))
    monkeypatch.setattr(cluster, "trust_bundle", lambda tls: Path("/tls/trust.pem"))
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
    assert demo.main(["release"]) == 0
    assert seen == ["/tls/trust.pem"]


def test_without_the_clusters_ca_nothing_is_released(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    released: list[object] = []
    monkeypatch.setattr(demo, "release", lambda *args, **kwargs: released.append(args))
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")
    assert demo.main(["release", "--tls", str(tmp_path)]) == 3
    assert released == []


# ---------------------------------------------------------------- the names the files share


def test_argo_cd_reads_the_one_repository_the_git_server_serves() -> None:
    server = {d["kind"]: d for d in yaml.safe_load_all((ARGOCD_DIR / "git-server.yaml").read_text("utf-8"))}
    command = server["Deployment"]["spec"]["template"]["spec"]["containers"][0]["command"]
    served = command[-1].removeprefix("/srv/git/")
    service = server["Service"]["metadata"]
    url = f"git://{service['name']}.{service['namespace']}.svc.cluster.local/{served}"
    project = yaml.safe_load((ARGOCD_DIR / "project.yaml").read_text("utf-8"))
    application = yaml.safe_load((ARGOCD_DIR / "application.yaml").read_text("utf-8"))
    assert served == cluster.GITOPS_REPOSITORY
    assert project["spec"]["sourceRepos"] == [url] and application["spec"]["source"]["repoURL"] == url
    volume = server["Deployment"]["spec"]["template"]["spec"]["volumes"][0]["hostPath"]["path"]
    assert volume == cluster.NODE_GITOPS


def test_the_application_deploys_the_chart_and_digest_demo_release_commits() -> None:
    application = yaml.safe_load((ARGOCD_DIR / "application.yaml").read_text("utf-8"))
    project = yaml.safe_load((ARGOCD_DIR / "project.yaml").read_text("utf-8"))
    namespace = yaml.safe_load((ARGOCD_DIR / "demo-shop-namespace.yaml").read_text("utf-8"))
    source, destination = application["spec"]["source"], application["spec"]["destination"]
    assert application["metadata"]["name"] == demo.APPLICATION
    assert (source["targetRevision"], source["path"], source["helm"]["valueFiles"]) == (
        "main", demo.CHART_PATH, [demo.RELEASE_VALUES],
    )  # fmt: skip
    assert application["spec"]["project"] == project["metadata"]["name"]
    assert destination == {"server": "https://kubernetes.default.svc", "namespace": demo.NAMESPACE}
    assert project["spec"]["destinations"] == [destination]
    assert project["spec"]["clusterResourceWhitelist"] == [], "nothing cluster-scoped"
    assert namespace["metadata"]["name"] == demo.NAMESPACE
    assert namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    assert application["spec"]["syncPolicy"]["automated"] == {"prune": True, "selfHeal": True}


def test_the_chart_names_the_image_where_the_policy_and_the_registry_expect_it() -> None:
    pins = cluster.load_pins()
    values = yaml.safe_load((ROOT / "deploy" / "helm" / "demo-shop" / "values.yaml").read_text("utf-8"))
    assert values["image"]["repository"] == f"{pins.registry_in_cluster}/{demo.IMAGE_PATH}"
    assert (values["image"]["repository"] + "/").startswith(cluster.IMAGE_GLOB.removesuffix("*").rstrip("/"))
