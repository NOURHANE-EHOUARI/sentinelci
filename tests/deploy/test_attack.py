"""`make demo-attack` (deploy/kind/demo.py, task A5b): each attack, who must refuse it, and what is undone.

The cluster, crane and `sentinel verify` are a recording fake that answers like them (Kyverno, the API
server's image policy and Argo CD included); git is real, on a GitOps repository in a temporary directory. The
real cluster runs it in cli/tests/supplychain/test_kind_demo.py, the tampering with the pinned crane and
`sentinel verify` in test_demo_bundle.py, and the API server's image policy with the Kyverno CLI in
test_admission.py.
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from sentinelci.supplychain.attestations import local_release_builder_id

ROOT = Path(__file__).resolve().parents[2]
KIND_DIR = ROOT / "deploy" / "kind"
RELEASE = "sha256:" + "ab" * 32
TAMPERED = "sha256:" + "ef" * 32
REPO = "NOURHANE-EHOUARI/sentinelci"
BUILDER = local_release_builder_id(REPO)  # a laptop release (ADR-0011), as `make release` records it
IN_CLUSTER = "kind-registry:5000/demo-shop/shop-api"
TEST_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO6hJTV7g+9HDqwapkmeWrwZLKCO0\n"
    "CXbM/ElQoClaQE7Ga/Wd1pC90tiggwgrTX9sJGGo7T0IWLSq6kCA1m8H7w==\n"
    "-----END PUBLIC KEY-----\n"
)
KYVERNO_DENIAL = (
    'Error from server: admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
    "signature: the image itself is not signed by the release key"
)
VAP_DENIAL = (
    'The deployments "shop-api-foreign" is invalid: : '
    "ValidatingAdmissionPolicy 'demo-shop-release-images-only' denied request: "
    "demo-shop runs SentinelCI releases only, from kind-registry:5000/demo-shop/: not quay.io/x"
)


def _load(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, KIND_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cluster = _load("cluster")
demo = _load("demo")


def live_deployment(image: str = f"{IN_CLUSTER}@{RELEASE}") -> dict[str, Any]:
    """The release's Deployment as the API server returns it (abridged)."""
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "shop-api", "namespace": "demo-shop", "uid": "u", "resourceVersion": "7",
                     "labels": {"app.kubernetes.io/instance": "demo-shop"}},
        "spec": {
            "replicas": 1, "selector": {"matchLabels": {"app.kubernetes.io/name": "shop-api"}},
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "shop-api"}},
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
                    "containers": [{"name": "shop-api", "image": image,
                                    "securityContext": {"readOnlyRootFilesystem": True}}],
                },
            },
        },
        "status": {"readyReplicas": 1},
    }  # fmt: skip


class Cluster:
    """kubectl, crane and `sentinel verify` against a demo cluster that runs the release; git is real.

    `admitted` lists the images the cluster's admission would let in (none, when everything works);
    `argo_syncs_attack` makes Argo CD sync the tampered commit; `argo_stuck` makes it never answer for it."""

    def __init__(
        self,
        key: Path,
        *,
        admitted: Sequence[str] = (),
        verify: int = 1,
        argo_syncs_attack: bool = False,
        argo_stuck: bool = False,
        running: str | None = f"{IN_CLUSTER}@{RELEASE}",
        create_error: str | None = None,
    ) -> None:
        from sentinelci.supplychain.admission import render_policy

        text = render_policy(public_key=key, image_glob=cluster.IMAGE_GLOB, repo=REPO, builder_id=BUILDER,
                             allow_http=True)  # fmt: skip
        self.policies = {d["metadata"]["name"]: d for d in yaml.safe_load_all(text)}
        self.admitted, self.verify, self.running = set(admitted), verify, running
        self.argo_syncs_attack, self.argo_stuck, self.create_error = (
            argo_syncs_attack,
            argo_stuck,
            create_error,
        )
        self.calls: list[list[str]] = []
        self.inputs: dict[int, str] = {}
        self.pushed: list[tuple[str, str]] = []  # (commit, subject)
        self.layer: list[str] = []

    def __call__(
        self, args: Sequence[str], *, input: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        self.calls.append(args)
        if input is not None:
            self.inputs[len(self.calls) - 1] = input
        if args[0] == "git":
            return self._git(args, input, check)
        out, err, code = "", "", 0
        if "imagevalidatingpolicies" in args:
            policy = self.policies[args[-3]]
            out = json.dumps({"spec": {**policy["spec"], "evaluation": {"mode": "Kubernetes"}}})
        elif args[1:3] == ["-m", "sentinelci.cli"]:
            code = self.verify
            out = "NOT TRUSTED: 0/16 checks passed\n" if code else "TRUSTED: 16/16 checks passed\n"
        elif args[0].endswith("crane") and args[1] == "mutate":
            with tarfile.open(args[args.index("--append") + 1]) as archive:
                self.layer = [
                    f"{m.name}:{archive.extractfile(m).read().decode()}" for m in archive.getmembers()
                ]  # type: ignore[union-attr]
            out = f"127.0.0.1:5001/demo-shop/shop-api@{TAMPERED}\n"
        elif "deployment/shop-api" in args and "json" in args:
            if self.running is None:
                code, err = 1, 'Error from server (NotFound): deployments.apps "shop-api" not found'
            else:
                out = json.dumps(live_deployment(self.running))
        elif any(a.startswith("jsonpath=") for a in args):
            out = self.running or ""
        elif "application" in args and "get" in args:
            out = json.dumps({"status": self._application()})
        elif "create" in args:
            image = json.loads(input or "{}")["spec"]["template"]["spec"]["containers"][0]["image"]
            if self.create_error is not None:
                code, err = 1, self.create_error
            elif image not in self.admitted:
                code, err = 1, (VAP_DENIAL if not image.startswith(IN_CLUSTER) else KYVERNO_DENIAL)
        return subprocess.CompletedProcess(args, code, out, err)

    def _git(self, args: list[str], input: str | None, check: bool) -> subprocess.CompletedProcess[str]:
        done = subprocess.run(args, input=input, capture_output=True, text=True, check=False)
        if check and done.returncode:
            raise cluster.ClusterError(f"git failed: {done.stderr}")
        if "push" in args:
            head = [*args[: args.index("push")], "log", "-1", "--format=%H %s"]
            commit, _, subject = (
                subprocess.run(head, capture_output=True, text=True, check=True).stdout.strip().partition(" ")
            )
            self.pushed.append((commit, subject))
        return done

    def _application(self) -> dict[str, Any]:
        commit, subject = self.pushed[-1]
        healthy = {"sync": {"status": "Synced", "revision": commit}, "health": {"status": "Healthy"}}
        if not subject.startswith("attack:"):
            self.running = f"{IN_CLUSTER}@{RELEASE}"
            return healthy
        if self.argo_stuck:
            return {"sync": {"status": "OutOfSync", "revision": commit}, "health": {"status": "Healthy"}}
        if self.argo_syncs_attack:
            self.running = f"{IN_CLUSTER}@{TAMPERED}"
            return healthy
        return {
            "sync": {"status": "OutOfSync", "revision": commit}, "health": {"status": "Healthy"},
            "operationState": {"phase": "Failed", "syncResult": {"revision": commit},
                               "message": f"one or more objects failed to apply, reason: {KYVERNO_DENIAL}"},
        }  # fmt: skip

    def commands(self) -> list[str]:
        return [" ".join(args) for args in self.calls]


@pytest.fixture
def key(tmp_path: Path) -> Path:
    path = tmp_path / "release.pub"
    path.write_text(TEST_KEY, encoding="ascii")
    return path


@pytest.fixture
def gitops(tmp_path: Path) -> Path:
    """The GitOps repository as `make demo-release` left it: main holds the release."""
    directory = tmp_path / "gitops"
    demo.commit_release(RELEASE, directory, cluster.run_command)
    return directory


@pytest.fixture(autouse=True)
def pinned_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(demo, "verified_tool", lambda name, tools_dir: f"/tools/bin/{name}")


def attack(fake: Cluster, key: Path, gitops: Path, block: Path | None = None, timeout_s: float = 30) -> Any:
    return demo.attack(key=key, repo=REPO, builder_id=BUILDER, tools_dir=Path("/tools"), block=block,
                       gitops=gitops, run=fake, timeout_s=timeout_s, sleep=lambda _: None)  # fmt: skip


def released_values(gitops: Path, tmp_path: Path) -> dict[str, Any]:
    clone = tmp_path / "check"
    subprocess.run(["git", "clone", "--quiet", str(gitops / "demo-shop.git"), str(clone)], check=True)
    values: dict[str, Any] = yaml.safe_load((clone / "demo-shop" / "release.yaml").read_text("utf-8"))
    return values


def layout(tmp_path: Path, manifest: bytes = b'{"schemaVersion": 2, "block": true}') -> tuple[Path, str]:
    directory = tmp_path / "block-image"
    (directory / "blobs" / "sha256").mkdir(parents=True)
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    (directory / "blobs" / "sha256" / digest.removeprefix("sha256:")).write_bytes(manifest)
    index = {"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                "digest": digest}]}  # fmt: skip
    (directory / "index.json").write_text(json.dumps(index), "utf-8")
    return directory, digest


# ---------------------------------------------------------------- every attack refused


def test_every_attack_is_refused_by_the_check_that_must_refuse_it(
    key: Path, gitops: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = Cluster(key)
    results = attack(fake, key, gitops, block=tmp_path / "absent")
    assert [(r.name, r.refused, r.by) for r in results] == [
        ("a tampered release (one layer added after signing)", True, "sentinel verify"),
        ("the tampered release committed to the GitOps repository", True, "Kyverno, during Argo CD's sync"),
        ("the tampered release applied with kubectl", True, "Kyverno"),
        ("an image from outside the release repository", True, "the API server's image policy"),
    ]
    assert [r.image for r in results] == [f"{IN_CLUSTER}@{TAMPERED}"] * 3 + ["quay.io/argoproj/argocd:v3.6.1"]
    assert results[0].message == "NOT TRUSTED: 0/16 checks passed"
    assert "not signed by the release key" in results[1].message and results[2].message == KYVERNO_DENIAL
    assert "demo-shop runs SentinelCI releases only" in results[3].message
    assert "the BLOCK image: skipped, no OCI layout" in capsys.readouterr().out

    commands = fake.commands()
    policy = max(i for i, c in enumerate(commands) if "imagevalidatingpolicies" in c)
    (mutate,) = [i for i, args in enumerate(fake.calls) if args[1:2] == ["mutate"]]
    args = fake.calls[mutate]
    assert args[:4] == [
        "/tools/bin/crane",
        "mutate",
        f"127.0.0.1:5001/demo-shop/shop-api@{RELEASE}",
        "--append",
    ]
    assert args[5:] == ["--repo", "127.0.0.1:5001/demo-shop/shop-api", "--insecure"]
    verify = next(i for i, c in enumerate(commands) if " verify " in c)
    assert commands[verify].split()[4] == f"127.0.0.1:5001/demo-shop/shop-api@{TAMPERED}"
    assert policy < mutate < verify
    assert fake.layer == [
        "sentinel-demo/tampered.txt:Added by `make demo-attack` after the release was signed: a new digest, "
        "with no signature.\n"
    ]
    assert not [c for c in commands if " delete " in c], "nothing was created, so nothing is deleted"


def test_the_gitops_attack_is_committed_then_the_release_restored(
    key: Path, gitops: Path, tmp_path: Path
) -> None:
    fake = Cluster(key)
    attack(fake, key, gitops)
    assert [subject for _, subject in fake.pushed] == [
        f"attack: deploy a tampered image {TAMPERED}",
        f"restore release {RELEASE}",
    ]
    assert released_values(gitops, tmp_path) == {"image": {"digest": RELEASE}}
    log = subprocess.run(["git", "-C", str(gitops / "demo-shop.git"), "log", "--format=%s", "main"],
                         capture_output=True, text=True, check=True).stdout.split("\n")  # fmt: skip
    assert log[:3] == [f"restore release {RELEASE}", f"attack: deploy a tampered image {TAMPERED}",
                       f"release {RELEASE}"], "the attack stays in the history, as evidence"  # fmt: skip
    rollout = [c for c in fake.commands() if " rollout status " in c]
    assert rollout, "the release's rollout is checked after the restore"


def test_the_attack_deployments_are_the_release_s_with_another_image(key: Path, gitops: Path) -> None:
    fake = Cluster(key)
    attack(fake, key, gitops)
    created = [json.loads(fake.inputs[i]) for i, args in enumerate(fake.calls) if "create" in args]
    assert [d["metadata"]["name"] for d in created] == ["shop-api-tampered", "shop-api-foreign"]
    release = live_deployment()["spec"]["template"]["spec"]
    for deployment in created:
        name = deployment["metadata"]["name"]
        assert deployment["metadata"] == {"name": name, "namespace": "demo-shop", "labels": {
            "app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "demo-shop-attack"}}  # fmt: skip
        assert deployment["spec"]["selector"] == {"matchLabels": {"app.kubernetes.io/name": name}}
        pod = deployment["spec"]["template"]["spec"]
        assert pod["securityContext"] == release["securityContext"], "only the image can be why it is denied"
        assert {k: v for k, v in pod["containers"][0].items() if k != "image"} == {
            k: v for k, v in release["containers"][0].items() if k != "image"
        }


def test_the_block_image_is_pushed_and_refused(key: Path, gitops: Path, tmp_path: Path) -> None:
    directory, digest = layout(tmp_path)
    fake = Cluster(key)
    results = attack(fake, key, gitops, block=directory)
    assert (results[-1].name, results[-1].image, results[-1].refused, results[-1].by) == (
        "the BLOCK image the release gate refused to sign", f"{IN_CLUSTER}@{digest}", True, "Kyverno",
    )  # fmt: skip
    assert (
        f"/tools/bin/crane push {directory} 127.0.0.1:5001/demo-shop/shop-api:block --insecure"
        in fake.commands()
    )


# ---------------------------------------------------------------- an attack that is not refused


def test_an_admitted_deployment_is_reported_and_deleted_at_once(key: Path, gitops: Path) -> None:
    fake = Cluster(key, admitted=[f"{IN_CLUSTER}@{TAMPERED}"])
    results = attack(fake, key, gitops)
    (applied,) = [r for r in results if r.name == "the tampered release applied with kubectl"]
    assert not applied.refused and applied.message == "created deployment/shop-api-tampered (deleted again)"
    assert (
        "kubectl --context kind-sentinel --namespace demo-shop delete deployment/shop-api-tampered "
        "--wait=false" in fake.commands()
    )


def test_a_tampered_image_argo_cd_deploys_is_reported_and_the_release_restored(
    key: Path, gitops: Path, tmp_path: Path
) -> None:
    fake = Cluster(key, argo_syncs_attack=True)
    results = attack(fake, key, gitops)
    assert not results[1].refused and "Argo CD synced the tampered image" in results[1].message
    assert released_values(gitops, tmp_path) == {"image": {"digest": RELEASE}}
    assert fake.running == f"{IN_CLUSTER}@{RELEASE}"


def test_sentinel_verify_trusting_the_tampered_image_is_reported(key: Path, gitops: Path) -> None:
    results = attack(Cluster(key, verify=0), key, gitops)
    assert not results[0].refused


@pytest.mark.parametrize(("refused", "code"), [(True, 0), (False, 1)])
def test_the_exit_code_says_whether_every_attack_was_refused(
    monkeypatch: pytest.MonkeyPatch, refused: bool, code: int
) -> None:
    outcome = [
        demo.Attack("one", "image", True, "Kyverno", "denied"),
        demo.Attack("two", "i", refused, "x", "m"),
    ]
    monkeypatch.setattr(demo, "attack", lambda **kwargs: outcome)
    assert demo.main(["attack"]) == code


# ---------------------------------------------------------------- an attack that could not be run


def test_without_a_running_release_nothing_is_tried(key: Path, gitops: Path) -> None:
    fake = Cluster(key, running=None)
    with pytest.raises(cluster.ClusterError, match="make demo-release first"):
        attack(fake, key, gitops)
    assert not [c for c in fake.commands() if " mutate " in c or " create " in c]


def test_a_create_that_fails_before_admission_proves_nothing(key: Path, gitops: Path) -> None:
    fake = Cluster(key, create_error='Error from server (NotFound): namespaces "demo-shop" not found')
    with pytest.raises(cluster.ClusterError, match="before admission could judge it"):
        attack(fake, key, gitops)


def test_the_gitops_repository_is_restored_even_when_argo_cd_never_answers(
    key: Path, gitops: Path, tmp_path: Path
) -> None:
    fake = Cluster(key, argo_stuck=True)
    with pytest.raises(cluster.ClusterError, match="did not sync"):
        attack(fake, key, gitops, timeout_s=0)
    assert released_values(gitops, tmp_path) == {"image": {"digest": RELEASE}}


@pytest.mark.parametrize(
    ("manifests", "message"),
    [([], "exactly one image"), (["a", "b"], "exactly one image"), (["sha256:" + "0" * 64], "does not have")],
    ids=["empty", "two", "not-that-digest"],
)
def test_a_block_layout_that_is_not_one_image_is_refused(
    tmp_path: Path, manifests: list[str], message: str
) -> None:
    directory, _ = layout(tmp_path)
    index = {"manifests": [{"digest": d} for d in manifests]}
    (directory / "index.json").write_text(json.dumps(index), "utf-8")
    with pytest.raises(cluster.ClusterError, match=message):
        demo.layout_digest(directory)
