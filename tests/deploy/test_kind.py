"""The demo cluster's setup (deploy/kind, task A5b): its pins and the commands `cluster.py` runs.

No Docker, kind or cluster is needed: the commands go to a recording fake that answers like the real tools.
The cluster itself is tested end to end by cli/tests/supplychain/test_kind_admission.py and test_kind_demo.py,
in the sentinel-kind workflow.
"""

import functools
import hashlib
import importlib.util
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
KIND_DIR = ROOT / "deploy" / "kind"
PINNED_IMAGE = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("cluster", KIND_DIR / "cluster.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their annotations through it
    spec.loader.exec_module(module)
    return module


cluster = _load()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


class Fake:
    """Records every command and answers like Docker, kind and kubectl would on a given machine."""

    def __init__(
        self,
        *,
        registry: str | None = None,
        clusters: str = "",
        network: str = "null",
        kubectl: str | None = '{"clientVersion": {"major": "1", "minor": "37", "gitVersion": "v1.37.0"}}',
        docker: bool = True,
        mounted: bool = True,
    ) -> None:
        self.registry, self.clusters, self.network = registry, clusters, network
        self.kubectl, self.docker, self.mounted = kubectl, docker, mounted  # kubectl None: not installed
        self.calls: list[tuple[list[str], str | None]] = []

    def __call__(
        self, args: Sequence[str], *, input: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        args = list(args)
        self.calls.append((args, input))
        out, code, err = "", 0, ""
        if args[:2] == ["kubectl", "version"]:
            if self.kubectl is None:  # what run_command says when the binary is missing
                raise cluster.ClusterError("kubectl could not run: FileNotFoundError")
            out = self.kubectl
        elif args[:2] == ["docker", "version"]:
            out, code, err = (
                ("29.1.0\n", 0, "") if self.docker else ("", 1, "Cannot connect to the Docker daemon")
            )
        elif args[:2] == ["docker", "inspect"] and args[3] == "{{.State.Running}}":
            out, code = (self.registry or "", 0) if self.registry is not None else ("", 1)
        elif args[:2] == ["docker", "inspect"]:
            out = self.network
        elif args[1:3] == ["get", "clusters"]:
            out = self.clusters
        elif args[1:3] == ["get", "nodes"]:
            out = "sentinel-control-plane\n"
        elif args[:2] == ["docker", "exec"] and args[3:5] == ["test", "-d"]:
            code = 0 if self.mounted else 1
        return subprocess.CompletedProcess(args, code, out, err)

    def commands(self) -> list[str]:
        return [" ".join(args) for args, _ in self.calls]


@pytest.fixture
def pins() -> Any:
    return cluster.load_pins()


@pytest.fixture
def cache(tmp_path: Path, pins: Any) -> Path:
    """A cache holding the pinned manifests, so no download happens."""
    directory = tmp_path / "cache"
    directory.mkdir()
    (directory / f"kyverno-{pins.kyverno.version}-install.yaml").write_bytes(b"pinned kyverno")
    (directory / f"argo-cd-{pins.argocd.version}-core-install.yaml").write_bytes(b"pinned argocd")
    return directory


@pytest.fixture
def pinned(pins: Any) -> Any:
    """The pins, with the manifests' sha256 being those of the cached test manifests."""
    return replace(
        pins,
        kyverno=replace(pins.kyverno, sha256=hashlib.sha256(b"pinned kyverno").hexdigest()),
        argocd=replace(pins.argocd, sha256=hashlib.sha256(b"pinned argocd").hexdigest()),
    )


@pytest.fixture
def gitops(tmp_path: Path) -> Path:
    return tmp_path / "gitops"


# ---------------------------------------------------------------- pins


def test_everything_the_cluster_pulls_or_applies_is_pinned() -> None:
    config = yaml.safe_load((KIND_DIR / "kind-config.yaml").read_text(encoding="utf-8"))
    assert config["name"] == cluster.CLUSTER
    assert config["networking"] == {"apiServerAddress": "127.0.0.1"}, "the API server stays on the loopback"
    assert [n["role"] for n in config["nodes"]] == ["control-plane"]
    assert all(PINNED_IMAGE.fullmatch(n["image"]) for n in config["nodes"])
    pins = cluster.load_pins()
    assert PINNED_IMAGE.fullmatch(pins.registry_image)
    assert all(re.fullmatch(r"[a-f0-9]{64}", m.sha256) for m in (pins.kyverno, pins.argocd))


def test_the_git_server_runs_the_image_of_the_pinned_argo_cd() -> None:
    """The git server reuses Argo CD's image (it ships git), so it moves with the Argo CD pin: the image the
    core-install.yaml of that version names for all its Argo CD workloads."""
    pins = cluster.load_pins()
    assert pins.argocd.url.endswith(f"/v{pins.argocd.version}/manifests/core-install.yaml")
    documents = list(yaml.safe_load_all((ROOT / "deploy" / "argocd" / "git-server.yaml").read_text("utf-8")))
    (deployment,) = [d for d in documents if d["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    assert container["image"] == f"quay.io/argoproj/argocd:v{pins.argocd.version}"


def test_kyverno_in_the_cluster_is_the_release_of_the_cli_the_tests_run() -> None:
    lock = tomllib.loads((ROOT / "tools.lock.toml").read_text(encoding="utf-8"))
    pins = cluster.load_pins()
    assert pins.kyverno.version == lock["tools"]["kyverno"]["version"]
    assert pins.kyverno.url.endswith(f"/v{pins.kyverno.version}/install.yaml")
    assert "kind" in lock["tools"] and lock["tools"]["kind"]["archive"] == "none"


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("registry", "image", "registry:3", "pinned by tag and digest"),
        ("registry", "container", "kind_registry", "DNS label"),
        ("registry", "host_port", 80, "unprivileged"),
        ("kyverno", "url", "https://example.com/v1.19.2/install.yaml", "release asset"),
        (
            "kyverno",
            "url",
            "https://github.com/kyverno/kyverno/releases/download/v1.18.0/install.yaml",
            "of version 1.19.2",
        ),
        ("kyverno", "sha256", "abc", "sha256"),
        (
            "argocd",
            "url",
            "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/core-install.yaml",
            "file at the release tag",
        ),
        (
            "argocd",
            "url",
            "http://raw.githubusercontent.com/argoproj/argo-cd/v3.6.1/manifests/core-install.yaml",
            "release asset",
        ),
        ("argocd", "sha256", "", "Argo CD's manifest needs its sha256"),
    ],
    ids=[
        "registry-by-tag",
        "container-name",
        "privileged-port",
        "not-github",
        "other-version",
        "no-sha256",
        "argocd-branch",
        "argocd-http",
        "argocd-no-sha256",
    ],
)
def test_a_pin_that_is_not_one_is_refused(
    tmp_path: Path, section: str, key: str, value: object, message: str
) -> None:
    data = tomllib.loads((KIND_DIR / "cluster.toml").read_text(encoding="utf-8"))
    data[section][key] = value
    lines = []
    for name, table in data.items():
        lines.append(f"[{name}]")
        lines += [f"{k} = {v!r}" if isinstance(v, int) else f'{k} = "{v}"' for k, v in table.items()]
    path = tmp_path / "cluster.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(cluster.ClusterError, match=message):
        cluster.load_pins(path)


# ---------------------------------------------------------------- up, down, policy


def test_up_on_a_new_machine_creates_everything_with_the_pins(pinned: Any, cache: Path, gitops: Path) -> None:
    fake = Fake()
    cluster.up(pinned, "/tools/bin/kind", cache, run=fake, gitops=gitops)
    commands = fake.commands()
    (start,) = [c for c in commands if c.startswith("docker run")]
    assert f"--publish 127.0.0.1:{pinned.registry_port}:5000" in start, "the registry is on the loopback only"
    assert start.endswith(pinned.registry_image) and "--name kind-registry" in start

    # The GitOps repository exists, exported, before the cluster that mounts it.
    repository = gitops / "demo-shop.git"
    init = commands.index(f"git init --quiet --bare --initial-branch=main {repository}")
    assert (repository / "git-daemon-export-ok").is_file()
    create = commands.index(
        f"/tools/bin/kind create cluster --name sentinel --config {cache}/kind-config.yaml --wait 180s"
    )
    assert init < create
    config = yaml.safe_load((cache / "kind-config.yaml").read_text(encoding="utf-8"))
    base = yaml.safe_load(cluster.KIND_CONFIG.read_text(encoding="utf-8"))
    (node,) = config["nodes"]
    assert node.pop("extraMounts") == [
        {"hostPath": str(gitops.resolve()), "containerPath": "/sentinel-gitops", "readOnly": True}
    ]
    assert config == base, "the written config is the pinned one plus the mount"

    hosts = [(args[-1], data) for args, data in fake.calls if args[-1].endswith("hosts.toml")]
    assert [path for path, _ in hosts] == [
        "/etc/containerd/certs.d/kind-registry:5000/hosts.toml",
        f"/etc/containerd/certs.d/localhost:{pinned.registry_port}/hosts.toml",
    ]
    assert all(
        data == '[host."http://kind-registry:5000"]\n  capabilities = ["pull", "resolve"]\n'
        for _, data in hosts
    )
    assert "docker network connect kind kind-registry" in commands
    config_map = next(data for args, data in fake.calls if args[-2:] == ["-f", "-"])
    assert 'host: "localhost:5001"' in str(config_map)
    assert 'hostFromClusterNetwork: "kind-registry:5000"' in str(config_map)

    kubectl = "kubectl --context kind-sentinel"
    kyverno = commands.index(f"{kubectl} apply --server-side -f {cache}/kyverno-1.19.2-install.yaml")
    assert commands[kyverno + 1].startswith(f"{kubectl} wait --namespace kyverno")
    namespace = [data for args, data in fake.calls if args[-2:] == ["-f", "-"]][1]
    assert namespace == "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: argocd\n"
    argocd = commands.index(
        f"{kubectl} apply --server-side --namespace argocd -f {cache}/argo-cd-3.6.1-core-install.yaml"
    )
    assert kyverno < argocd
    assert commands[argocd + 1].startswith(f"{kubectl} wait --namespace argocd --for=condition=Available")
    assert commands[argocd + 2].startswith(
        f"{kubectl} rollout status --namespace argocd statefulset/argocd-application-controller"
    )
    assert commands[argocd + 3 :] == [
        f"{kubectl} apply -f {cluster.ARGOCD_DIR}/git-server.yaml",
        f"{kubectl} apply -f {cluster.ARGOCD_DIR}/demo-shop-namespace.yaml",
        f"{kubectl} wait --namespace sentinel-gitops --for=condition=Available deployment/gitops "
        "--timeout=180s",
    ]


def test_up_twice_keeps_what_exists(pinned: Any, cache: Path, gitops: Path) -> None:
    fake = Fake(registry="true", clusters="other\nsentinel\n", network='{"NetworkID":"x"}')
    cluster.up(pinned, "kind", cache, run=fake, gitops=gitops)
    commands = fake.commands()
    assert not [c for c in commands if c.startswith(("docker run", "docker start", "docker network connect"))]
    assert not [c for c in commands if " create cluster " in c]
    (gitops / "demo-shop.git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    stopped = Fake(registry="false", clusters="sentinel")
    cluster.up(pinned, "kind", cache, run=stopped, gitops=gitops)
    assert "docker start kind-registry" in stopped.commands()
    assert not [c for c in stopped.commands() if c.startswith("git init")], "the repository is kept"


def test_a_cluster_created_without_the_gitops_mount_is_refused_before_anything_is_applied(
    pinned: Any, cache: Path, gitops: Path
) -> None:
    fake = Fake(registry="true", clusters="sentinel", mounted=False)
    with pytest.raises(cluster.ClusterError, match=r"make kind-down`, then `make kind-up"):
        cluster.up(pinned, "kind", cache, run=fake, gitops=gitops)
    # Only the client version was read: nothing reached the cluster.
    assert not [c for c in fake.commands() if c.startswith("kubectl --context")]


@pytest.mark.parametrize("which", ["kyverno", "argocd"])
def test_a_manifest_that_is_not_the_pinned_one_is_refused_before_anything_is_applied(
    pinned: Any, cache: Path, gitops: Path, which: str
) -> None:
    other = replace(pinned, **{which: replace(getattr(pinned, which), sha256="0" * 64)})
    fake = Fake(registry="true", clusters="sentinel", network="{}")
    with pytest.raises(cluster.ClusterError, match="not the pinned"):
        cluster.up(other, "kind", cache, run=fake, gitops=gitops)
    assert not [c for c in fake.commands() if "--server-side" in c], "neither manifest is applied"
    left = sorted(path.name for path in cache.glob("*-install.yaml"))
    assert len(left) == 1, "the file that did not match is deleted, not kept for next time"


def test_the_gitops_repository_is_served_by_the_git_servers_command(tmp_path: Path) -> None:
    """The git server's own command and environment, run here with the local git: it serves the one
    repository, read-only, even when its files belong to another user (the laptop's user, in the cluster)."""
    git = shutil.which("git")
    if (
        git is None
        or subprocess.run([git, "daemon", "-h"], capture_output=True, check=False).returncode == 127
    ):
        pytest.skip("needs git with git daemon")
    gitops = tmp_path / "gitops"
    repository = cluster.ensure_gitops_repository(gitops)
    work = tmp_path / "work"
    run = functools.partial(subprocess.run, check=True, capture_output=True, text=True)
    run([git, "clone", "--quiet", str(repository), str(work)])
    (work / "release.yaml").write_text("image: {}\n", encoding="utf-8")
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
    run([git, "-C", str(work), "add", "release.yaml"])
    run([git, "-C", str(work), *identity, "commit", "--quiet", "-m", "release"])
    run([git, "-C", str(work), "push", "--quiet", "origin", "HEAD:main"])
    if os.geteuid() == 0:  # as root, the files can belong to someone else, as the laptop user's do in the Pod
        run(["chown", "-R", "65534:65534", str(gitops)])

    documents = yaml.safe_load_all((ROOT / "deploy" / "argocd" / "git-server.yaml").read_text("utf-8"))
    (deployment,) = [d for d in documents if d["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    port = free_port()
    command = [
        arg.replace("/srv/git", str(gitops)).replace("--port=9418", f"--port={port}")
        for arg in container["command"]
    ]
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path)} | {
        e["name"]: e["value"] for e in container["env"]
    }
    daemon = subprocess.Popen([git, *command[1:], "--listen=127.0.0.1"], env=env, stderr=subprocess.PIPE)
    try:
        url = f"git://127.0.0.1:{port}/demo-shop.git"
        for _ in range(50):
            listed = subprocess.run([git, "ls-remote", url], capture_output=True, text=True, check=False)
            if listed.returncode == 0:
                break
            time.sleep(0.1)
        assert listed.returncode == 0 and "refs/heads/main" in listed.stdout, listed.stderr
        other = subprocess.run([git, "ls-remote", f"git://127.0.0.1:{port}/demo-shop"], capture_output=True,
                               check=False)  # fmt: skip
        assert other.returncode != 0, "--strict-paths serves the one path listed, nothing else"
        clone = tmp_path / "clone"
        run([git, "clone", "--quiet", url, str(clone)])
        (clone / "attack").write_text("x", encoding="utf-8")
        run([git, "-C", str(clone), "add", "attack"])
        run([git, "-C", str(clone), *identity, "commit", "--quiet", "-m", "attack"])
        pushed = subprocess.run([git, "-C", str(clone), "push", "origin", "HEAD:main"], capture_output=True,
                                text=True, check=False)  # fmt: skip
        assert pushed.returncode != 0, "nothing can be pushed to it"
    finally:
        daemon.terminate()
        log = daemon.communicate(timeout=10)[1].decode(errors="replace")
    assert "'receive-pack': service not enabled" in log, log


def test_the_policy_is_rendered_for_the_clusters_registry_and_applied(tmp_path: Path) -> None:
    key = tmp_path / "release.pub"
    key.write_text(
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexample0000000000000000000000\n"
        "-----END PUBLIC KEY-----\n",
        encoding="ascii",
    )
    out, fake = tmp_path / "out" / "policy.yaml", Fake()
    cluster.policy(key, out, run=fake)
    documents = list(yaml.safe_load_all(out.read_text(encoding="utf-8")))
    assert [d["spec"]["matchImageReferences"] for d in documents] == [
        [{"expression": "ref.lowerAscii().startsWith('kind-registry:5000/demo-shop/')"}]
    ] * 2
    assert all(d["spec"]["credentials"] == {"allowInsecureRegistry": True} for d in documents)
    assert fake.commands() == [
        "kubectl version --client --output=json",
        f"kubectl --context kind-sentinel apply -f {out}",
    ]


def test_down_deletes_the_cluster_and_the_registry(pins: Any) -> None:
    fake = Fake()
    cluster.down(pins, "kind", run=fake)
    assert fake.commands() == ["kind delete cluster --name sentinel", "docker rm --force kind-registry"]


def test_a_failing_command_is_named_and_stops_the_setup() -> None:
    with pytest.raises(cluster.ClusterError, match=r"false failed \(1\)"):
        cluster.run_command(["false"])
    with pytest.raises(cluster.ClusterError, match="could not run"):
        cluster.run_command(["/nonexistent/sentinel-kind-test"])


# ---------------------------------------------------------------- what comes from the machine


def test_the_node_image_gives_the_clusters_kubernetes_version() -> None:
    assert cluster.node_version() == (1, 37, 0)
    assert "kindest/node:v1.37.0@sha256:" in cluster.KIND_CONFIG.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (Fake(kubectl=None), r"kubectl is not installed: install kubectl v1\.36 to v1\.38 \(the cluster runs "
         r"Kubernetes v1\.37\.0, kind-config\.yaml\)"),
        (Fake(kubectl='{"clientVersion": {"major": "1", "minor": "34"}}'), r"kubectl is v1\.34, outside the "
         r"supported skew: use kubectl v1\.36 to v1\.38"),
        (Fake(kubectl='{"clientVersion": {"major": "1", "minor": "40"}}'), r"kubectl is v1\.40, outside"),
        (Fake(kubectl="error: unknown flag: --output"), r"gave no version: use kubectl v1\.36 to v1\.38"),
        (Fake(docker=False), r"the Docker daemon does not answer \(`docker version`: Cannot connect to the "
         r"Docker daemon\): start Docker"),
    ],
    ids=["no-kubectl", "kubectl-too-old", "kubectl-too-new", "kubectl-unreadable", "no-docker"],
)  # fmt: skip
def test_up_refuses_a_machine_without_docker_or_a_supported_kubectl_before_creating_anything(
    fake: Fake, message: str, pinned: Any, cache: Path
) -> None:
    with pytest.raises(cluster.ClusterError, match=message):
        cluster.up(pinned, "kind", cache, run=fake)
    created = [c for c in fake.commands() if not c.startswith(("docker version", "kubectl version"))]
    assert created == [], "nothing is started, created or applied"


@pytest.mark.parametrize("minor", ["36", "37", "38", "37+"])
def test_kubectl_within_one_minor_version_of_the_cluster_is_accepted(
    minor: str, pinned: Any, cache: Path
) -> None:
    fake = Fake(kubectl=f'{{"clientVersion": {{"major": "1", "minor": "{minor}"}}}}')
    cluster.up(pinned, "kind", cache, run=fake)
    assert fake.commands()[:2] == [
        "docker version --format {{.Server.Version}}",
        "kubectl version --client --output=json",
    ]


def test_the_policy_is_not_rendered_without_a_supported_kubectl(tmp_path: Path) -> None:
    out, fake = tmp_path / "policy.yaml", Fake(kubectl=None)
    with pytest.raises(cluster.ClusterError, match="kubectl is not installed"):
        cluster.policy(tmp_path / "release.pub", out, run=fake)
    assert not out.exists()
