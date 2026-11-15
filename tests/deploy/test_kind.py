"""The demo cluster's setup (deploy/kind, task A5b): its pins and the commands `cluster.py` runs.

No Docker, kind or cluster is needed: the commands go to a recording fake that answers like the real tools.
The cluster itself is tested end to end by cli/tests/supplychain/test_kind_admission.py, in the sentinel-kind
workflow.
"""

import hashlib
import importlib.util
import re
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
KIND_DIR = ROOT / "deploy" / "kind"
PINNED_IMAGE = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("kind_cluster", KIND_DIR / "cluster.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their annotations through it
    spec.loader.exec_module(module)
    return module


cluster = _load()


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
    ) -> None:
        self.registry, self.clusters, self.network = registry, clusters, network
        self.kubectl, self.docker = kubectl, docker  # kubectl None: not installed
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
        return subprocess.CompletedProcess(args, code, out, err)

    def commands(self) -> list[str]:
        return [" ".join(args) for args, _ in self.calls]


@pytest.fixture
def pins() -> Any:
    return cluster.load_pins()


@pytest.fixture
def cache(tmp_path: Path, pins: Any) -> Path:
    """A cache holding the pinned manifest, so no download happens."""
    directory = tmp_path / "cache"
    directory.mkdir()
    path = directory / f"kyverno-{pins.kyverno_version}-install.yaml"
    path.write_bytes(b"pinned")
    return directory


@pytest.fixture
def pinned(pins: Any) -> Any:
    """The pins, with Kyverno's sha256 being that of the cached test manifest."""
    return cluster.Pins(**{**pins.__dict__, "kyverno_sha256": hashlib.sha256(b"pinned").hexdigest()})


# ---------------------------------------------------------------- pins


def test_everything_the_cluster_pulls_or_applies_is_pinned() -> None:
    config = yaml.safe_load((KIND_DIR / "kind-config.yaml").read_text(encoding="utf-8"))
    assert config["name"] == cluster.CLUSTER
    assert config["networking"] == {"apiServerAddress": "127.0.0.1"}, "the API server stays on the loopback"
    assert [n["role"] for n in config["nodes"]] == ["control-plane"]
    assert all(PINNED_IMAGE.fullmatch(n["image"]) for n in config["nodes"])
    pins = cluster.load_pins()
    assert PINNED_IMAGE.fullmatch(pins.registry_image)
    assert re.fullmatch(r"[a-f0-9]{64}", pins.kyverno_sha256)


def test_kyverno_in_the_cluster_is_the_release_of_the_cli_the_tests_run() -> None:
    lock = tomllib.loads((ROOT / "tools.lock.toml").read_text(encoding="utf-8"))
    pins = cluster.load_pins()
    assert pins.kyverno_version == lock["tools"]["kyverno"]["version"]
    assert pins.kyverno_url.endswith(f"/v{pins.kyverno_version}/install.yaml")
    assert "kind" in lock["tools"] and lock["tools"]["kind"]["archive"] == "none"


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("registry", "image", "registry:3", "pinned by tag and digest"),
        ("registry", "container", "kind_registry", "DNS label"),
        ("registry", "host_port", 80, "unprivileged"),
        ("kyverno", "url", "https://example.com/install.yaml", "release asset"),
        (
            "kyverno",
            "url",
            "https://github.com/kyverno/kyverno/releases/download/v1.18.0/install.yaml",
            "release",
        ),
        ("kyverno", "sha256", "abc", "sha256"),
    ],
    ids=["registry-by-tag", "container-name", "privileged-port", "not-github", "other-version", "no-sha256"],
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


def test_up_on_a_new_machine_creates_everything_with_the_pins(pinned: Any, cache: Path) -> None:
    fake = Fake()
    cluster.up(pinned, "/tools/bin/kind", cache, run=fake)
    commands = fake.commands()
    (start,) = [c for c in commands if c.startswith("docker run")]
    assert f"--publish 127.0.0.1:{pinned.registry_port}:5000" in start, "the registry is on the loopback only"
    assert start.endswith(pinned.registry_image) and "--name kind-registry" in start
    assert (
        f"/tools/bin/kind create cluster --name sentinel --config {cluster.KIND_CONFIG} --wait 180s"
        in commands
    )
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
    (config_map,) = [data for args, data in fake.calls if args[-2:] == ["-f", "-"]]
    assert 'host: "localhost:5001"' in str(
        config_map
    ) and 'hostFromClusterNetwork: "kind-registry:5000"' in str(config_map)
    applied = commands.index(
        f"kubectl --context kind-sentinel apply --server-side -f {cache}/kyverno-1.19.2-install.yaml"
    )
    assert commands[applied + 1].startswith("kubectl --context kind-sentinel wait --namespace kyverno")


def test_up_twice_keeps_what_exists(pinned: Any, cache: Path) -> None:
    fake = Fake(registry="true", clusters="other\nsentinel\n", network='{"NetworkID":"x"}')
    cluster.up(pinned, "kind", cache, run=fake)
    commands = fake.commands()
    assert not [c for c in commands if c.startswith(("docker run", "docker start", "docker network connect"))]
    assert not [c for c in commands if " create cluster " in c]
    stopped = Fake(registry="false", clusters="sentinel")
    cluster.up(pinned, "kind", cache, run=stopped)
    assert "docker start kind-registry" in stopped.commands()


def test_a_manifest_that_is_not_the_pinned_one_is_refused_before_anything_is_applied(
    pins: Any, cache: Path
) -> None:
    fake = Fake(registry="true", clusters="sentinel", network="{}")
    with pytest.raises(cluster.ClusterError, match="not the pinned"):
        cluster.up(pins, "kind", cache, run=fake)
    assert not [c for c in fake.commands() if "--server-side" in c]
    assert not list(cache.glob("kyverno-*")), "the file that did not match is deleted, not kept for next time"


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


def test_the_policy_expects_the_builder_a_laptop_release_records() -> None:
    """Hiba's kind run (#60): with the CI workflow's builder, Kyverno and `sentinel verify` refuse every
    release `make release` signs, since its provenance names the release script. In the private phase, that is
    every release."""
    from sentinelci.supplychain.attestations import local_release_builder_id

    assert local_release_builder_id(cluster.REPO) == cluster.BUILDER_ID
    assert cluster.BUILDER_ID.endswith("/deploy/release/release.py@refs/heads/main")


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
