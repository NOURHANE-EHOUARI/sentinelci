"""The demo cluster's setup (deploy/kind, task A5b): its pins and the commands `cluster.py` runs.

No Docker, kind or cluster is needed: the commands go to a recording fake that answers like the real tools.
The cluster itself is tested end to end by cli/tests/supplychain/test_kind_admission.py, in the sentinel-kind
workflow.
"""

import hashlib
import importlib.util
import json
import re
import shutil
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
        openssl: str = "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\n",
        registry_tls: bool = True,
    ) -> None:
        self.registry, self.clusters, self.network = registry, clusters, network
        self.kubectl, self.docker = kubectl, docker  # kubectl None: not installed
        self.openssl, self.registry_tls = openssl, registry_tls
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
        elif args[:2] == ["openssl", "version"]:
            out = self.openssl
        elif args[:2] == ["docker", "inspect"] and args[3] == "{{.State.Running}}":
            out, code = (self.registry or "", 0) if self.registry is not None else ("", 1)
        elif args[:2] == ["docker", "inspect"] and args[3] == "{{json .Config.Env}}":
            tls = ["REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt"] if self.registry_tls else []
            out = json.dumps(["PATH=/usr/bin", *tls])
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
def tls(tmp_path: Path) -> Path:
    """The registry's certificate, already issued: `up` keeps it, so no openssl runs in these tests."""
    directory = tmp_path / "tls"
    directory.mkdir()
    for name in ("ca.crt", "registry.crt", "registry.key"):
        (directory / name).write_text(f"-----BEGIN TEST {name}-----\n", encoding="ascii")
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


def test_up_on_a_new_machine_creates_everything_with_the_pins(pinned: Any, cache: Path, tls: Path) -> None:
    fake = Fake()
    cluster.up(pinned, "/tools/bin/kind", cache, run=fake, tls=tls)
    commands = fake.commands()
    (start,) = [c for c in commands if c.startswith("docker run")]
    assert f"--publish 127.0.0.1:{pinned.registry_port}:5000" in start, "the registry is on the loopback only"
    assert start.endswith(pinned.registry_image) and "--name kind-registry" in start
    # TLS only (Hiba's kind run, #60): Kyverno reads cosign's bundles over HTTPS whatever the policy says.
    assert f"--volume {tls.resolve()}:/certs:ro" in start
    assert "--env REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt" in start
    assert "--env REGISTRY_HTTP_TLS_KEY=/certs/registry.key" in start
    assert (
        f"/tools/bin/kind create cluster --name sentinel --config {cluster.KIND_CONFIG} --wait 180s"
        in commands
    )
    hosts = [(args[-1], data) for args, data in fake.calls if args[-1].endswith("hosts.toml")]
    assert [path for path, _ in hosts] == [
        "/etc/containerd/certs.d/kind-registry:5000/hosts.toml",
        f"/etc/containerd/certs.d/localhost:{pinned.registry_port}/hosts.toml",
    ]
    node_ca = "/etc/containerd/certs.d/kind-registry:5000/ca.crt"
    assert all(
        data == '[host."https://kind-registry:5000"]\n  capabilities = ["pull", "resolve"]\n'
        f'  ca = "{node_ca}"\n'
        for _, data in hosts
    )
    ca = (tls / "ca.crt").read_text(encoding="ascii")
    assert (["docker", "exec", "-i", "sentinel-control-plane", "cp", "/dev/stdin", node_ca], ca) in fake.calls
    assert "docker network connect kind kind-registry" in commands
    registry_hosting, ca_map = [data for args, data in fake.calls if args[-2:] == ["-f", "-"]]
    assert 'host: "localhost:5001"' in str(registry_hosting)
    assert 'hostFromClusterNetwork: "kind-registry:5000"' in str(registry_hosting)
    assert json.loads(str(ca_map)) == {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "kind-registry-ca", "namespace": "kyverno"}, "data": {"ca.crt": ca},
    }  # fmt: skip
    applied = commands.index(
        f"kubectl --context kind-sentinel apply --server-side -f {cache}/kyverno-1.19.2-install.yaml"
    )
    (patch,) = [args for args, _ in fake.calls if "patch" in args]
    assert patch[:8] == ["kubectl", "--context", "kind-sentinel", "--namespace", "kyverno", "patch",
                         "deployment", "kyverno-admission-controller"]  # fmt: skip
    template = json.loads(patch[-1])["spec"]["template"]["spec"]
    assert template["volumes"] == [
        {"name": "sentinel-registry-ca", "configMap": {"name": "kind-registry-ca"}}
    ]
    (container,) = template["containers"]
    assert container["name"] == "kyverno"
    assert container["env"] == [{"name": "SSL_CERT_DIR", "value": "/sentinel-registry-ca"}]
    assert container["volumeMounts"] == [
        {"name": "sentinel-registry-ca", "mountPath": "/sentinel-registry-ca", "readOnly": True}
    ]
    rollout = commands.index(
        "kubectl --context kind-sentinel --namespace kyverno rollout status "
        "deployment/kyverno-admission-controller --timeout=300s"
    )
    assert applied < commands.index(" ".join(patch)) < rollout
    assert commands[rollout + 1].startswith("kubectl --context kind-sentinel wait --namespace kyverno")


def test_up_twice_keeps_what_exists(pinned: Any, cache: Path, tls: Path) -> None:
    fake = Fake(registry="true", clusters="other\nsentinel\n", network='{"NetworkID":"x"}')
    cluster.up(pinned, "kind", cache, run=fake, tls=tls)
    commands = fake.commands()
    assert not [c for c in commands if c.startswith(("docker run", "docker start", "docker network connect"))]
    assert not [c for c in commands if " create cluster " in c]
    assert not [c for c in commands if c.startswith("openssl req")], "the certificate is kept"
    stopped = Fake(registry="false", clusters="sentinel")
    cluster.up(pinned, "kind", cache, run=stopped, tls=tls)
    assert "docker start kind-registry" in stopped.commands()


def test_a_registry_an_older_up_made_without_tls_is_refused(pinned: Any, cache: Path, tls: Path) -> None:
    fake = Fake(registry="true", clusters="sentinel", registry_tls=False)
    with pytest.raises(cluster.ClusterError, match=r"serves plain HTTP.*make kind-down"):
        cluster.up(pinned, "kind", cache, run=fake, tls=tls)
    assert not [c for c in fake.commands() if " create cluster " in c or c.startswith("kubectl --context")]


def test_up_refuses_a_machine_without_openssl_3_before_creating_anything(
    pinned: Any, cache: Path, tmp_path: Path
) -> None:
    fake = Fake(openssl="LibreSSL 2.8.3\n")
    with pytest.raises(cluster.ClusterError, match="OpenSSL 3 is needed"):
        cluster.up(pinned, "kind", cache, run=fake, tls=tmp_path / "none")
    assert not [c for c in fake.commands() if c.startswith(("docker run", "openssl req"))]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_the_registry_certificate_is_issued_once_by_a_ca_whose_key_is_deleted(
    pins: Any, tmp_path: Path
) -> None:
    directory = tmp_path / "tls"
    ca = cluster.registry_tls(pins, directory)
    assert sorted(p.name for p in directory.iterdir()) == ["ca.crt", "registry.crt", "registry.key"]

    def openssl(*args: str) -> str:
        done = subprocess.run(["openssl", *args], capture_output=True, text=True, check=True)
        return done.stdout

    assert openssl("verify", "-CAfile", str(ca), str(directory / "registry.crt")).strip().endswith("OK")
    text = openssl("x509", "-in", str(directory / "registry.crt"), "-noout", "-text")
    assert "DNS:kind-registry, DNS:localhost, IP Address:127.0.0.1" in text
    assert "TLS Web Server Authentication" in text and "CA:FALSE" in text
    assert "CA:TRUE, pathlen:0" in openssl("x509", "-in", str(ca), "-noout", "-text")
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert cluster.registry_tls(pins, directory) == ca
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before, "kept: up is safe to run twice"


def test_a_manifest_that_is_not_the_pinned_one_is_refused_before_anything_is_applied(
    pins: Any, cache: Path, tls: Path
) -> None:
    fake = Fake(registry="true", clusters="sentinel", network="{}")
    with pytest.raises(cluster.ClusterError, match="not the pinned"):
        cluster.up(pins, "kind", cache, run=fake, tls=tls)
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
    assert all(d["spec"]["credentials"] == {"allowInsecureRegistry": False} for d in documents), "TLS only"
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
    fake: Fake, message: str, pinned: Any, cache: Path, tls: Path
) -> None:
    with pytest.raises(cluster.ClusterError, match=message):
        cluster.up(pinned, "kind", cache, run=fake, tls=tls)
    created = [c for c in fake.commands() if not c.startswith(("docker version", "kubectl version"))]
    assert created == [], "nothing is started, created or applied"


@pytest.mark.parametrize("minor", ["36", "37", "38", "37+"])
def test_kubectl_within_one_minor_version_of_the_cluster_is_accepted(
    minor: str, pinned: Any, cache: Path, tls: Path
) -> None:
    fake = Fake(kubectl=f'{{"clientVersion": {{"major": "1", "minor": "{minor}"}}}}')
    cluster.up(pinned, "kind", cache, run=fake, tls=tls)
    assert fake.commands()[:2] == [
        "docker version --format {{.Server.Version}}",
        "kubectl version --client --output=json",
    ]


def test_the_policy_is_not_rendered_without_a_supported_kubectl(tmp_path: Path) -> None:
    out, fake = tmp_path / "policy.yaml", Fake(kubectl=None)
    with pytest.raises(cluster.ClusterError, match="kubectl is not installed"):
        cluster.policy(tmp_path / "release.pub", out, run=fake)
    assert not out.exists()
