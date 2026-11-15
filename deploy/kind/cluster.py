"""The SentinelCI demo cluster: kind, its registry, Kyverno and Argo CD (task A5b, SPEC section 7, ADR-0011).

    uv run python deploy/kind/cluster.py up        # safe to run twice: what exists is kept
    uv run python deploy/kind/cluster.py policy --key deploy/keys/release.pub
    uv run python deploy/kind/cluster.py down

`up` starts the registry container, creates the GitOps repository and the cluster, tells containerd where the
registry is, and installs Kyverno, Argo CD, the git server that serves the GitOps repository to Argo CD, and
the demo-shop namespace. `policy` renders the release admission policy with `sentinel admission-policy`'s
code, for the images of the cluster's registry, and applies it. `down` deletes the cluster and the registry;
the GitOps repository is kept (it is on the laptop, in .sentinel/gitops).

Everything `up` runs or applies is pinned: kind by sha256 in tools.lock.toml (installed and checked with
`sentinel tools`, and verified again before it runs), the node image by digest in kind-config.yaml, the
registry image by digest and the Kyverno and Argo CD install manifests by sha256 in cluster.toml. A manifest
whose sha256 differs is refused before anything is applied. Docker, git and kubectl come from the machine:
`up` checks that the Docker daemon answers and that kubectl is within one minor version of the node image's
Kubernetes before it creates anything.

The registry is published on the host's loopback only (127.0.0.1:5001). Inside the cluster's network it is
`kind-registry:5000`, plain HTTP, and that is the name the admission policy matches: containerd on the nodes
and Kyverno both reach it there, and `localhost:5001` is an alias of it on the nodes, so a push from the host
and a pull in the cluster name the same images.

The GitOps repository (.sentinel/gitops/demo-shop.git, written by `make demo-release`, deploy/kind/demo.py) is
mounted read-only into the node at /sentinel-gitops, and served from there by deploy/argocd/git-server.yaml.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from sentinelci.supplychain.attestations import local_release_builder_id

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "deploy" / "kind"
ARGOCD_DIR = ROOT / "deploy" / "argocd"
KIND_CONFIG = HERE / "kind-config.yaml"
PINS = HERE / "cluster.toml"
CACHE = ROOT / ".sentinel" / "cache" / "kind"
GITOPS_DIR = ROOT / ".sentinel" / "gitops"
GITOPS_REPOSITORY = "demo-shop.git"
NODE_GITOPS = "/sentinel-gitops"
CLUSTER = "sentinel"
CONTEXT = f"kind-{CLUSTER}"
IMAGE_GLOB = "kind-registry:5000/demo-shop/*"
REPO = "NOURHANE-EHOUARI/sentinelci"
# The builder `make release` records (ADR-0011): in the private phase every release is a laptop release. A
# release from the CI workflow passes --builder-id (Hiba's kind run, #60: that builder refused it).
BUILDER_ID = local_release_builder_id(REPO)
_PINNED_IMAGE = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_NODE_IMAGE = re.compile(r"image:\s*kindest/node:v(\d+)\.(\d+)\.(\d+)@sha256:[a-f0-9]{64}\s")
# A release asset, or a file of the repository at a release tag: either way the version is in the path.
_MANIFEST_URL = re.compile(
    r"^https://(github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download"
    r"|raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/v(?P<version>[^/]+)/[A-Za-z0-9_./-]+\.yaml$"
)
_TIMEOUT_S = 600


class ClusterError(Exception):
    """The cluster could not be set up as pinned: nothing that failed a check was applied."""


@dataclass(frozen=True)
class Manifest:
    """An install manifest, pinned by version and sha256."""

    name: str
    version: str
    url: str
    sha256: str


@dataclass(frozen=True)
class Pins:
    registry_image: str
    registry_container: str
    registry_port: int
    kyverno: Manifest
    argocd: Manifest

    @property
    def registry_in_cluster(self) -> str:
        return f"{self.registry_container}:5000"

    @property
    def registry_on_host(self) -> str:
        return f"localhost:{self.registry_port}"


def _manifest(path: Path, name: str, table: dict[str, str]) -> Manifest:
    pinned = Manifest(name=name, version=table["version"], url=table["url"], sha256=table["sha256"])
    match = _MANIFEST_URL.fullmatch(pinned.url)
    if match is None or match["version"] != pinned.version:
        raise ClusterError(
            f"{path}: {name}'s manifest must be a release asset, or a file at the release tag, of version "
            f"{pinned.version}"
        )
    if not _SHA256.fullmatch(pinned.sha256):
        raise ClusterError(f"{path}: {name}'s manifest needs its sha256")
    return pinned


def load_pins(path: Path = PINS) -> Pins:
    """The pins of cluster.toml, checked: the image by digest, each manifest of its version with a sha256."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    registry = data["registry"]
    pins = Pins(
        registry_image=registry["image"],
        registry_container=registry["container"],
        registry_port=int(registry["host_port"]),
        kyverno=_manifest(path, "Kyverno", data["kyverno"]),
        argocd=_manifest(path, "Argo CD", data["argocd"]),
    )
    if not _PINNED_IMAGE.fullmatch(pins.registry_image):
        raise ClusterError(f"{path}: the registry image must be pinned by tag and digest")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", pins.registry_container):
        raise ClusterError(f"{path}: the registry container name must be a plain DNS label")
    if not 1024 <= pins.registry_port <= 65535:
        raise ClusterError(f"{path}: the registry port must be an unprivileged port")
    return pins


Run = Callable[..., subprocess.CompletedProcess[str]]


def run_command(
    args: Sequence[str], *, input: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a command with its output captured; a failure is a ClusterError that names the command."""
    try:
        done = subprocess.run(  # noqa: S603 (fixed commands, arguments from the pins and the CLI)
            list(args), input=input, capture_output=True, text=True, timeout=_TIMEOUT_S, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ClusterError(f"{args[0]} could not run: {type(exc).__name__}") from exc
    if check and done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["no output"])[-1]
        raise ClusterError(f"{' '.join(args[:3])} failed ({done.returncode}): {last}")
    return done


def kind_binary(tools_dir: Path) -> str:
    """The pinned kind, verified against tools.lock.toml before it runs."""
    from sentinelci.scanners.errors import ToolIntegrityError
    from sentinelci.scanners.installer import verify_tools
    from sentinelci.scanners.lock import load_lock

    try:
        (entry,) = verify_tools(load_lock(ROOT / "tools.lock.toml"), tools_dir, only=["kind"]).entries
    except ToolIntegrityError as exc:  # missing, or not the pinned binary
        raise ClusterError(
            f"kind is not installed as pinned in {tools_dir}: `uv run sentinel tools install kind` ({exc})"
        ) from exc
    return str(entry.path)


def manifest(pinned: Manifest, cache: Path) -> Path:
    """An install manifest, downloaded once into `cache` and checked against its pinned sha256 every time: a
    file that does not match is deleted and refused."""
    cache.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", pinned.name.lower())
    path = cache / f"{slug}-{pinned.version}-{pinned.url.rsplit('/', 1)[-1]}"
    if not path.exists():
        partial = path.with_suffix(".part")
        with urllib.request.urlopen(pinned.url, timeout=120) as response:  # noqa: S310 (pinned https)
            partial.write_bytes(response.read())
        partial.replace(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != pinned.sha256:
        path.unlink()
        raise ClusterError(
            f"{pinned.name}'s install manifest has sha256 {digest}, not the pinned {pinned.sha256}: "
            "not applied"
        )
    return path


def ensure_gitops_repository(gitops: Path, run: Run = run_command) -> Path:
    """The demo's GitOps repository: a bare repository with one branch, main, that the git server exports.
    Created empty if missing; an existing one is kept as it is."""
    repository = gitops / GITOPS_REPOSITORY
    if not (repository / "HEAD").exists():
        repository.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "--quiet", "--bare", "--initial-branch=main", str(repository)])
    (repository / "git-daemon-export-ok").touch()
    return repository


def kind_config(gitops: Path, cache: Path) -> Path:
    """kind-config.yaml with the GitOps directory mounted, read-only, into every node. kind needs the absolute
    path of this checkout, so the file is written into the cache."""
    config = yaml.safe_load(KIND_CONFIG.read_text(encoding="utf-8"))
    for node in config["nodes"]:
        node["extraMounts"] = [
            {"hostPath": str(gitops.resolve()), "containerPath": NODE_GITOPS, "readOnly": True}
        ]
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / "kind-config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


def _hosts_toml(pins: Pins) -> str:
    return f'[host."http://{pins.registry_in_cluster}"]\n  capabilities = ["pull", "resolve"]\n'


def node_version(config: Path = KIND_CONFIG) -> tuple[int, int, int]:
    """The Kubernetes version of the pinned node image (`kindest/node:vX.Y.Z@sha256:...`)."""
    found = _NODE_IMAGE.search(config.read_text(encoding="utf-8"))
    if found is None:
        raise ClusterError(f"{config}: no node image pinned as kindest/node:vX.Y.Z@sha256:<digest>")
    major, minor, patch = (int(part) for part in found.groups())
    return major, minor, patch


def check_kubectl(node: tuple[int, int, int], run: Run = run_command) -> None:
    """kubectl comes from the machine: it must be there, and within one minor version of the cluster's
    Kubernetes (the version skew Kubernetes supports for kubectl), before anything is created or applied."""
    major, minor, patch = node
    wanted = (
        f"kubectl v{major}.{minor - 1} to v{major}.{minor + 1} "
        f"(the cluster runs Kubernetes v{major}.{minor}.{patch}, {KIND_CONFIG.name})"
    )
    try:
        done = run(["kubectl", "version", "--client", "--output=json"], check=False)
    except ClusterError as exc:  # not installed, or not runnable
        raise ClusterError(f"kubectl is not installed: install {wanted}") from exc
    try:
        client = json.loads(done.stdout)["clientVersion"]
        digits = re.match(r"\d+", str(client["minor"]))  # some builds say "37+"
        if digits is None:
            raise ValueError(client["minor"])
        found = (int(client["major"]), int(digits[0]))
    except (ValueError, KeyError, TypeError) as exc:
        raise ClusterError(f"`kubectl version --client` gave no version: use {wanted}") from exc
    if found[0] != major or abs(found[1] - minor) > 1:
        raise ClusterError(f"kubectl is v{found[0]}.{found[1]}, outside the supported skew: use {wanted}")


def check_docker(run: Run = run_command) -> None:
    """The Docker daemon must answer before the registry or the cluster is created."""
    done = run(["docker", "version", "--format", "{{.Server.Version}}"], check=False)
    if done.returncode != 0 or not done.stdout.strip():
        last = (done.stderr.strip().splitlines() or ["no output"])[-1]
        raise ClusterError(f"the Docker daemon does not answer (`docker version`: {last}): start Docker")


def up(pins: Pins, kind: str, cache: Path, run: Run = run_command, *, gitops: Path = GITOPS_DIR) -> None:
    """Registry, GitOps repository, cluster, registry configuration on the nodes, Kyverno, Argo CD, the git
    server and the demo-shop namespace. What already exists is kept.

    Docker and kubectl are checked first, so a machine without them gets one clear error and no half-made
    cluster."""
    check_docker(run)
    check_kubectl(node_version(), run)
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", pins.registry_container], check=False)
    if state.returncode != 0:
        run([
            "docker", "run", "--detach", "--restart=always",
            "--publish", f"127.0.0.1:{pins.registry_port}:5000",
            "--network", "bridge", "--name", pins.registry_container, pins.registry_image,
        ])  # fmt: skip
    elif state.stdout.strip() != "true":
        run(["docker", "start", pins.registry_container])

    ensure_gitops_repository(gitops, run)
    if CLUSTER not in run([kind, "get", "clusters"]).stdout.split():
        config = kind_config(gitops, cache)
        run([kind, "create", "cluster", "--name", CLUSTER, "--config", str(config), "--wait", "180s"])

    # containerd resolves both names to the registry container: kind-registry:5000 (what the cluster's
    # manifests and the policy name) and localhost:5001 (what a push from the host names).
    for node in run([kind, "get", "nodes", "--name", CLUSTER]).stdout.split():
        if run(
            ["docker", "exec", node, "test", "-d", f"{NODE_GITOPS}/{GITOPS_REPOSITORY}"], check=False
        ).returncode:
            raise ClusterError(
                f"node {node} does not see the GitOps repository at {NODE_GITOPS}: the cluster was created "
                "without its mount (an older `make kind-up`). Run `make kind-down`, then `make kind-up`."
            )
        for host in (pins.registry_in_cluster, pins.registry_on_host):
            directory = f"/etc/containerd/certs.d/{host}"
            run(["docker", "exec", node, "mkdir", "-p", directory])
            run(
                ["docker", "exec", "-i", node, "cp", "/dev/stdin", f"{directory}/hosts.toml"],
                input=_hosts_toml(pins),
            )

    network = run(
        ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks.kind}}", pins.registry_container]
    )
    if network.stdout.strip() == "null":
        run(["docker", "network", "connect", "kind", pins.registry_container])

    kubectl = ["kubectl", "--context", CONTEXT]
    run([*kubectl, "apply", "-f", "-"], input=_registry_config_map(pins))
    # Both manifests are checked before either is applied.
    kyverno, argocd = manifest(pins.kyverno, cache), manifest(pins.argocd, cache)
    run([*kubectl, "apply", "--server-side", "-f", str(kyverno)])
    run([*kubectl, "wait", "--namespace", "kyverno", "--for=condition=Available", "deployment", "--all",
         "--timeout=300s"])  # fmt: skip
    run([*kubectl, "apply", "-f", "-"], input=_namespace("argocd"))
    run([*kubectl, "apply", "--server-side", "--namespace", "argocd", "-f", str(argocd)])
    run([*kubectl, "wait", "--namespace", "argocd", "--for=condition=Available", "deployment", "--all",
         "--timeout=300s"])  # fmt: skip
    run([*kubectl, "rollout", "status", "--namespace", "argocd", "statefulset/argocd-application-controller",
         "--timeout=300s"])  # fmt: skip
    for name in ("git-server.yaml", "demo-shop-namespace.yaml"):
        run([*kubectl, "apply", "-f", str(ARGOCD_DIR / name)])
    run([*kubectl, "wait", "--namespace", "sentinel-gitops", "--for=condition=Available", "deployment/gitops",
         "--timeout=180s"])  # fmt: skip


def _namespace(name: str) -> str:
    return f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {name}\n"


def _registry_config_map(pins: Pins) -> str:
    """KEP-1755's description of the local registry, as kind's documented setup applies it."""
    return (
        "apiVersion: v1\nkind: ConfigMap\n"
        "metadata:\n  name: local-registry-hosting\n  namespace: kube-public\n"
        "data:\n  localRegistryHosting.v1: |\n"
        f'    host: "{pins.registry_on_host}"\n'
        f'    hostFromClusterNetwork: "{pins.registry_in_cluster}"\n'
        '    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"\n'
    )


def policy(
    key: Path, out: Path, run: Run = run_command, *, repo: str = REPO, builder_id: str = BUILDER_ID
) -> None:
    """Render the release admission policy for the cluster's registry and apply it."""
    from sentinelci.supplychain.admission import render_policy

    check_kubectl(node_version(), run)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        render_policy(
            public_key=key, image_glob=IMAGE_GLOB, repo=repo, builder_id=builder_id, allow_http=True
        ),
        encoding="utf-8",
    )
    run(["kubectl", "--context", CONTEXT, "apply", "-f", str(out)])


def down(pins: Pins, kind: str, run: Run = run_command) -> None:
    run([kind, "delete", "cluster", "--name", CLUSTER])
    run(["docker", "rm", "--force", pins.registry_container], check=False)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["up", "policy", "down"])
    parser.add_argument(
        "--tools-dir", type=Path, default=Path(os.environ.get("SENTINEL_TOOLS_DIR", ".sentinel/tools"))
    )
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--key", type=Path, default=ROOT / "deploy" / "keys" / "release.pub")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--builder-id", default=BUILDER_ID)
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "kind" / "release-admission-policy.yaml")
    args = parser.parse_args(argv)
    try:
        pins = load_pins()
        if args.command == "policy":
            policy(args.key, args.out, repo=args.repo, builder_id=args.builder_id)
        elif args.command == "up":
            up(pins, kind_binary(args.tools_dir), args.cache)
        else:
            down(pins, kind_binary(args.tools_dir))
    except ClusterError as exc:
        print(f"cluster {args.command}: {exc}", file=sys.stderr)
        return 3
    print(f"cluster {args.command}: done (context {CONTEXT})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
