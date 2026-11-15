"""`make demo-release`: deploy a SentinelCI release to the demo cluster through GitOps (task A5b, SPEC
section 7, ADR-0011 decision 5).

    uv run python deploy/kind/demo.py release --bundle out/release/bundle

The release bundle is what `make release` writes with `cosign save`: an OCI layout holding the image, its
signature and its four attestations. In order, and nothing past a failed step runs:

1. The bundle names exactly one image, whose manifest is in the bundle with that digest.
2. The cluster's admission policy is the one rendered from --key (else: `make kind-policy KEY=...`), so
   Kyverno trusts exactly what step 4 trusts.
3. `cosign load` pushes the bundle into the cluster's registry, digest unchanged.
4. `sentinel verify` checks the release there (registry mode) with --key, --repo and --builder-id.
5. The digest, and the chart (deploy/helm/demo-shop), are committed to the GitOps repository
   (.sentinel/gitops/demo-shop.git); nothing is committed if neither changed.
6. The Argo CD project and application are applied (deploy/argocd); Argo CD refreshes and must sync that
   commit, which Kyverno admits only with the release's evidence.
7. `kubectl rollout status`, then the Deployment must run exactly that digest.

Safe to run twice. Exit 0 deployed, 1 not trusted by `sentinel verify`, 3 anything else failed.

    uv run python deploy/kind/demo.py attack [--block out/release/block-image]

`make demo-attack` then tries to run what must not run, next to the release, and shows who refuses it:

1. a tampered release (one file layer added after signing, so a new digest): `sentinel verify` does not
   trust it;
2. the same image committed to the GitOps repository, as someone who can write there would: Argo CD's sync is
   denied by Kyverno, the release keeps running, and the repository is restored;
3. the same image applied directly with kubectl: Kyverno denies it;
4. an image from outside the release repository: the API server's own policy denies it (Kyverno's matches only
   the release repository);
5. the BLOCK image `make release` built and `sentinel attest` refused to sign (an OCI layout; skipped until
   A4c writes it): Kyverno denies it.

Exit 0 when every attack was refused, 1 when one was not (it is undone), 3 when an attack could not be run.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cluster
import yaml
from cluster import CONTEXT, ROOT, ClusterError, Pins, Run, run_command

CHART = ROOT / "deploy" / "helm" / "demo-shop"
ARGOCD_DIR = ROOT / "deploy" / "argocd"
IMAGE_PATH = "demo-shop/shop-api"
APPLICATION = "demo-shop"
NAMESPACE = "demo-shop"
DEPLOYMENT = "shop-api"
# In the GitOps repository: the chart's directory, and the values file holding the digest.
CHART_PATH = "demo-shop"
RELEASE_VALUES = "release.yaml"
COSIGN_IMAGE = "dev.cosignproject.cosign/image"
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_GIT = [
    "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
    "-c", "user.name=SentinelCI demo release", "-c", "user.email=demo-release@sentinelci.invalid",
]  # fmt: skip


class NotTrusted(Exception):
    """`sentinel verify` did not trust the release: nothing was deployed."""


# ---------------------------------------------------------------- the bundle and the policy


def bundle_digest(bundle: Path) -> str:
    """The digest of the one image of a `cosign save` layout, whose manifest must be in it, with that
    digest."""
    try:
        index = json.loads((bundle / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ClusterError(
            f"{bundle} is not a release bundle (an OCI layout from `make release`): {exc}"
        ) from exc
    images = [
        entry.get("digest", "")
        for entry in index.get("manifests") or []
        if (entry.get("annotations") or {}).get("kind") == COSIGN_IMAGE
    ]
    if len(images) != 1 or not _DIGEST.fullmatch(images[0]):
        raise ClusterError(f"{bundle} must name exactly one image by sha256 digest, not {images}")
    blob = bundle / "blobs" / "sha256" / images[0].removeprefix("sha256:")
    if not blob.is_file() or "sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest() != images[0]:
        raise ClusterError(f"{bundle}: the manifest of {images[0]} is missing or does not have that digest")
    return str(images[0])


def contains(expected: Any, actual: Any) -> bool:
    """Every field of `expected` is in `actual` with the same value: the API server only adds defaults."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and contains(v, actual[k]) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(contains(e, a) for e, a in zip(expected, actual, strict=True))
        )
    return bool(expected == actual)


def check_policy(key: Path, repo: str, builder_id: str, run: Run) -> None:
    """The cluster's admission policy must be the one rendered from `key` for this repository and builder."""
    from sentinelci.supplychain.admission import render_policy

    rendered = render_policy(
        public_key=key, image_glob=cluster.IMAGE_GLOB, repo=repo, builder_id=builder_id, allow_http=False
    )
    for document in yaml.safe_load_all(rendered):
        name = document["metadata"]["name"]
        got = run(["kubectl", "--context", CONTEXT, "get", "imagevalidatingpolicies", name, "-o", "json"],
                  check=False)  # fmt: skip
        applied = json.loads(got.stdout) if got.returncode == 0 else {}
        if not contains(document["spec"], applied.get("spec")):
            raise ClusterError(
                f"the cluster's admission policy {name} is not the one rendered from {key} for {repo}: "
                f"run `make kind-policy KEY={key}` first"
            )


def verified_tool(name: str, tools_dir: Path) -> str:
    """A pinned tool, verified against tools.lock.toml right before it runs."""
    from sentinelci.scanners.errors import ToolIntegrityError
    from sentinelci.scanners.installer import verify_tools
    from sentinelci.scanners.lock import load_lock

    try:
        (entry,) = verify_tools(load_lock(ROOT / "tools.lock.toml"), tools_dir, only=[name]).entries
    except ToolIntegrityError as exc:
        raise ClusterError(f"{name} is not installed as pinned in {tools_dir} ({exc})") from exc
    return str(entry.path)


def on_host(pins: Pins) -> str:
    """The release repository as the host names it (the registry's loopback port)."""
    return f"127.0.0.1:{pins.registry_port}/{IMAGE_PATH}"


def sentinel_verify(
    reference: str, *, key: Path, repo: str, builder_id: str, tools_dir: Path, run: Run
) -> subprocess.CompletedProcess[str]:
    """`sentinel verify` in registry mode: exit 0 trusted, 1 not trusted. Anything else is a ClusterError."""
    verify = run(
        [
            sys.executable, "-m", "sentinelci.cli", "verify", reference, "--key", str(key),
            "--repo", repo, "--builder-id", builder_id,
            "--lock", str(ROOT / "tools.lock.toml"), "--tools-dir", str(tools_dir),
        ],
        check=False,
    )  # fmt: skip
    if verify.returncode not in (0, 1):
        last = (verify.stderr.strip().splitlines() or ["no output"])[-1]
        raise ClusterError(f"sentinel verify could not run ({verify.returncode}): {last}")
    return verify


def load_and_verify(
    bundle: Path, digest: str, pins: Pins, *, key: Path, repo: str, builder_id: str, tools_dir: Path, run: Run
) -> str:
    """Push the bundle into the cluster's registry with `cosign load`, then `sentinel verify` it there. Both
    reach the registry over TLS, trusting the cluster's CA through SSL_CERT_FILE (`cluster.trust_bundle`)."""
    repository = on_host(pins)
    cosign = verified_tool("cosign", tools_dir)
    run([cosign, "load", "--dir", str(bundle), repository])
    verify = sentinel_verify(
        f"{repository}@{digest}", key=key, repo=repo, builder_id=builder_id, tools_dir=tools_dir, run=run
    )
    print(verify.stdout, end="")
    if verify.returncode == 1:
        raise NotTrusted(f"sentinel verify does not trust {repository}@{digest}: not deployed")
    return verify.stdout


# ---------------------------------------------------------------- the GitOps repository


def release_values(digest: str) -> str:
    return (
        "# Written by `make demo-release` (deploy/kind/demo.py): the release this cluster runs, which\n"
        "# `sentinel verify` trusted. Kyverno admits it again, from its signature and evidence.\n"
        f"image:\n  digest: {digest}\n"
    )


def commit_release(digest: str, gitops: Path, run: Run, *, chart: Path = CHART) -> tuple[str, bool]:
    """Commit the chart and the digest to the GitOps repository's main branch. Returns the commit main points
    to, and whether this run made it. The same release twice makes no commit."""
    source = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=False).stdout.strip() or "unknown"
    message = (
        f"release {digest}\n\nVerified by sentinel verify (registry mode) before this commit.\n\n"
        f"Sentinel-Image: {digest}\nSentinel-Source: {source}\n"
    )
    return commit_digest(digest, gitops, run, message=message, chart=chart)


def commit_digest(
    digest: str, gitops: Path, run: Run, *, message: str, chart: Path = CHART
) -> tuple[str, bool]:
    """Commit the chart and `digest` (release.yaml) to the GitOps repository's main branch, with `message`,
    unless main already holds them. Returns the commit main points to, and whether this call made it."""
    repository = cluster.ensure_gitops_repository(gitops, run)
    with tempfile.TemporaryDirectory(prefix="sentinel-gitops-") as temporary:
        work = Path(temporary) / "work"
        run([*_GIT, "clone", "--quiet", str(repository), str(work)])
        git = [*_GIT, "-C", str(work)]
        run([*git, "symbolic-ref", "HEAD", "refs/heads/main"])
        target = work / CHART_PATH
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(chart, target)
        (target / RELEASE_VALUES).write_text(release_values(digest), encoding="utf-8")
        run([*git, "add", "--all", "--", CHART_PATH])
        changed = run([*git, "diff", "--cached", "--quiet"], check=False).returncode != 0
        if changed:
            run([*git, "commit", "--quiet", "--file", "-"], input=message)
            run([*git, "push", "--quiet", "origin", "HEAD:refs/heads/main"])
        commit = run([*git, "rev-parse", "HEAD"]).stdout.strip()
    return commit, changed


# ---------------------------------------------------------------- Argo CD and the rollout


def _application(run: Run) -> dict[str, Any]:
    got = run(["kubectl", "--context", CONTEXT, "--namespace", "argocd", "get", "application", APPLICATION,
               "-o", "json"], check=False)  # fmt: skip
    return json.loads(got.stdout) if got.returncode == 0 else {}


def refresh(run: Run) -> None:
    """Ask Argo CD to compare the application with the repository now, not at its next poll."""
    run(["kubectl", "--context", CONTEXT, "--namespace", "argocd", "annotate", "--overwrite",
         f"application/{APPLICATION}", "argocd.argoproj.io/refresh=normal"])  # fmt: skip


def sync_result(
    commit: str,
    run: Run,
    *,
    timeout_s: float = 300,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, str]:
    """Until Argo CD has synced `commit` healthy, (True, ""), or failed to sync it, (False, Argo CD's message:
    Kyverno's denial, for instance). A ClusterError if neither happens in time."""
    deadline = clock() + timeout_s
    status: dict[str, Any] = {}
    while True:
        status = _application(run).get("status") or {}
        sync, health = status.get("sync") or {}, status.get("health") or {}
        operation = status.get("operationState") or {}
        synced_revision = ((operation.get("syncResult") or {}).get("revision")) or ""
        if synced_revision == commit and operation.get("phase") in ("Failed", "Error"):
            return False, str(operation.get("message", "no message"))
        if (
            sync.get("revision") == commit
            and sync.get("status") == "Synced"
            and health.get("status") == "Healthy"
        ):
            return True, ""
        if clock() > deadline:
            conditions = "; ".join(c.get("message", "") for c in status.get("conditions") or [])
            raise ClusterError(
                f"Argo CD did not sync {commit[:12]} within {timeout_s:.0f} s: sync {sync.get('status')} at "
                f"{str(sync.get('revision'))[:12]}, health {health.get('status')}"
                + (f", {conditions}" if conditions else "")
            )
        sleep(3)


def wait_for_sync(
    commit: str,
    run: Run,
    *,
    timeout_s: float = 300,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Until Argo CD has synced `commit` and the application is healthy. A failed sync of that commit
    (Kyverno's denial, for instance) stops the wait with Argo CD's message."""
    synced, message = sync_result(commit, run, timeout_s=timeout_s, clock=clock, sleep=sleep)
    if not synced:
        raise ClusterError(f"Argo CD could not sync {commit[:12]}: {message}")


def running_image(run: Run) -> str:
    return str(
        run(
            [
                "kubectl",
                "--context",
                CONTEXT,
                "--namespace",
                NAMESPACE,
                "get",
                f"deployment/{DEPLOYMENT}",
                "-o",
                "jsonpath={.spec.template.spec.containers[0].image}",
            ]
        ).stdout.strip()
    )


def release(
    bundle: Path,
    *,
    key: Path,
    repo: str,
    builder_id: str,
    tools_dir: Path,
    gitops: Path = cluster.GITOPS_DIR,
    run: Run = run_command,
    timeout_s: float = 300,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Deploy the release in `bundle`; returns its digest. See the module's docstring for the steps."""
    pins = cluster.load_pins()
    digest = bundle_digest(bundle)
    print(f"release {digest} (bundle {bundle})")
    check_policy(key, repo, builder_id, run)
    load_and_verify(
        bundle, digest, pins, key=key, repo=repo, builder_id=builder_id, tools_dir=tools_dir, run=run
    )
    commit, changed = commit_release(digest, gitops, run)
    print(f"GitOps: main is {commit[:12]} ({'committed' if changed else 'already this release'})")

    kubectl = ["kubectl", "--context", CONTEXT]
    run(
        [
            *kubectl,
            "apply",
            "-f",
            str(ARGOCD_DIR / "project.yaml"),
            "-f",
            str(ARGOCD_DIR / "application.yaml"),
        ]
    )
    refresh(run)
    wait_for_sync(commit, run, timeout_s=timeout_s, sleep=sleep)
    run([*kubectl, "--namespace", NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
         f"--timeout={int(timeout_s)}s"])  # fmt: skip
    expected = f"{pins.registry_in_cluster}/{IMAGE_PATH}@{digest}"
    running = running_image(run)
    if running != expected:
        raise ClusterError(f"the Deployment runs {running!r}, not the release {expected}")
    print(f"deployed: {expected} (Argo CD synced {commit[:12]}, Kyverno admitted it)")
    return digest


# ---------------------------------------------------------------- make demo-attack


TAMPERED_FILE = "sentinel-demo/tampered.txt"


@dataclass(frozen=True)
class Attack:
    """One attempt to run what must not run, and what came of it."""

    name: str
    image: str
    refused: bool
    by: str
    message: str


def _last_line(text: str) -> str:
    return (text.strip().splitlines() or ["no output"])[-1].strip()


def released_digest(pins: Pins, run: Run) -> tuple[dict[str, Any], str]:
    """The running release's Deployment and digest: the cluster must run a release (`make demo-release`)."""
    got = run(["kubectl", "--context", CONTEXT, "--namespace", NAMESPACE, "get", f"deployment/{DEPLOYMENT}",
               "-o", "json"], check=False)  # fmt: skip
    live: dict[str, Any] = json.loads(got.stdout) if got.returncode == 0 else {}
    containers = (((live.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or [
        {}
    ]
    image, prefix = str(containers[0].get("image", "")), f"{pins.registry_in_cluster}/{IMAGE_PATH}@"
    if not image.startswith(prefix) or not _DIGEST.fullmatch(image.removeprefix(prefix)):
        raise ClusterError(
            f"no release is running in {NAMESPACE} ({image or 'no Deployment'}): make demo-release first"
        )
    return live, image.removeprefix(prefix)


def tamper(reference: str, pins: Pins, tools_dir: Path, run: Run) -> str:
    """The release with one more layer, one text file, pushed next to it: what someone with write access to
    the registry could do after the release was signed. Returns the new digest."""
    with tempfile.TemporaryDirectory(prefix="sentinel-attack-") as temporary:
        layer = Path(temporary) / "tampered.tar"
        content = (
            b"Added by `make demo-attack` after the release was signed: a new digest, with no signature.\n"
        )
        with tarfile.open(layer, "w") as archive:
            info = tarfile.TarInfo(TAMPERED_FILE)
            info.size, info.mode = len(content), 0o644
            archive.addfile(info, io.BytesIO(content))
        crane = verified_tool("crane", tools_dir)
        pushed = run([crane, "mutate", reference, "--append", str(layer), "--repo", on_host(pins)])
    digest = _last_line(pushed.stdout).rpartition("@")[2]
    if not _DIGEST.fullmatch(digest):
        raise ClusterError(f"crane mutate did not print the tampered image's digest: {pushed.stdout!r}")
    return digest


def layout_digest(layout: Path) -> str:
    """The digest of the one image of an OCI layout (the BLOCK image `make release` built), whose manifest
    must be in it with that digest."""
    try:
        manifests = json.loads((layout / "index.json").read_text(encoding="utf-8")).get("manifests") or []
    except (OSError, ValueError) as exc:
        raise ClusterError(f"{layout} is not an OCI layout: {exc}") from exc
    digests = [str(entry.get("digest", "")) for entry in manifests]
    if len(digests) != 1 or not _DIGEST.fullmatch(digests[0]):
        raise ClusterError(f"{layout} must hold exactly one image, by sha256 digest, not {digests}")
    blob = layout / "blobs" / "sha256" / digests[0].removeprefix("sha256:")
    if not blob.is_file() or "sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest() != digests[0]:
        raise ClusterError(f"{layout}: the manifest of {digests[0]} is missing or does not have that digest")
    return digests[0]


def attack_deployment(live: dict[str, Any], name: str, image: str) -> dict[str, Any]:
    """The running release's Deployment, copied under another name with another image: everything else, the
    Pod Security context included, is the release's, so only the image can be the reason for a denial."""
    labels = {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "demo-shop-attack"}
    spec = copy.deepcopy(live["spec"])
    spec["replicas"] = 1
    spec["selector"] = {"matchLabels": {"app.kubernetes.io/name": name}}
    spec["template"]["metadata"] = {"labels": labels}
    spec["template"]["spec"]["containers"][0]["image"] = image
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels}, "spec": spec,
    }  # fmt: skip


def try_create(deployment: dict[str, Any], run: Run) -> tuple[bool, str]:
    """`kubectl create` the Deployment for real. (True, the denial) when admission refuses it; (False, ...)
    when it was created, and then it is deleted at once. Any other failure is a ClusterError: an attack that
    did not reach admission proves nothing."""
    kubectl = ["kubectl", "--context", CONTEXT, "--namespace", NAMESPACE]
    created = run([*kubectl, "create", "-f", "-"], input=json.dumps(deployment), check=False)
    if created.returncode == 0:
        name = deployment["metadata"]["name"]
        run([*kubectl, "delete", f"deployment/{name}", "--wait=false"], check=False)
        return False, f"created deployment/{name} (deleted again)"
    message = _last_line(created.stderr)
    if "denied" not in message:
        raise ClusterError(f"kubectl create failed before admission could judge it: {message}")
    return True, message


def gitops_attack(
    live_digest: str,
    tampered: str,
    pins: Pins,
    gitops: Path,
    run: Run,
    *,
    timeout_s: float,
    sleep: Callable[[float], None],
) -> tuple[bool, str]:
    """Commit the tampered digest to the GitOps repository, as someone who can write there would, and see what
    Argo CD's sync of it gets; then restore the release, whatever happened, and wait until Argo CD has synced
    it again."""
    attack_commit, _ = commit_digest(
        tampered, gitops, run,
        message=f"attack: deploy a tampered image {tampered}\n\nSentinel-Attack: make demo-attack\n",
    )  # fmt: skip
    expected = f"{pins.registry_in_cluster}/{IMAGE_PATH}@{live_digest}"
    try:
        refresh(run)
        synced, message = sync_result(attack_commit, run, timeout_s=timeout_s, sleep=sleep)
        still_running = running_image(run) == expected
    finally:
        restore, _ = commit_digest(
            live_digest, gitops, run,
            message=f"restore release {live_digest}\n\nAfter make demo-attack.\n\n"
            f"Sentinel-Image: {live_digest}\n",
        )  # fmt: skip
        refresh(run)
        wait_for_sync(restore, run, timeout_s=timeout_s, sleep=sleep)
        run(["kubectl", "--context", CONTEXT, "--namespace", NAMESPACE, "rollout", "status",
             f"deployment/{DEPLOYMENT}", f"--timeout={int(timeout_s)}s"])  # fmt: skip
        if running_image(run) != expected:
            raise ClusterError(f"the release {expected} is not running again after the GitOps attack")
        print(f"  GitOps restored: main is {restore[:12]}, Argo CD synced it, the release runs")
    if synced or not still_running:
        return False, f"Argo CD synced the tampered image (commit {attack_commit[:12]})"
    return True, f"Argo CD could not sync {attack_commit[:12]}: {message}"


def attack(
    *,
    key: Path,
    repo: str,
    builder_id: str,
    tools_dir: Path,
    block: Path | None = None,
    gitops: Path = cluster.GITOPS_DIR,
    run: Run = run_command,
    timeout_s: float = 300,
    sleep: Callable[[float], None] = time.sleep,
) -> list[Attack]:
    """Try each attack of the module's docstring next to the running release; returns what came of each."""
    pins = cluster.load_pins()
    check_policy(key, repo, builder_id, run)
    live, digest = released_digest(pins, run)
    print(f"the release running in {NAMESPACE}: {digest}")
    results: list[Attack] = []

    def record(result: Attack) -> None:
        results.append(result)
        verdict = "REFUSED" if result.refused else "NOT REFUSED"
        print(
            f"attack {len(results)}: {result.name}\n  {result.image}\n"
            f"  {verdict} by {result.by}: {result.message}"
        )

    tampered = tamper(f"{on_host(pins)}@{digest}", pins, tools_dir, run)
    verify = sentinel_verify(
        f"{on_host(pins)}@{tampered}", key=key, repo=repo, builder_id=builder_id, tools_dir=tools_dir, run=run
    )
    tampered_in_cluster = f"{pins.registry_in_cluster}/{IMAGE_PATH}@{tampered}"
    record(Attack("a tampered release (one layer added after signing)", tampered_in_cluster,
                  verify.returncode == 1, "sentinel verify", _last_line(verify.stdout)))  # fmt: skip
    refused, message = gitops_attack(digest, tampered, pins, gitops, run, timeout_s=timeout_s, sleep=sleep)
    record(Attack("the tampered release committed to the GitOps repository", tampered_in_cluster, refused,
                  "Kyverno, during Argo CD's sync", message))  # fmt: skip
    refused, message = try_create(attack_deployment(live, "shop-api-tampered", tampered_in_cluster), run)
    record(
        Attack("the tampered release applied with kubectl", tampered_in_cluster, refused, "Kyverno", message)
    )
    foreign = f"quay.io/argoproj/argocd:v{pins.argocd.version}"
    refused, message = try_create(attack_deployment(live, "shop-api-foreign", foreign), run)
    record(Attack("an image from outside the release repository", foreign, refused,
                  "the API server's image policy", message))  # fmt: skip
    if block is None or not block.exists():
        print(
            f"attack {len(results) + 1}: the BLOCK image: skipped, no OCI layout at {block} (`make release`)"
        )
    else:
        block_digest = layout_digest(block)
        run([verified_tool("crane", tools_dir), "push", str(block), f"{on_host(pins)}:block"])
        image = f"{pins.registry_in_cluster}/{IMAGE_PATH}@{block_digest}"
        refused, message = try_create(attack_deployment(live, "shop-api-block", image), run)
        record(Attack("the BLOCK image the release gate refused to sign", image, refused, "Kyverno", message))
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["release", "attack"])
    parser.add_argument("--bundle", type=Path, default=ROOT / "out" / "release" / "bundle")
    parser.add_argument("--block", type=Path, default=ROOT / "out" / "release" / "block-image",
                        help="attack: the BLOCK image's OCI layout, from `make release`")  # fmt: skip
    parser.add_argument("--key", type=Path, default=ROOT / "deploy" / "keys" / "release.pub")
    parser.add_argument("--repo", default=cluster.REPO)
    parser.add_argument("--builder-id", default=cluster.BUILDER_ID)
    parser.add_argument(
        "--tools-dir", type=Path, default=Path(os.environ.get("SENTINEL_TOOLS_DIR", ".sentinel/tools"))
    )
    parser.add_argument("--timeout", type=float, default=300, help="seconds for Argo CD and the rollout")
    parser.add_argument(
        "--tls", type=Path, default=cluster.TLS_DIR, help="the registry's CA, from `make kind-up`"
    )
    args = parser.parse_args(argv)
    try:
        os.environ["SSL_CERT_FILE"] = str(
            cluster.trust_bundle(args.tls)
        )  # for cosign, crane, `sentinel verify`
        if args.command == "attack":
            results = attack(
                key=args.key, repo=args.repo, builder_id=args.builder_id, tools_dir=args.tools_dir,
                block=args.block, timeout_s=args.timeout,
            )  # fmt: skip
            failed = [result.name for result in results if not result.refused]
            if failed:
                print(f"demo attack: NOT REFUSED: {'; '.join(failed)}", file=sys.stderr)
                return 1
            print(f"demo attack: {len(results)}/{len(results)} attacks refused")
            return 0
        release(
            args.bundle, key=args.key, repo=args.repo, builder_id=args.builder_id, tools_dir=args.tools_dir,
            timeout_s=args.timeout,
        )  # fmt: skip
    except NotTrusted as exc:
        print(f"demo {args.command}: {exc}", file=sys.stderr)
        return 1
    except (ClusterError, subprocess.SubprocessError, OSError) as exc:
        print(f"demo {args.command}: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
