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
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
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
        public_key=key, image_glob=cluster.IMAGE_GLOB, repo=repo, builder_id=builder_id, allow_http=True
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


def load_and_verify(
    bundle: Path, digest: str, pins: Pins, *, key: Path, repo: str, builder_id: str, tools_dir: Path, run: Run
) -> str:
    """Push the bundle into the cluster's registry with `cosign load`, then `sentinel verify` it there."""
    on_host = f"127.0.0.1:{pins.registry_port}/{IMAGE_PATH}"
    cosign = verified_tool("cosign", tools_dir)
    run([cosign, "load", "--allow-http-registry", "--dir", str(bundle), on_host])
    verify = run(
        [
            sys.executable, "-m", "sentinelci.cli", "verify", f"{on_host}@{digest}", "--key", str(key),
            "--repo", repo, "--builder-id", builder_id, "--registry-http",
            "--lock", str(ROOT / "tools.lock.toml"), "--tools-dir", str(tools_dir),
        ],
        check=False,
    )  # fmt: skip
    print(verify.stdout, end="")
    if verify.returncode == 1:
        raise NotTrusted(f"sentinel verify does not trust {on_host}@{digest}: not deployed")
    if verify.returncode != 0:
        last = (verify.stderr.strip().splitlines() or ["no output"])[-1]
        raise ClusterError(f"sentinel verify could not run ({verify.returncode}): {last}")
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
    repository = cluster.ensure_gitops_repository(gitops, run)
    source = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=False).stdout.strip() or "unknown"
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
            message = (
                f"release {digest}\n\nVerified by sentinel verify (registry mode) before this commit.\n\n"
                f"Sentinel-Image: {digest}\nSentinel-Source: {source}\n"
            )
            run([*git, "commit", "--quiet", "--file", "-"], input=message)
            run([*git, "push", "--quiet", "origin", "HEAD:refs/heads/main"])
        commit = run([*git, "rev-parse", "HEAD"]).stdout.strip()
    return commit, changed


# ---------------------------------------------------------------- Argo CD and the rollout


def _application(run: Run) -> dict[str, Any]:
    got = run(["kubectl", "--context", CONTEXT, "--namespace", "argocd", "get", "application", APPLICATION,
               "-o", "json"], check=False)  # fmt: skip
    return json.loads(got.stdout) if got.returncode == 0 else {}


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
    deadline = clock() + timeout_s
    status: dict[str, Any] = {}
    while True:
        status = _application(run).get("status") or {}
        sync, health = status.get("sync") or {}, status.get("health") or {}
        operation = status.get("operationState") or {}
        synced_revision = ((operation.get("syncResult") or {}).get("revision")) or ""
        if synced_revision == commit and operation.get("phase") in ("Failed", "Error"):
            raise ClusterError(
                f"Argo CD could not sync {commit[:12]}: {operation.get('message', 'no message')}"
            )
        if (
            sync.get("revision") == commit
            and sync.get("status") == "Synced"
            and health.get("status") == "Healthy"
        ):
            return
        if clock() > deadline:
            conditions = "; ".join(c.get("message", "") for c in status.get("conditions") or [])
            raise ClusterError(
                f"Argo CD did not sync {commit[:12]} within {timeout_s:.0f} s: sync {sync.get('status')} at "
                f"{str(sync.get('revision'))[:12]}, health {health.get('status')}"
                + (f", {conditions}" if conditions else "")
            )
        sleep(3)


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
    run([*kubectl, "--namespace", "argocd", "annotate", "--overwrite", f"application/{APPLICATION}",
         "argocd.argoproj.io/refresh=normal"])  # fmt: skip
    wait_for_sync(commit, run, timeout_s=timeout_s, sleep=sleep)
    run([*kubectl, "--namespace", NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
         f"--timeout={int(timeout_s)}s"])  # fmt: skip
    expected = f"{pins.registry_in_cluster}/{IMAGE_PATH}@{digest}"
    running = run([*kubectl, "--namespace", NAMESPACE, "get", f"deployment/{DEPLOYMENT}", "-o",
                   "jsonpath={.spec.template.spec.containers[0].image}"]).stdout.strip()  # fmt: skip
    if running != expected:
        raise ClusterError(f"the Deployment runs {running!r}, not the release {expected}")
    print(f"deployed: {expected} (Argo CD synced {commit[:12]}, Kyverno admitted it)")
    return digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["release"])
    parser.add_argument("--bundle", type=Path, default=ROOT / "out" / "release" / "bundle")
    parser.add_argument("--key", type=Path, default=ROOT / "deploy" / "keys" / "release.pub")
    parser.add_argument("--repo", default=cluster.REPO)
    parser.add_argument("--builder-id", default=cluster.BUILDER_ID)
    parser.add_argument(
        "--tools-dir", type=Path, default=Path(os.environ.get("SENTINEL_TOOLS_DIR", ".sentinel/tools"))
    )
    parser.add_argument("--timeout", type=float, default=300, help="seconds for Argo CD and the rollout")
    args = parser.parse_args(argv)
    try:
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
