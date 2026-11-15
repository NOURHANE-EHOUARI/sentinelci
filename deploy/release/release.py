"""`make release`: build shop-api's release image, decide on it and sign it on this laptop (A4c, ADR-0011).

    uv run python deploy/release/release.py [--key ~/.sentinelci/release.key]
    uv run python deploy/release/release.py --requirements requirements.block.txt --expect-block
    uv run python deploy/release/release.py key [--key ~/.sentinelci/release.key]
    uv run python deploy/release/release.py self-gate
    uv run python deploy/release/release.py sentinelci --version X.Y.Z [--key ~/.sentinelci/release.key]

During the private phase the laptop is the only signer (ADR-0011, decision 7): the release key never reaches
GitHub. In order, and nothing past a failed step runs:

1. Preconditions, the laptop analog of ADR-0008 (the CLI, lock, policies and waivers that decide, and this
   script, are the reviewed ones): the working tree is clean, no tracked file is hidden from `git status` by
   an index flag, every tracked file is compared with HEAD's blob, byte for byte (the index's stat data and
   a replace ref cannot hide an edit), no variable points git at another repository or index, no gate input
   is a file git ignores, `origin` is the release repository, and HEAD is its `main`, fetched now.
   COSIGN_PASSWORD must not be set: the key password is asked on the terminal, checked against
   deploy/keys/release.pub, and given only to the processes that use the key.
2. The build context comes from the commit, not the working tree: `git archive HEAD` of the release
   Dockerfile, its `.dockerignore` allow-list and exactly the files that list admits (no link, nothing git
   ignores).
3. `docker buildx build --output type=oci --provenance=false --sbom=false --metadata-file`: no registry, no
   credentials. The release digest is the one BuildKit recorded (`containerimage.digest`), and the layout's
   index.json must name exactly that one manifest; `sentinel sbom` and `sentinel scan image` then check every
   blob of the layout against its digest before Syft reads it.
4. Decide (ADR-0011, decision 3), in the release context: the SBOM of the image (`sentinel sbom`), Grype's
   database (`sentinel tools grype-db`), the source scans of the build context (secrets, SAST, IaC, CI
   workflows), the image's own scan (CONTAINER findings: the dependencies it ships), then `sentinel score` and
   `sentinel evaluate --context release --image-digest --sbom`. A scan that fails with a status is recorded
   in the tool status and blocks (SC-010); the empty findings file it leaves never passes alone. A scan that
   leaves no status (killed, crashed) stops the release before anything is decided: every scanner of the
   release must have reported, whatever `required_tools` lists. The requirements files
   are not scanned as source: the image scan reads what was installed from the selected one (hash-pinned,
   `--no-deps`), and the context also holds the other one, which this build does not install.
   A BLOCK stops here, with nothing signed: the image's OCI layout goes to `<out>/block-image` (for
   `make demo-attack`) with its evidence in `<out>/block-evidence`.
5. Sign (ADR-0011, decision 4). The digest is read from the layout again and must be the decision's. The
   layout is pushed by digest to `crane registry serve` on 127.0.0.1, then `sentinel attest --push --builder
   local-release` signs the image and its four attestations there, `sentinel verify` must trust it in registry
   mode (what Kyverno checks) and from the evidence bundles, and `cosign save` writes the release bundle.
6. Only then do `<out>/bundle` (for `make demo-release`) and `<out>/evidence` replace the previous release's.

Exit 0: released, the bundle is trusted. 1: the gate blocked the image, nothing was signed. 3: the release
could not be made (a precondition, a failed step, or a signed release `sentinel verify` did not trust: no
bundle). With --expect-block (`make release-block`, the demo's BLOCK image), 0 means the gate blocked it, and
1 that it did not: nothing is signed either way.

`self-gate` (`make self-gate`, A10, SPEC principle P4) runs the same release gate on SentinelCI itself, and
like the workflow (ADR-0008) the commit judged is not the one that judges (#95 review). The checkout is the
pipeline commit: clean, a commit main was at (on its first-parent line), and a release tag `vX.Y.Z` or named
on purpose with `--pipeline <HEAD>`; its CLI, policies, tool lock and `.sentinel/self-gate-waivers.yaml`
decide. The target is origin's main, fetched now: its own files without demo-shop (exported from the commit
and checked blob by blob, so no export attribute can hide or rewrite one), scanned by the gate's five scanners
(secrets, SAST, IaC, CI workflows, and Grype on the SBOM of the lockfiles), then `sentinel evaluate --context
release` with the waivers (and VEX) always named. The pipeline files changed between the two are printed and
kept with the evidence. The decision and its evidence go to `out/self-gate/evidence`; nothing is signed. Exit
0: PASS or WARN; 1: BLOCK; 3: no decision.

`sentinelci --version X.Y.Z` (`make release-sentinelci VERSION=X.Y.Z`, A10) releases SentinelCI itself,
origin's main judged by the pipeline commit as above: the self-gate first (a BLOCK builds nothing), then the
wheels and source distributions of both packages and the policy bundle (the policies and the tool lock), built
twice from the exported target with the commit's time as SOURCE_DATE_EPOCH and the build backend pinned by
hash (`deploy/release/build-constraints.txt` of the pipeline commit, `--require-hashes`), and refused unless
both builds are byte for byte the same. Each artifact and SHA256SUMS is signed with the release key, each
artifact attested twice (SLSA provenance v1, and the self-gate's decision), everything verified with the
committed public key, and only then kept in `<out>/sentinelci-X.Y.Z` and tagged `vX.Y.Z` here (pushing the tag
is left to the person). A version is released once: its tag must not exist here or on origin, and both
packages must declare it.

`key` (`make release-key`) makes the release key pair with the pinned Cosign: the private key, password
protected, in ~/.sentinelci (never in the repository), and its public key at deploy/keys/release.pub, to be
committed through a pull request.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import functools
import getpass
import hashlib
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[2]
REPO = "NOURHANE-EHOUARI/sentinelci"
MAIN = "refs/heads/main"
SERVICE_DIR = "demo-shop/services/shop-api"
DOCKERFILE = "Dockerfile.release"
DOCKERIGNORE = f"{DOCKERFILE}.dockerignore"
DEFAULT_REQUIREMENTS = "requirements.release.txt"
IMAGE_NAME = "demo-shop/shop-api"
IMAGE_REF = f"kind-registry:5000/{IMAGE_NAME}"  # where the release runs (deploy/kind), named in its findings
PUBLIC_KEY = Path("deploy") / "keys" / "release.pub"  # in the repository
DEFAULT_KEY = Path.home() / ".sentinelci" / "release.key"
WORK_MARKER = ".sentinel-release-work"
SCANS = ("secrets", "sast", "iac", "pipelines", "container")
# The self-gate (A10): SentinelCI's own tree, scanned by its own pipeline. demo-shop is left out: it is the
# intentionally vulnerable target, gated by its own workflow (demo-shop.yml), never released as SentinelCI.
SELF_SCANS = ("secrets", "sast", "iac", "pipelines", "sca")
NOT_SELF = ("demo-shop",)
# The self-gate's own exceptions, read from the pipeline commit (the checkout), never from the commit it
# judges: a waiver applies once it is reviewed and merged, never to the change that adds it (ADR-0008, #95
# review). They are apart from .sentinel/waivers.yaml, which every `sentinel evaluate` of demo-shop reads by
# default (nit 1).
SELF_WAIVERS = Path(".sentinel") / "self-gate-waivers.yaml"
SELF_VEX = Path(".sentinel") / "self-gate-vex.json"
# What decides: the files whose changes between the pipeline commit and the target are printed and kept with
# the evidence (judged by the pipeline, not judging), as ADR-0008 decision 4 warns on a pull request.
PIPELINE_FILES = (
    ".github/workflows", ".sentinel", "cli", "deploy/release", "eval/feeds", "policies", "pyproject.toml",
    "tools.lock.toml", "uv.lock",
)  # fmt: skip
# SentinelCI's own release (A10): its two Python packages, and the policy bundle the gate decides with.
PACKAGES = {"sentinelci": "cli", "sentinel-ai": "ai"}  # package -> its directory
POLICY_BUNDLE = ("policies", "tools.lock.toml")
# The build backend and its dependencies, pinned by hash and read from the pipeline commit (#95 review): `uv
# build` would otherwise resolve `hatchling>=1.27` from the index at release time, outside uv.lock.
BUILD_CONSTRAINTS = Path("deploy") / "release" / "build-constraints.txt"
DECISION_TYPE = "https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1"  # as for images
PROVENANCE_TYPE = "slsaprovenance1"  # https://slsa.dev/provenance/v1
BUILD_TYPE = f"https://github.com/{REPO}/specs/local-release/v1"
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
# Every scanner those scans run. `required_tools` asks only some of them in `release`, so the script checks
# that each one reported (ok or not) before the gate decides (#82 review).
RELEASE_TOOLS = frozenset({"gitleaks", "opengrep", "trivy", "zizmor", "syft", "grype"})
# With --expect-block, 0 is "blocked as expected" and 1 "not blocked": nothing is signed in either case.
EXIT_RELEASED, EXIT_BLOCKED, EXIT_FAILED = 0, 1, 3
COSIGN_IMAGE = "dev.cosignproject.cosign/image"
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_ORIGIN = re.compile(
    rf"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/){re.escape(REPO)}(?:\.git)?/?",
    re.IGNORECASE,
)
_ALLOWED = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/?")
_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_STEP_TIMEOUT_S = 3600


# The files the gate reads from the checkout, beside the CLI and this script (#82 review, round 3).
GATE_INPUTS = ("policies", ".sentinel/waivers.yaml", ".sentinel/vex.json", "tools.lock.toml")
# git with no file-system monitor: a configured core.fsmonitor hook answers which files changed, so it could
# hide an edit from `git status`.
GIT_STATUS = ("git", "-c", "core.fsmonitor=false")
# Variables that point git at another repository, index or object store: with one set, every check below would
# look at something else than this checkout (#129 review). Config variables are not refused: the byte
# comparison of every tracked file makes them unable to hide an edit.
GIT_ELSEWHERE = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE",
)  # fmt: skip


class ReleaseError(Exception):
    """The release could not be made: nothing was signed, or nothing signed was kept."""


class Runner(Protocol):
    def __call__(
        self,
        args: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]: ...


def run_command(
    args: Sequence[str],
    *,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command from the repository root. `capture=False` streams its output (the build, the scans); a
    failure with `check` is a ReleaseError naming the command, never its environment."""
    try:
        done = subprocess.run(  # noqa: S603 (fixed commands; arguments from the commit, the lock and the CLI)
            list(args),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=capture,
            text=True,
            timeout=_STEP_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError(f"{args[0]} could not run: {type(exc).__name__}") from exc
    if check and done.returncode != 0:
        last = ((done.stderr or "").strip().splitlines() or ["see the output above"])[-1]
        raise ReleaseError(f"{_named(args)} failed ({done.returncode}): {last}")
    return done


def _named(args: Sequence[str]) -> str:
    """How a failure names its command: `sentinel scan combine` for the CLI, not the interpreter's path."""
    if list(args[1:3]) == ["-m", "sentinelci.cli"]:
        return " ".join(["sentinel", *itertools.takewhile(lambda arg: not arg.startswith("-"), args[3:5])])
    return " ".join(args[:3])


def sentinel(*args: str) -> list[str]:
    """The CLI of this checkout (the reviewed one, once the preconditions hold)."""
    return [sys.executable, "-m", "sentinelci.cli", *args]


def verified_tool(name: str, tools_dir: Path, lock: Path) -> Path:
    """A pinned tool, checked against the lock right before it is used."""
    from sentinelci.scanners.errors import ToolIntegrityError
    from sentinelci.scanners.installer import verify_tools
    from sentinelci.scanners.lock import load_lock

    try:
        (entry,) = verify_tools(load_lock(lock), tools_dir, only=[name]).entries
    except ToolIntegrityError as exc:
        raise ReleaseError(f"{name} is not installed as pinned in {tools_dir} ({exc})") from exc
    return Path(entry.path)


def builder_id() -> str:
    """The provenance builder of a laptop release: this script at main (`sentinel attest --builder
    local-release`), which `sentinel verify` and the admission policy require."""
    from sentinelci.supplychain.attestations import local_release_builder_id

    return str(local_release_builder_id(REPO))


def _tool_env(home: Path) -> dict[str, str]:
    """What crane and Cosign get when the release runs them directly: no inherited tokens or credentials."""
    home.mkdir(parents=True, exist_ok=True)
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}


# ---------------------------------------------------------------- 1. preconditions


def check_origin(url: str) -> None:
    if _ORIGIN.fullmatch(url.strip()) is None:
        raise ReleaseError(
            f"origin is {url.strip()!r}, not github.com/{REPO}: release only the reviewed repository"
        )


def checkout_is_clean(run: Runner, *, environ: Mapping[str, str]) -> None:
    """No COSIGN_PASSWORD, `origin` this repository with one URL, nothing that points git elsewhere (a
    `GIT_DIR`-like variable, a replace ref), and a clean working tree: no index flag, no ignored gate input,
    and every tracked file HEAD's blob, byte for byte (#129). The release and the self-gate's pipeline
    checkout both rely on it: their CLI, policies and lock come from this working tree."""
    if "COSIGN_PASSWORD" in environ:
        raise ReleaseError(
            "COSIGN_PASSWORD is set: unset it. The key password is asked on the terminal and given only to "
            "the processes that use the key (ADR-0011, decision 4)"
        )
    origin = run(["git", "config", "--get-all", "remote.origin.url"], check=False)
    if origin.returncode != 0:
        raise ReleaseError("this checkout has no `origin` remote")
    urls = origin.stdout.split()
    if len(urls) != 1:  # git reads the last, but fetches from the first (#82 review)
        raise ReleaseError(f"origin has {len(urls)} URLs: give it exactly one, github.com/{REPO}")
    check_origin(urls[0])
    told = sorted(key for key in GIT_ELSEWHERE if key in environ)
    if told:
        raise ReleaseError(f"{', '.join(told)} set: unset it, git must look at this checkout (#129 review)")
    if run(["git", "for-each-ref", "--count=1", "refs/replace/"]).stdout.strip():
        raise ReleaseError(
            "this checkout has replace refs (refs/replace/): remove them, git reads them for HEAD"
        )
    # `git status` believes the index: a file marked skip-worktree or assume-unchanged may differ from the
    # commit and still look clean. Any tracked file counts, this script and the CLI included (#82 review,
    # round 3).
    flagged = [
        line[2:] for line in run([*GIT_STATUS, "ls-files", "-v"]).stdout.splitlines() if line[:2] != "H "
    ]
    if flagged:
        shown = ", ".join(flagged[:5]) + (", ..." if len(flagged) > 5 else "")
        raise ReleaseError(
            f"git is told not to look at {shown}: clear the skip-worktree or assume-unchanged flag"
        )
    dirty = run([*GIT_STATUS, "status", "--porcelain=v1", "--untracked-files=all"]).stdout.splitlines()
    if dirty:
        shown = ", ".join(line[3:] for line in dirty[:5]) + (", ..." if len(dirty) > 5 else "")
        raise ReleaseError(f"the working tree is not clean ({shown}): release only what main holds")
    # The gate reads these from the checkout, ignored files too: OPA loads every file under policies/ (a
    # `build/` or `__pycache__/` left by another branch survives `git checkout main`), and `sentinel evaluate`
    # reads the waivers and VEX files when they exist. An ignored one, through .gitignore or
    # .git/info/exclude, would decide without being in the commit (#82 review, rounds 2 and 3).
    stray = run(
        # `traditional` with every untracked file lists each ignored file, even inside a wholly ignored
        # directory (`matching` would name `.sentinel/` for its tools alone).
        [
            *GIT_STATUS,
            "status",
            "--porcelain=v1",
            "--ignored=traditional",
            "--untracked-files=all",
            "--",
            *GATE_INPUTS,
        ]
    ).stdout.splitlines()
    if stray:
        shown = ", ".join(line[3:] for line in stray[:5]) + (", ..." if len(stray) > 5 else "")
        raise ReleaseError(f"the gate's inputs hold files git ignores ({shown}): the gate would read them")
    # `git status` also believes the index's stat data: an edit with the same size and time, cached once
    # under core.checkStat=minimal, stays hidden afterwards. So every tracked file is compared with HEAD's
    # blob, byte for byte (#129 review).
    top = Path(run(["git", "rev-parse", "--show-toplevel"]).stdout.strip())
    for record in filter(None, run(["git", "ls-tree", "-r", "-z", "HEAD"]).stdout.split("\0")):
        meta, _, path = record.partition("\t")
        mode, kind, blob = meta.split()
        if kind != "blob":
            continue
        file = top / path
        data = os.readlink(file).encode() if mode == "120000" else file.read_bytes()
        if hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest() != blob:
            raise ReleaseError(f"{path} is not HEAD's blob {blob}, though git status says it is")


def preconditions(run: Runner, *, fetch: bool, environ: Mapping[str, str]) -> str:
    """The commit to release: HEAD, which must be origin's main, with a clean working tree."""
    checkout_is_clean(run, environ=environ)
    if fetch:
        run(["git", "fetch", "--quiet", "--no-tags", "origin", f"+{MAIN}:refs/remotes/origin/main"])
    head = run(["git", "rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip()
    main = run(
        ["git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False
    ).stdout.strip()
    if not _COMMIT.fullmatch(head) or head != main:
        raise ReleaseError(
            f"HEAD is {head}, origin/main is {main or 'unknown'}: check out main as it is on GitHub "
            "(ADR-0011, decision 4)"
        )
    return head


@dataclass(frozen=True)
class Pipeline:
    """Who judges what, ADR-0008 on the laptop (#95 review): `commit` is the checkout, whose CLI, policies,
    tool lock and self-gate waivers decide; `target` is origin's main, which is judged (and released) as
    data."""

    commit: str
    target: str
    changed: tuple[str, ...]  # PIPELINE_FILES that differ between the two

    def evidence(self) -> dict[str, Any]:
        return {
            "pipeline_commit": self.commit,
            "target_commit": self.target,
            "pipeline_files_changed": list(self.changed),
            "target_is_its_own_pipeline": self.commit == self.target,
        }


def pipeline_preconditions(
    run: Runner, *, fetch: bool, environ: Mapping[str, str], named: str | None
) -> Pipeline:
    """The pipeline commit (HEAD, clean, a commit main was at: on origin/main's first-parent line, not only an
    ancestor, which a merged branch's commits are too; a release tag, or named on purpose with --pipeline) and
    the target (origin's main, fetched now)."""
    checkout_is_clean(run, environ=environ)
    if fetch:
        run(["git", "fetch", "--quiet", "--no-tags", "origin", f"+{MAIN}:refs/remotes/origin/main"])
    head = run(["git", "rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip()
    target = run(
        ["git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False
    ).stdout.strip()
    if not _COMMIT.fullmatch(head) or not _COMMIT.fullmatch(target):
        raise ReleaseError(f"HEAD is {head}, origin/main is {target or 'unknown'}: fetch origin's main first")
    if head not in run(["git", "rev-list", "--first-parent", target]).stdout.split():
        raise ReleaseError(
            f"HEAD {head} is not on origin/main (its first-parent line): the pipeline must be a commit main "
            "was at, not one of a branch merged into it (ADR-0008)"
        )
    if named is not None:
        if named != head:
            raise ReleaseError(
                f"--pipeline {named} is not HEAD ({head}): check out the pipeline commit first"
            )
    elif not [t for t in run(["git", "tag", "--points-at", head]).stdout.split() if _TAG.fullmatch(t)]:
        raise ReleaseError(
            f"HEAD {head} is no release tag (vX.Y.Z): check out the last release to judge main with it, or "
            "name the pipeline commit on purpose with --pipeline <HEAD>"
        )
    changed = run(["git", "diff", "--name-only", "-z", "--no-renames", head, target, "--", *PIPELINE_FILES])
    return Pipeline(head, target, tuple(sorted(filter(None, changed.stdout.split("\0")))))


def announce(pipe: Pipeline, what: str) -> None:
    """Which commit judges which, and what of the pipeline changed in between (judged here, not judging)."""
    print(f"{what}: {REPO} at {pipe.target} (main), judged by the pipeline at {pipe.commit}")
    if pipe.commit == pipe.target:
        print(f"{what}: the target is its own pipeline: this decision shows it passes its own gate, not "
              "one it did not write")  # fmt: skip
    elif pipe.changed:
        shown = ", ".join(pipe.changed[:20]) + (", ..." if len(pipe.changed) > 20 else "")
        print(f"{what}: {len(pipe.changed)} pipeline file(s) changed since the pipeline commit, judged here "
              f"and not judging: {shown}")  # fmt: skip


# ---------------------------------------------------------------- the key


def pem_der(text: str, what: str) -> bytes:
    """The DER bytes of the one PEM public key in `text`."""
    match = re.search(r"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END PUBLIC KEY-----", text)
    if match is None:
        raise ReleaseError(f"{what} holds no PEM public key")
    try:
        return base64.b64decode("".join(match.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseError(f"{what}: the public key is not valid base64") from exc


def check_key_files(key: Path, public_key: Path) -> None:
    if not key.is_file():
        raise ReleaseError(f"no release key at {key} (`make release-key` makes one; KEY=... names another)")
    if not public_key.is_file():
        raise ReleaseError(f"no public key at {public_key}: commit the release key's public key there first")


def check_key_pair(key: Path, public_key: Path, password: str, cosign: Path, run: Runner, home: Path) -> None:
    """The private key opens with this password and is the pair of the committed public key: Kyverno and
    `sentinel verify` trust only that one."""
    check_key_files(key, public_key)
    derived = run(
        [str(cosign), "public-key", "--key", str(key)],
        env=_tool_env(home) | {"COSIGN_PASSWORD": password},
        check=False,
    )
    if derived.returncode != 0:
        raise ReleaseError(f"cosign could not open {key}: wrong password, or not a Cosign private key")
    committed = pem_der(public_key.read_text(encoding="utf-8"), str(public_key))
    if pem_der(derived.stdout, f"the public key of {key}") != committed:
        raise ReleaseError(f"{key} is not the pair of {public_key}: the cluster would refuse this release")


# ---------------------------------------------------------------- 2. the build context, from the commit


@dataclass(frozen=True)
class Context:
    files: tuple[str, ...]  # repository paths: the Dockerfile, its .dockerignore, what the allow-list admits
    requirements: str  # the requirements file the build installs, relative to SERVICE_DIR


def allow_list(text: str) -> tuple[str, ...]:
    """The paths a `.dockerignore` allow-list admits: `*`, then `!path` or `!dir/` lines, nothing else (no
    other pattern is understood, so none is guessed at)."""
    lines = [line.strip() for line in text.splitlines()]
    rules = [line for line in lines if line and not line.startswith("#")]
    if not rules or rules[0] != "*":
        raise ReleaseError(f"{DOCKERIGNORE} must start with `*` (an allow-list)")
    allowed = []
    for rule in rules[1:]:
        path = rule[1:]
        if not rule.startswith("!") or not _ALLOWED.fullmatch(path) or ".." in path.split("/"):
            raise ReleaseError(f"{DOCKERIGNORE}: {rule!r} is not a `!path` or `!dir/` line")
        allowed.append(path)
    if not allowed:
        raise ReleaseError(f"{DOCKERIGNORE} admits nothing")
    return tuple(allowed)


def build_context(commit: str, requirements: str, run: Runner) -> Context:
    """The files of the build context at `commit`, as BuildKit would send them, refusing links."""
    listing = run(["git", "ls-tree", "-r", "-z", "--full-tree", commit, "--", SERVICE_DIR]).stdout
    modes = {}
    for record in filter(None, listing.split("\0")):
        meta, _, path = record.partition("\t")
        modes[path] = meta.split()[0]
    for name in (DOCKERFILE, DOCKERIGNORE):
        if f"{SERVICE_DIR}/{name}" not in modes:
            raise ReleaseError(f"{commit} has no {SERVICE_DIR}/{name}")
    allowed = allow_list(run(["git", "show", f"{commit}:{SERVICE_DIR}/{DOCKERIGNORE}"]).stdout)

    def admitted(path: str) -> bool:
        relative = path.removeprefix(f"{SERVICE_DIR}/")
        return any(relative == a or (a.endswith("/") and relative.startswith(a)) for a in allowed)

    files = sorted(path for path in modes if admitted(path))
    links = [path for path in files if modes[path] == "120000"]
    if links:
        raise ReleaseError(f"the build context holds links, which could read outside it: {', '.join(links)}")
    if "/" in requirements or f"{SERVICE_DIR}/{requirements}" not in files:
        raise ReleaseError(
            f"{requirements} is not a requirements file of the build context ({', '.join(allowed)})"
        )
    return Context(
        files=(f"{SERVICE_DIR}/{DOCKERFILE}", f"{SERVICE_DIR}/{DOCKERIGNORE}", *files),
        requirements=requirements,
    )


def extract(archive: Path, destination: Path) -> None:
    """Unpack a tar archive with the `data` filter: no links out, no absolute paths, no devices."""
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseError(f"{archive.name} could not be unpacked: {exc}") from exc


def stage(commit: str, context: Context, source: Path, run: Runner) -> Path:
    """Write the context's files at `commit` under `source` (repository paths kept, so findings name them);
    returns the build context directory."""
    archive = source.parent / "source.tar"
    run(["git", "archive", "--format=tar", f"--output={archive}", commit, "--", *context.files])
    extract(archive, source)
    archive.unlink()
    return source / SERVICE_DIR


# ---------------------------------------------------------------- 3. the image


def build(
    context_dir: Path,
    requirements: str,
    archive: Path,
    metadata: Path,
    run: Runner,
    *,
    wheels_only: bool = True,
) -> None:
    """Build the image as an OCI layout, and have BuildKit record the digest it built in `metadata`. A
    release installs wheels only (no setup.py runs, every byte is hashed); only the demo's BLOCK image, whose
    seeded pyyaml 5.3.1 has no wheel, may build from an sdist."""
    run(
        [
            "docker", "buildx", "build", "--file", str(context_dir / DOCKERFILE),
            "--build-arg", f"REQUIREMENTS={requirements}",
            "--build-arg", f"ONLY_BINARY={':all:' if wheels_only else ':none:'}",
            "--output", f"type=oci,dest={archive}", "--provenance=false", "--sbom=false",
            "--metadata-file", str(metadata),
            str(context_dir),
        ],
        capture=False,
    )  # fmt: skip


def built_digest(metadata: Path) -> str:
    """The digest BuildKit recorded for the image it built (`containerimage.digest`): the builder's word,
    not the layout's own index.json. A layout only shows it holds the image it is asked about (#70)."""
    try:
        recorded = json.loads(metadata.read_text(encoding="utf-8")).get("containerimage.digest")
    except (OSError, ValueError, AttributeError) as exc:
        raise ReleaseError(f"the build's metadata {metadata} cannot be read: {exc}") from exc
    if not isinstance(recorded, str) or not _DIGEST.fullmatch(recorded):
        raise ReleaseError(f"the build's metadata names no image digest ({recorded!r})")
    return recorded


def layout_digest(layout: Path) -> str:
    """The digest of the one image manifest an OCI layout holds, after checking its bytes have that digest."""
    try:
        index = json.loads((layout / "index.json").read_text(encoding="utf-8"))
        manifests = index.get("manifests") or []
    except (OSError, ValueError, AttributeError) as exc:
        raise ReleaseError(f"{layout} is not an OCI layout: {exc}") from exc
    if len(manifests) != 1 or not isinstance(manifests[0], dict):
        raise ReleaseError(f"{layout} must hold exactly one image, not {len(manifests)} manifests")
    entry = manifests[0]
    digest = str(entry.get("digest", ""))
    if not _DIGEST.fullmatch(digest) or entry.get("mediaType") != _IMAGE_MANIFEST:
        raise ReleaseError(
            f"{layout}: {digest or 'no digest'} is not one image manifest ({entry.get('mediaType')})"
        )
    blob = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    if not blob.is_file() or "sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest() != digest:
        raise ReleaseError(f"{layout}: the manifest of {digest} is missing or does not have that digest")
    return digest


def bundle_digest(bundle: Path) -> str:
    """The image a `cosign save` layout holds (what `make demo-release` reads, deploy/kind/demo.py)."""
    try:
        index = json.loads((bundle / "index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"{bundle} is not an OCI layout: {exc}") from exc
    images = [
        str(entry.get("digest", ""))
        for entry in index.get("manifests") or []
        if (entry.get("annotations") or {}).get("kind") == COSIGN_IMAGE
    ]
    if len(images) != 1 or not _DIGEST.fullmatch(images[0]):
        raise ReleaseError(f"{bundle} must name exactly one image by sha256 digest, not {images}")
    return images[0]


# ---------------------------------------------------------------- 4. the decision


@dataclass(frozen=True)
class Paths:
    """Where one run writes. `work` is this run's own; the final directories are replaced only at the end."""

    out: Path

    @property
    def work(self) -> Path:
        return self.out / "work"

    @property
    def source(self) -> Path:
        return self.work / "source"

    @property
    def archive(self) -> Path:
        return self.work / "image.oci.tar"

    @property
    def metadata(self) -> Path:
        return self.work / "build.json"

    @property
    def layout(self) -> Path:
        return self.work / "image"

    @property
    def scans(self) -> Path:
        return self.work / "scans"

    @property
    def evidence(self) -> Path:
        return self.work / "evidence"

    @property
    def bundle(self) -> Path:
        return self.work / "bundle"

    @property
    def home(self) -> Path:
        return self.work / "home"

    @property
    def decision(self) -> Path:
        return self.evidence / "decision.v1.json"

    @property
    def findings(self) -> Path:
        return self.evidence / "findings.ndjson"

    @property
    def sbom(self) -> Path:
        return self.evidence / "sbom.cdx.json"

    @property
    def tool_status(self) -> Path:
        return self.evidence / "tool-status.json"


def fresh_work(paths: Paths) -> None:
    """An empty work directory; an existing one is removed only if an earlier release made it."""
    if paths.work.exists():
        if not (paths.work / WORK_MARKER).is_file():
            raise ReleaseError(
                f"{paths.work} exists and was not made by a release: remove it or choose --out"
            )
        shutil.rmtree(paths.work)
    paths.work.mkdir(parents=True)
    (paths.work / WORK_MARKER).write_text("made by deploy/release/release.py\n", encoding="utf-8")
    for directory in (paths.scans, paths.evidence):
        directory.mkdir()


@dataclass(frozen=True)
class Settings:
    root: Path  # the checkout: its lock, policies and public key decide and verify
    tools_dir: Path
    grype_db: Path
    timeout_s: int = 1200

    @property
    def lock(self) -> Path:
        return self.root / "tools.lock.toml"

    @property
    def policies(self) -> Path:
        return self.root / "policies"

    @property
    def public_key(self) -> Path:
        return self.root / PUBLIC_KEY

    def tool_args(self, *, with_tools_dir: bool = True) -> list[str]:
        return ["--lock", str(self.lock)] + (["--tools-dir", str(self.tools_dir)] if with_tools_dir else [])


def scan_commands(
    commit: str, target: Path, source: Path, digest: str, paths: Paths, settings: Settings
) -> dict[str, list[str]]:
    """Each scan of the release: `<scan>.ndjson` and `<scan>-status.json` in the scans directory."""
    run = ["--repo", REPO, "--commit", commit, "--context", "release", "--ref", MAIN]
    timeout = ["--timeout", str(settings.timeout_s)]

    def outputs(name: str) -> list[str]:
        scans = paths.scans
        return [
            "--out",
            str(scans / f"{name}.ndjson"),
            "--tool-status-out",
            str(scans / f"{name}-status.json"),
        ]

    source_scan = [str(target), "--repo-root", str(source), *run, *timeout]
    tools = settings.tool_args()
    return {
        "secrets": sentinel("scan", "secrets", *source_scan, "--mode", "dir", *outputs("secrets"), *tools),
        "sast": sentinel("scan", "sast", *source_scan, *outputs("sast"), *tools),
        "iac": sentinel("scan", "iac", *source_scan, *outputs("iac"), *tools),
        "pipelines": sentinel(  # zizmor is the CLI's own (a Python dependency), not a lock binary
            "scan", "pipelines", *source_scan, *outputs("pipelines"),
            *settings.tool_args(with_tools_dir=False),
        ),
        "container": sentinel(
            "scan", "image", str(paths.archive), "--image-digest", digest, "--image-ref", IMAGE_REF,
            "--db-dir", str(settings.grype_db), *run, *timeout, *outputs("container"), *tools,
        ),
    }  # fmt: skip


def tool_versions(*documents: Path) -> list[str]:
    """`--tool-version name=version` for every tool the tool status and the OPA manifest name."""
    versions: dict[str, str] = {}
    for document in documents:
        if document.is_file():
            tools = json.loads(document.read_text(encoding="utf-8")).get("tools") or {}
            versions |= {name: str(e.get("version")) for name, e in tools.items() if e.get("version")}
    return [f"--tool-version={name}={version}" for name, version in sorted(versions.items())]


def check_reported(tool_status: Path) -> None:
    """Every scanner of the release reported, ok or not. A scan killed or crashed before it wrote its status
    is left out by `scan combine`, and the gate blocks a missing tool only if `required_tools` lists it."""
    try:
        tools = json.loads(tool_status.read_text(encoding="utf-8")).get("tools") or {}
    except (OSError, ValueError, AttributeError) as exc:
        raise ReleaseError(f"no combined tool status ({exc}): nothing is decided") from exc
    missing = sorted(RELEASE_TOOLS - set(tools))
    if missing:
        raise ReleaseError(
            f"no tool status for {', '.join(missing)}: a scan ended without reporting, nothing is decided"
        )


@dataclass(frozen=True)
class Decided:
    verdict: str
    image_digest: str
    rules: tuple[str, ...] = ()  # "SC-010 (BLOCK)", ...: what the release prints

    @property
    def blocked(self) -> bool:
        return self.verdict == "BLOCK"


def prepare_grype_db(paths: Paths, settings: Settings, run: Runner) -> None:
    """Grype's database, offline afterwards. When it cannot be prepared, the scans that need it fail and the
    gate blocks (SC-010): nothing is skipped."""
    database = run(
        sentinel(
            "tools", "grype-db", "--db-dir", str(settings.grype_db),
            "--report", str(paths.evidence / "grype-db.json"), "--timeout", str(settings.timeout_s),
            *settings.tool_args(),
        ),
        check=False,
        capture=False,
    )  # fmt: skip
    if database.returncode != 0:
        print(f"release: Grype's database could not be prepared ({database.returncode}): the scans that "
              "need it fail, and the gate blocks (SC-010)", file=sys.stderr)  # fmt: skip


def run_scans(commands: Mapping[str, list[str]], paths: Paths, run: Runner) -> None:
    for name, command in commands.items():
        if run(command, check=False, capture=False).returncode != 0:
            print(f"release: the {name} scan failed: left to the gate", file=sys.stderr)
            (paths.scans / f"{name}.ndjson").write_text("", encoding="utf-8")  # its status says why


def decide(commit: str, target: Path, digest: str, paths: Paths, settings: Settings, run: Runner) -> Decided:
    """ADR-0011, decision 3: the SBOM, the scans, the score, then the release gate on this digest."""
    run(
        sentinel(
            "sbom", str(paths.archive), "--name", IMAGE_NAME, "--source", "oci-archive",
            "--image-digest", digest, "--cyclonedx", str(paths.sbom),
            "--spdx", str(paths.evidence / "sbom.spdx.json"), *settings.tool_args(),
        ),
        capture=False,
    )  # fmt: skip
    prepare_grype_db(paths, settings, run)
    run_scans(scan_commands(commit, target, paths.source, digest, paths, settings), paths, run)
    return gate(commit, SCANS, paths, settings, run, image_digest=digest)


def gate(
    commit: str,
    scans: Sequence[str],
    paths: Paths,
    settings: Settings,
    run: Runner,
    *,
    image_digest: str | None = None,
    waivers: Path | None = None,
    vex: Path | None = None,
) -> Decided:
    """The release gate on the scans' findings: combined, scored, then `sentinel evaluate` in the release
    context, about the image when there is one."""
    combined = paths.work / "combined.ndjson"
    combine = sentinel("scan", "combine", "--out", str(combined), "--tool-status-out", str(paths.tool_status))
    for name in scans:
        combine += ["--findings", str(paths.scans / f"{name}.ndjson")]
        combine += ["--tool-status", str(paths.scans / f"{name}-status.json")]
    run(combine)
    check_reported(paths.tool_status)
    opa_manifest = paths.work / "opa-manifest.json"
    run(sentinel("tools", "verify", "opa", "--lock", str(settings.lock), "--dest", str(settings.tools_dir),
                 "--report", str(opa_manifest)))  # fmt: skip
    run(sentinel("score", "--findings", str(combined), "--policy-dir", str(settings.policies),
                 "--out", str(paths.findings)))  # fmt: skip
    image = ["--image-digest", image_digest, "--sbom", str(paths.sbom)] if image_digest else []
    waived = ["--waivers", str(waivers)] if waivers is not None else []
    waived += ["--vex", str(vex)] if vex is not None else []
    evaluated = run(
        sentinel(
            "evaluate", "--findings", str(paths.findings), "--repo", REPO, "--commit", commit,
            "--context", "release", "--ref", MAIN, *image, *waived,
            "--policy-dir", str(settings.policies), "--opa", str(settings.tools_dir / "bin" / "opa"),
            *tool_versions(paths.tool_status, opa_manifest), "--tool-status", str(paths.tool_status),
            "--store", str(paths.evidence / "store"), "--output", str(paths.decision),
        ),
        check=False,
    )  # fmt: skip
    if evaluated.returncode not in (0, 1) or not paths.decision.is_file():
        last = ((evaluated.stderr or "").strip().splitlines() or ["no output"])[-1]
        raise ReleaseError(f"sentinel evaluate made no decision ({evaluated.returncode}): {last}")
    decision = json.loads(paths.decision.read_text(encoding="utf-8"))
    verdict = str(decision.get("verdict"))
    if (verdict == "BLOCK") != (evaluated.returncode == 1):
        raise ReleaseError(
            f"the decision says {verdict}, but sentinel evaluate exited {evaluated.returncode}"
        )
    subject = decision.get("subject") or {}
    about = subject.get("image_digest") == image_digest if image_digest else subject.get("commit") == commit
    if not about or (image_digest is None and "image_digest" in subject):
        raise ReleaseError(f"the decision is not about {image_digest or commit}")
    rules = sorted({f"{v.get('rule')} ({v.get('effect')})" for v in decision.get("violations") or []})
    return Decided(verdict, image_digest or "", tuple(rules))


# ---------------------------------------------------------------- 5. signing


@contextmanager
def crane_registry(crane: Path, home: Path) -> Iterator[str]:
    """`crane registry serve` on a free 127.0.0.1 port, in memory: gone when the release ends."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen(  # noqa: S603 (the verified crane)
        [str(crane), "registry", "serve", "--address", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_tool_env(home),
    )
    try:
        for _ in range(200):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/v2/", timeout=1):
                    break
            except OSError:
                if server.poll() is not None:
                    raise ReleaseError(f"crane registry serve stopped ({server.returncode})") from None
                time.sleep(0.05)
        else:
            raise ReleaseError("crane registry serve did not start")
        yield f"127.0.0.1:{port}"
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


Registry = Callable[[Path, Path], AbstractContextManager[str]]  # crane, home -> host:port while it runs


@dataclass(frozen=True)
class Signed:
    reference: str  # <registry>/demo-shop/shop-api@<digest>
    trust_report: str


def sign(
    decided: Decided,
    *,
    key: Path,
    password: str,
    paths: Paths,
    settings: Settings,
    run: Runner,
    environ: Mapping[str, str],
    tool: Callable[[str], Path],
    registry: Registry = crane_registry,
) -> Signed:
    """ADR-0011, decision 4: attest in a throwaway registry, verify there and from the evidence, then save."""
    digest = layout_digest(paths.layout)  # again: never the digest an earlier step printed
    if decided.blocked or digest != decided.image_digest:
        raise ReleaseError(
            f"the layout holds {digest}; the decision is {decided.verdict} on {decided.image_digest}"
        )
    crane = tool("crane")
    with registry(crane, paths.home) as host:
        reference = f"{host}/{IMAGE_NAME}@{digest}"
        pushed = run(
            [str(crane), "push", str(paths.layout), f"{host}/{IMAGE_NAME}:release", "--insecure"],
            env=_tool_env(paths.home),
        ).stdout.strip()
        if pushed.splitlines()[-1:] != [reference]:
            raise ReleaseError(f"crane pushed {pushed!r}, not {reference}")
        run(
            sentinel(
                "attest", reference, "--decision", str(paths.decision), "--findings", str(paths.findings),
                "--sbom", str(paths.sbom), "--key", str(key), "--out", str(paths.evidence), "--push",
                "--registry-http", "--builder", "local-release", *settings.tool_args(),
            ),
            env={**environ, "COSIGN_PASSWORD": password},
            capture=False,
        )  # fmt: skip
        trust = sentinel("verify", reference, "--key", str(settings.public_key), "--repo", REPO,
                         "--builder-id", builder_id(), *settings.tool_args())  # fmt: skip
        reports = []
        for mode in (["--registry-http"], ["--evidence", str(paths.evidence)]):
            verified = run([*trust, *mode], check=False)
            reports.append(verified.stdout)
            if verified.returncode != 0:
                print(verified.stdout, end="", file=sys.stderr)
                raise ReleaseError(
                    f"sentinel verify ({mode[0]}) does not trust what was just signed: no bundle"
                )
        run([str(tool("cosign")), "save", "--allow-http-registry", "--dir", str(paths.bundle), reference],
            env=_tool_env(paths.home))  # fmt: skip
    if bundle_digest(paths.bundle) != digest:
        raise ReleaseError(f"the bundle does not name {digest}")
    report = "".join(reports)
    (paths.evidence / "trust-report.txt").write_text(report, encoding="utf-8")
    return Signed(reference, report)


# ---------------------------------------------------------------- the whole release


def replace_dir(source: Path, destination: Path) -> None:
    """Move `source` to `destination`, replacing what an earlier release left there."""
    if destination.is_symlink() or destination.is_file():
        destination.unlink()
    elif destination.exists():
        shutil.rmtree(destination)
    source.rename(destination)


@dataclass
class Release:
    key: Path
    out: Path
    settings: Settings
    requirements: str = DEFAULT_REQUIREMENTS
    expect_block: bool = False
    fetch: bool = True
    run: Runner | None = None  # default: run_command in settings.root
    ask_password: Callable[[str], str] = getpass.getpass
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    registry: Registry = crane_registry
    tool: Callable[[str], Path] | None = None  # default: the pinned tool, verified

    def _run(self) -> Runner:
        return self.run if self.run is not None else functools.partial(run_command, cwd=self.settings.root)

    def _tool(self, name: str) -> Path:
        if self.tool is not None:
            return self.tool(name)
        return verified_tool(name, self.settings.tools_dir, self.settings.lock)

    def __call__(self) -> int:
        run, paths, public_key = self._run(), Paths(self.out), self.settings.public_key
        commit = preconditions(run, fetch=self.fetch, environ=self.environ)
        print(f"release: {REPO} at {commit} (main), {SERVICE_DIR}/{DOCKERFILE} with {self.requirements}")
        password = ""
        if not self.expect_block:  # before the long steps, so a wrong key or password costs nothing
            check_key_files(self.key, public_key)
            password = self.ask_password(f"Password of the release key {self.key}: ")
        fresh_work(paths)
        if not self.expect_block:
            check_key_pair(self.key, public_key, password, self._tool("cosign"), run, paths.home)
        context = build_context(commit, self.requirements, run)
        target = stage(commit, context, paths.source, run)
        build(
            target,
            context.requirements,
            paths.archive,
            paths.metadata,
            run,
            wheels_only=not self.expect_block,
        )
        extract(paths.archive, paths.layout)
        digest = layout_digest(paths.layout)
        recorded = built_digest(paths.metadata)
        if digest != recorded:
            raise ReleaseError(f"the layout holds {digest}, not the image the build recorded ({recorded})")
        print(f"release: built {IMAGE_NAME}@{digest}")
        decided = decide(commit, target, digest, paths, self.settings, run)
        print(
            f"release: the gate says {decided.verdict} for {digest}: {', '.join(decided.rules) or 'no rule'}"
        )
        if decided.blocked:
            replace_dir(paths.layout, self.out / "block-image")
            replace_dir(paths.evidence, self.out / "block-evidence")
            print(f"release: nothing signed; the image is in {self.out / 'block-image'} (`make demo-attack`)")
            return EXIT_RELEASED if self.expect_block else EXIT_BLOCKED
        if self.expect_block:
            print(
                "release: --expect-block, but the gate did not block this image: nothing signed",
                file=sys.stderr,
            )
            return EXIT_BLOCKED
        signed = sign(
            decided, key=self.key, password=password, paths=paths, settings=self.settings, run=run,
            environ=self.environ, tool=self._tool, registry=self.registry,
        )  # fmt: skip
        replace_dir(paths.bundle, self.out / "bundle")
        replace_dir(paths.evidence, self.out / "evidence")
        print(signed.trust_report, end="")
        print(f"release: {IMAGE_NAME}@{digest} signed; bundle {self.out / 'bundle'}, evidence "
              f"{self.out / 'evidence'} (next: `make demo-release`)")  # fmt: skip
        return EXIT_RELEASED


# ---------------------------------------------------------------- the self-gate (A10)


def git_blob_id(data: bytes) -> str:
    """The id git gives these bytes as a blob (SHA-1, object format of this repository)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def export_tree(
    commit: str, destination: Path, run: Runner, *, exclude: Sequence[str] = NOT_SELF
) -> list[str]:
    """The files of `commit` under `destination`, without the `exclude` directories: from `git archive`, never
    the working tree, then checked file by file against the commit's blobs. An export attribute (a
    `.gitattributes` with export-ignore or export-subst) could otherwise hide or rewrite what is scanned, and
    a link or a submodule could point outside what the commit holds: either is refused."""
    listing = run(["git", "ls-tree", "-r", "-z", "--full-tree", commit]).stdout
    blobs: dict[str, str] = {}
    for record in filter(None, listing.split("\0")):
        meta, _, path = record.partition("\t")
        mode, kind, blob = meta.split()
        if any(path == top or path.startswith(f"{top}/") for top in exclude):
            continue
        if kind != "blob" or mode == "120000":
            raise ReleaseError(
                f"{path} is a {'link' if mode == '120000' else kind}: the self-gate scans files only"
            )
        blobs[path] = blob
    archive = destination.parent / "self.tar"
    run(["git", "archive", "--format=tar", f"--output={archive}", commit, "--", *sorted(blobs)])
    extract(archive, destination)
    archive.unlink()
    found = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if found != set(blobs):
        differ = sorted(found ^ set(blobs))
        raise ReleaseError(f"git archive did not give exactly the commit's files: {', '.join(differ[:5])}")
    for path, blob in sorted(blobs.items()):
        if git_blob_id((destination / path).read_bytes()) != blob:
            raise ReleaseError(f"{path} is not the commit's blob {blob} (an export attribute?)")
    return sorted(blobs)


def self_scan_commands(commit: str, paths: Paths, settings: Settings) -> dict[str, list[str]]:
    """Each scan of SentinelCI's own tree: the gate's five scanners, Grype on its lockfiles' SBOM included."""
    tree = [str(paths.source), "--repo-root", str(paths.source)]
    run = ["--repo", REPO, "--commit", commit, "--context", "release", "--ref", MAIN]
    timeout = ["--timeout", str(settings.timeout_s)]

    def outputs(name: str) -> list[str]:
        scans = paths.scans
        return [
            "--out",
            str(scans / f"{name}.ndjson"),
            "--tool-status-out",
            str(scans / f"{name}-status.json"),
        ]

    tools = settings.tool_args()
    return {
        "secrets": sentinel(
            "scan", "secrets", *tree, *run, *timeout, "--mode", "dir", *outputs("secrets"), *tools
        ),
        "sast": sentinel("scan", "sast", *tree, *run, *timeout, *outputs("sast"), *tools),
        "iac": sentinel("scan", "iac", *tree, *run, *timeout, *outputs("iac"), *tools),
        "pipelines": sentinel(
            "scan", "pipelines", *tree, *run, *timeout, *outputs("pipelines"),
            *settings.tool_args(with_tools_dir=False),
        ),
        "sca": sentinel(
            "scan", "sca", *tree, *run, *timeout, "--db-dir", str(settings.grype_db), *outputs("sca"), *tools
        ),
    }  # fmt: skip


def from_commit(commit: str, path: Path, destination: Path, run: Runner) -> bool:
    """`path` as `commit` holds it (its blob, never the working tree's copy), written to `destination`; False
    when the commit has no such file."""
    listed = run(["git", "ls-tree", "-z", commit, "--", path.as_posix()]).stdout.rstrip("\0")
    if not listed:
        return False
    meta, _, _ = listed.partition("\t")
    mode, kind, blob = meta.split()
    if kind != "blob" or mode == "120000":
        raise ReleaseError(f"{path} is not a file in {commit}")
    destination.write_text(run(["git", "cat-file", "blob", blob]).stdout, encoding="utf-8")
    return True


def self_gate_inputs(
    pipe: Pipeline, settings: Settings, paths: Paths, run: Runner
) -> tuple[Path, Path | None]:
    """The self-gate's waivers and VEX, from the pipeline commit's blobs, kept with the evidence and always
    named to `sentinel evaluate` (#95 review, nit 2): no waivers file is an empty one, so nothing falls back
    to the working directory's. A VEX document holds at least one statement, so with none, the
    `.sentinel/vex.json` that `sentinel evaluate` reads by default from its working directory (the checkout)
    must not exist either."""
    waivers = paths.evidence / SELF_WAIVERS.name
    if not from_commit(pipe.commit, SELF_WAIVERS, waivers, run):
        waivers.write_text("version: 1\nwaivers: []\n", encoding="utf-8")
    vex = paths.evidence / SELF_VEX.name
    if from_commit(pipe.commit, SELF_VEX, vex, run):
        return waivers, vex
    if (settings.root / ".sentinel" / "vex.json").exists():
        raise ReleaseError(
            f".sentinel/vex.json would be read by default: the self-gate's VEX is {SELF_VEX} only"
        )
    return waivers, None


def export_target(pipe: Pipeline, paths: Paths, run: Runner, what: str) -> None:
    """The target's own files without demo-shop, and which pipeline judges them, kept with the evidence."""
    files = export_tree(pipe.target, paths.source, run)
    announce(pipe, what)
    print(f"{what}: {len(files)} files, without {', '.join(NOT_SELF)}/")
    (paths.evidence / "pipeline.json").write_text(
        json.dumps(pipe.evidence(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def judge(pipe: Pipeline, paths: Paths, settings: Settings, run: Runner) -> Decided:
    """The self-gate on the exported target: scanned and decided by the pipeline commit."""
    prepare_grype_db(paths, settings, run)
    run_scans(self_scan_commands(pipe.target, paths, settings), paths, run)
    waivers, vex = self_gate_inputs(pipe, settings, paths, run)
    return gate(pipe.target, SELF_SCANS, paths, settings, run, waivers=waivers, vex=vex)


@dataclass
class SelfGate:
    """SPEC principle P4, practice what we preach: SentinelCI's release gate on SentinelCI itself. Like the
    workflow (ADR-0008), the commit judged is not the one that judges: the checkout is the pipeline commit (a
    release tag, or named with --pipeline), and origin's main is the target, exported and scanned without
    demo-shop by the pipeline's five scanners, with the pipeline's own self-gate waivers. The decision is kept
    with its evidence and the pipeline it was made with. Nothing is signed here."""

    out: Path
    settings: Settings
    fetch: bool = True
    run: Runner | None = None
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    pipeline: str | None = None  # --pipeline: HEAD named on purpose when it is no release tag

    def __call__(self) -> int:
        run = self.run if self.run is not None else functools.partial(run_command, cwd=self.settings.root)
        paths = Paths(self.out)
        pipe = pipeline_preconditions(run, fetch=self.fetch, environ=self.environ, named=self.pipeline)
        fresh_work(paths)
        export_target(pipe, paths, run, "self-gate")
        decided = judge(pipe, paths, self.settings, run)
        replace_dir(paths.evidence, self.out / "evidence")
        rules = ", ".join(decided.rules) or "no rule"
        print(f"self-gate: the gate says {decided.verdict} for {pipe.target}: {rules}; evidence in "
              f"{self.out / 'evidence'}")  # fmt: skip
        return EXIT_BLOCKED if decided.blocked else EXIT_RELEASED


# ---------------------------------------------------------------- SentinelCI's own release (A10)


def package_versions(source: Path) -> dict[str, str]:
    """The version each package's pyproject.toml declares, in the exported tree."""
    versions = {}
    for package, directory in PACKAGES.items():
        project = tomllib.loads((source / directory / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
        if project.get("name") != package:
            raise ReleaseError(f"{directory}/pyproject.toml is not {package}'s")
        versions[package] = str(project.get("version"))
    return versions


def check_tag_is_new(tag: str, run: Runner) -> None:
    """A version is released once: its tag exists neither here nor on origin."""
    if run(["git", "rev-parse", "--quiet", "--verify", f"refs/tags/{tag}"], check=False).returncode == 0:
        raise ReleaseError(f"{tag} already exists here: a version is released once")
    if run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"]).stdout.strip():
        raise ReleaseError(f"{tag} already exists on origin: a version is released once")


def build_artifacts(
    commit: str,
    version: str,
    source: Path,
    dist: Path,
    run: Runner,
    environ: Mapping[str, str],
    constraints: Path,
) -> list[Path]:
    """The wheels and source distributions of both packages, built from the exported tree with the commit's
    time as SOURCE_DATE_EPOCH and the build backend pinned by hash (`constraints`, `--require-hashes`), and
    the policy bundle (`git archive` of the policies and the tool lock)."""
    dist.mkdir(parents=True)
    epoch = run(["git", "log", "-1", "--format=%ct", commit]).stdout.strip()
    env = {key: value for key, value in environ.items() if key != "COSIGN_PASSWORD"} | {
        "SOURCE_DATE_EPOCH": epoch
    }
    for package in PACKAGES:
        run(
            [
                "uv",
                "--directory",
                str(source),
                "build",
                "--quiet",
                "--package",
                package,
                "--out-dir",
                str(dist),
                "--build-constraints",
                str(constraints),
                "--require-hashes",
            ],
            env=env,
            capture=False,
        )
    bundle = dist / f"sentinelci-policies-{version}.tar.gz"
    run([
        "git", "archive", "--format=tar.gz", f"--prefix=sentinelci-policies-{version}/", f"--output={bundle}",
        commit, "--", *POLICY_BUNDLE,
    ])  # fmt: skip
    built = sorted(path for path in dist.iterdir() if path.is_file())
    names = [path.name for path in built]
    for package in PACKAGES:
        stem = package.replace("-", "_")
        if not any(n.startswith(f"{stem}-{version}-") and n.endswith(".whl") for n in names) or (
            f"{stem}-{version}.tar.gz" not in names
        ):
            raise ReleaseError(
                f"uv build gave no wheel and source distribution of {package} {version}: {names}"
            )
    return built


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def reproducible(first: Sequence[Path], second: Sequence[Path]) -> dict[str, str]:
    """name -> sha256 of artifacts built twice, which must be byte for byte the same."""
    a = {path.name: sha256_file(path) for path in first}
    b = {path.name: sha256_file(path) for path in second}
    differ = sorted(name for name in a.keys() | b.keys() if a.get(name) != b.get(name))
    if differ:
        raise ReleaseError(f"the build is not reproducible: {', '.join(differ)} differ between two builds")
    return a


def provenance(
    commit: str, version: str, *, pipeline: str, constraints_sha256: str, uv: str
) -> dict[str, Any]:
    """SLSA provenance v1 of the release: what was built, from which commit, with which build backend and uv,
    judged by which pipeline commit, by which builder. No clock: the same inputs give the same document."""
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "repository": f"https://github.com/{REPO}",
                "ref": MAIN,
                "version": version,
            },
            "internalParameters": {"gatePipeline": {"gitCommit": pipeline}, "uv": uv},
            "resolvedDependencies": [
                {"uri": f"git+https://github.com/{REPO}@{MAIN}", "digest": {"gitCommit": commit}},
                {
                    "uri": f"git+https://github.com/{REPO}@{pipeline}#{BUILD_CONSTRAINTS.as_posix()}",
                    "digest": {"sha256": constraints_sha256},
                },
            ],
        },
        "runDetails": {"builder": {"id": builder_id()}},
    }


@dataclass
class SentinelRelease:
    """`release.py sentinelci --version X.Y.Z` (`make release-sentinelci`): SentinelCI's own release, gated by
    the self-gate and signed on this laptop like shop-api's image. Nothing is kept unless every signature and
    attestation verifies with the committed public key."""

    version: str
    key: Path
    out: Path
    settings: Settings
    fetch: bool = True
    run: Runner | None = None
    ask_password: Callable[[str], str] = getpass.getpass
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    tool: Callable[[str], Path] | None = None  # default: the pinned tool, verified
    pipeline: str | None = None  # --pipeline: HEAD named on purpose when it is no release tag

    def _run(self) -> Runner:
        return self.run if self.run is not None else functools.partial(run_command, cwd=self.settings.root)

    def _tool(self, name: str) -> Path:
        if self.tool is not None:
            return self.tool(name)
        return verified_tool(name, self.settings.tools_dir, self.settings.lock)

    def _cosign(self, args: Sequence[str], home: Path, password: str | None = None) -> None:
        env = _tool_env(home) | ({"COSIGN_PASSWORD": password} if password is not None else {})
        self._run()([str(self._tool("cosign")), *args], env=env)

    def _sign(self, built: Sequence[Path], sums: Path, predicate: Path, paths: Paths, password: str) -> None:
        """Each artifact and SHA256SUMS signed; each artifact attested: its provenance, then the decision."""
        private = ["--key", str(self.key), "--tlog-upload=false", "--use-signing-config=false", "--yes"]
        for artifact in [*built, sums]:
            self._cosign(["sign-blob", *private, "--bundle", f"{artifact}.sigstore.json", str(artifact)],
                         paths.home, password)  # fmt: skip
        for artifact in built:
            for kind, kind_type, document in (
                ("provenance", PROVENANCE_TYPE, predicate), ("decision", DECISION_TYPE, paths.decision),
            ):  # fmt: skip
                self._cosign(
                    ["attest-blob", *private, "--type", kind_type, "--predicate", str(document),
                     "--bundle", f"{artifact}.{kind}.sigstore.json", str(artifact)],
                    paths.home, password,
                )  # fmt: skip

    def _verify(self, built: Sequence[Path], sums: Path, paths: Paths) -> None:
        """With the committed public key only, as anyone who downloads the release (no log: ADR-0006)."""
        public = ["--key", str(self.settings.public_key), "--insecure-ignore-tlog=true"]
        for artifact in [*built, sums]:
            self._cosign(["verify-blob", *public, "--bundle", f"{artifact}.sigstore.json", str(artifact)],
                         paths.home)  # fmt: skip
        for artifact in built:
            for kind, kind_type in (("provenance", PROVENANCE_TYPE), ("decision", DECISION_TYPE)):
                self._cosign(
                    ["verify-blob-attestation", *public, "--type", kind_type,
                     "--bundle", f"{artifact}.{kind}.sigstore.json", str(artifact)],
                    paths.home,
                )  # fmt: skip

    def __call__(self) -> int:
        run = self._run()
        if not _VERSION.fullmatch(self.version):
            raise ReleaseError(f"{self.version!r} is not a version (X.Y.Z)")
        tag, paths, public_key = f"v{self.version}", Paths(self.out / "sentinelci"), self.settings.public_key
        final, blocked = (
            self.out / f"sentinelci-{self.version}",
            self.out / f"sentinelci-{self.version}-block",
        )
        pipe = pipeline_preconditions(run, fetch=self.fetch, environ=self.environ, named=self.pipeline)
        commit = pipe.target
        check_tag_is_new(tag, run)
        if final.exists():
            raise ReleaseError(f"{final} exists: a version is released once")
        check_key_files(self.key, public_key)
        password = self.ask_password(f"Password of the release key {self.key}: ")
        fresh_work(paths)
        check_key_pair(self.key, public_key, password, self._tool("cosign"), run, paths.home)
        export_target(pipe, paths, run, "release")
        constraints = paths.work / BUILD_CONSTRAINTS.name
        if not from_commit(pipe.commit, BUILD_CONSTRAINTS, constraints, run):
            raise ReleaseError(
                f"the pipeline commit has no {BUILD_CONSTRAINTS}: the build backend must be pinned"
            )
        versions = package_versions(paths.source)
        if set(versions.values()) != {self.version}:
            raise ReleaseError(
                f"the packages declare {versions}, not {self.version}: bump them in a PR first"
            )
        print(f"release: SentinelCI {self.version} at {commit} (main): the self-gate first")
        decided = judge(pipe, paths, self.settings, run)
        print(
            f"release: the gate says {decided.verdict} for {commit}: {', '.join(decided.rules) or 'no rule'}"
        )
        if decided.blocked:
            replace_dir(paths.evidence, blocked)
            print(f"release: nothing built or signed; the evidence is in {blocked}")
            return EXIT_BLOCKED
        dist = paths.work / "dist"
        built = build_artifacts(commit, self.version, paths.source, dist, run, self.environ, constraints)
        again = build_artifacts(
            commit, self.version, paths.source, paths.work / "again", run, self.environ, constraints
        )
        digests = reproducible(built, again)
        sums = dist / "SHA256SUMS"
        sums.write_text("".join(f"{digests[name]}  {name}\n" for name in sorted(digests)), encoding="utf-8")
        predicate = paths.work / "provenance.json"
        uv = run(["uv", "--version"]).stdout.strip()
        document = provenance(
            commit, self.version, pipeline=pipe.commit, constraints_sha256=sha256_file(constraints), uv=uv
        )
        predicate.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        self._sign(built, sums, predicate, paths, password)
        self._verify(built, sums, paths)
        shutil.copyfile(predicate, dist / "provenance.json")
        shutil.copyfile(paths.decision, dist / "decision.v1.json")
        replace_dir(paths.evidence, dist / "evidence")
        replace_dir(dist, final)
        message = f"SentinelCI {self.version}\n\nSHA256SUMS sha256:{sha256_file(final / 'SHA256SUMS')}\n"
        run(["git", "tag", "--annotate", tag, "--message", message, commit])
        print(f"release: SentinelCI {self.version} signed and verified in {final}; tag {tag} made here, "
              f"published with `git push origin {tag}`")  # fmt: skip
        return EXIT_RELEASED


# ---------------------------------------------------------------- the key pair


def make_key(
    key: Path,
    *,
    public_key: Path,
    cosign: Callable[[], Path],
    ask_password: Callable[[str], str] = getpass.getpass,
    run: Runner = run_command,
) -> None:
    """Make the release key pair with the pinned Cosign; never overwrites a key."""
    if key.suffix != ".key":
        raise ReleaseError(f"{key} must end in .key (git ignores *.key)")
    existing = [str(path) for path in (key, key.with_suffix(".pub"), public_key) if path.exists()]
    if existing:
        raise ReleaseError(f"{', '.join(existing)} already exist: a key is never overwritten")
    password = ask_password("Password for the new release key: ")
    if not password or password != ask_password("Again: "):
        raise ReleaseError("the passwords are empty or differ: no key was made")
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    home = key.parent / ".cosign-home"
    try:
        run(
            [str(cosign()), "generate-key-pair", "--output-key-prefix", str(key.with_suffix(""))],
            env=_tool_env(home) | {"COSIGN_PASSWORD": password},
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)
    key.chmod(0o600)
    public_key.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(key.with_suffix(".pub"), public_key)
    print(f"release key: {key} (keep it, and its password, on this laptop only); public key: {public_key}, "
          "to commit through a pull request")  # fmt: skip


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "command", nargs="?", choices=["release", "key", "self-gate", "sentinelci"], default="release"
    )
    parser.add_argument(
        "--version", help="sentinelci: the version to release (X.Y.Z), as the packages declare"
    )
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY, help="the release private key (Cosign)")
    parser.add_argument("--requirements", default=DEFAULT_REQUIREMENTS,
                        help=f"the requirements file the image installs, in {SERVICE_DIR}")  # fmt: skip
    parser.add_argument(
        "--expect-block", action="store_true", help="the demo's BLOCK image: the gate must block"
    )
    parser.add_argument("--out", type=Path, help="default: out/release, out/self-gate for self-gate")
    parser.add_argument("--grype-db", type=Path, default=ROOT / "out" / "grype-db",
                        help="Grype's database, kept between releases (out/ is git-ignored)")  # fmt: skip
    parser.add_argument(
        "--tools-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_TOOLS_DIR", ROOT / ".sentinel" / "tools")),
    )
    parser.add_argument("--timeout", type=int, default=1200, help="seconds for each scanner run")
    parser.add_argument(
        "--no-fetch", action="store_true", help="compare HEAD with origin/main as last fetched"
    )
    parser.add_argument(
        "--pipeline",
        help="self-gate, sentinelci: HEAD's full commit id, to judge origin/main with a pipeline commit "
        "that is no release tag (on purpose)",
    )
    args = parser.parse_args(argv)
    settings = Settings(
        root=ROOT,
        tools_dir=args.tools_dir.resolve(),
        grype_db=args.grype_db.resolve(),
        timeout_s=args.timeout,
    )
    try:
        if args.command == "key":
            make_key(
                args.key.expanduser(), public_key=settings.public_key,
                cosign=lambda: verified_tool("cosign", settings.tools_dir, settings.lock),
            )  # fmt: skip
            return EXIT_RELEASED
        if args.command == "sentinelci":
            if not args.version:
                raise ReleaseError("sentinelci needs --version X.Y.Z")
            return SentinelRelease(
                version=args.version, key=args.key.expanduser().resolve(),
                out=(args.out or ROOT / "out" / "release").resolve(), settings=settings,
                fetch=not args.no_fetch, pipeline=args.pipeline,
            )()  # fmt: skip
        if args.command == "self-gate":
            out = (args.out or ROOT / "out" / "self-gate").resolve()
            return SelfGate(out=out, settings=settings, fetch=not args.no_fetch, pipeline=args.pipeline)()
        return Release(
            key=args.key.expanduser().resolve(), out=(args.out or ROOT / "out" / "release").resolve(),
            settings=settings,
            requirements=args.requirements, expect_block=args.expect_block, fetch=not args.no_fetch,
        )()  # fmt: skip
    except (ReleaseError, subprocess.SubprocessError, OSError, ValueError) as exc:
        print(f"release: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:
        print("release: interrupted, nothing kept", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
