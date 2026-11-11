"""`make release`: build shop-api's release image, decide on it and sign it on this laptop (A4c, ADR-0011).

    uv run python deploy/release/release.py [--key ~/.sentinelci/release.key]
    uv run python deploy/release/release.py --requirements requirements.block.txt --expect-block
    uv run python deploy/release/release.py key [--key ~/.sentinelci/release.key]
    uv run python deploy/release/release.py self-gate

During the private phase the laptop is the only signer (ADR-0011, decision 7): the release key never reaches
GitHub. In order, and nothing past a failed step runs:

1. Preconditions, the laptop analog of ADR-0008 (the CLI, lock, policies and waivers that decide, and this
   script, are the reviewed ones): the working tree is clean, `origin` is the release repository, and HEAD is
   its `main`, fetched now. COSIGN_PASSWORD must not be set: the key password is asked on the terminal,
   checked against deploy/keys/release.pub, and given only to the processes that use the key.
2. The build context comes from the commit, not the working tree: `git archive HEAD` of the release
   Dockerfile, its `.dockerignore` allow-list and exactly the files that list admits (no link, nothing git
   ignores).
3. `docker buildx build --output type=oci --provenance=false --sbom=false`: no registry, no credentials. The
   image is the one manifest of the layout's index.json, and its digest is the release's.
4. Decide (ADR-0011, decision 3), in the release context: the SBOM of the image (`sentinel sbom`), Grype's
   database (`sentinel tools grype-db`), the source scans of the build context (secrets, SAST, IaC, CI
   workflows), the image's own scan (CONTAINER findings: the dependencies it ships), then `sentinel score` and
   `sentinel evaluate --context release --image-digest --sbom`. A scan that fails is recorded in the tool
   status and blocks (SC-010); the empty findings file it leaves never passes alone. The requirements files
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

`self-gate` (`make self-gate`, A10, SPEC principle P4) runs the same release gate on SentinelCI itself: the
same preconditions, the commit's own files without demo-shop (exported from the commit and checked blob by
blob, so no export attribute can hide or rewrite one), the five scanners of the gate (secrets, SAST, IaC, CI
workflows, and Grype on the SBOM of the lockfiles), the commit's own `.sentinel/waivers.yaml`, then
`sentinel evaluate --context release`. The decision and its evidence go to `out/self-gate/evidence`;
nothing is signed. Exit 0: PASS or WARN; 1: BLOCK; 3: no decision.

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
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

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
WAIVERS = Path(".sentinel") / "waivers.yaml"  # read from the commit's tree, like the workflow's (ADR-0008)
# With --expect-block, 0 is "blocked as expected" and 1 "not blocked": nothing is signed in either case.
EXIT_RELEASED, EXIT_BLOCKED, EXIT_FAILED = 0, 1, 3
COSIGN_IMAGE = "dev.cosignproject.cosign/image"
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_ORIGIN = re.compile(
    rf"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/){re.escape(REPO)}(?:\.git)?/?",
    re.IGNORECASE,
)
_ALLOWED = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/?")
_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_STEP_TIMEOUT_S = 3600


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
        raise ReleaseError(f"{' '.join(args[:3])} failed ({done.returncode}): {last}")
    return done


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


def preconditions(run: Runner, *, fetch: bool, environ: Mapping[str, str]) -> str:
    """The commit to release: HEAD, which must be origin's main, with a clean working tree."""
    if "COSIGN_PASSWORD" in environ:
        raise ReleaseError(
            "COSIGN_PASSWORD is set: unset it. The key password is asked on the terminal and given only to "
            "the processes that use the key (ADR-0011, decision 4)"
        )
    origin = run(["git", "config", "--get", "remote.origin.url"], check=False)
    if origin.returncode != 0:
        raise ReleaseError("this checkout has no `origin` remote")
    check_origin(origin.stdout)
    dirty = run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).stdout.splitlines()
    if dirty:
        shown = ", ".join(line[3:] for line in dirty[:5]) + (", ..." if len(dirty) > 5 else "")
        raise ReleaseError(f"the working tree is not clean ({shown}): release only what main holds")
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


def build(context_dir: Path, requirements: str, archive: Path, run: Runner) -> None:
    run(
        [
            "docker", "buildx", "build", "--file", str(context_dir / DOCKERFILE),
            "--build-arg", f"REQUIREMENTS={requirements}",
            "--output", f"type=oci,dest={archive}", "--provenance=false", "--sbom=false",
            str(context_dir),
        ],
        capture=False,
    )  # fmt: skip


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
            print(f"release: the {name} scan failed: recorded for the gate (SC-010)", file=sys.stderr)
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
) -> Decided:
    """The release gate on the scans' findings: combined, scored, then `sentinel evaluate` in the release
    context, about the image when there is one."""
    combined = paths.work / "combined.ndjson"
    combine = sentinel("scan", "combine", "--out", str(combined), "--tool-status-out", str(paths.tool_status))
    for name in scans:
        combine += ["--findings", str(paths.scans / f"{name}.ndjson")]
        combine += ["--tool-status", str(paths.scans / f"{name}-status.json")]
    run(combine)
    opa_manifest = paths.work / "opa-manifest.json"
    run(sentinel("tools", "verify", "opa", "--lock", str(settings.lock), "--dest", str(settings.tools_dir),
                 "--report", str(opa_manifest)))  # fmt: skip
    run(sentinel("score", "--findings", str(combined), "--policy-dir", str(settings.policies),
                 "--out", str(paths.findings)))  # fmt: skip
    status = ["--tool-status", str(paths.tool_status)] if paths.tool_status.is_file() else []
    image = ["--image-digest", image_digest, "--sbom", str(paths.sbom)] if image_digest else []
    waived = ["--waivers", str(waivers)] if waivers is not None else []
    evaluated = run(
        sentinel(
            "evaluate", "--findings", str(paths.findings), "--repo", REPO, "--commit", commit,
            "--context", "release", "--ref", MAIN, *image, *waived,
            "--policy-dir", str(settings.policies), "--opa", str(settings.tools_dir / "bin" / "opa"),
            *tool_versions(paths.tool_status, opa_manifest), *status,
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
        build(target, context.requirements, paths.archive, run)
        extract(paths.archive, paths.layout)
        digest = layout_digest(paths.layout)
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


@dataclass
class SelfGate:
    """SPEC principle P4, practice what we preach: SentinelCI's release gate on SentinelCI itself, at `main`.
    The same preconditions as a release (a clean checkout of origin's main), the commit's own files without
    demo-shop, the gate's five scanners, its own waivers (`.sentinel/waivers.yaml` of the commit), and a
    decision kept with its evidence. Nothing is signed here."""

    out: Path
    settings: Settings
    fetch: bool = True
    run: Runner | None = None
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))

    def __call__(self) -> int:
        run = self.run if self.run is not None else functools.partial(run_command, cwd=self.settings.root)
        paths = Paths(self.out)
        commit = preconditions(run, fetch=self.fetch, environ=self.environ)
        fresh_work(paths)
        files = export_tree(commit, paths.source, run)
        print(f"self-gate: {REPO} at {commit} (main): {len(files)} files, without {', '.join(NOT_SELF)}/")
        prepare_grype_db(paths, self.settings, run)
        run_scans(self_scan_commands(commit, paths, self.settings), paths, run)
        waivers = paths.source / WAIVERS
        decided = gate(
            commit, SELF_SCANS, paths, self.settings, run, waivers=waivers if waivers.is_file() else None
        )
        replace_dir(paths.evidence, self.out / "evidence")
        rules = ", ".join(decided.rules) or "no rule"
        print(f"self-gate: the gate says {decided.verdict} for {commit}: {rules}; evidence in "
              f"{self.out / 'evidence'}")  # fmt: skip
        return EXIT_BLOCKED if decided.blocked else EXIT_RELEASED


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
    parser.add_argument("command", nargs="?", choices=["release", "key", "self-gate"], default="release")
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
        if args.command == "self-gate":
            out = (args.out or ROOT / "out" / "self-gate").resolve()
            return SelfGate(out=out, settings=settings, fetch=not args.no_fetch)()
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
