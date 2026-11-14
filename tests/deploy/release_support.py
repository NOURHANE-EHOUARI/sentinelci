"""Shared by tests/deploy/test_release*.py: deploy/release/release.py loaded by path (a script, not a
package), a throwaway release repository, and a stand-in for `docker buildx build --output type=oci`.

The stand-in writes the OCI layout archive BuildKit would, byte by byte, from the staged build context: the
application files and a dist-info of the pyyaml version the selected requirements file pins (what Syft finds
in a Python image). No Docker daemon, no registry, nothing from demo-shop is run.
"""

import gzip
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPO = "NOURHANE-EHOUARI/sentinelci"
SERVICE = "demo-shop/services/shop-api"
DOCKERIGNORE = "*\n!app/\n!requirements.release.txt\n!requirements.block.txt\n"
DOCKERFILE = 'FROM scratch\nCOPY app/ /app/\nCMD ["python", "-m", "app"]\n'


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve annotations through it
    spec.loader.exec_module(module)
    return module


release = _load("sentinel_release_script", ROOT / "deploy" / "release" / "release.py")


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    )  # fmt: skip
    return done.stdout


def make_repo(path: Path, files: Mapping[str, str] | None = None) -> Path:
    """A release repository: shop-api's release Dockerfile, its allow-list, an application, both requirements
    files and a seeded configuration outside the context; origin is the GitHub repository and origin/main is
    HEAD (as after a fetch)."""
    content = {
        ".gitignore": "out/\n__pycache__/\n",
        f"{SERVICE}/Dockerfile.release": DOCKERFILE,
        f"{SERVICE}/Dockerfile.release.dockerignore": DOCKERIGNORE,
        f"{SERVICE}/app/__init__.py": "",
        f"{SERVICE}/app/main.py": "def health() -> dict[str, str]:\n    return {'status': 'ok'}\n",
        f"{SERVICE}/requirements.release.txt": "pyyaml==6.0.3 \\\n    --hash=sha256:" + "1" * 64 + "\n",
        f"{SERVICE}/requirements.block.txt": "pyyaml==5.3.1 \\\n    --hash=sha256:" + "2" * 64 + "\n",
        f"{SERVICE}/config/settings.yaml": "token: not-in-the-context\n",
        **(files or {}),
    }
    path.mkdir(parents=True)
    git(path, "init", "--quiet", "--initial-branch=main")
    for name, text in content.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text, encoding="utf-8")
    git(path, "add", "-A")
    git(path, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", "release")
    git(path, "remote", "add", "origin", f"https://github.com/{REPO}.git")
    git(path, "update-ref", "refs/remotes/origin/main", "HEAD")
    return path


def _layer(files: Mapping[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def oci_archive(path: Path, files: Mapping[str, bytes]) -> str:
    """Write a one-layer OCI layout archive holding `files`; return its manifest digest."""
    layer_tar = _layer(files)
    layer = gzip.compress(layer_tar, mtime=0)
    config = json.dumps({
        "architecture": "amd64", "os": "linux", "config": {"User": "10001:10001"},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer_tar).hexdigest()]},
    }, sort_keys=True).encode()  # fmt: skip

    def descriptor(media_type: str, data: bytes) -> dict[str, Any]:
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": descriptor("application/vnd.oci.image.config.v1+json", config),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer)],
    }, sort_keys=True).encode()  # fmt: skip
    index = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [descriptor("application/vnd.oci.image.manifest.v1+json", manifest)],
    }).encode()  # fmt: skip
    with tarfile.open(path, "w") as archive:
        blobs = [(f"blobs/sha256/{hashlib.sha256(b).hexdigest()}", b) for b in (config, layer, manifest)]
        for name, data in [("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'), ("index.json", index), *blobs]:
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            archive.addfile(info, io.BytesIO(data))
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def fake_build(args: Sequence[str]) -> str:
    """What `docker buildx build --output type=oci,dest=X` writes, from the context it was given; returns the
    image's digest."""
    assert list(args[:3]) == ["docker", "buildx", "build"], args
    assert "--provenance=false" in args and "--sbom=false" in args, args
    dest = next(a.removeprefix("type=oci,dest=") for a in args if a.startswith("type=oci,dest="))
    requirements = next(a.removeprefix("REQUIREMENTS=") for a in args if a.startswith("REQUIREMENTS="))
    context = Path(args[-1])
    pin = re.search(r"^pyyaml==([0-9.]+)", (context / requirements).read_text(encoding="utf-8"), re.M)
    assert pin is not None
    files = {
        f"app/{p.relative_to(context / 'app')}": p.read_bytes()
        for p in (context / "app").rglob("*")
        if p.is_file()
    }
    files["etc/os-release"] = b'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n'
    dist_info = f"opt/venv/lib/python3.12/site-packages/PyYAML-{pin.group(1)}.dist-info/METADATA"
    files[dist_info] = f"Metadata-Version: 2.1\nName: PyYAML\nVersion: {pin.group(1)}\n".encode()
    digest = oci_archive(Path(dest), files)
    # BuildKit's --metadata-file: the digest of the image it built, which the release trusts over the layout.
    metadata = Path(args[list(args).index("--metadata-file") + 1])
    metadata.write_text(json.dumps({"containerimage.digest": digest, "buildx.build.ref": "fake/fake/fake"}))
    return digest


@dataclass
class Call:
    args: list[str]
    env: dict[str, str] | None

    @property
    def line(self) -> str:
        """`sentinel scan secrets ...` for the CLI, `crane push ...` for a tool (by its file name)."""
        if self.args[1:3] == ["-m", "sentinelci.cli"]:
            return " ".join(["sentinel", *self.args[3:]])
        return " ".join([Path(self.args[0]).name, *self.args[1:]])

    def option(self, name: str) -> str:
        return self.args[self.args.index(name) + 1]


@dataclass
class Recorder:
    """Runs git (and, given a `real` runner, everything not faked) for real; fakes the build with fake_build,
    and records every call with the environment it was given."""

    repo: Path
    fakes: dict[str, Any] = field(default_factory=dict)  # first word(s) -> handler(Call) -> CompletedProcess
    calls: list[Call] = field(default_factory=list)
    real: bool = False

    def __call__(
        self,
        args: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        call = Call(list(args), dict(env) if env is not None else None)
        self.calls.append(call)
        for prefix, handler in self.fakes.items():
            if call.line.startswith(prefix):
                done: subprocess.CompletedProcess[str] = handler(call)
                if check and done.returncode != 0:
                    raise release.ReleaseError(f"{prefix} failed ({done.returncode})")
                return done
        if call.args[0] == "docker":
            fake_build(call.args)
            return subprocess.CompletedProcess(call.args, 0, "", "")
        if call.args[0] == "git" or self.real:
            return release.run_command(args, cwd=self.repo, env=env, check=check, capture=capture)
        raise AssertionError(f"unexpected command {call.args}")

    def named(self, prefix: str) -> list[Call]:
        return [c for c in self.calls if c.line.startswith(prefix)]


def done(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, "")
