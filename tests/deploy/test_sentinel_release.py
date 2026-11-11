"""SentinelCI's own release (`release.py sentinelci`, task A10): gated by the self-gate, built twice, signed,
attested and verified on the laptop, then tagged."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.deploy.release_support import Call, Recorder, done, git, make_repo, release
from tests.deploy.test_self_gate import FakeCli


def pem(data: bytes) -> str:
    return "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(data).decode() + "\n-----END PUBLIC KEY-----\n"


RELEASE_PUB = pem(b"release key " * 4)
PASSWORD = "correct horse battery staple"  # noqa: S105 (a test value, for the fake Cosign only)
VERSION = "1.0.0"


def pyproject(name: str, version: str = VERSION) -> str:
    return f'[project]\nname = "{name}"\nversion = "{version}"\n'


OWN = {
    "cli/pyproject.toml": pyproject("sentinelci"),
    "ai/pyproject.toml": pyproject("sentinel-ai"),
    "policies/gate.rego": "package sentinel.gate\n",
    "tools.lock.toml": "[tools]\n",
    "deploy/keys/release.pub": RELEASE_PUB,
    ".sentinel/waivers.yaml": "version: 1\nwaivers: []\n",
}


class FakeTools:
    """`uv build` and Cosign as the release calls them; `reproducible=False` builds differ each time."""

    def __init__(self, recorder: Recorder, *, reproducible: bool = True, trusted: bool = True) -> None:
        self.reproducible, self.trusted, self.builds = reproducible, trusted, 0
        recorder.fakes.update({
            "uv --directory": self.build,
            "cosign public-key": lambda call: done(RELEASE_PUB, 0 if self.password(call) else 1),
            "cosign sign-blob": self.write_bundle,
            "cosign attest-blob": self.write_bundle,
            "cosign verify-blob": lambda call: done(returncode=0 if self.trusted else 1),
        })  # fmt: skip

    @staticmethod
    def password(call: Call) -> bool:
        return bool(call.env) and call.env.get("COSIGN_PASSWORD") == PASSWORD  # type: ignore[union-attr]

    def build(self, call: Call) -> Any:
        package, out = call.option("--package"), Path(call.option("--out-dir"))
        stem = package.replace("-", "_")
        self.builds += 1
        salt = "" if self.reproducible else str(self.builds)
        (out / f"{stem}-{VERSION}-py3-none-any.whl").write_text(f"wheel {package}{salt}")
        (out / f"{stem}-{VERSION}.tar.gz").write_text(f"sdist {package}{salt}")
        return done()

    def write_bundle(self, call: Call) -> Any:
        if not self.password(call):
            return done(returncode=1)
        Path(call.option("--bundle")).write_text(json.dumps({"signed": call.args[-1]}))
        return done()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo", OWN)


def make_release(repo: Path, tmp_path: Path, recorder: Recorder, **changes: Any) -> Any:
    key = tmp_path / "keys" / "release.key"
    key.parent.mkdir(exist_ok=True)
    key.write_text("encrypted test key")
    settings = release.Settings(root=repo, tools_dir=tmp_path / "tools", grype_db=tmp_path / "grype-db")
    options: dict[str, Any] = {
        "version": VERSION, "key": key, "out": repo / "out" / "release", "settings": settings, "fetch": False,
        "run": recorder, "ask_password": lambda prompt: PASSWORD,
        "environ": {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, "tool": lambda name: Path(f"/t/{name}"),
    }  # fmt: skip
    return release.SentinelRelease(**(options | changes))


def tags(repo: Path) -> list[str]:
    return git(repo, "tag", "--list").split()


def setup(repo: Path, **tools: Any) -> tuple[Recorder, FakeCli, FakeTools]:
    recorder = Recorder(repo)
    recorder.fakes["git ls-remote"] = lambda call: done("")  # origin has no such tag
    return recorder, FakeCli(recorder), FakeTools(recorder, **tools)


def test_a_release_the_self_gate_lets_through_is_built_signed_verified_and_tagged(
    repo: Path, tmp_path: Path
) -> None:
    recorder, _, _ = setup(repo)
    made = make_release(repo, tmp_path, recorder)
    assert made() == release.EXIT_RELEASED
    final = made.out / f"sentinelci-{VERSION}"
    artifacts = [
        f"sentinel_ai-{VERSION}-py3-none-any.whl", f"sentinel_ai-{VERSION}.tar.gz",
        f"sentinelci-policies-{VERSION}.tar.gz",
        f"sentinelci-{VERSION}-py3-none-any.whl", f"sentinelci-{VERSION}.tar.gz",
    ]  # fmt: skip
    sums = (final / "SHA256SUMS").read_text().splitlines()
    assert [line.split("  ")[1] for line in sums] == sorted(artifacts)
    for line in sums:
        digest, name = line.split("  ")
        assert hashlib.sha256((final / name).read_bytes()).hexdigest() == digest
    for name in artifacts:
        for suffix in (".sigstore.json", ".provenance.sigstore.json", ".decision.sigstore.json"):
            assert (final / f"{name}{suffix}").is_file(), name + suffix
    assert (final / "SHA256SUMS.sigstore.json").is_file()
    assert (final / "decision.v1.json").is_file() and (final / "evidence").is_dir()
    assert tags(repo) == [f"v{VERSION}"]
    message = git(repo, "tag", "--list", "--format=%(contents)", f"v{VERSION}")
    assert hashlib.sha256((final / "SHA256SUMS").read_bytes()).hexdigest() in message
    assert git(repo, "rev-parse", f"v{VERSION}^{{commit}}") == git(repo, "rev-parse", "HEAD")


def test_the_gate_comes_first_then_two_builds_then_signatures_then_verification(
    repo: Path, tmp_path: Path
) -> None:
    recorder, _, _ = setup(repo)
    make_release(repo, tmp_path, recorder)()
    steps = ("sentinel evaluate", "uv ", "cosign sign-blob", "cosign attest-blob", "cosign verify-blob")
    order = [
        "evaluate" if c.line.startswith("sentinel") else c.line.split()[0]
        for c in recorder.calls
        if c.line.startswith(steps)
    ]
    assert order[0] == "evaluate" and order.count("uv") == 4, "both packages, built twice"
    first_cosign = order.index("cosign")
    assert set(order[1:first_cosign]) == {"uv"}
    lines = [c.line for c in recorder.calls if c.line.startswith("cosign")]
    signing = [
        i for i, line in enumerate(lines) if line.startswith(("cosign sign-blob", "cosign attest-blob"))
    ]
    verifying = [i for i, line in enumerate(lines) if line.startswith("cosign verify-blob")]
    assert max(signing) < min(verifying), "everything is signed before anything is verified"
    for call in recorder.named("cosign verify-blob"):
        assert call.option("--key") == str(repo / "deploy" / "keys" / "release.pub")
        assert "--insecure-ignore-tlog=true" in call.args and not FakeTools.password(call)
    for call in recorder.named("cosign sign-blob") + recorder.named("cosign attest-blob"):
        assert {"--tlog-upload=false", "--use-signing-config=false"} <= set(call.args)


def test_the_builds_use_the_commits_time_and_never_the_key_password(repo: Path, tmp_path: Path) -> None:
    recorder, _, _ = setup(repo)
    make_release(repo, tmp_path, recorder)()
    epoch = git(repo, "log", "-1", "--format=%ct").strip()
    for call in recorder.named("uv --directory"):
        assert call.env is not None and call.env["SOURCE_DATE_EPOCH"] == epoch
        assert "COSIGN_PASSWORD" not in call.env
        assert call.args[2].endswith("sentinelci/work/source"), "built from the exported tree"


def test_a_block_builds_and_signs_nothing(repo: Path, tmp_path: Path) -> None:
    recorder, cli, _ = setup(repo)
    cli.verdict = "BLOCK"
    made = make_release(repo, tmp_path, recorder)
    assert made() == release.EXIT_BLOCKED
    assert not recorder.named("uv ") and not recorder.named("cosign sign-blob")
    assert (made.out / f"sentinelci-{VERSION}-block" / "decision.v1.json").is_file()
    assert not (made.out / f"sentinelci-{VERSION}").exists() and tags(repo) == []


def test_a_build_that_is_not_reproducible_is_not_signed(repo: Path, tmp_path: Path) -> None:
    recorder, _, _ = setup(repo, reproducible=False)
    with pytest.raises(release.ReleaseError, match="not reproducible"):
        make_release(repo, tmp_path, recorder)()
    assert not recorder.named("cosign sign-blob") and tags(repo) == []


def test_what_does_not_verify_is_not_kept_or_tagged(repo: Path, tmp_path: Path) -> None:
    recorder, _, _ = setup(repo, trusted=False)
    made = make_release(repo, tmp_path, recorder)
    with pytest.raises(release.ReleaseError):
        made()
    assert not (made.out / f"sentinelci-{VERSION}").exists() and tags(repo) == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda repo: git(repo, "tag", f"v{VERSION}"), "already exists here"),
        (lambda repo: None, "already exists on origin"),
    ],
)
def test_a_version_is_released_once(repo: Path, tmp_path: Path, change: Any, message: str) -> None:
    recorder, _, _ = setup(repo)
    change(repo)
    if "origin" in message:
        recorder.fakes["git ls-remote"] = lambda call: done(f"{'a' * 40}\trefs/tags/v{VERSION}\n")
    asked: list[str] = []
    with pytest.raises(release.ReleaseError, match=message):
        make_release(repo, tmp_path, recorder, ask_password=lambda prompt: asked.append(prompt) or PASSWORD)()
    assert asked == [], "refused before the password is asked"


def test_packages_that_do_not_declare_the_version_are_refused_before_the_scans(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "ai" / "pyproject.toml").write_text(pyproject("sentinel-ai", "0.9.0"))
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-am", "ai 0.9")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    recorder, _, _ = setup(repo)
    with pytest.raises(release.ReleaseError, match="bump them in a PR first"):
        make_release(repo, tmp_path, recorder)()
    assert not recorder.named("sentinel scan")


@pytest.mark.parametrize("version", ["1.0", "v1.0.0", "01.0.0", "1.0.0-rc1"])
def test_only_a_plain_version_is_released(repo: Path, tmp_path: Path, version: str) -> None:
    recorder, _, _ = setup(repo)
    with pytest.raises(release.ReleaseError, match="is not a version"):
        make_release(repo, tmp_path, recorder, version=version)()


def test_the_provenance_names_the_commit_and_the_builder_and_reads_no_clock() -> None:
    first = release.provenance("a" * 40, VERSION)
    assert first == release.provenance("a" * 40, VERSION)
    assert first["buildDefinition"]["resolvedDependencies"][0]["digest"] == {"gitCommit": "a" * 40}
    assert first["runDetails"]["builder"]["id"] == release.builder_id()
    assert "startedOn" not in json.dumps(first)


# ---------------------------------------------------------------- with the real Cosign (opt-in)

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to the pinned tools (cosign)")
def test_the_real_cosign_signs_attests_and_verifies_offline(tmp_path: Path) -> None:
    cosign = Path(str(TOOLS_DIR)) / "bin" / "cosign"
    keys = tmp_path / "keys"
    keys.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home"), "COSIGN_PASSWORD": PASSWORD}
    subprocess.run([str(cosign), "generate-key-pair"], cwd=keys, env=env, check=True, capture_output=True)
    repo = make_repo(tmp_path / "repo", OWN | {"deploy/keys/release.pub": (keys / "cosign.pub").read_text()})
    recorder = Recorder(repo, real=True)
    recorder.fakes["git ls-remote"] = lambda call: done("")
    FakeCli(recorder)
    tools = FakeTools(recorder)
    for prefix in ("cosign public-key", "cosign sign-blob", "cosign attest-blob", "cosign verify-blob"):
        del recorder.fakes[prefix]  # the real Cosign, offline
    shutil.copyfile(keys / "cosign.key", tmp_path / "release.key")
    made = make_release(repo, tmp_path, recorder, key=tmp_path / "release.key", tool=lambda name: cosign)
    assert made() == release.EXIT_RELEASED, tools
    final = made.out / f"sentinelci-{VERSION}"
    wheel = final / f"sentinelci-{VERSION}-py3-none-any.whl"
    public = repo / "deploy" / "keys" / "release.pub"
    check = [str(cosign), "verify-blob", "--key", str(public), "--insecure-ignore-tlog=true"]
    verified = subprocess.run(
        [*check, "--bundle", f"{wheel}.sigstore.json", str(wheel)], env=env, check=False
    )
    assert verified.returncode == 0
    wheel.write_bytes(wheel.read_bytes() + b"tampered")
    tampered = subprocess.run(
        [*check, "--bundle", f"{wheel}.sigstore.json", str(wheel)], env=env, check=False, capture_output=True
    )
    assert tampered.returncode != 0, "a changed artifact no longer verifies"
