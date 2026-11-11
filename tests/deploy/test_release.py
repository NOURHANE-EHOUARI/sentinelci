"""`make release` (deploy/release/release.py, task A4c, ADR-0011): what it refuses, what it builds from, and
that nothing is signed unless the gate let the image through.

git is real, on a throwaway release repository; the build is tests/deploy/release_support.fake_build; the CLI,
crane and Cosign are a recording fake that writes what they would. The real CLI, crane and Cosign run in
test_release_tools.py.
"""

import base64
import importlib.util
import json
import os
import re
import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _support() -> ModuleType:
    name = "release_support"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("release_support.py"))
        assert spec is not None and spec.loader is not None
        sys.modules[name] = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sys.modules[name])
    return sys.modules[name]


support = _support()
release = support.release
Call, Recorder, done = support.Call, support.Recorder, support.done
SERVICE = support.SERVICE


def pem(data: bytes) -> str:
    return "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(data).decode() + "\n-----END PUBLIC KEY-----\n"


RELEASE_PUB = pem(b"release key " * 4)
OTHER_PUB = pem(b"another key " * 4)
PASSWORD = "correct horse battery staple"  # noqa: S105 (a test value, for the fake Cosign only)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return support.make_repo(tmp_path / "repo", {"deploy/keys/release.pub": RELEASE_PUB})


def runner(repo: Path) -> Any:
    return lambda args, **kwargs: release.run_command(args, cwd=repo, **kwargs)


# ---------------------------------------------------------------- preconditions


def test_a_clean_checkout_of_main_is_released_at_head(repo: Path) -> None:
    head = support.git(repo, "rev-parse", "HEAD").strip()
    assert release.preconditions(runner(repo), fetch=False, environ={}) == head


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda repo: (repo / "notes.txt").write_text("x"), "not clean (notes.txt)"),
        (lambda repo: (repo / SERVICE / "app/main.py").write_text("x"), "not clean"),
        (lambda repo: support.git(repo, "remote", "set-url", "origin", "https://github.com/someone/fork.git"),
         "not github.com/NOURHANE-EHOUARI/sentinelci"),
        (lambda repo: support.git(repo, "remote", "remove", "origin"), "no `origin` remote"),
        (lambda repo: support.git(repo, "update-ref", "-d", "refs/remotes/origin/main"),
         "origin/main is unknown"),
    ],
)  # fmt: skip
def test_anything_but_a_clean_checkout_of_main_is_refused(repo: Path, change: Any, message: str) -> None:
    change(repo)
    with pytest.raises(release.ReleaseError, match=re.escape(message)):
        release.preconditions(runner(repo), fetch=False, environ={})


def test_a_commit_not_yet_on_main_is_refused(repo: Path) -> None:
    support.git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet",
                "--allow-empty", "-m", "unreviewed")  # fmt: skip
    with pytest.raises(release.ReleaseError, match="check out main as it is on GitHub"):
        release.preconditions(runner(repo), fetch=False, environ={})


def test_ignored_files_do_not_make_the_tree_dirty(repo: Path) -> None:
    (repo / "out").mkdir()
    (repo / "out" / "previous-release.json").write_text("{}")
    release.preconditions(runner(repo), fetch=False, environ={})


def test_main_is_fetched_from_origin_before_it_is_compared(repo: Path, tmp_path: Path) -> None:
    """origin's main moved on: the local checkout is no longer main, though origin/main said so before."""
    remote = tmp_path / "remote.git"
    support.git(tmp_path, "clone", "--quiet", "--bare", str(repo), str(remote))
    newer = support.git(remote, "commit-tree", "-m", "newer", "-p", "main", "main^{tree}").strip()
    support.git(remote, "update-ref", "refs/heads/main", newer)
    support.git(repo, "config", f"url.{remote}.insteadOf", f"https://github.com/{release.REPO}.git")
    release.preconditions(runner(repo), fetch=False, environ={})  # as last fetched
    with pytest.raises(release.ReleaseError, match="check out main as it is on GitHub"):
        release.preconditions(runner(repo), fetch=True, environ={})


def test_a_password_in_the_environment_is_refused_before_anything_runs(repo: Path) -> None:
    recorder = Recorder(repo)
    with pytest.raises(release.ReleaseError, match="COSIGN_PASSWORD is set"):
        release.preconditions(recorder, fetch=False, environ={"COSIGN_PASSWORD": ""})
    assert recorder.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/NOURHANE-EHOUARI/sentinelci.git",
        "https://github.com/NOURHANE-EHOUARI/sentinelci",
        "git@github.com:NOURHANE-EHOUARI/sentinelci.git",
        "ssh://git@github.com/NOURHANE-EHOUARI/sentinelci.git",
    ],
)
def test_the_release_repository_by_any_github_url(url: str) -> None:
    release.check_origin(url + "\n")


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/NOURHANE-EHOUARI/sentinelci-fork.git",
        "https://github.com.evil.example/NOURHANE-EHOUARI/sentinelci.git",
        "https://gitlab.com/NOURHANE-EHOUARI/sentinelci.git",
        "/home/user/sentinelci",
    ],
)
def test_any_other_origin_is_refused(url: str) -> None:
    with pytest.raises(release.ReleaseError, match=r"not github\.com"):
        release.check_origin(url)


# ---------------------------------------------------------------- the build context


def test_the_allow_list_reads_star_then_bang_lines() -> None:
    text = "# comment\n*\n\n!app/\n!requirements.release.txt\n"
    assert release.allow_list(text) == ("app/", "requirements.release.txt")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "!app/\n",
        "*\n",
        "*\napp/\n",
        "*\n!app/*.py\n",
        "*\n!../config/\n",
        "*\n!/etc/passwd\n",
        "*\n!**\n",
    ],
)
def test_any_other_dockerignore_is_refused(text: str) -> None:
    with pytest.raises(release.ReleaseError, match="dockerignore"):
        release.allow_list(text)


def test_the_context_is_the_commit_s_allow_listed_files(repo: Path, tmp_path: Path) -> None:
    """Untracked and ignored files, and the seeded configuration outside the allow-list, never enter it."""
    (repo / SERVICE / "app" / "__pycache__").mkdir()
    (repo / SERVICE / "app" / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"ignored")
    (repo / SERVICE / "app" / "untracked.py").write_text("print('not committed')\n")
    commit = support.git(repo, "rev-parse", "HEAD").strip()
    context = release.build_context(commit, "requirements.release.txt", runner(repo))
    assert context.files == tuple(f"{SERVICE}/{name}" for name in (
        "Dockerfile.release", "Dockerfile.release.dockerignore", "app/__init__.py", "app/main.py",
        "requirements.block.txt", "requirements.release.txt",
    ))  # fmt: skip
    target = release.stage(commit, context, tmp_path / "source", runner(repo))
    staged = sorted(
        str(p.relative_to(tmp_path / "source")) for p in (tmp_path / "source").rglob("*") if p.is_file()
    )
    assert staged == list(context.files)
    assert target == tmp_path / "source" / SERVICE
    assert not (tmp_path / "source.tar").exists()


def test_the_requirements_file_must_be_one_of_the_context(repo: Path) -> None:
    commit = support.git(repo, "rev-parse", "HEAD").strip()
    for requirements in (
        "requirements.txt",
        "config/settings.yaml",
        "../requirements.release.txt",
        "app/main.py",
    ):
        with pytest.raises(release.ReleaseError, match="is not a requirements file of the build context"):
            release.build_context(commit, requirements, runner(repo))


def test_a_link_in_the_context_is_refused(tmp_path: Path) -> None:
    repo = support.make_repo(tmp_path / "repo")
    (repo / SERVICE / "app" / "settings.yaml").symlink_to("../config/settings.yaml")
    support.git(repo, "add", "-A")
    support.git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "link")
    commit = support.git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(release.ReleaseError, match="holds links"):
        release.build_context(commit, "requirements.release.txt", runner(repo))


def test_a_commit_without_the_release_dockerfile_is_refused(tmp_path: Path) -> None:
    repo = support.make_repo(tmp_path / "repo")
    support.git(repo, "rm", "-q", f"{SERVICE}/Dockerfile.release.dockerignore")
    support.git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "no list")
    with pytest.raises(release.ReleaseError, match=r"has no .*dockerignore"):
        release.build_context("HEAD", "requirements.release.txt", runner(repo))


# ---------------------------------------------------------------- the image's digest


def layout(tmp_path: Path, files: dict[str, bytes] | None = None) -> tuple[Path, str]:
    archive = tmp_path / "image.oci.tar"
    digest = support.oci_archive(archive, files or {"app/main.py": b"print('hi')\n"})
    release.extract(archive, tmp_path / "image")
    return tmp_path / "image", digest


def test_the_digest_is_the_one_manifest_of_the_layout(tmp_path: Path) -> None:
    image, digest = layout(tmp_path)
    assert release.layout_digest(image) == digest


def test_a_layout_whose_manifest_bytes_changed_is_refused(tmp_path: Path) -> None:
    image, digest = layout(tmp_path)
    blob = image / "blobs" / "sha256" / digest.removeprefix("sha256:")
    blob.write_bytes(blob.read_bytes() + b"\n")
    with pytest.raises(release.ReleaseError, match="does not have that digest"):
        release.layout_digest(image)


@pytest.mark.parametrize(
    "change",
    [
        lambda index: index["manifests"].append(index["manifests"][0]),
        lambda index: index["manifests"].clear(),
        lambda index: index["manifests"][0].update(mediaType="application/vnd.oci.image.index.v1+json"),
        lambda index: index["manifests"][0].update(digest="sha256:" + "A" * 64),
    ],
)
def test_a_layout_that_is_not_one_image_is_refused(tmp_path: Path, change: Any) -> None:
    image, _ = layout(tmp_path)
    index = json.loads((image / "index.json").read_text())
    change(index)
    (image / "index.json").write_text(json.dumps(index))
    with pytest.raises(release.ReleaseError, match=r"exactly one image|not one image manifest"):
        release.layout_digest(image)


# ---------------------------------------------------------------- the whole release, with a recording fake


@contextmanager
def fake_registry(crane: Path, home: Path) -> Iterator[str]:
    yield "127.0.0.1:5999"


class FakeTools:
    """The CLI, crane and Cosign, writing what they would; `verdict` is the gate's answer."""

    def __init__(self, recorder: Recorder, *, verdict: str = "WARN", public_key: str = RELEASE_PUB) -> None:
        self.verdict, self.public_key, self.trusted, self.failing_scan = verdict, public_key, True, ""
        self.after_evaluate: Any = None
        recorder.fakes.update({
            "cosign public-key": self.public_key_of,
            "sentinel sbom": self.sbom,
            "sentinel tools grype-db": lambda call: done(),
            "sentinel scan combine": self.combine,
            "sentinel scan": self.scan,
            "sentinel tools verify opa": self.opa,
            "sentinel score": self.score,
            "sentinel evaluate": self.evaluate,
            "crane push": self.push,
            "sentinel attest": lambda call: done(),
            "sentinel verify": lambda call: done("TRUSTED: 16/16 checks passed\n", 0 if self.trusted else 1),
            "cosign save": self.save,
        })  # fmt: skip

    def public_key_of(self, call: Call) -> Any:
        return done(self.public_key, 0 if call.env and call.env.get("COSIGN_PASSWORD") == PASSWORD else 1)

    def sbom(self, call: Call) -> Any:
        Path(call.option("--cyclonedx")).write_text('{"bomFormat": "CycloneDX"}')
        Path(call.option("--spdx")).write_text('{"spdxVersion": "SPDX-2.3"}')
        return done()

    def scan(self, call: Call) -> Any:
        name = Path(call.option("--out")).stem
        if name == self.failing_scan:
            return done(returncode=3)
        Path(call.option("--out")).write_text("")
        Path(call.option("--tool-status-out")).write_text(json.dumps({"tools": {name: {"version": "1.0.0"}}}))
        return done()

    def combine(self, call: Call) -> Any:
        Path(call.option("--out")).write_text("")
        Path(call.option("--tool-status-out")).write_text(
            json.dumps({"tools": {"gitleaks": {"version": "8.30.1"}}})
        )
        return done()

    def opa(self, call: Call) -> Any:
        Path(call.option("--report")).write_text(json.dumps({"tools": {"opa": {"version": "1.10.1"}}}))
        return done()

    def score(self, call: Call) -> Any:
        Path(call.option("--out")).write_text(Path(call.option("--findings")).read_text())
        return done()

    def evaluate(self, call: Call) -> Any:
        rule = (
            {"rule": "SC-002", "effect": "BLOCK"}
            if self.verdict == "BLOCK"
            else {"rule": "SC-006", "effect": "WARN"}
        )
        decision = {"verdict": self.verdict, "subject": {"image_digest": call.option("--image-digest")},
                    "violations": [rule]}  # fmt: skip
        Path(call.option("--output")).write_text(json.dumps(decision))
        if self.after_evaluate is not None:
            self.after_evaluate(call)
        return done(returncode=1 if self.verdict == "BLOCK" else 0)

    def push(self, call: Call) -> Any:
        host = call.args[3].split("/", 1)[0]
        return done(f"{host}/demo-shop/shop-api@{release.layout_digest(Path(call.args[2]))}\n")

    def save(self, call: Call) -> Any:
        bundle = Path(call.option("--dir"))
        digest = call.args[-1].rsplit("@", 1)[1]
        bundle.mkdir(parents=True)
        index = {"manifests": [{"digest": digest, "annotations": {"kind": release.COSIGN_IMAGE}}]}
        (bundle / "index.json").write_text(json.dumps(index))
        return done()


def make_release(repo: Path, tmp_path: Path, recorder: Recorder, **changes: Any) -> Any:
    key = tmp_path / "keys" / "release.key"
    key.parent.mkdir(exist_ok=True)
    key.write_text("encrypted test key")
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return PASSWORD

    settings = release.Settings(root=repo, tools_dir=tmp_path / "tools", grype_db=tmp_path / "grype-db")
    options: dict[str, Any] = {
        "key": key, "out": repo / "out" / "release", "settings": settings, "fetch": False, "run": recorder,
        "ask_password": ask, "environ": {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        "registry": fake_registry, "tool": lambda name: Path(f"/opt/tools/bin/{name}"),
    }  # fmt: skip
    made = release.Release(**(options | changes))
    made.asked = asked
    return made


def test_a_release_the_gate_lets_through_is_signed_and_saved(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    made = make_release(repo, tmp_path, recorder)
    assert made() == release.EXIT_RELEASED
    out = repo / "out" / "release"
    assert release.bundle_digest(out / "bundle") == recorder.named("sentinel evaluate")[0].option(
        "--image-digest"
    )
    assert (out / "evidence" / "decision.v1.json").is_file() and (
        out / "evidence" / "trust-report.txt"
    ).is_file()
    assert not (out / "block-image").exists()
    assert len(made.asked) == 1
    # The order of ADR-0011: build, decide, then attest, verify (registry, then evidence) and save.
    order = [" ".join(c.line.split()[:2]) for c in recorder.calls if not c.line.startswith("git")]
    assert order[:3] == ["cosign public-key", "docker buildx", "sentinel sbom"]
    assert order[-5:] == [
        "crane push",
        "sentinel attest",
        "sentinel verify",
        "sentinel verify",
        "cosign save",
    ]


def test_the_password_reaches_only_the_processes_that_use_the_key(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    assert make_release(repo, tmp_path, recorder)() == release.EXIT_RELEASED
    holders = [c.line.split(" ")[0:2] for c in recorder.calls if c.env and "COSIGN_PASSWORD" in c.env]
    assert holders == [["cosign", "public-key"], ["sentinel", "attest"]]
    for call in recorder.calls:
        assert PASSWORD not in " ".join(call.args)


def test_every_scan_is_of_the_release_context_and_the_decision_names_the_image(
    repo: Path, tmp_path: Path
) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    make_release(repo, tmp_path, recorder)()
    commit = support.git(repo, "rev-parse", "HEAD").strip()
    scans = [c for c in recorder.named("sentinel scan") if "combine" not in c.line]
    assert [c.args[4] for c in scans] == ["secrets", "sast", "iac", "pipelines", "image"]
    source = repo / "out" / "release" / "work" / "source"
    for call in scans:
        assert (call.option("--context"), call.option("--commit"), call.option("--ref")) == (
            "release", commit, "refs/heads/main")  # fmt: skip
        if call.args[4] != "image":
            assert call.args[5] == str(source / SERVICE) and call.option("--repo-root") == str(source)
    evaluate = recorder.named("sentinel evaluate")[0]
    assert evaluate.option("--context") == "release"
    assert evaluate.option("--sbom").endswith("sbom.cdx.json") and evaluate.option("--tool-status")
    assert "--tool-version=opa=1.10.1" in evaluate.args
    attest = recorder.named("sentinel attest")[0]
    assert attest.option("--builder") == "local-release" and "--push" in attest.args
    for verify in recorder.named("sentinel verify"):
        assert verify.option("--builder-id") == release.builder_id()
        assert verify.option("--key") == str(repo / "deploy" / "keys" / "release.pub")


def test_the_build_reads_the_staged_context_not_the_working_tree(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    make_release(repo, tmp_path, recorder)()
    (build,) = recorder.named("docker buildx build")
    assert build.args[-1] == str(repo / "out" / "release" / "work" / "source" / SERVICE)
    assert "REQUIREMENTS=requirements.release.txt" in build.args


def test_a_block_signs_nothing_and_keeps_the_image_for_the_attack_demo(repo: Path, tmp_path: Path) -> None:
    out = repo / "out" / "release"
    (out / "bundle").mkdir(parents=True)
    (out / "bundle" / "index.json").write_text("previous release")
    recorder = Recorder(repo)
    FakeTools(recorder, verdict="BLOCK")
    assert make_release(repo, tmp_path, recorder)() == release.EXIT_BLOCKED
    assert release.layout_digest(out / "block-image")
    assert (out / "block-evidence" / "decision.v1.json").is_file()
    assert (out / "bundle" / "index.json").read_text() == "previous release"
    for tool in ("crane push", "sentinel attest", "sentinel verify", "cosign save"):
        assert recorder.named(tool) == []


def test_the_demo_block_image_is_never_asked_a_password(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder, verdict="BLOCK")
    made = make_release(repo, tmp_path, recorder, expect_block=True, requirements="requirements.block.txt")
    assert made() == release.EXIT_RELEASED
    assert made.asked == [] and recorder.named("cosign") == []
    assert "REQUIREMENTS=requirements.block.txt" in recorder.named("docker")[0].args


def test_an_expected_block_that_passes_signs_nothing(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder, verdict="PASS")
    made = make_release(repo, tmp_path, recorder, expect_block=True, requirements="requirements.block.txt")
    assert made() == release.EXIT_BLOCKED
    assert recorder.named("sentinel attest") == [] and not (repo / "out" / "release" / "bundle").exists()


def test_a_failed_scan_is_left_to_the_gate_with_an_empty_findings_file(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    tools = FakeTools(recorder, verdict="BLOCK")
    tools.failing_scan = "secrets"
    assert make_release(repo, tmp_path, recorder)() == release.EXIT_BLOCKED
    combine = recorder.named("sentinel scan combine")[0]
    findings = [combine.args[i + 1] for i, a in enumerate(combine.args) if a == "--findings"]
    assert len(findings) == 5 and all(Path(path).name.endswith(".ndjson") for path in findings)
    assert (repo / "out" / "release" / "work" / "scans" / "secrets.ndjson").read_text() == ""


def test_no_decision_is_a_failed_release(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    recorder.fakes["sentinel evaluate"] = lambda call: done(returncode=3)
    with pytest.raises(release.ReleaseError, match="made no decision"):
        make_release(repo, tmp_path, recorder)()
    assert recorder.named("sentinel attest") == []


def test_a_layout_changed_after_the_decision_is_not_signed(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    tools = FakeTools(recorder)
    other = tmp_path / "other"
    other.mkdir()

    def swap(call: Call) -> None:
        image, _ = layout(other, {"app/main.py": b"print('swapped')\n"})
        work_image = repo / "out" / "release" / "work" / "image"
        for path in ("index.json", "blobs"):
            target = work_image / path
            if target.is_dir():
                shutil.rmtree(target)
                shutil.copytree(image / path, target)
            else:
                target.write_bytes((image / path).read_bytes())

    tools.after_evaluate = swap
    with pytest.raises(release.ReleaseError, match="the decision is WARN on"):
        make_release(repo, tmp_path, recorder)()
    assert recorder.named("crane push") == [] and recorder.named("sentinel attest") == []


def test_what_verify_does_not_trust_is_not_kept(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder).trusted = False
    with pytest.raises(release.ReleaseError, match="does not trust what was just signed"):
        make_release(repo, tmp_path, recorder)()
    assert recorder.named("cosign save") == []
    assert not (repo / "out" / "release" / "bundle").exists()
    assert not (repo / "out" / "release" / "evidence").exists()


def test_a_key_that_is_not_the_committed_one_is_refused_before_the_build(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder, public_key=OTHER_PUB)
    with pytest.raises(release.ReleaseError, match="is not the pair of"):
        make_release(repo, tmp_path, recorder)()
    assert recorder.named("docker") == []


def test_a_wrong_password_is_refused_before_the_build(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeTools(recorder)
    made = make_release(repo, tmp_path, recorder, ask_password=lambda prompt: "wrong")
    with pytest.raises(release.ReleaseError, match="wrong password"):
        made()
    assert recorder.named("docker") == []


def test_no_key_is_refused_before_the_password_is_asked(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    made = make_release(repo, tmp_path, recorder, key=tmp_path / "missing.key")
    with pytest.raises(release.ReleaseError, match="no release key at"):
        made()
    assert made.asked == []


def test_a_work_directory_the_release_did_not_make_is_not_removed(tmp_path: Path) -> None:
    paths = release.Paths(tmp_path / "out")
    paths.work.mkdir(parents=True)
    (paths.work / "precious.txt").write_text("keep")
    with pytest.raises(release.ReleaseError, match="was not made by a release"):
        release.fresh_work(paths)
    assert (paths.work / "precious.txt").read_text() == "keep"
    (paths.work / "precious.txt").unlink()
    (paths.work / release.WORK_MARKER).write_text("")
    (paths.work / "old").write_text("from an earlier release")
    release.fresh_work(paths)
    assert not (paths.work / "old").exists() and paths.scans.is_dir() and paths.evidence.is_dir()


def test_tool_versions_come_from_the_tool_status_and_the_opa_manifest(tmp_path: Path) -> None:
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"tools": {"trivy": {"version": "0.76.1"}, "grype": {"status": "failed"}}}))
    opa = tmp_path / "opa.json"
    opa.write_text(json.dumps({"tools": {"opa": {"version": "1.10.1"}}}))
    assert release.tool_versions(status, opa, tmp_path / "missing.json") == [
        "--tool-version=opa=1.10.1", "--tool-version=trivy=0.76.1",
    ]  # fmt: skip


# ---------------------------------------------------------------- the key pair


def test_a_key_is_never_overwritten(tmp_path: Path) -> None:
    key = tmp_path / "home" / "release.key"
    public = tmp_path / "repo" / "deploy" / "keys" / "release.pub"
    public.parent.mkdir(parents=True)
    public.write_text(RELEASE_PUB)
    with pytest.raises(release.ReleaseError, match="already exist"):
        release.make_key(
            key, public_key=public, cosign=lambda: Path("/unused"), ask_password=lambda p: PASSWORD
        )
    assert public.read_text() == RELEASE_PUB


@pytest.mark.parametrize("answers", [["", ""], [PASSWORD, "typo"]])
def test_a_key_needs_a_password_typed_twice(tmp_path: Path, answers: list[str]) -> None:
    replies = iter(answers)
    with pytest.raises(release.ReleaseError, match="empty or differ"):
        release.make_key(tmp_path / "release.key", public_key=tmp_path / "release.pub",
                         cosign=lambda: Path("/unused"), ask_password=lambda p: next(replies))  # fmt: skip
    assert list(tmp_path.iterdir()) == []


def test_the_key_pair_is_made_by_cosign_and_its_public_key_is_copied_to_the_repository(
    tmp_path: Path,
) -> None:
    key = tmp_path / "home" / ".sentinelci" / "release.key"
    public = tmp_path / "repo" / "deploy" / "keys" / "release.pub"
    calls: list[Call] = []

    def cosign(args: list[str], *, env: dict[str, str] | None = None, **kwargs: Any) -> Any:
        calls.append(Call(list(args), env))
        prefix = Path(args[args.index("--output-key-prefix") + 1])
        prefix.with_suffix(".key").write_text("encrypted")
        prefix.with_suffix(".pub").write_text(RELEASE_PUB)
        return done()

    release.make_key(
        key,
        public_key=public,
        cosign=lambda: Path("/opt/cosign"),
        ask_password=lambda p: PASSWORD,
        run=cosign,
    )
    assert public.read_text() == RELEASE_PUB
    assert key.stat().st_mode & 0o777 == 0o600 and key.parent.stat().st_mode & 0o777 == 0o700
    assert calls[0].env is not None and calls[0].env["COSIGN_PASSWORD"] == PASSWORD
    assert not (key.parent / ".cosign-home").exists()


def test_main_refuses_a_password_in_the_environment(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    monkeypatch.setenv("COSIGN_PASSWORD", "exported")
    assert release.main(["--no-fetch"]) == release.EXIT_FAILED
    assert "COSIGN_PASSWORD is set" in capsys.readouterr().err
