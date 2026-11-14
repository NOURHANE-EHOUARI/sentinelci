"""The self-gate (`release.py self-gate`, task A10): SentinelCI's release gate on its own tree."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, ClassVar

import pytest

from tests.deploy.release_support import Call, Recorder, done, git, make_repo, release

OWN = {
    "cli/src/sentinelci/__init__.py": "VERSION = '1.0.0'\n",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    ".sentinel/self-gate-waivers.yaml": "version: 1\nwaivers: []\n",
    "uv.lock": "version = 1\n",
}


class FakeCli:
    """`sentinel` as the self-gate calls it, writing what it would; `verdict` is the gate's answer."""

    def __init__(self, recorder: Recorder, *, verdict: str = "PASS") -> None:
        self.verdict, self.failing_scan, self.decided_commit, self.image_digest = verdict, "", "", ""
        self.scanned: dict[str, set[str]] = {}
        recorder.fakes.update({
            "sentinel tools grype-db": lambda call: done(),
            "sentinel scan combine": self.combine,
            "sentinel scan": self.scan,
            "sentinel tools verify opa": self.opa,
            "sentinel score": self.score,
            "sentinel evaluate": self.evaluate,
        })  # fmt: skip

    # Each scan's tools, as the real CLI names them in its tool status (the release checks they all reported).
    TOOLS: ClassVar[dict[str, tuple[str, ...]]] = {
        "secrets": ("gitleaks",), "sast": ("opengrep",), "iac": ("trivy",), "pipelines": ("zizmor",),
        "sca": ("syft", "grype"),
    }  # fmt: skip

    def scan(self, call: Call) -> Any:
        name = Path(call.option("--out")).stem
        target = Path(call.args[5])
        self.scanned[name] = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
        failed = name == self.failing_scan
        status = {"status": "failed", "detail": "exit 3"} if failed else {"status": "ok"}
        tools = {tool: {"version": "1.0.0", **status} for tool in self.TOOLS[name]}
        Path(call.option("--tool-status-out")).write_text(json.dumps({"tools": tools}))
        if failed:
            return done(returncode=3)
        Path(call.option("--out")).write_text("")
        return done()

    def combine(self, call: Call) -> Any:
        """Merges the tool statuses that exist, as the real one does (a missing one is skipped)."""
        tools: dict[str, Any] = {}
        for path in [call.args[i + 1] for i, arg in enumerate(call.args) if arg == "--tool-status"]:
            if Path(path).is_file():
                tools |= json.loads(Path(path).read_text())["tools"]
        Path(call.option("--out")).write_text("")
        Path(call.option("--tool-status-out")).write_text(json.dumps({"tools": tools}))
        return done()

    def opa(self, call: Call) -> Any:
        Path(call.option("--report")).write_text(json.dumps({"tools": {"opa": {"version": "1.10.1"}}}))
        return done()

    def score(self, call: Call) -> Any:
        Path(call.option("--out")).write_text(Path(call.option("--findings")).read_text())
        return done()

    def evaluate(self, call: Call) -> Any:
        rules = {
            "BLOCK": [{"rule": "SC-001", "effect": "BLOCK"}],
            "WARN": [{"rule": "SC-006", "effect": "WARN"}],
        }
        subject = {"commit": self.decided_commit or call.option("--commit"), "context": "release"}
        if self.image_digest:
            subject["image_digest"] = self.image_digest
        decision = {"verdict": self.verdict, "subject": subject, "violations": rules.get(self.verdict, [])}
        Path(call.option("--output")).write_text(json.dumps(decision))
        return done(returncode=1 if self.verdict == "BLOCK" else 0)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo", OWN)


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").strip()


def self_gate(repo: Path, tmp_path: Path, recorder: Recorder, **changes: Any) -> Any:
    """The self-gate from this checkout; HEAD is named as the pipeline unless `pipeline` says otherwise."""
    settings = release.Settings(root=repo, tools_dir=tmp_path / "tools", grype_db=tmp_path / "grype-db")
    options: dict[str, Any] = {
        "out": repo / "out" / "self-gate", "settings": settings, "fetch": False, "run": recorder,
        "environ": {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, "pipeline": head(repo),
    }  # fmt: skip
    return release.SelfGate(**(options | changes))


def advance_main(repo: Path, files: dict[str, str]) -> str:
    """origin's main moves on by one commit holding `files`; the checkout stays at the pipeline commit."""
    pipeline = head(repo)
    commit(repo, files)
    target = head(repo)
    git(repo, "update-ref", "refs/remotes/origin/main", target)
    git(repo, "checkout", "--quiet", "--detach", pipeline)
    return target


def test_the_commits_own_tree_without_demo_shop_is_scanned_by_the_five_scanners(
    repo: Path, tmp_path: Path
) -> None:
    recorder = Recorder(repo)
    cli = FakeCli(recorder)
    assert self_gate(repo, tmp_path, recorder)() == release.EXIT_RELEASED
    assert set(cli.scanned) == set(release.SELF_SCANS)
    for files in cli.scanned.values():
        assert set(OWN) | {".gitignore"} == files, "the commit's files, demo-shop/ left out"
    commit = head(repo)
    for name in release.SELF_SCANS:
        (call,) = recorder.named(f"sentinel scan {name} ")
        assert call.option("--commit") == commit and call.option("--context") == "release"
        assert call.option("--ref") == "refs/heads/main" and call.option("--repo-root") == call.args[5]
    assert recorder.named("sentinel scan secrets")[0].option("--mode") == "dir"
    assert recorder.named("sentinel scan sca")[0].option("--db-dir") == str(tmp_path / "grype-db")


def test_the_decision_is_about_the_commit_with_its_own_waivers_and_no_image(
    repo: Path, tmp_path: Path
) -> None:
    recorder = Recorder(repo)
    FakeCli(recorder, verdict="WARN")
    gate = self_gate(repo, tmp_path, recorder)
    assert gate() == release.EXIT_RELEASED
    (evaluate,) = recorder.named("sentinel evaluate")
    waivers = Path(evaluate.option("--waivers"))
    assert waivers == gate.out / "work" / "evidence" / "self-gate-waivers.yaml", "kept with the evidence"
    assert "--vex" not in evaluate.args
    assert "--image-digest" not in evaluate.args and "--sbom" not in evaluate.args
    assert (gate.out / "evidence" / "decision.v1.json").is_file(), "the decision is kept with its evidence"


def test_the_waivers_come_from_the_pipeline_commit_not_the_working_tree(repo: Path, tmp_path: Path) -> None:
    git(repo, "rm", "--quiet", ".sentinel/self-gate-waivers.yaml")
    commit(repo, {})
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    (repo / ".sentinel").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text(".sentinel/\n")  # an ignored local file: still not read
    (repo / ".sentinel" / "self-gate-waivers.yaml").write_text("version: 1\nwaivers:\n  - id: local\n")
    recorder = Recorder(repo)
    FakeCli(recorder)
    gate = self_gate(repo, tmp_path, recorder)
    assert gate() == release.EXIT_RELEASED
    named = Path(recorder.named("sentinel evaluate")[0].option("--waivers"))
    kept = gate.out / "evidence" / named.name
    assert kept.read_text() == "version: 1\nwaivers: []\n", "none in the commit: an empty file, named"


def test_main_is_judged_by_the_pipeline_commit_not_by_itself(repo: Path, tmp_path: Path, capsys: Any) -> None:
    """#95 review, should-fix 1: a commit that adds a token and its waiver together cannot pick the gate that
    judges it. The target's files are scanned; the pipeline commit's waivers decide."""
    pipeline = head(repo)
    target = advance_main(repo, {
        "cli/src/sentinelci/planted.py": "TOKEN = 'not a real token'\n",
        ".sentinel/self-gate-waivers.yaml": "version: 1\nwaivers:\n  - id: added-with-the-token\n",
        "policies/gate.rego": "package sentinel.gate\n",
    })  # fmt: skip
    recorder = Recorder(repo)
    cli = FakeCli(recorder)
    gate = self_gate(repo, tmp_path, recorder, pipeline=pipeline)
    assert gate() == release.EXIT_RELEASED
    assert "cli/src/sentinelci/planted.py" in cli.scanned["secrets"], "the target's files are scanned"
    (evaluate,) = recorder.named("sentinel evaluate")
    assert evaluate.option("--commit") == target
    kept = gate.out / "evidence" / Path(evaluate.option("--waivers")).name
    assert kept.read_text() == OWN[".sentinel/self-gate-waivers.yaml"], "the pipeline's, not the target's"
    assert evaluate.option("--policy-dir") == str(repo / "policies"), "the pipeline checkout's policies"
    kept = json.loads((gate.out / "evidence" / "pipeline.json").read_text())
    assert kept == {
        "pipeline_commit": pipeline, "target_commit": target, "target_is_its_own_pipeline": False,
        "pipeline_files_changed": [".sentinel/self-gate-waivers.yaml", "cli/src/sentinelci/planted.py",
                                   "policies/gate.rego"],
    }  # fmt: skip
    printed = capsys.readouterr().out
    assert f"judged by the pipeline at {pipeline}" in printed and "3 pipeline file(s) changed" in printed


def test_a_release_tag_is_a_pipeline_without_naming_it(repo: Path, tmp_path: Path) -> None:
    git(repo, "tag", "v0.9.0")
    recorder = Recorder(repo)
    FakeCli(recorder)
    assert self_gate(repo, tmp_path, recorder, pipeline=None)() == release.EXIT_RELEASED


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (lambda repo: None, "no release tag (vX.Y.Z)"),
        (lambda repo: git(repo, "tag", "release-candidate"), "no release tag (vX.Y.Z)"),
        (lambda repo: git(repo, "tag", "v1.0"), "no release tag (vX.Y.Z)"),
    ],
)  # fmt: skip
def test_a_pipeline_that_is_no_release_tag_must_be_named(
    repo: Path, tmp_path: Path, setup: Any, message: str
) -> None:
    setup(repo)
    recorder = Recorder(repo)
    FakeCli(recorder)
    with pytest.raises(release.ReleaseError, match=re.escape(message)):
        self_gate(repo, tmp_path, recorder, pipeline=None)()
    assert not recorder.named("sentinel")


def test_the_named_pipeline_must_be_head(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeCli(recorder)
    with pytest.raises(release.ReleaseError, match="is not HEAD"):
        self_gate(repo, tmp_path, recorder, pipeline="f" * 40)()


def test_a_pipeline_that_is_not_on_main_is_refused(repo: Path, tmp_path: Path) -> None:
    git(repo, "checkout", "--quiet", "-b", "unreviewed")
    commit(repo, {"policies/gate.rego": "package sentinel.gate\ndecision := {}\n"})
    recorder = Recorder(repo)
    FakeCli(recorder)
    with pytest.raises(release.ReleaseError, match="is not on origin/main"):
        self_gate(repo, tmp_path, recorder)()
    assert not recorder.named("sentinel")


def test_the_pipelines_vex_is_named_and_demo_shops_never_read(repo: Path, tmp_path: Path) -> None:
    vex = '{"statements": []}\n'
    commit(repo, {".sentinel/self-gate-vex.json": vex})
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    recorder = Recorder(repo)
    FakeCli(recorder)
    gate = self_gate(repo, tmp_path, recorder)
    assert gate() == release.EXIT_RELEASED
    named = Path(recorder.named("sentinel evaluate")[0].option("--vex"))
    assert (gate.out / "evidence" / named.name).read_text() == vex
    git(repo, "rm", "--quiet", ".sentinel/self-gate-vex.json")
    commit(repo, {".sentinel/vex.json": vex})
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    recorder = Recorder(repo)
    FakeCli(recorder)
    with pytest.raises(release.ReleaseError, match="would be read by default"):
        self_gate(repo, tmp_path, recorder)()


def test_a_decision_about_an_image_is_refused(repo: Path, tmp_path: Path) -> None:
    """#95 review, nit 3: the self-gate decides about a commit, never about an image."""
    recorder = Recorder(repo)
    cli = FakeCli(recorder)
    cli.image_digest = "sha256:" + "a" * 64
    with pytest.raises(release.ReleaseError, match="the decision is not about"):
        self_gate(repo, tmp_path, recorder)()


def test_a_block_is_exit_1_and_its_evidence_is_kept(repo: Path, tmp_path: Path, capsys: Any) -> None:
    recorder = Recorder(repo)
    FakeCli(recorder, verdict="BLOCK")
    gate = self_gate(repo, tmp_path, recorder)
    assert gate() == release.EXIT_BLOCKED
    assert (gate.out / "evidence" / "decision.v1.json").is_file()
    printed = capsys.readouterr().out
    assert "the gate says BLOCK" in printed and "SC-001 (BLOCK)" in printed


def test_a_failed_scan_is_left_to_the_gate_with_an_empty_findings_file(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    cli = FakeCli(recorder)
    cli.failing_scan = "sca"
    gate = self_gate(repo, tmp_path, recorder)
    gate()
    assert (gate.out / "work" / "scans" / "sca.ndjson").read_text() == "", "its status says why (SC-010)"
    assert "--findings" in recorder.named("sentinel scan combine")[0].args


def test_a_decision_about_another_commit_is_refused(repo: Path, tmp_path: Path) -> None:
    recorder = Recorder(repo)
    FakeCli(recorder).decided_commit = "f" * 40
    with pytest.raises(release.ReleaseError, match="the decision is not about"):
        self_gate(repo, tmp_path, recorder)()


def test_a_dirty_tree_or_a_commit_not_on_main_is_refused_before_anything_runs(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "cli" / "src" / "sentinelci" / "__init__.py").write_text("changed\n")
    recorder = Recorder(repo)
    FakeCli(recorder)
    with pytest.raises(release.ReleaseError, match="not clean"):
        self_gate(repo, tmp_path, recorder)()
    assert not recorder.named("sentinel")


# ---------------------------------------------------------------- the exported tree


def export(repo: Path, tmp_path: Path) -> list[str]:
    files: list[str] = release.export_tree(head(repo), tmp_path / "source", Recorder(repo))
    return files


def commit(repo: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", "change")


def test_the_export_is_the_commits_blobs(repo: Path, tmp_path: Path) -> None:
    files = export(repo, tmp_path)
    assert files == sorted(set(OWN) | {".gitignore"})
    for name in files:
        assert (tmp_path / "source" / name).read_bytes() == git(repo, "show", f"HEAD:{name}").encode()


@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        ("uv.lock export-ignore\n", "did not give exactly the commit's files: uv.lock"),
        ("cli/src/sentinelci/__init__.py export-subst\n", "is not the commit's blob"),
    ],
)
def test_an_export_attribute_cannot_hide_or_rewrite_what_is_scanned(
    repo: Path, tmp_path: Path, attributes: str, message: str
) -> None:
    commit(
        repo, {".gitattributes": attributes, "cli/src/sentinelci/__init__.py": "VERSION = '$Format:%H$'\n"}
    )
    with pytest.raises(release.ReleaseError, match=message):
        export(repo, tmp_path)


def test_a_link_is_refused(repo: Path, tmp_path: Path) -> None:
    (repo / "outside").symlink_to("/etc/passwd")
    git(repo, "add", "outside")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", "link")
    with pytest.raises(release.ReleaseError, match="outside is a link"):
        export(repo, tmp_path)


def test_main_runs_the_self_gate_into_out_self_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(release.SelfGate, "__call__", lambda gate: seen.append(gate) or 0)
    assert release.main(["self-gate", "--no-fetch"]) == 0
    (gate,) = seen
    assert gate.out == release.ROOT / "out" / "self-gate" and gate.fetch is False and gate.pipeline is None
    assert release.main(["self-gate", "--no-fetch", "--pipeline", "a" * 40]) == 0
    assert seen[1].pipeline == "a" * 40
