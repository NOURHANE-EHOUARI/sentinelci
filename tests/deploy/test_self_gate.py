"""The self-gate (`release.py self-gate`, task A10): SentinelCI's release gate on its own tree."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests.deploy.release_support import Call, Recorder, done, git, make_repo, release

OWN = {
    "cli/src/sentinelci/__init__.py": "VERSION = '1.0.0'\n",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    ".sentinel/waivers.yaml": "version: 1\nwaivers: []\n",
    "uv.lock": "version = 1\n",
}


class FakeCli:
    """`sentinel` as the self-gate calls it, writing what it would; `verdict` is the gate's answer."""

    def __init__(self, recorder: Recorder, *, verdict: str = "PASS") -> None:
        self.verdict, self.failing_scan, self.decided_commit = verdict, "", ""
        self.scanned: dict[str, set[str]] = {}
        recorder.fakes.update({
            "sentinel tools grype-db": lambda call: done(),
            "sentinel scan combine": self.combine,
            "sentinel scan": self.scan,
            "sentinel tools verify opa": self.opa,
            "sentinel score": self.score,
            "sentinel evaluate": self.evaluate,
        })  # fmt: skip

    def scan(self, call: Call) -> Any:
        name = Path(call.option("--out")).stem
        target = Path(call.args[5])
        self.scanned[name] = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
        if name == self.failing_scan:
            return done(returncode=3)
        Path(call.option("--out")).write_text("")
        Path(call.option("--tool-status-out")).write_text(json.dumps({"tools": {name: {"version": "1.0.0"}}}))
        return done()

    def combine(self, call: Call) -> Any:
        Path(call.option("--out")).write_text("")
        Path(call.option("--tool-status-out")).write_text(
            json.dumps({"tools": {"gitleaks": {"version": "8"}}})
        )
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
        decision = {"verdict": self.verdict, "subject": subject, "violations": rules.get(self.verdict, [])}
        Path(call.option("--output")).write_text(json.dumps(decision))
        return done(returncode=1 if self.verdict == "BLOCK" else 0)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo", OWN)


def self_gate(repo: Path, tmp_path: Path, recorder: Recorder) -> Any:
    settings = release.Settings(root=repo, tools_dir=tmp_path / "tools", grype_db=tmp_path / "grype-db")
    return release.SelfGate(
        out=repo / "out" / "self-gate", settings=settings, fetch=False, run=recorder,
        environ={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )  # fmt: skip


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD").strip()


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
    assert evaluate.option("--waivers") == str(gate.out / "work" / "source" / ".sentinel" / "waivers.yaml")
    assert "--image-digest" not in evaluate.args and "--sbom" not in evaluate.args
    assert (gate.out / "evidence" / "decision.v1.json").is_file(), "the decision is kept with its evidence"


def test_the_waivers_come_from_the_commit_not_the_working_tree(repo: Path, tmp_path: Path) -> None:
    git(repo, "rm", "--quiet", ".sentinel/waivers.yaml")
    git(
        repo,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "no waivers",
    )
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    (repo / ".sentinel").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text(".sentinel/\n")  # an ignored local file: still not read
    (repo / ".sentinel" / "waivers.yaml").write_text("version: 1\nwaivers: []\n")
    recorder = Recorder(repo)
    FakeCli(recorder)
    assert self_gate(repo, tmp_path, recorder)() == release.EXIT_RELEASED
    assert "--waivers" not in recorder.named("sentinel evaluate")[0].args


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
    assert gate.out == release.ROOT / "out" / "self-gate" and gate.fetch is False
