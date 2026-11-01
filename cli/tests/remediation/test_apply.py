"""`sentinel remediate apply` (task A6, SPEC section 9): a proposal becomes one commit on a new branch of a
local clone, and nothing else happens. Real git, a throwaway repository per test."""

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.apply import BOT_EMAIL, apply_proposal, default_branch
from sentinelci.remediation.kubernetes import propose
from sentinelci.remediation.proposal import RemediationError, unified_diff

from .conftest import NOW, SEED, SEED_PATH, seed_findings


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "clone"
    (repo / SEED_PATH).parent.mkdir(parents=True)
    (repo / SEED_PATH).write_text(SEED.read_text())
    (repo / "README.md").write_text("demo\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "seed")
    return repo


@pytest.fixture
def proposal(repo: Path) -> PatchProposal:
    plan = propose(seed_findings(), repo, created_at=NOW)
    assert plan.proposal is not None
    return plan.proposal


def test_the_proposal_becomes_one_commit_on_a_new_branch_and_nothing_else_changes(
    repo: Path, proposal: PatchProposal
) -> None:
    head, status = git(repo, "rev-parse", "HEAD"), git(repo, "status", "--porcelain")
    applied = apply_proposal(proposal, repo)
    assert applied.branch == default_branch(proposal) and applied.branch.startswith("sentinel/fix/")
    assert applied.base == head and git(repo, "rev-parse", applied.branch) == applied.commit
    assert git(repo, "rev-parse", "HEAD") == head and git(repo, "status", "--porcelain") == status
    assert git(repo, "branch", "--show-current") == "main", "the current branch is never changed"
    assert git(repo, "rev-parse", f"{applied.commit}^") == head, "one commit on the base"
    assert git(repo, "diff", "--name-only", head, applied.commit).splitlines() == [SEED_PATH]
    check = repo.parent / "check"
    (check / SEED_PATH).parent.mkdir(parents=True)
    (check / SEED_PATH).write_text(SEED.read_text())
    subprocess.run(["git", "apply", "-"], input=proposal.diff, text=True, cwd=check, check=True)
    patched = git(repo, "show", f"{applied.commit}:{SEED_PATH}") + "\n"
    assert patched == (check / SEED_PATH).read_text(), "the commit is exactly the proposal's diff"
    still = subprocess.run(["git", "apply", "--check", "-"], input=proposal.diff, text=True, cwd=repo)
    assert still.returncode == 0, "the clone itself was not touched, so the diff still applies to it"
    message = git(repo, "log", "-1", "--format=%B", applied.commit)
    assert f"Sentinel-Proposal: {proposal.proposal_id}" in message
    assert all(f"Sentinel-Finding: {finding}" in message for finding in proposal.finding_ids)
    assert git(repo, "log", "-1", "--format=%ae %ce", applied.commit) == f"{BOT_EMAIL} {BOT_EMAIL}"
    assert git(repo, "worktree", "list").count("\n") == 0, "the scratch worktree is gone"


def test_a_proposal_is_applied_once(repo: Path, proposal: PatchProposal) -> None:
    apply_proposal(proposal, repo)
    with pytest.raises(RemediationError, match="already exists: a proposal is applied once"):
        apply_proposal(proposal, repo)


@pytest.mark.parametrize(
    "branch", ["main", "fix/x", "sentinel/fix/", "sentinel/fix/../main", "sentinel/fix/X"]
)
def test_only_a_new_sentinel_fix_branch(repo: Path, proposal: PatchProposal, branch: str) -> None:
    with pytest.raises(RemediationError, match="is not a new sentinel/fix/"):
        apply_proposal(proposal, repo, branch=branch)
    assert git(repo, "branch", "--list").strip() == "* main"


def _with_diff(proposal: PatchProposal, diff: str, files: list[str] | None = None) -> PatchProposal:
    return proposal.model_copy(update={"diff": diff, "files": files or proposal.files})


def test_a_diff_that_changes_an_unlisted_file_is_refused(repo: Path, proposal: PatchProposal) -> None:
    extra = unified_diff("README.md", "demo\n", "demo, patched\n")
    with pytest.raises(RemediationError, match="the proposal lists"):
        apply_proposal(_with_diff(proposal, proposal.diff + extra), repo)


@pytest.mark.parametrize(
    ("diff", "files"),
    [
        ("diff --git a/new.sh b/new.sh\nnew file mode 100755\n--- /dev/null\n+++ b/new.sh\n"
         "@@ -0,0 +1 @@\n+echo pwned\n", ["new.sh"]),
        ("diff --git a/README.md b/README.md\ndeleted file mode 100644\n--- a/README.md\n+++ /dev/null\n"
         "@@ -1 +0,0 @@\n-demo\n", ["README.md"]),
        ("diff --git a/README.md b/README.md\nold mode 100644\nnew mode 100755\n", ["README.md"]),
        ("diff --git a/README.md b/docs/README.md\nsimilarity index 100%\nrename from README.md\n"
         "rename to docs/README.md\n", ["README.md"]),
    ],
    ids=["creates-a-file", "deletes-a-file", "makes-a-file-executable", "renames-a-file"],
)  # fmt: skip
def test_a_diff_that_does_more_than_edit_in_place_is_refused(
    repo: Path, proposal: PatchProposal, diff: str, files: list[str]
) -> None:
    with pytest.raises(RemediationError, match=r"more than edit files in place|the proposal lists"):
        apply_proposal(_with_diff(proposal, diff, files), repo)
    assert git(repo, "branch", "--list").strip() == "* main"


def test_a_stale_proposal_does_not_apply(repo: Path, proposal: PatchProposal) -> None:
    (repo / SEED_PATH).write_text((repo / SEED_PATH).read_text().replace("shop-api", "shop-api-v2"))
    git(repo, "commit", "-qam", "moved on")
    with pytest.raises(RemediationError, match="does not apply to the base"):
        apply_proposal(proposal, repo)
    assert apply_proposal(proposal, repo, base="HEAD~1").base == git(repo, "rev-parse", "HEAD~1")


def test_a_symbolic_link_is_never_retargeted(repo: Path, proposal: PatchProposal) -> None:
    """git applies a symlink's new target as an in-place edit, with an empty summary: only the file mode at
    the base tells it apart from a regular file."""
    (repo / "link.yaml").symlink_to(SEED_PATH)
    git(repo, "add", "link.yaml")
    git(repo, "commit", "-qm", "link")
    (repo / "link.yaml").unlink()
    (repo / "link.yaml").symlink_to("/etc/passwd")
    retarget = git(repo, "diff") + "\n"
    git(repo, "checkout", "-q", "--", "link.yaml")
    with pytest.raises(
        RemediationError, match=r"link\.yaml is not a regular file tracked at the base commit"
    ):
        apply_proposal(_with_diff(proposal, retarget, ["link.yaml"]), repo)


def test_a_listed_file_the_diff_leaves_alone_is_refused(repo: Path, proposal: PatchProposal) -> None:
    with pytest.raises(RemediationError, match="the proposal lists"):
        apply_proposal(_with_diff(proposal, proposal.diff, [*proposal.files, "README.md"]), repo)


def test_the_repositorys_hooks_never_run(repo: Path, proposal: PatchProposal) -> None:
    marker = repo.parent / "hook-ran"
    for name in ("pre-commit", "commit-msg", "post-commit", "post-checkout", "reference-transaction"):
        hook = repo / ".git" / "hooks" / name
        hook.write_text(f"#!/bin/sh\necho {name} >> {marker}\n")
        hook.chmod(0o755)
    apply_proposal(proposal, repo)
    assert not marker.exists(), marker.read_text() if marker.exists() else ""


@pytest.mark.parametrize("base", ["no-such-ref", "--output=/tmp/x"])
def test_a_base_that_is_not_a_commit_is_refused(repo: Path, proposal: PatchProposal, base: str) -> None:
    with pytest.raises(RemediationError, match="is not a commit"):
        apply_proposal(proposal, repo, base=base)


def test_cli_prints_the_branch_and_refuses_a_bad_proposal(
    repo: Path, proposal: PatchProposal, tmp_path: Path
) -> None:
    path = tmp_path / "proposal.json"
    path.write_text(proposal.model_dump_json(exclude_none=True))
    result = CliRunner().invoke(
        app, ["remediate", "apply", "--proposal", str(path), "--repo-root", str(repo)]
    )
    assert result.exit_code == 0, result.output
    printed = json.loads(result.output)
    assert (
        printed["branch"] == default_branch(proposal)
        and git(repo, "rev-parse", printed["branch"]) == printed["commit"]
    )
    path.write_text("{}")
    result = CliRunner().invoke(
        app, ["remediate", "apply", "--proposal", str(path), "--repo-root", str(repo)]
    )
    assert result.exit_code == 3 and "nothing was committed" in result.output
