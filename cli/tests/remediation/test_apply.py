"""`sentinel remediate apply` (task A6, SPEC section 9): a proposal becomes one commit on a new branch of a
local clone, and nothing else happens. Real git, a throwaway repository per test."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.remediation.apply import BOT_EMAIL, apply_proposal, default_branch, diff_sha256
from sentinelci.remediation.kubernetes import propose
from sentinelci.remediation.proposal import RemediationError, proposal_id_of, unified_diff

from .conftest import NOW, SEED, SEED_PATH, iac_finding, seed_findings

# The base scan the proposals are made from, plus findings in the files the hostile diffs below touch, so that
# those diffs reach the checks they are about.
FINDINGS = [
    *seed_findings(),
    *(iac_finding("KSV-0014", path) for path in ("README.md", "new.sh", "link.yaml", "docs/README.md")),
]


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
    applied = apply_proposal(proposal, repo, findings=FINDINGS)
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
    apply_proposal(proposal, repo, findings=FINDINGS)
    with pytest.raises(RemediationError, match="already exists: a proposal is applied once"):
        apply_proposal(proposal, repo, findings=FINDINGS)


@pytest.mark.parametrize(
    "branch", ["main", "fix/x", "sentinel/fix/", "sentinel/fix/../main", "sentinel/fix/X"]
)
def test_only_a_new_sentinel_fix_branch(repo: Path, proposal: PatchProposal, branch: str) -> None:
    with pytest.raises(RemediationError, match="is not a new sentinel/fix/"):
        apply_proposal(proposal, repo, findings=FINDINGS, branch=branch)
    assert git(repo, "branch", "--list").strip() == "* main"


def _with_diff(
    proposal: PatchProposal, diff: str, files: list[str] | None = None, findings: list[str] | None = None
) -> PatchProposal:
    """Another diff in a well-formed proposal: its id matches its content, as a hostile one's would."""
    ids = findings or sorted(f.id for f in FINDINGS)
    identity = proposal_id_of(proposal.strategy, proposal.attempt, ids, diff)
    return proposal.model_copy(
        update={"diff": diff, "files": files or proposal.files, "finding_ids": ids, "proposal_id": identity}
    )


def test_a_diff_that_changes_an_unlisted_file_is_refused(repo: Path, proposal: PatchProposal) -> None:
    extra = unified_diff("README.md", "demo\n", "demo, patched\n")
    with pytest.raises(RemediationError, match="the proposal lists"):
        apply_proposal(_with_diff(proposal, proposal.diff + extra), repo, findings=FINDINGS)


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
    with pytest.raises(RemediationError, match=r"more than edit|renames or copies|the proposal lists"):
        apply_proposal(_with_diff(proposal, diff, files), repo, findings=FINDINGS)
    assert git(repo, "branch", "--list").strip() == "* main"


def test_a_stale_proposal_does_not_apply(repo: Path, proposal: PatchProposal) -> None:
    (repo / SEED_PATH).write_text((repo / SEED_PATH).read_text().replace("shop-api", "shop-api-v2"))
    git(repo, "commit", "-qam", "moved on")
    with pytest.raises(RemediationError, match="does not apply to the base"):
        apply_proposal(proposal, repo, findings=FINDINGS)
    assert apply_proposal(proposal, repo, findings=FINDINGS, base="HEAD~1").base == git(
        repo, "rev-parse", "HEAD~1"
    )


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
        apply_proposal(_with_diff(proposal, retarget, ["link.yaml"]), repo, findings=FINDINGS)


def test_a_listed_file_the_diff_leaves_alone_is_refused(repo: Path, proposal: PatchProposal) -> None:
    with pytest.raises(RemediationError, match="the proposal lists"):
        apply_proposal(
            _with_diff(proposal, proposal.diff, [*proposal.files, "README.md"]), repo, findings=FINDINGS
        )


def test_the_repositorys_hooks_never_run(repo: Path, proposal: PatchProposal) -> None:
    marker = repo.parent / "hook-ran"
    for name in ("pre-commit", "commit-msg", "post-commit", "post-checkout", "reference-transaction"):
        hook = repo / ".git" / "hooks" / name
        hook.write_text(f"#!/bin/sh\necho {name} >> {marker}\n")
        hook.chmod(0o755)
    apply_proposal(proposal, repo, findings=FINDINGS)
    assert not marker.exists(), marker.read_text() if marker.exists() else ""


@pytest.mark.parametrize("base", ["no-such-ref", "--output=/tmp/x"])
def test_a_base_that_is_not_a_commit_is_refused(repo: Path, proposal: PatchProposal, base: str) -> None:
    with pytest.raises(RemediationError, match="is not a commit"):
        apply_proposal(proposal, repo, findings=FINDINGS, base=base)


def test_cli_prints_the_branch_and_refuses_a_bad_proposal(
    repo: Path, proposal: PatchProposal, tmp_path: Path
) -> None:
    path, findings = tmp_path / "proposal.json", tmp_path / "base.ndjson"
    path.write_text(proposal.model_dump_json(exclude_none=True))
    findings.write_text(dumps_ndjson(FINDINGS))
    args = [
        "remediate",
        "apply",
        "--proposal",
        str(path),
        "--findings",
        str(findings),
        "--repo-root",
        str(repo),
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    printed = json.loads(result.output)
    assert (
        printed["branch"] == default_branch(proposal)
        and git(repo, "rev-parse", printed["branch"]) == printed["commit"]
        and printed["diff_sha256"] == diff_sha256(proposal)
    )
    path.write_text("{}")
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 3 and "nothing was committed" in result.output
    path.write_text(proposal.model_dump_json(exclude_none=True))
    findings.write_text("not json\n")
    result = CliRunner().invoke(app, [*args[:-2], "--repo-root", str(repo), "--branch", "sentinel/fix/other"])
    assert result.exit_code == 3 and "nothing was committed" in result.output


def test_a_proposal_whose_id_does_not_match_its_content_is_refused(
    repo: Path, proposal: PatchProposal
) -> None:
    """#48 review, should fix 1: the id is in the branch name and the trailers: it must identify the diff."""
    swapped = proposal.model_copy(update={"diff": proposal.diff.replace("true", "false")})
    with pytest.raises(RemediationError, match="id does not match"):
        apply_proposal(swapped, repo, findings=FINDINGS)
    assert git(repo, "branch", "--list").strip() == "* main"


def test_a_finding_the_base_scan_does_not_have_is_refused(repo: Path, proposal: PatchProposal) -> None:
    with pytest.raises(RemediationError, match="claims findings the base scan does not have"):
        apply_proposal(proposal, repo, findings=FINDINGS[1:])


def test_a_file_none_of_the_claimed_findings_is_in_is_refused(repo: Path, proposal: PatchProposal) -> None:
    """#48 review, should fix 1: the seed's findings, and a diff that widens a workflow's permissions."""
    workflow = ".github/workflows/ci.yml"
    (repo / workflow).parent.mkdir(parents=True)
    (repo / workflow).write_text("on: push\npermissions: {}\n")
    git(repo, "add", workflow)
    git(repo, "commit", "-qm", "ci")
    diff = unified_diff(workflow, "on: push\npermissions: {}\n", "on: push\npermissions: write-all\n")
    hostile = _with_diff(proposal, diff, [workflow], findings=proposal.finding_ids)
    with pytest.raises(RemediationError, match=f"changes {workflow}, where none of its findings was found"):
        apply_proposal(hostile, repo, findings=FINDINGS)
    assert git(repo, "branch", "--list").strip() == "* main"


def test_the_commit_names_its_diff_and_is_the_same_on_every_run(
    repo: Path, proposal: PatchProposal, tmp_path: Path
) -> None:
    """#48 review, should fix 1 and nit 2: the Sentinel-Diff trailer, and dates from the proposal."""
    other = tmp_path / "other-clone"
    subprocess.run(["git", "clone", "-q", str(repo), str(other)], check=True)
    first = apply_proposal(proposal, repo, findings=FINDINGS)
    second = apply_proposal(proposal, other, findings=FINDINGS)
    assert first.commit == second.commit and first.diff_sha256 == diff_sha256(proposal)
    assert f"Sentinel-Diff: {first.diff_sha256}" in git(repo, "log", "-1", "--format=%B", first.commit)
    created = int(NOW.timestamp())
    assert git(repo, "log", "-1", "--format=%at %ct", first.commit) == f"{created} {created}"


def test_the_callers_git_environment_is_not_used(
    repo: Path, proposal: PatchProposal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("GIT_DIR", str(elsewhere))
    monkeypatch.setenv("GIT_INDEX_FILE", str(elsewhere / "index"))
    applied = apply_proposal(proposal, repo, findings=FINDINGS)
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_INDEX_FILE")
    assert git(repo, "rev-parse", applied.branch) == applied.commit


@pytest.mark.parametrize("plant", ["fsmonitor", "fsmonitor-included", "filter", "filter-info-attributes"])
def test_configuration_of_the_clone_that_runs_code_never_runs(
    repo: Path, proposal: PatchProposal, plant: str
) -> None:
    """#48 review, blocking 1: core.fsmonitor and filter drivers in the clone's .git/config ran on the
    checkout of a scratch worktree. Nothing is checked out now."""
    marker = repo.parent / "ran"
    script = repo.parent / "planted.sh"
    script.write_text(f"#!/bin/sh\necho ran >> {marker}\ncat\n")
    script.chmod(0o755)
    config = repo / ".git" / "config"
    if plant == "fsmonitor":
        git(repo, "config", "core.fsmonitor", str(script))
    elif plant == "fsmonitor-included":
        included = repo.parent / "included.cfg"
        included.write_text(f"[core]\n\tfsmonitor = {script}\n")
        git(repo, "config", "include.path", str(included))
    else:
        git(repo, "config", "filter.x.smudge", str(script))
        git(repo, "config", "filter.x.clean", str(script))
        if plant == "filter":
            (repo / ".gitattributes").write_text("*.yaml filter=x\n")
            git(repo, "-c", "filter.x.clean=cat", "add", ".gitattributes")
            git(repo, "-c", "filter.x.clean=cat", "commit", "-qm", "attributes")
        else:
            (repo / ".git" / "info").mkdir(exist_ok=True)
            (repo / ".git" / "info" / "attributes").write_text("* filter=x\n")
    assert config.is_file()
    marker.unlink(missing_ok=True)  # only what apply runs counts
    applied = apply_proposal(proposal, repo, findings=FINDINGS)
    assert not marker.exists(), "the clone's configuration ran code during apply"
    assert git(repo, "-c", "core.fsmonitor=false", "rev-parse", applied.branch) == applied.commit


# Review of #48, round 2.


@pytest.mark.parametrize(
    "smuggled",
    [
        "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-demo\n+demo, patched\n",
        "--- /dev/null\n+++ b/new.sh\n@@ -0,0 +1 @@\n+echo pwned\n",
    ],
    ids=["edits-an-unlisted-file", "creates-a-file"],
)
def test_a_patch_without_a_git_header_after_the_last_hunk_is_refused(
    repo: Path, proposal: PatchProposal, smuggled: str
) -> None:
    """git apply reads a traditional ---/+++ pair after a hunk as one more file to change."""
    hostile = _with_diff(proposal, proposal.diff + smuggled)
    with pytest.raises(RemediationError, match=r"not a plain edit|the proposal lists|more than edit"):
        apply_proposal(hostile, repo, findings=FINDINGS)
    assert git(repo, "branch", "--list").strip() == "* main"


def test_a_branch_created_meanwhile_is_never_overwritten(
    repo: Path, proposal: PatchProposal, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.remediation.apply as apply_module

    real = apply_module._git

    def racing(where: Path, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[0] == "update-ref":  # someone else creates the branch after the existence check
            git(where, "branch", default_branch(proposal), "HEAD")
        return real(where, *args, **kwargs)

    monkeypatch.setattr(apply_module, "_git", racing)
    with pytest.raises(RemediationError, match="update-ref"):
        apply_proposal(proposal, repo, findings=FINDINGS)
    assert git(repo, "rev-parse", default_branch(proposal)) == git(repo, "rev-parse", "HEAD")


def test_the_clones_whitespace_settings_never_change_what_is_committed(
    repo: Path, proposal: PatchProposal
) -> None:
    """apply.whitespace=fix in the clone's own .git/config would strip trailing spaces from added lines, so
    the commit would not be base + diff although its Sentinel-Diff trailer names that diff."""
    git(repo, "config", "apply.whitespace", "fix")
    old = (repo / SEED_PATH).read_text()
    new = old.replace("\n", "  \n", 1)  # the first line gains two trailing spaces
    spaced = _with_diff(proposal, unified_diff(SEED_PATH, old, new), files=[SEED_PATH])
    applied = apply_proposal(spaced, repo, findings=FINDINGS)
    assert git(repo, "show", f"{applied.commit}:{SEED_PATH}").split("\n")[0].endswith("  ")
