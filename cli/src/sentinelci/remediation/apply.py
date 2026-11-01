"""Make a patch proposal a commit on its own branch (task A6, SPEC section 9), never more.

The remediation bot proposes; this step turns the proposal into one commit on a new `sentinel/fix/...` branch
of a local clone. It never pushes, never touches the working tree or the current branch, and never runs the
repository's hooks: the bot's workflow pushes the branch and opens the pull request, the pull request is
scanned like any change, and `sentinel remediate verify` decides.

What the diff may do is checked against the proposal before anything is written: it changes exactly the
files the proposal lists, each a regular file tracked at the base commit, with no file created, deleted,
renamed or made executable, and it applies cleanly to that base.
"""

import os
import re
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.proposal import RemediationError

BRANCH_PREFIX = "sentinel/fix/"
BOT_NAME = "SentinelCI bot"
BOT_EMAIL = "bot@sentinelci.invalid"
_BRANCH = re.compile(r"sentinel/fix/[a-z0-9][a-z0-9._-]{0,63}")
_REGULAR_FILE_MODES = frozenset({"100644", "100755"})
# The repository's own configuration must not change what git does here: no hooks, no signing prompt, no
# filters or attributes from the user's or system configuration.
_GIT = ("git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false")


@dataclass(frozen=True)
class Applied:
    branch: str
    commit: str
    base: str


def _git(
    repo: Path, *args: str, stdin: str | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",  # no user configuration, and none from the repository either
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": BOT_NAME, "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME, "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        "LC_ALL": "C",
    }  # fmt: skip
    completed = subprocess.run(  # noqa: S603 (git, an argument list, no shell)
        [*_GIT, "-C", str(repo), *args], input=stdin, capture_output=True, text=True, env=env, check=False
    )
    if check and completed.returncode != 0:
        raise RemediationError(
            f"git {args[0]} failed: {completed.stderr.strip()[-300:] or 'no reason given'}"
        )
    return completed


def default_branch(proposal: PatchProposal) -> str:
    return BRANCH_PREFIX + proposal.proposal_id.replace("-", "")[:12]


def _commit_message(proposal: PatchProposal) -> str:
    rationale = "\n".join(textwrap.wrap(" ".join(proposal.rationale.split()), width=72))
    trailers = [f"Sentinel-Proposal: {proposal.proposal_id}", f"Sentinel-Strategy: {proposal.strategy}"]
    trailers += [f"Sentinel-Finding: {finding}" for finding in proposal.finding_ids]
    subject = f"fix(security): {proposal.strategy} proposal, attempt {proposal.attempt}"
    return f"{subject}\n\n{rationale}\n\n" + "\n".join(trailers) + "\n"


def _check_diff(worktree: Path, proposal: PatchProposal) -> None:
    """The diff changes exactly the proposal's files, in place, and applies to the base."""
    checked = _git(
        worktree, "apply", "--check", "--numstat", "--summary", "-", stdin=proposal.diff, check=False
    )
    if checked.returncode != 0:
        raise RemediationError(f"the diff does not apply to the base: {checked.stderr.strip()[-300:]}")
    touched, summary = set(), []
    for line in checked.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            touched.add(parts[2])
        elif line.strip():
            summary.append(line.strip())
    if summary:  # creates, deletes, renames, copies, mode changes
        raise RemediationError(f"the diff does more than edit files in place: {summary[0]}")
    if touched != set(proposal.files):
        raise RemediationError(
            f"the diff changes {sorted(touched)}, the proposal lists {sorted(proposal.files)}"
        )
    for path in sorted(touched):
        listed = _git(worktree, "ls-files", "--stage", "--", path).stdout.split()
        if not listed or listed[0] not in _REGULAR_FILE_MODES:
            raise RemediationError(f"{path} is not a regular file tracked at the base commit")


def apply_proposal(
    proposal: PatchProposal, repo: Path, *, base: str = "HEAD", branch: str | None = None
) -> Applied:
    """Commit `proposal` on a new branch from `base`; the clone's working tree and HEAD stay as they are."""
    name = branch or default_branch(proposal)
    if (
        _BRANCH.fullmatch(name) is None
        or _git(repo, "check-ref-format", f"refs/heads/{name}", check=False).returncode
    ):
        raise RemediationError(f"branch {name!r} is not a new {BRANCH_PREFIX}<name> branch")
    if _git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{name}", check=False).returncode == 0:
        raise RemediationError(f"branch {name} already exists: a proposal is applied once")
    resolved = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}", check=False)
    if resolved.returncode != 0:
        raise RemediationError(f"{base!r} is not a commit of {repo}")
    base_commit = resolved.stdout.strip()
    with tempfile.TemporaryDirectory(prefix="sentinel-apply-") as scratch:
        worktree = Path(scratch) / "worktree"
        _git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), base_commit)
        try:
            _check_diff(worktree, proposal)
            _git(worktree, "apply", "--index", "-", stdin=proposal.diff)
            _git(worktree, "commit", "--quiet", "--no-verify", "--file", "-", stdin=_commit_message(proposal))
            commit = _git(worktree, "rev-parse", "HEAD").stdout.strip()
        finally:
            _git(repo, "worktree", "remove", "--force", str(worktree), check=False)
            _git(repo, "worktree", "prune", check=False)
    _git(repo, "branch", "--no-track", name, commit)
    return Applied(branch=name, commit=commit, base=base_commit)
