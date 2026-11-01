"""Make a patch proposal a commit on its own branch (task A6, SPEC section 9), never more.

The remediation bot proposes; this step turns the proposal into one commit on a new `sentinel/fix/...` branch
of a local clone. It never pushes, never touches the working tree, the index or the current branch, and runs
no code the clone could configure: the bot's workflow pushes the branch and opens the pull request, the pull
request is scanned like any change, and `sentinel remediate verify` decides.

Nothing is checked out. The commit is built with plumbing commands on a temporary index (`read-tree`,
`apply --cached`, `write-tree`, `commit-tree`, `update-ref`), so no smudge or clean filter, no fsmonitor and
no hook can run, whatever the clone's `.git/config` or `.gitattributes` say. Git still reads the clone's own
configuration; what could run code there is overridden on the command line (`core.hooksPath`,
`core.fsmonitor`, `commit.gpgsign`), and the user's and system's configuration are not read at all.

Before anything is written, the proposal is checked against itself and against the base scan, with the
verification gate's own check (`gate.check_proposal`):
- its id is recomputed from its strategy, attempt, findings and diff, so the branch name and the
  `Sentinel-Proposal` trailer identify the content, and the `Sentinel-Diff` trailer holds the diff's sha256;
- every finding it claims is in the base findings, and every file it changes is where one of them was found;
- the diff only edits files in place. Git then confirms it: the diff changes exactly the files it lists,
  each a regular file at the base commit (a symbolic link is not), with no file created, deleted, renamed or
  made executable, and it applies cleanly to that base.

The commit's dates are the proposal's `created_at`: the same proposal on the same base is the same commit.
"""

import hashlib
import os
import re
import subprocess
import tempfile
import textwrap
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.gate import check_proposal
from sentinelci.remediation.proposal import RemediationError

BRANCH_PREFIX = "sentinel/fix/"
BOT_NAME = "SentinelCI bot"
BOT_EMAIL = "bot@sentinelci.invalid"
_BRANCH = re.compile(r"sentinel/fix/[a-z0-9][a-z0-9._-]{0,63}")
_REGULAR_FILE_MODES = frozenset({"100644", "100755"})
# What in the clone's own configuration could run code or prompt is turned off on the command line, which
# wins over every configuration file (hooks, fsmonitor, signing); line endings are never converted.
_GIT = (
    "git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
    "-c", "core.autocrlf=false",
)  # fmt: skip


@dataclass(frozen=True)
class Applied:
    branch: str
    commit: str
    base: str
    diff_sha256: str


def _git(
    repo: Path, *args: str, stdin: str | None = None, check: bool = True, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """git in `repo`, with an environment built from scratch: none of the caller's GIT_* variables."""
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",  # no user configuration (and no safe.directory from it)
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": BOT_NAME, "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME, "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        "LC_ALL": "C",
        **(env or {}),
    }  # fmt: skip
    completed = subprocess.run(  # noqa: S603 (git, an argument list, no shell)
        [*_GIT, "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RemediationError(
            f"git {args[0]} failed: {completed.stderr.strip()[-300:] or 'no reason given'}"
        )
    return completed


def default_branch(proposal: PatchProposal) -> str:
    return BRANCH_PREFIX + proposal.proposal_id.replace("-", "")[:12]


def diff_sha256(proposal: PatchProposal) -> str:
    return "sha256:" + hashlib.sha256(proposal.diff.encode("utf-8")).hexdigest()


def _commit_message(proposal: PatchProposal) -> str:
    rationale = "\n".join(textwrap.wrap(" ".join(proposal.rationale.split()), width=72))
    trailers = [
        f"Sentinel-Proposal: {proposal.proposal_id}",
        f"Sentinel-Strategy: {proposal.strategy}",
        f"Sentinel-Diff: {diff_sha256(proposal)}",
    ]
    trailers += [f"Sentinel-Finding: {finding}" for finding in proposal.finding_ids]
    subject = f"fix(security): {proposal.strategy} proposal, attempt {proposal.attempt}"
    return f"{subject}\n\n{rationale}\n\n" + "\n".join(trailers) + "\n"


def _check_diff(repo: Path, proposal: PatchProposal, base: str, index: Mapping[str, str]) -> None:
    """The diff changes exactly the proposal's files, in place, and applies to the base (in the index)."""
    checked = _git(
        repo, "apply", "--cached", "--check", "--numstat", "--summary", "-",
        stdin=proposal.diff, check=False, env=index,
    )  # fmt: skip
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
        listed = _git(repo, "ls-tree", base, "--", path).stdout.split()
        if not listed or listed[0] not in _REGULAR_FILE_MODES:
            raise RemediationError(f"{path} is not a regular file tracked at the base commit")


def apply_proposal(
    proposal: PatchProposal,
    repo: Path,
    *,
    findings: Sequence[Finding],
    base: str = "HEAD",
    branch: str | None = None,
) -> Applied:
    """Commit `proposal` on a new branch from `base`; the clone's working tree, index and HEAD stay as they
    are. `findings` are the base scan's findings: the proposal may claim and edit only those."""
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
    check_proposal(proposal, {finding.id: finding for finding in findings})  # the gate's own check
    with tempfile.TemporaryDirectory(prefix="sentinel-apply-") as scratch:
        index = {"GIT_INDEX_FILE": str(Path(scratch) / "index")}  # never the clone's own index
        _git(repo, "read-tree", base_commit, env=index)
        _check_diff(repo, proposal, base_commit, index)
        _git(repo, "apply", "--cached", "-", stdin=proposal.diff, env=index)
        tree = _git(repo, "write-tree", env=index).stdout.strip()
    created = f"@{int(proposal.created_at.timestamp())} +0000"
    dates = {"GIT_AUTHOR_DATE": created, "GIT_COMMITTER_DATE": created}
    commit = _git(
        repo, "commit-tree", tree, "-p", base_commit, "-F", "-", stdin=_commit_message(proposal), env=dates
    ).stdout.strip()
    # The zero old value makes "the branch does not exist yet" part of the update itself.
    _git(repo, "update-ref", "--no-deref", f"refs/heads/{name}", commit, "0" * len(base_commit))
    return Applied(branch=name, commit=commit, base=base_commit, diff_sha256=diff_sha256(proposal))
