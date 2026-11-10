"""The remediation bot's workflow (.github/workflows/sentinel-remediate.yml, task A6, ADR-0013).

Its trust boundary is checked on the file, and its `publish` script, the only code that holds a write token,
is run here as the workflow runs it: extracted from the YAML, with bash, the local git and jq, against a local
"origin" (a bare repository served over file://, which, like GitHub, lets a client fetch a commit by its id)
and a `gh` that records what it is asked. The proposals are real: the Kubernetes fixer's, committed by
`sentinel remediate apply`, bundled as the `propose` job bundles them.
"""

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.apply import apply_proposal
from sentinelci.remediation.kubernetes import propose

from .conftest import NOW, ROOT, SEED, SEED_PATH, seed_findings

WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-remediate.yml"
REPO = "NOURHANE-EHOUARI/sentinelci"
PUBLISH_STEP = "Push each verified branch and open its pull request"
FAKE_TOKEN = "fake-token-for-the-recording-gh"  # noqa: S105 (not a credential: the local gh records it)

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None, reason="the publish script uses jq, as the runner"
)


def workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return loaded


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


# ---------------------------------------------------------------- the trust boundary, on the file


def test_only_publish_can_write_and_it_runs_no_repository_code() -> None:
    jobs = workflow()["jobs"]
    assert list(workflow()[True]) == ["workflow_dispatch"], "by hand only"  # YAML reads `on` as True
    assert workflow()["permissions"] == {}
    assert jobs["propose"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert jobs["publish"]["needs"] == "propose"
    steps = jobs["publish"]["steps"]
    assert [step.get("uses", "").split("@")[0] for step in steps] == ["actions/download-artifact", ""]
    script = steps[1]["run"]
    # Where a command starts (a line, after ; & | or in $( )), it is never one that runs repository code.
    runs_code = re.compile(
        r"(?:^|[;&|(])\s*(uv|python3?|pip|make|sentinel|npm|node|bash|sh|source|\.|\./\S*)(?=\s|$)",
        re.MULTILINE,
    )
    assert runs_code.findall(script) == []
    assert re.findall(r"(?:^|[;&|(])\s*(git|jq|gh)\s", script, re.MULTILINE), "the runner's git, jq and gh"
    propose_text = json.dumps(jobs["propose"])
    assert "secrets." not in propose_text and "github.token" not in propose_text
    assert "github.token" in json.dumps(steps[1]["env"]), "the write token is publish's only"


# ---------------------------------------------------------------- the publish script, run


class Bot:
    """An origin, a clone that proposes, and the publish step run against them."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.origin = tmp_path / "origin.git"
        self.clone = tmp_path / "clone"
        (self.clone / SEED_PATH).parent.mkdir(parents=True)
        (self.clone / SEED_PATH).write_text(SEED.read_text())
        (self.clone / "README.md").write_text("demo\n")
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.clone)], check=True)
        git(self.clone, "add", ".")
        git(self.clone, "commit", "-qm", "seed")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        git(self.origin, "config", "uploadpack.allowReachableSHA1InWant", "true")  # as GitHub
        git(self.clone, "push", "-q", str(self.origin), "main")
        self.base = git(self.clone, "rev-parse", "HEAD")
        self.artifact = tmp_path / "remediation"
        (self.artifact / "proposals").mkdir(parents=True)
        (self.artifact / "bundles").mkdir()
        self.calls = tmp_path / "gh-calls.jsonl"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\nimport json, os, sys\n"
            "args = sys.argv[1:]\n"
            "body = args[args.index('--body-file') + 1] if '--body-file' in args else None\n"
            "record = {'args': args, 'body': open(body).read() if body else None,"
            " 'token': os.environ.get('GH_TOKEN')}\n"
            f"open({str(self.calls)!r}, 'a').write(json.dumps(record) + '\\n')\n"
            "print('https://github.com/o/r/pull/1')\n",
            encoding="utf-8",
        )
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        self.path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

    def propose(self, name: str = "kubernetes") -> tuple[PatchProposal, dict[str, str]]:
        """What the propose job hands over: the proposal, apply's output and the bundle."""
        plan = propose(seed_findings(), self.clone, created_at=NOW)
        assert plan.proposal is not None
        applied = apply_proposal(plan.proposal, self.clone, findings=seed_findings())
        record = {"branch": applied.branch, "commit": applied.commit, "base": applied.base,
                  "diff_sha256": applied.diff_sha256}  # fmt: skip
        self.write(name, plan.proposal.model_dump(mode="json"), record, [applied.branch])
        return plan.proposal, record

    def write(self, name: str, proposal: dict[str, Any], applied: dict[str, str], refs: list[str]) -> None:
        (self.artifact / "proposals" / f"{name}.json").write_text(json.dumps(proposal), encoding="utf-8")
        (self.artifact / "proposals" / f"{name}.applied.json").write_text(
            json.dumps(applied), encoding="utf-8"
        )
        bundle = self.artifact / "bundles" / f"{name}.bundle"
        bundle.unlink(missing_ok=True)
        git(
            self.clone,
            "bundle",
            "create",
            str(bundle),
            *(f"refs/heads/{ref}" for ref in refs),
            f"^{self.base}",
        )

    def publish(self) -> subprocess.CompletedProcess[str]:
        (step,) = [s for s in workflow()["jobs"]["publish"]["steps"] if s.get("name") == PUBLISH_STEP]
        env = {
            "PATH": self.path, "HOME": str(self.tmp), "GH_TOKEN": FAKE_TOKEN, "REPO": REPO,
            "REMOTE": f"file://{self.origin}", "BASE_SHA": self.base, "BASE_BRANCH": "main",
            "RUN_URL": "https://github.com/o/r/actions/runs/1", "PROPOSALS": str(self.artifact),
            "WORK": str(self.tmp / "work"), "GIT_CONFIG_NOSYSTEM": "1",
        }  # fmt: skip
        shutil.rmtree(self.tmp / "work", ignore_errors=True)
        return subprocess.run(
            ["bash", "-c", step["run"]], env=env, capture_output=True, text=True, check=False
        )

    def gh(self) -> list[dict[str, Any]]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def remote_branches(self) -> dict[str, str]:
        listed = git(self.origin, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads")
        return dict(line.split(" ") for line in listed.splitlines())


@pytest.fixture
def bot(tmp_path: Path) -> Bot:
    return Bot(tmp_path)


def test_a_verified_branch_is_pushed_and_its_pull_request_opened(bot: Bot) -> None:
    proposal, applied = bot.propose()
    done = bot.publish()
    assert done.returncode == 0, done.stdout + done.stderr
    assert bot.remote_branches() == {"main": bot.base, applied["branch"]: applied["commit"]}
    (call,) = bot.gh()
    args = call["args"]
    assert args[:2] == ["pr", "create"] and call["token"] == FAKE_TOKEN
    assert args[args.index("--repo") + 1] == REPO and args[args.index("--base") + 1] == "main"
    assert args[args.index("--head") + 1] == applied["branch"]
    count = len(proposal.finding_ids)
    assert args[args.index("--title") + 1] == f"fix(remediation): kubernetes hardening for {count} finding(s)"
    body = call["body"]
    assert proposal.rationale in body and proposal.proposal_id in body and bot.base in body
    assert all(f"- `{finding}`" in body for finding in proposal.finding_ids)
    assert "The bot never merges it." in body


def test_running_it_again_opens_nothing_new(bot: Bot) -> None:
    bot.propose()
    assert bot.publish().returncode == 0
    again = bot.publish()
    assert again.returncode == 0 and "exists already" in again.stdout
    assert len(bot.gh()) == 1


def test_no_proposal_publishes_nothing(bot: Bot) -> None:
    done = bot.publish()
    assert done.returncode == 0 and not bot.gh() and bot.remote_branches() == {"main": bot.base}


def tampered(bot: Bot, how: str) -> None:
    """A propose job's output changed one way after the fact, as a compromised job could."""
    proposal, applied = bot.propose()
    document = proposal.model_dump(mode="json")
    branch, commit = applied["branch"], applied["commit"]
    if how == "another-base":
        bot.write("kubernetes", document, applied | {"base": "0" * 40}, [branch])
    elif how == "not-a-fix-branch":
        git(bot.clone, "branch", "-f", "main-fix", commit)
        bot.write("kubernetes", document, applied | {"branch": "main-fix"}, ["main-fix"])
    elif how == "two-refs":
        git(bot.clone, "branch", "-f", "sentinel/fix/extra", commit)
        bot.write("kubernetes", document, applied, [branch, "sentinel/fix/extra"])
    elif how == "another-proposal":
        bot.write(
            "kubernetes",
            document | {"proposal_id": "00000000-0000-4000-8000-000000000000"},
            applied,
            [branch],
        )
    elif how in ("another-file", "two-commits", "executable"):
        work = bot.tmp / "work-tree"
        git(bot.clone, "worktree", "add", "-q", str(work), branch)
        if how == "another-file":
            (work / "README.md").write_text("changed\n")
            git(work, "commit", "-qa", "--amend", "--no-edit")
        elif how == "two-commits":
            (work / "README.md").write_text("changed\n")
            git(work, "commit", "-qam", "a second commit")
        else:
            path = work / SEED_PATH
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            git(work, "commit", "-qa", "--amend", "--no-edit")
        new = git(work, "rev-parse", "HEAD")
        bot.write("kubernetes", document, applied | {"commit": new}, [branch])
    else:
        raise AssertionError(how)


@pytest.mark.parametrize(
    ("how", "message"),
    [
        ("another-base", "proposed against another commit"),
        ("not-a-fix-branch", "not a sentinel/fix/ branch"),
        ("two-refs", "the bundle must hold exactly"),
        ("another-proposal", "the commit is not proposal"),
        ("another-file", "exactly the files the proposal lists"),
        ("two-commits", "exactly one parent"),
        ("executable", "changes a file mode"),
    ],
)
def test_a_proposal_changed_after_the_fact_is_refused_and_nothing_is_published(
    bot: Bot, how: str, message: str
) -> None:
    tampered(bot, how)
    done = bot.publish()
    assert done.returncode == 1 and message in done.stdout, done.stdout + done.stderr
    assert bot.remote_branches() == {"main": bot.base} and not bot.gh()


def test_one_refused_proposal_does_not_stop_the_others(bot: Bot) -> None:
    proposal, applied = bot.propose()
    good = proposal.model_dump(mode="json")
    bot.write("aaa-broken", good | {"proposal_id": "00000000-0000-4000-8000-000000000000"}, applied,
              [applied["branch"]])  # fmt: skip
    done = bot.publish()
    assert done.returncode == 1, "the run fails: one proposal was refused"
    assert applied["branch"] in bot.remote_branches() and len(bot.gh()) == 1, "the good one is still opened"
