"""The remediation bot's workflow (.github/workflows/sentinel-remediate.yml, task A6, ADR-0013).

Its trust boundary is checked on the file. Its scripts are run here as the workflow runs them: extracted from
the YAML, with bash, the local git and jq, against a local "origin" (a bare repository served over file://,
which, like GitHub, lets a client fetch a commit by its id) and a `gh` that records what it is asked.
- `publish` and `report`, the code that holds a write token, always. The proposals are real: the Kubernetes
  fixer's, committed by `sentinel remediate apply`, bundled as the `propose` job bundles them.
- `verify`, end to end with the real Gitleaks, Trivy and OPA (opt-in with SENTINEL_TOOLS_DIR, like the other
  real-tool tests): propose, publish, verify and report, as one run would.
"""

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.apply import apply_proposal
from sentinelci.remediation.kubernetes import propose

from .conftest import NOW, ROOT, SEED, SEED_PATH, seed_findings

WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-remediate.yml"
REPO = "NOURHANE-EHOUARI/sentinelci"
PUBLISH_STEP = "Push each verified branch and open its pull request"
VERIFY_STEP = "Verify each pull request the bot opened"
REPORT_STEP = "Comment each result and set its commit status"
FAKE_TOKEN = "fake-token-for-the-recording-gh"  # noqa: S105 (not a credential: the local gh records it)
SCAN_PATH = "demo-shop"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
# Where a command starts (a line, after ; & | or in $( )), it is never one that runs repository code.
RUNS_CODE = re.compile(
    r"(?:^|[;&|(])\s*(uv|python3?|pip|make|sentinel|npm|node|bash|sh|source|\.|\./\S*)(?=\s|$)", re.MULTILINE
)

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None, reason="the publish script uses jq, as the runner"
)


def workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return loaded


def step(job: str, name: str) -> dict[str, Any]:
    (found,) = [s for s in workflow()["jobs"][job]["steps"] if s.get("name") == name]
    return found


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


# ---------------------------------------------------------------- the trust boundary, on the file


def test_only_publish_can_push_and_no_job_with_a_write_token_runs_repository_code() -> None:
    jobs = workflow()["jobs"]
    assert list(workflow()[True]) == ["workflow_dispatch"], "by hand only"  # YAML reads `on` as True
    assert workflow()["permissions"] == {}
    assert list(jobs) == ["propose", "publish", "verify", "report"]
    assert jobs["propose"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert jobs["verify"]["permissions"] == {"contents": "read"}
    assert jobs["report"]["permissions"] == {"pull-requests": "write", "statuses": "write"}
    assert jobs["publish"]["needs"] == "propose"
    assert jobs["verify"]["needs"] == ["propose", "publish"] and jobs["report"]["needs"] == [
        "publish",
        "verify",
    ]
    for job, script in (("publish", PUBLISH_STEP), ("report", REPORT_STEP)):
        steps = jobs[job]["steps"]
        assert {s["uses"].split("@")[0] for s in steps if "uses" in s} == {"actions/download-artifact"}
        assert not [s for s in steps if "run" in s and s["name"] != script and RUNS_CODE.findall(s["run"])]
        run = step(job, script)["run"]
        assert RUNS_CODE.findall(run) == [], job
        assert re.findall(r"(?:^|[;&|(])\s*(git|jq|gh)\s", run, re.MULTILINE), "the runner's git, jq and gh"
        assert "github.token" in json.dumps(step(job, script)["env"])
    for job in ("propose", "verify"):
        expressions = " ".join(re.findall(r"\$\{\{(.*?)\}\}", json.dumps(jobs[job])))
        assert "secrets" not in expressions and "token" not in expressions, f"{job} runs repository code"


def test_verify_judges_with_the_scanned_commits_pipeline_and_the_scanners_the_pr_gate_requires() -> None:
    verify = workflow()["jobs"]["verify"]
    (checkout,) = [s for s in verify["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert checkout["with"] == {"path": "pipeline", "persist-credentials": False}, "the run's own commit"
    run = step("verify", VERIFY_STEP)["run"]
    required = re.search(r'"pr": \{([^}]*)\}', (ROOT / "policies" / "required_tools.rego").read_text())
    assert required is not None
    tools = set(re.findall(r'"(\w+)"', required[1]))
    kinds = {"gitleaks": "scan secrets", "trivy": "scan iac", "zizmor": "scan pipelines"}
    assert tools <= kinds.keys(), (
        f"a scanner the pr gate requires is not run by verify: {tools - kinds.keys()}"
    )
    for tool in tools:
        assert run.count(kinds[tool]) == 2, f"{tool}: the scanned commit and the patched commit"
    assert "--context pr" in run and '--baseline "$WORK/before.ndjson"' in run
    assert '(cd "$PIPELINE" && "$SENTINEL" evaluate' in run, "waivers from the pipeline checkout"


def test_verify_reads_trees_the_commit_cannot_configure_and_replays_the_fixer(tmp_path: Path) -> None:
    run = step("verify", VERIFY_STEP)["run"]
    archives = re.findall(r'git -C "\$repo" archive [^|]*', run)
    assert len(archives) == 2 and all("--worktree-attributes" in a for a in archives), archives
    # #85 review: both trees whole, so Trivy sees the same local Terraform modules on either side.
    assert all(" -- " not in a for a in archives), archives
    assert 'archive --worktree-attributes --format=tar "$BASE_SHA" |' in run, "the whole scanned commit"
    assert '--findings "$WORK/base-iac.ndjson"' in run, (
        "the fixer re-run on the scanned commit's IaC findings"
    )
    # #98 review, nit 3: a crash exits 1 too, so only a whole result counts (else FAILED, never REJECTED).
    whole = run.index('jq -e \'(.build_ok | type == "boolean") and (.tests_ok | type == "boolean")')
    assert run.index('"$SENTINEL" remediate check') < whole < run.index("jq -r '.problems[]'")
    # #98 review: the attributes come from the empty tree, set right after the bare repository is made and
    # before anything is fetched into it, so no later step can bring the commit's back by making HEAD resolve.
    init = run.index('git init --quiet --bare "$repo"')
    pinned = run.index('git -C "$repo" config attr.tree "$(git hash-object -t tree /dev/null)"')
    assert init < pinned < run.index('git -C "$repo" fetch')
    # What this relies on, with HEAD resolving to the scanned commit: archive --worktree-attributes and
    # Gitleaks' git log read no attribute of the commit.
    source, bare = tmp_path / "source", tmp_path / "bare.git"
    source.mkdir()
    git(source, "init", "--quiet")
    (source / ".gitattributes").write_text(
        "Dockerfile export-ignore\napp.yaml export-subst\nid.txt ident\n*.env -diff\n"
    )
    (source / "Dockerfile").write_text("FROM scratch\n")
    (source / "app.yaml").write_text("commit: $Format:%H$\n")
    (source / "id.txt").write_text("$Id$\n")
    git(source, "add", "-A")
    git(source, "commit", "--quiet", "-m", "attributes")
    (source / "a.env").write_text("TOKEN=fake-not-a-secret\n")
    git(source, "add", "-A")
    git(source, "commit", "--quiet", "-m", "a fake token")
    git(tmp_path, "init", "--quiet", "--bare", str(bare))
    empty = subprocess.run(
        ["git", "hash-object", "-t", "tree", "/dev/null"], check=True, capture_output=True, text=True
    ).stdout.strip()
    git(bare, "config", "attr.tree", empty)
    git(bare, "fetch", "--quiet", str(source), "+HEAD:refs/sentinel/base")
    git(bare, "symbolic-ref", "HEAD", "refs/sentinel/base")  # any later step that makes HEAD resolve
    archive = subprocess.run(
        ["git", "-C", str(bare), "archive", "--worktree-attributes", "--format=tar", "refs/sentinel/base"],
        check=True, capture_output=True,
    ).stdout  # fmt: skip
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        exported = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}  # type: ignore[union-attr]
    assert exported["Dockerfile"] == b"FROM scratch\n", "export-ignore dropped nothing"
    assert exported["app.yaml"] == b"commit: $Format:%H$\n", "export-subst rewrote nothing"
    assert exported["id.txt"] == b"$Id$\n", "ident expanded nothing"
    log = subprocess.run(
        ["git", "-C", str(bare), "log", "-p", "refs/sentinel/base"],
        check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip
    assert "+TOKEN=fake-not-a-secret" in log, "-diff hid nothing from Gitleaks' git log"


def test_the_check_judges_an_add_on_the_scanned_commits_whole_tree() -> None:
    """#85 review: the fixer looks for an ADD source next to the Dockerfile and at the repository root, so the
    check's base tree is the whole scanned commit, not the scanned directory."""
    run = step("verify", VERIFY_STEP)["run"]
    (export,) = re.findall(r'git -C "\$repo" archive [^|]*"\$BASE_SHA"[^|]*\| tar -x -C "([^"]+)"', run)
    assert re.search(r'archive [^|]*"\$BASE_SHA" \|', run), "the whole commit: no pathspec"
    assert f'remediate check --proposal "$proposal" --base-root "{export}"' in run


def test_the_verify_job_outlives_every_scanner_run() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    per_run = int(re.search(r'^  SCANNER_TIMEOUT_S: "(\d+)"$', text, re.MULTILINE)[1])  # type: ignore[index]
    strategies = len(re.search(r"for strategy in ([a-z ]+); do", text)[1].split())  # type: ignore[index]
    run = step("verify", VERIFY_STEP)["run"]
    assert run.count('"${common[@]}"') == 4 and run.count('"${audit[@]}"') == 3
    assert '--timeout "$SCANNER_TIMEOUT_S"' in run
    # The scanned commit: Gitleaks on its tree, Trivy, zizmor. Each proposal: Gitleaks in git mode (two
    # passes), Trivy, zizmor.
    trivy = per_run + 60  # the runner's own limit on top of Trivy's --timeout (scanners/trivy.py)
    setup = 300  # setup, installs, OPA, uploads
    worst = setup + 2 * per_run + trivy + strategies * (3 * per_run + trivy)
    assert worst <= workflow()["jobs"]["verify"]["timeout-minutes"] * 60


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
        # Files a Kubernetes proposal must never edit: not a manifest, SentinelCI's own, outside the path.
        for other in ("demo-shop/NOTES.txt", "demo-shop/sentinel.yaml", "deploy/kind/cluster.yaml"):
            (self.clone / other).parent.mkdir(parents=True, exist_ok=True)
            (self.clone / other).write_text("kind: Config\n")
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
        self.pull_request = tmp_path / "next-pull-request"
        self.pull_request.write_text("1")
        gh.write_text(
            "#!/usr/bin/env python3\nimport json, os, sys\n"
            "args = sys.argv[1:]\n"
            "body = args[args.index('--body-file') + 1] if '--body-file' in args else None\n"
            "body = body or next((a[6:] for a in args if a.startswith('body=@')), None)\n"
            "record = {'args': args, 'body': open(body).read() if body else None,"
            " 'token': os.environ.get('GH_TOKEN')}\n"
            f"open({str(self.calls)!r}, 'a').write(json.dumps(record) + '\\n')\n"
            f"number = open({str(self.pull_request)!r}).read().strip()\n"
            "if number == 'fail': sys.exit(1)\n"
            "if args[:2] == ['pr', 'create']: print('https://github.com/o/r/pull/' + number)\n",
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

    def run(self, job: str, name: str, **env: str) -> subprocess.CompletedProcess[str]:
        """A step's script, with the environment the workflow gives it (`env`) and a fresh GITHUB_OUTPUT."""
        self.output = self.tmp / f"{job}-output"
        self.output.write_text("")
        base = {
            "PATH": self.path, "HOME": str(self.tmp), "GIT_CONFIG_NOSYSTEM": "1",
            "GITHUB_OUTPUT": str(self.output), "REPO": REPO, "SCAN_PATH": SCAN_PATH,
            "RUN_URL": "https://github.com/o/r/actions/runs/1",
        }  # fmt: skip
        return subprocess.run(
            ["bash", "-c", step(job, name)["run"]],
            env=base | env,
            capture_output=True,
            text=True,
            check=False,
        )

    def outputs(self) -> dict[str, str]:
        return dict(line.split("=", 1) for line in self.output.read_text().splitlines())

    def publish(self, scan_path: str = SCAN_PATH) -> subprocess.CompletedProcess[str]:
        shutil.rmtree(self.tmp / "work", ignore_errors=True)
        return self.run(
            "publish", PUBLISH_STEP, GH_TOKEN=FAKE_TOKEN, REMOTE=f"file://{self.origin}", BASE_SHA=self.base,
            BASE_BRANCH="main", PROPOSALS=str(self.artifact), WORK=str(self.tmp / "work"),
            SCAN_PATH=scan_path,
        )  # fmt: skip

    def opened(self) -> list[dict[str, Any]]:
        opened: list[dict[str, Any]] = json.loads(self.outputs()["opened"])
        return opened

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
    assert bot.outputs()["refused"] == "0"
    assert bot.opened() == [{
        "name": "kubernetes", "branch": applied["branch"], "commit": applied["commit"],
        "proposal_id": proposal.proposal_id, "pull_request": 1,
    }], "what verify judges"  # fmt: skip


def test_running_it_again_opens_nothing_new(bot: Bot) -> None:
    bot.propose()
    assert bot.publish().returncode == 0
    again = bot.publish()
    assert again.returncode == 0 and "exists already" in again.stdout
    assert len(bot.gh()) == 1 and bot.opened() == [], "nothing new to verify"


def test_no_proposal_publishes_nothing(bot: Bot) -> None:
    done = bot.publish()
    assert done.returncode == 0 and not bot.gh() and bot.remote_branches() == {"main": bot.base}
    assert bot.outputs() == {"opened": "[]", "refused": "0"}


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
    elif how == "another-proposal":  # a consistent id and branch, but not the commit's trailer
        git(bot.clone, "branch", "-f", "sentinel/fix/000000000000", commit)
        bot.write(
            "kubernetes",
            document | {"proposal_id": "00000000-0000-4000-8000-000000000000"},
            applied | {"branch": "sentinel/fix/000000000000"},
            ["sentinel/fix/000000000000"],
        )
    elif how == "odd-name":
        (bot.artifact / "proposals" / "kubernetes.applied.json").unlink()
        bot.write("Kubernetes\n::warning::x", document, applied, [branch])
    elif how == "branch-of-another-id":
        bot.write("kubernetes", document | {"proposal_id": "00000000-0000-4000-8000-000000000000"}, applied,
                  [branch])  # fmt: skip
    elif how == "another-strategy":
        bot.write("kubernetes", document | {"strategy": "llm:code"}, applied, [branch])
    elif how == "malformed-finding-id":
        bot.write("kubernetes", document | {"finding_ids": ["`@someone`"]}, applied, [branch])
    elif how.startswith("listed-"):
        listed = {"listed-readme": "README.md", "listed-not-a-manifest": "demo-shop/NOTES.txt",
                  "listed-sentinel-yaml": "demo-shop/sentinel.yaml",
                  "listed-outside-the-path": "deploy/kind/cluster.yaml"}[how]  # fmt: skip
        work = bot.tmp / "work-tree"
        git(bot.clone, "worktree", "add", "-q", str(work), branch)
        (work / listed).write_text("changed by a compromised propose job\n")
        git(work, "commit", "-qa", "--amend", "--no-edit")
        new = git(work, "rev-parse", "HEAD")
        files = sorted([*document["files"], listed])
        bot.write("kubernetes", document | {"files": files}, applied | {"commit": new}, [branch])
    elif how in ("another-file", "outside-the-path", "two-commits", "executable"):
        work = bot.tmp / "work-tree"
        git(bot.clone, "worktree", "add", "-q", str(work), branch)
        if how in ("another-file", "outside-the-path"):
            (work / "README.md").write_text("changed\n")
            git(work, "commit", "-qa", "--amend", "--no-edit")
            if how == "outside-the-path":  # listed too: only the path check stops it
                document = document | {"files": [*document["files"], "README.md"]}
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
        ("outside-the-path", "deterministic:kubernetes cannot edit README.md"),
        ("two-commits", "exactly one parent"),
        ("executable", "changes a file mode"),
        ("odd-name", "proposal: a proposal's file name must be lower-case letters, digits and -"),
        ("branch-of-another-id", "the branch is not named after the proposal's id"),
        ("another-strategy", "the kubernetes and dockerfile fixers only"),
        ("malformed-finding-id", "attempt or finding ids are malformed"),
        ("listed-readme", "deterministic:kubernetes cannot edit README.md"),
        ("listed-not-a-manifest", "deterministic:kubernetes cannot edit demo-shop/NOTES.txt"),
        ("listed-sentinel-yaml", "deterministic:kubernetes cannot edit demo-shop/sentinel.yaml"),
        ("listed-outside-the-path", "deterministic:kubernetes cannot edit deploy/kind/cluster.yaml"),
    ],
)
def test_a_proposal_changed_after_the_fact_is_refused_and_nothing_is_published(
    bot: Bot, how: str, message: str
) -> None:
    tampered(bot, how)
    done = bot.publish()
    assert done.returncode == 0 and message in done.stdout, done.stdout + done.stderr
    assert bot.outputs() == {"opened": "[]", "refused": "1"}, "the next step fails the job"
    assert bot.remote_branches() == {"main": bot.base} and not bot.gh()
    assert "::warning::" not in done.stdout, "a file name is never echoed"


def test_one_refused_proposal_does_not_stop_the_others(bot: Bot) -> None:
    proposal, applied = bot.propose()
    good = proposal.model_dump(mode="json")
    bot.write("aaa-broken", good | {"proposal_id": "00000000-0000-4000-8000-000000000000"}, applied,
              [applied["branch"]])  # fmt: skip
    done = bot.publish()
    assert done.returncode == 0 and bot.outputs()["refused"] == "1"
    assert applied["branch"] in bot.remote_branches() and len(bot.gh()) == 1, "the good one is still opened"
    assert [entry["name"] for entry in bot.opened()] == ["kubernetes"]


def test_a_pull_request_gh_could_not_open_is_refused(bot: Bot) -> None:
    bot.propose()
    bot.pull_request.write_text("fail")
    done = bot.publish()
    assert done.returncode == 0 and "could not be opened" in done.stdout
    assert bot.outputs() == {"opened": "[]", "refused": "1"}


def test_the_failing_step_fails_the_job_when_a_proposal_is_refused() -> None:
    publish = workflow()["jobs"]["publish"]
    assert publish["outputs"] == {"opened": "${{ steps.publish.outputs.opened }}"}
    last = publish["steps"][-1]
    assert last["if"] == "steps.publish.outputs.refused != '0'" and "exit 1" in last["run"]


def test_a_run_with_nothing_to_propose_still_hands_over_an_artifact() -> None:
    """`publish` downloads the artifact by name: with nothing proposed, an empty upload would make it fail."""
    propose = workflow()["jobs"]["propose"]["steps"]
    (script,) = [step["run"] for step in propose if "remediate apply" in step.get("run", "")]
    assert script.rstrip().endswith('> "$out/summary.txt"'), "written after the loop, whatever it proposed"
    (upload,) = [step for step in propose if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert upload["with"]["if-no-files-found"] == "error"


# ---------------------------------------------------------------- the report script, run

COMMIT = "c" * 40
PROPOSAL_ID = "11111111-1111-5111-8111-111111111111"


def opened_entry(pull_request: int = 7) -> dict[str, Any]:
    return {"name": "kubernetes", "branch": "sentinel/fix/111111111111", "commit": COMMIT,
            "proposal_id": PROPOSAL_ID, "pull_request": pull_request}  # fmt: skip


def a_result(**changes: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "proposal_id": PROPOSAL_ID, "attempt": 1, "build_ok": True, "tests_ok": True,
        "target_resolved": True, "new_findings": [], "verdict": "PASS", "outcome": "VERIFIED",
        "pull_request": 7, "verified_at": "2026-11-10T10:00:00Z",
    } | changes  # fmt: skip


def report(
    bot: Bot, opened: list[dict[str, Any]], results: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    directory = bot.tmp / "verification"
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir()
    for name, result in results.items():
        (directory / f"{name}.json").write_text(json.dumps(result), encoding="utf-8")
    return bot.run(
        "report", REPORT_STEP, GH_TOKEN=FAKE_TOKEN, OPENED=json.dumps(opened), RESULTS=str(directory),
        WORK=str(bot.tmp / "report"),
    )  # fmt: skip


@pytest.mark.parametrize(
    ("result", "outcome", "state", "code"),
    [
        (a_result(), "VERIFIED", "success", 0),
        (a_result(verdict="BLOCK", outcome="REJECTED"), "REJECTED", "failure", 0),
        (a_result(tests_ok=False, outcome="FAILED", attempt=3), "FAILED", "failure", 0),
        (None, "FAILED", "failure", 1),
        (a_result(verdict="BLOCK"), "FAILED", "failure", 1),
        (a_result(new_findings=["a" * 64]), "FAILED", "failure", 1),
        (a_result(proposal_id="22222222-2222-5222-8222-222222222222"), "FAILED", "failure", 1),
        (a_result(pull_request=8), "FAILED", "failure", 1),
        (a_result(build_ok="true"), "FAILED", "failure", 1),
    ],
    ids=["verified", "rejected", "failed", "no-result", "verified-but-block", "verified-but-new-findings",
         "another-proposal", "another-pull-request", "not-a-boolean"],
)  # fmt: skip
def test_each_result_is_commented_and_set_as_the_commit_status(
    bot: Bot, result: dict[str, Any] | None, outcome: str, state: str, code: int
) -> None:
    done = report(bot, [opened_entry()], {} if result is None else {"kubernetes": result})
    assert done.returncode == code, done.stdout + done.stderr
    comment, status = bot.gh()
    assert comment["args"][:4] == ["api", "--method", "POST", f"repos/{REPO}/issues/7/comments"]
    assert comment["token"] == FAKE_TOKEN
    assert comment["body"].startswith("<!-- sentinelci:remediation-verification -->\n")
    assert f"**SentinelCI verification: {outcome}**" in comment["body"]
    assert "the bot never merges" in comment["body"].lower()
    assert status["args"][:4] == ["api", "--method", "POST", f"repos/{REPO}/statuses/{COMMIT}"]
    assert f"state={state}" in status["args"] and "context=sentinelci/remediation" in status["args"]
    assert f"description=Verification: {outcome}" in status["args"]
    if outcome == "REJECTED":
        assert "| Gate verdict on the patched commit (pr context) | BLOCK |" in comment["body"]


# ---------------------------------------------------------------- one run, end to end, with the real tools


def tools_with_opa() -> Path:
    if not TOOLS_DIR:
        pytest.skip("set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
    tools = Path(TOOLS_DIR)
    if not all((tools / "bin" / tool).exists() for tool in ("gitleaks", "trivy", "opa")):
        pytest.skip("SENTINEL_TOOLS_DIR needs gitleaks, trivy and opa")
    return tools


def test_one_run_proposes_publishes_verifies_and_reports(bot: Bot) -> None:
    tools = tools_with_opa()
    sentinel = str(Path(sys.executable).parent / "sentinel")
    lock = str(ROOT / "tools.lock.toml")
    # propose, as the job does: the real scan, the fixer, apply, a bundle.
    scanned = bot.tmp / "findings.ndjson"
    subprocess.run(
        [sentinel, "scan", "iac", str(bot.clone / SCAN_PATH), "--repo-root", str(bot.clone),
         "--out", str(scanned), "--repo", REPO, "--commit", bot.base, "--ref", "refs/heads/main",
         "--run-id", "1", "--context", "release", "--lock", lock, "--tools-dir", str(tools),
         "--tool-status-out", str(bot.tmp / "status.json")],
        check=True, capture_output=True,
    )  # fmt: skip
    findings = [Finding.model_validate_json(line) for line in scanned.read_text().splitlines()]
    plan = propose(findings, bot.clone, created_at=NOW)
    assert plan.proposal is not None
    applied = apply_proposal(plan.proposal, bot.clone, findings=findings)
    record = {"branch": applied.branch, "commit": applied.commit, "base": applied.base,
              "diff_sha256": applied.diff_sha256}  # fmt: skip
    bot.write("kubernetes", plan.proposal.model_dump(mode="json"), record, [applied.branch])
    assert bot.publish().returncode == 0
    opened = bot.opened()
    manifest = bot.tmp / "opa-manifest.json"
    subprocess.run([sentinel, "tools", "verify", "opa", "--lock", lock, "--dest", str(tools), "--report",
                    str(manifest)], check=True, capture_output=True)  # fmt: skip

    def verify(entries: list[dict[str, Any]], work: str) -> subprocess.CompletedProcess[str]:
        return bot.run(
            "verify", VERIFY_STEP, SENTINEL=sentinel, PIPELINE=str(ROOT), CHECKOUT=str(bot.clone),
            TOOLS=str(tools), OPA_MANIFEST=str(manifest), OPENED=json.dumps(entries),
            PROPOSALS=str(bot.artifact), WORK=str(bot.tmp / work), RESULTS=str(bot.tmp / work / "results"),
            BASE_SHA=bot.base, BASE_REF="refs/heads/main", RUN_ID="1", SCANNER_TIMEOUT_S="300",
        )  # fmt: skip

    done = verify(opened, "verify")
    assert done.returncode == 0, done.stdout + done.stderr
    result = json.loads((bot.tmp / "verify" / "results" / "kubernetes.json").read_text())
    assert result["outcome"] == "VERIFIED" and result["verdict"] in ("PASS", "WARN"), result
    assert result["pull_request"] == 1 and result["proposal_id"] == plan.proposal.proposal_id
    reported = bot.run(
        "report", REPORT_STEP, GH_TOKEN=FAKE_TOKEN, OPENED=json.dumps(opened),
        RESULTS=str(bot.tmp / "verify" / "results"), WORK=str(bot.tmp / "report"),
    )  # fmt: skip
    assert reported.returncode == 0, reported.stdout + reported.stderr
    _, comment, status = bot.gh()
    assert "**SentinelCI verification: VERIFIED**" in comment["body"] and "state=success" in status["args"]
    # A pull request whose commit is not the proposal applied to the scanned commit gets no result.
    other = git(
        bot.clone, "commit-tree", f"{applied.commit}^{{tree}}", "-p", bot.base, "-m", "not the proposal"
    )
    done = verify([opened[0] | {"commit": other}], "verify-other")
    assert done.returncode == 1 and "is not the proposal applied to" in done.stdout, done.stdout + done.stderr
    assert not (bot.tmp / "verify-other" / "results" / "kubernetes.json").exists()


def test_the_fixers_text_is_shown_as_text(bot: Bot) -> None:
    """The rationale is free text from the propose job: no mention, closing keyword, link or image renders."""
    proposal, applied = bot.propose()
    document = proposal.model_dump(mode="json")
    document["rationale"] = "Closes #1 @someone [x](https://example.invalid/p.png) ```\n# Approved"
    bot.write("kubernetes", document, applied, [applied["branch"]])
    done = bot.publish()
    assert done.returncode == 0, done.stdout + done.stderr
    (call,) = bot.gh()
    fenced = call["body"].split("```text\n", 1)[1].split("\n```\n", 1)
    assert fenced[0] == "Closes #1 @someone [x](https://example.invalid/p.png) '''\n# Approved"
    assert "@someone" not in fenced[1] and "@someone" not in call["body"].split("```text", 1)[0]


def test_a_failed_push_is_named_and_the_others_still_go(bot: Bot) -> None:
    proposal, applied = bot.propose()
    hook = bot.origin / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
    bot.write("aaa", proposal.model_dump(mode="json"), applied, [applied["branch"]])
    done = bot.publish()
    assert done.returncode == 0 and not bot.gh() and bot.outputs() == {"opened": "[]", "refused": "2"}
    assert done.stdout.count("the push of") == 2, "both proposals were tried, and each failure is named"
