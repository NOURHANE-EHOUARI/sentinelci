"""`make remediate-code` (deploy/remediate/remediate_code.py, task A6, ADR-0014).

The loop runs for real against a throwaway repository: git (the bare copy, `git archive`) and this checkout's
`sentinel remediate apply`. The scanners, the gate, the check and the verification gate are stand-ins that
write what the real commands write and answer as each scenario needs; the model is a scripted `propose`.
Nothing is pushed: `git push` and `gh` are recorded.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentinelci.contracts.remediation import Model, PatchProposal
from sentinelci.remediation.proposal import proposal_id_of, unified_diff

ROOT = Path(__file__).resolve().parents[2]
NOW_ISO = "2026-11-11T22:00:00+00:00"
SERVICE = "demo-shop/services/shop-api"
TARGET = f"{SERVICE}/app/db.py"
OLD = "def find(cur, q):\n    return cur.execute(f\"SELECT * FROM items WHERE name = '{q}'\")\n"
FIXED = 'def find(cur, q):\n    return cur.execute("SELECT * FROM items WHERE name = ?", (q,))\n'
FINDING_ID = "f" * 64
IMAGE = "python@sha256:" + "a" * 64


def _load() -> ModuleType:
    name = "sentinel_remediate_code"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / "remediate" / "remediate_code.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


remediate = _load()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t",
         "-c", "user.email=t@example.invalid", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip


SECURITY = "security_tests/test_python_sql_built_from_strings.py"
PASSED_LOG = (
    "$ pytest tests (behaviour tests, patched code)\n12 passed in 0.31s\n\n"
    f"$ pytest {SECURITY} ({SECURITY}, base code, expected to fail)\n3 failed in 0.11s\n\n"
    f"$ pytest {SECURITY} ({SECURITY}, patched code)\n3 passed in 0.09s\n"
)


def make_repo(path: Path) -> Path:
    files = {
        ".gitignore": "out/\n",
        TARGET: OLD,
        f"{SERVICE}/tests/test_db.py": "def test_find():\n    pass\n",
        f"{SERVICE}/{SECURITY}": "def test_no_injection():\n    pass\n",
        # A commit's own attributes must not hide or rewrite what is scanned (--worktree-attributes).
        ".gitattributes": f"{SERVICE}/** export-ignore\n",
    }
    path.mkdir(parents=True)
    git(path, "init", "--quiet", "--initial-branch=main")
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text, encoding="utf-8")
    git(path, "add", "-A")
    git(path, "commit", "--quiet", "-m", "base")
    git(path, "remote", "add", "origin", "https://github.com/NOURHANE-EHOUARI/sentinelci.git")
    git(path, "update-ref", "refs/remotes/origin/main", "HEAD")
    return path


def finding(commit: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "id": FINDING_ID, "tool": {"name": "opengrep", "version": "1.33.1"},
        "rule_id": "python-sql-built-from-strings", "category": "SAST", "title": "SQL built from strings",
        "severity": "HIGH", "location": {"path": TARGET, "start_line": 2, "end_line": 2},
        "run": {"repo": "NOURHANE-EHOUARI/sentinelci", "commit": commit, "context": "pr"},
    }  # fmt: skip


NEW = finding("0" * 40) | {
    "id": "f" * 64, "rule_id": "python-tls-verification-disabled", "title": "TLS verification disabled",
    "location": {"path": TARGET, "start_line": 3, "end_line": 3},
}  # fmt: skip


def proposal_for(attempt: int, new: str = FIXED, rationale: str = "Bind the parameter.") -> PatchProposal:
    diff = unified_diff(TARGET, OLD, new)
    return PatchProposal(
        schema_version="1.0", proposal_id=proposal_id_of("llm:code", attempt, [FINDING_ID], diff),
        finding_ids=[FINDING_ID], strategy="llm:code", diff=diff, files=[TARGET], rationale=rationale,
        attempt=attempt, model=Model(name="gemma4:12b-it-qat", prompt_version="sentinel-patch-code/1"),
        created_at=NOW_ISO,  # type: ignore[arg-type]
    )  # fmt: skip


@dataclass
class Proposed:
    status: str
    reason: str = ""
    proposal: PatchProposal | None = None


@dataclass
class Feedback:
    previous_diff: str
    ci_log: str


@dataclass
class Scenario:
    """How each stand-in answers, attempt by attempt (1-based)."""

    outcomes: list[str] = field(default_factory=lambda: ["VERIFIED"])  # the verification gate's
    check_exit: int = 0  # `remediate check`: 0, 1 or 3
    proposed: list[Proposed] | None = None
    new_finding: bool = False  # the patched commit's SAST scan reports NEW, which a REJECTED verify names


class Loop:
    """The loop with its stand-ins; `calls` holds every command, `asked` every `propose` call."""

    def __init__(self, repo: Path, tmp_path: Path, scenario: Scenario, **settings: Any) -> None:
        self.repo, self.scenario = repo, scenario
        self.calls: list[list[str]] = []
        self.asked: list[dict[str, Any]] = []
        self.attempt = 0
        settings = {"test_image": IMAGE, "tools_dir": tmp_path / "tools", **settings}
        self.loop = remediate.RemediateCode(
            remediate.Settings(**settings), self.propose, provider=object(), model="gemma4:12b-it-qat",
            model_version="sha256:" + "3" * 64, run=self.run, fetch=False, feedback_type=Feedback,
            out=tmp_path / "out", root=repo,
        )  # fmt: skip

    def __call__(self) -> Any:
        return self.loop()

    def propose(self, target: Any, findings: Any, repo_root: Path, provider: Any, **kwargs: Any) -> Proposed:
        self.asked.append({"target": target.id, "root": repo_root, **kwargs})
        number = kwargs["attempt"]
        if self.scenario.proposed is not None:
            return self.scenario.proposed[number - 1]
        new = FIXED if number == 1 else FIXED.replace("?", "%s").replace("%s", "?", 1) + f"# try {number}\n"
        return Proposed("proposed", proposal=proposal_for(number, new))

    # -------------------------------------------------------------- commands

    def run(
        self, args: Sequence[str], *, cwd: Path = ROOT, env: Mapping[str, str] | None = None,
        check: bool = True, capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:  # fmt: skip
        args = list(args)
        self.calls.append(args)
        if args[1:3] == ["-m", "sentinelci.cli"]:
            done = self.cli(args[3:])
        elif args[0] == "git" and ("push" in args):
            done = subprocess.CompletedProcess(args, 0, "", "")
        elif args[0] == "gh":
            done = subprocess.CompletedProcess(args, 0, "https://github.com/x/y/pull/7\n", "")
        else:
            where = self.repo if cwd == ROOT else cwd
            done = subprocess.run(args, cwd=where, capture_output=True, text=True, check=False)
        if check and done.returncode != 0:
            raise remediate.RemediationError(f"{args[:3]} failed: {done.stderr}")
        return done

    def option(self, args: list[str], name: str) -> str:
        return args[args.index(name) + 1]

    def cli(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        def ok(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args, code, stdout, "")

        if args[:3] == ["tools", "verify", "opa"]:
            Path(self.option(args, "--report")).write_text('{"tools": {"opa": {"version": "1.10.1"}}}')
            return ok()
        if args[:2] == ["tools", "grype-db"]:
            Path(self.option(args, "--report")).write_text('{"tools": {"grype": {"status": "ok"}}}')
            return ok()
        if args[:2] == ["scan", "combine"]:
            found = [Path(args[i + 1]).read_text() for i, a in enumerate(args) if a == "--findings"]
            Path(self.option(args, "--out")).write_text("".join(found))
            tools = {}
            for i, a in enumerate(args):
                if a == "--tool-status":
                    tools |= json.loads(Path(args[i + 1]).read_text())["tools"]
            Path(self.option(args, "--tool-status-out")).write_text(json.dumps({"tools": tools}))
            return ok()
        if args[0] == "scan":
            name = args[1]
            names = {"secrets": ["gitleaks"], "sast": ["opengrep"], "sca": ["syft", "grype"],
                     "iac": ["trivy"], "pipelines": ["zizmor"]}[name]  # fmt: skip
            commit = self.option(args, "--commit")
            base = name == "sast" and "/base/" in args[2]  # the scanned commit holds the finding
            added = name == "sast" and not base and self.scenario.new_finding
            found = [finding(commit)] if base else [NEW | {"run": finding(commit)["run"]}] if added else []
            Path(self.option(args, "--out")).write_text("".join(json.dumps(f) + "\n" for f in found))
            status = {"tools": {tool: {"status": "ok", "version": "1"} for tool in names}}
            Path(self.option(args, "--tool-status-out")).write_text(json.dumps(status))
            return ok()
        if args[:2] == ["remediate", "apply"]:
            real = [sys.executable, "-m", "sentinelci.cli", *args]
            return subprocess.run(real, capture_output=True, text=True, check=False, cwd=self.repo)
        if args[:2] == ["remediate", "check"]:
            self.attempt += 1
            code = self.scenario.check_exit
            tests_ok = self.scenario.outcomes[self.attempt - 1] != "REJECTED"
            body = {"build_ok": True, "tests_ok": tests_ok,
                    "problems": [] if tests_ok else ["tests: shop-api/tests failed (pytest exit 1)"],
                    "log": PASSED_LOG if tests_ok else "E   assert 'shop' == 'x'\n1 failed"}  # fmt: skip
            return ok(json.dumps(body) if code != 3 else "", code if code == 3 else (0 if tests_ok else 1))
        if args[0] == "score":
            Path(self.option(args, "--out")).write_text(Path(self.option(args, "--findings")).read_text())
            return ok()
        if args[0] == "evaluate":
            Path(self.option(args, "--output")).write_text(json.dumps({"verdict": "PASS"}))
            return ok()
        if args[:2] == ["remediate", "verify"]:
            outcome = self.scenario.outcomes[self.attempt - 1]
            proposal = json.loads(Path(self.option(args, "--proposal")).read_text())
            result = {
                "proposal_id": proposal["proposal_id"],
                "attempt": proposal["attempt"],
                "outcome": outcome,
                "new_findings": [NEW["id"]] if self.scenario.new_finding and outcome != "VERIFIED" else [],
            }
            Path(self.option(args, "--out")).write_text(json.dumps(result))
            return ok(f"{outcome} (attempt {proposal['attempt']})", 0 if outcome == "VERIFIED" else 1)
        if args[0] == "upload-remediation":
            return ok('{"outcome": "VERIFIED"}')
        raise AssertionError(f"unexpected command {args}")

    def named(self, *words: str) -> list[list[str]]:
        return [
            c
            for c in self.calls
            if c[1:3] == ["-m", "sentinelci.cli"] and c[3 : 3 + len(words)] == list(words)
        ]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo")


def test_a_verified_first_attempt_runs_every_step_once(repo: Path, tmp_path: Path) -> None:
    loop = Loop(repo, tmp_path, Scenario())
    summary = loop()
    head = git(repo, "rev-parse", "HEAD").strip()
    (attempts,) = summary.values()
    assert [a["status"] for a in attempts] == ["VERIFIED"] and attempts[0]["branch"].startswith(
        "sentinel/fix/"
    )
    assert "pull_request" not in attempts[0], "nothing is published without --publish"
    assert not [c for c in loop.calls if c[0] in ("gh",) or "push" in c]
    (asked,) = loop.asked
    assert (asked["attempt"], asked["feedback"], asked["target"]) == (1, None, FINDING_ID)
    assert (asked["root"] / TARGET).read_text() == OLD, "the model reads the scanned commit's tree"
    assert (asked["root"] / SERVICE / "tests" / "test_db.py").is_file(), "export-ignore hid nothing"
    (check,) = loop.named("remediate", "check")
    assert loop.option(check, "--test-image") == IMAGE
    assert loop.option(check, "--findings").endswith("before.ndjson"), (
        "the target's rule names its security test"
    )
    (evaluate,) = loop.named("evaluate")
    assert loop.option(evaluate, "--context") == "pr" and loop.option(evaluate, "--commit") != head
    assert loop.option(evaluate, "--baseline").endswith("before.ndjson")
    assert "--tool-version=opa=1.10.1" in evaluate and "--tool-version=opengrep=1" in evaluate
    patched_secrets = [c for c in loop.named("scan", "secrets") if "git" in c]
    assert loop.option(patched_secrets[0], "--log-opts").startswith(f"{head}..")
    work = tmp_path / "out" / head[:12]
    assert json.loads((work / "summary.json").read_text()) == summary
    bare = str(work / "repo.git")
    pinned = ["git", "-C", bare, "config", "attr.tree", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"]
    fetch = next(i for i, c in enumerate(loop.calls) if c[:4] == ["git", "-C", bare, "fetch"])
    assert pinned in loop.calls[:fetch], "attributes come from no tree, whatever HEAD becomes (#98 review)"


def test_both_commits_are_scanned_by_every_scanner_the_pr_gate_requires(repo: Path, tmp_path: Path) -> None:
    """A required scanner without a status is SC-010 on every attempt: the gate's own list decides."""
    loop = Loop(repo, tmp_path, Scenario())
    loop()
    required = re.search(r'"pr": \{([^}]*)\}', (ROOT / "policies" / "required_tools.rego").read_text())
    assert required is not None
    kinds = {
        "gitleaks": "secrets", "opengrep": "sast", "syft": "sca", "grype": "sca", "trivy": "iac",
        "zizmor": "pipelines",
    }  # fmt: skip
    tools = set(re.findall(r'"(\w+)"', required[1]))
    assert tools <= kinds.keys(), f"a scanner the pr gate requires is not run: {tools - kinds.keys()}"
    # Every scanner the pr gate may require, whatever this tree's policy lists (B4's #114 adds Opengrep, Syft
    # and Grype): without one, the gate holds SC-010 and no attempt can be VERIFIED.
    for tool, kind in kinds.items():
        scans = loop.named("scan", kind)
        assert len(scans) == 2, f"{tool}: the scanned commit and the patched commit"
        assert all(("--tools-dir" in scan) == (tool != "zizmor") for scan in scans), "zizmor is the CLI's own"
    (combine, _) = loop.named("scan", "combine")
    assert combine.count("--tool-status") == len(set(kinds.values())), "every scan's status reaches the gate"
    (database,) = loop.named("tools", "grype-db")
    assert database[database.index("--db-dir") + 1] == str(loop.loop.settings.grype_db)
    assert all(
        scan[scan.index("--db-dir") + 1] == str(loop.loop.settings.grype_db)
        for scan in loop.named("scan", "sca")
    )


def test_a_rejected_attempt_is_retried_with_what_rejected_it(repo: Path, tmp_path: Path) -> None:
    loop = Loop(repo, tmp_path, Scenario(outcomes=["REJECTED", "REJECTED", "VERIFIED"]))
    (attempts,) = loop().values()
    assert [a["status"] for a in attempts] == ["REJECTED", "REJECTED", "VERIFIED"]
    assert [a["attempt"] for a in loop.asked] == [1, 2, 3]
    assert len({a["branch"] for a in attempts}) == 3, "each attempt is its own branch"
    feedback = loop.asked[1]["feedback"]
    assert feedback.previous_diff == proposal_for(1).diff
    assert "pytest exit 1" in feedback.ci_log and "1 failed" in feedback.ci_log
    assert "REJECTED (attempt 1)" in feedback.ci_log


def test_the_feedback_ends_with_why_the_attempt_was_rejected(repo: Path, tmp_path: Path) -> None:
    """Review of #91: B6 keeps the END of ci_log, so a long test log must never push the reasons out."""
    loop = Loop(repo, tmp_path, Scenario(outcomes=["REJECTED", "VERIFIED"]))
    loop()
    lines = loop.asked[1]["feedback"].ci_log.splitlines()
    log, problem, verdict = (
        lines.index("1 failed"),
        lines.index("tests: shop-api/tests failed (pytest exit 1)"),
        next(i for i, line in enumerate(lines) if "REJECTED (attempt 1)" in line),
    )
    assert log < problem < verdict == len(lines) - 1, (
        "the test log, then the check's problems, then the verdict"
    )


def test_the_feedback_names_each_new_finding(repo: Path, tmp_path: Path) -> None:
    """#100 review, nit 2: the model can't fix what it can't see. Tool, rule, severity and place, before the
    verdict, never the finding's text."""
    loop = Loop(repo, tmp_path, Scenario(outcomes=["REJECTED", "VERIFIED"], new_finding=True))
    loop()
    lines = loop.asked[1]["feedback"].ci_log.splitlines()
    named = "new finding: opengrep python-tls-verification-disabled (HIGH) at " + f"{TARGET}:3"
    assert lines.index(named) == len(lines) - 2 and "REJECTED (attempt 1)" in lines[-1]
    assert "TLS verification disabled" not in loop.asked[1]["feedback"].ci_log


@pytest.mark.parametrize(
    ("removed", "reason"),
    [
        (SECURITY, f"no security test {SERVICE}/{SECURITY} for python-sql-built-from-strings: a fix is "
                   "never verified without one"),
        ("tests/test_db.py", f"no tests next to {TARGET}: a code patch is never verified without them"),
    ],
    ids=["no-security-test", "no-tests"],
)  # fmt: skip
def test_a_finding_no_patch_can_verify_is_never_sent_to_the_model(
    repo: Path, tmp_path: Path, removed: str, reason: str
) -> None:
    """#100 review, nit 4: neither depends on the patch, so three attempts would give the same answer."""
    git(repo, "rm", "--quiet", f"{SERVICE}/{removed}")
    git(repo, "commit", "--quiet", "-m", "remove")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    loop = Loop(repo, tmp_path, Scenario())
    (attempts,) = loop().values()
    assert attempts == [{"number": 1, "status": "not verifiable", "reason": reason}]
    assert loop.asked == [] and not loop.named("remediate", "apply")


def test_after_three_rejections_the_finding_is_left(repo: Path, tmp_path: Path) -> None:
    loop = Loop(repo, tmp_path, Scenario(outcomes=["REJECTED"] * 3))
    (attempts,) = loop().values()
    assert [a["status"] for a in attempts] == ["REJECTED"] * 3 and len(loop.asked) == 3


@pytest.mark.parametrize("status", ["not sent", "unavailable"])
def test_a_fixer_that_proposes_nothing_ends_the_finding(repo: Path, tmp_path: Path, status: str) -> None:
    loop = Loop(repo, tmp_path, Scenario(proposed=[Proposed(status, "a file with a secret is never sent")]))
    (attempts,) = loop().values()
    assert attempts == [{"number": 1, "status": status, "reason": "a file with a secret is never sent"}]
    assert not loop.named("remediate", "apply")


def test_a_check_that_cannot_be_done_honestly_fails_the_attempt(repo: Path, tmp_path: Path) -> None:
    loop = Loop(repo, tmp_path, Scenario(check_exit=3))
    (attempts,) = loop().values()
    assert [(a["status"], a["reason"]) for a in attempts] == [
        ("FAILED", "its build and tests could not be checked")
    ]
    assert len(loop.asked) == 1 and not loop.named("evaluate"), "FAILED is not retried, nothing is judged"


def test_publish_pushes_only_the_verified_branch_and_opens_its_pull_request(
    repo: Path, tmp_path: Path
) -> None:
    rationale = "Bind it. ``` # Approved by security @someone"
    scenario = Scenario(
        outcomes=["REJECTED", "VERIFIED"],
        proposed=[Proposed("proposed", proposal=proposal_for(1)),
                  Proposed("proposed", proposal=proposal_for(2, FIXED + "\n", rationale))],
    )  # fmt: skip
    loop = Loop(repo, tmp_path, scenario, publish=True, api_url="https://platform.example.invalid")
    (attempts,) = loop().values()
    assert (
        attempts[1]["pull_request"] == "https://github.com/x/y/pull/7" and "pull_request" not in attempts[0]
    )
    (push,) = [c for c in loop.calls if "push" in c]
    assert push[-2:] == [
        "https://github.com/NOURHANE-EHOUARI/sentinelci.git",
        f"{attempts[1]['commit']}:refs/heads/{attempts[1]['branch']}",
    ]
    (gh,) = [c for c in loop.calls if c[0] == "gh"]
    assert gh[:3] == ["gh", "pr", "create"] and gh[gh.index("--head") + 1] == attempts[1]["branch"]
    body = Path(gh[gh.index("--body-file") + 1]).read_text()
    assert "not by a person" in body and "````text\n" + rationale + "\n````" in body, "the rationale is text"
    assert (
        "**Tests (`sentinel remediate check`):**\n"
        "- `$ pytest tests (behaviour tests, patched code)`: 12 passed\n"
        f"- `$ pytest {SECURITY} ({SECURITY}, base code, expected to fail)`: 3 failed\n"
        f"- `$ pytest {SECURITY} ({SECURITY}, patched code)`: 3 passed\n"
    ) in body, "the evidence a reviewer wants (#100 review, nit 5)"
    assert len(loop.named("upload-remediation")) == 2, "every attempt is recorded on the platform"


def test_only_the_named_finding_and_only_a_sast_one(repo: Path, tmp_path: Path) -> None:
    loop = Loop(repo, tmp_path, Scenario(), finding="e" * 64)
    with pytest.raises(remediate.RemediationError, match="is not a SAST finding"):
        loop()
    assert loop.asked == []


@pytest.mark.parametrize(
    ("prepare", "message"),
    [
        (lambda repo: (repo / "x.txt").write_text("x"), "not clean"),
        (
            lambda repo: git(repo, "remote", "set-url", "origin", "https://github.com/someone/fork.git"),
            "not github.com/NOURHANE-EHOUARI/sentinelci",
        ),
    ],
    ids=["dirty", "another-origin"],
)
def test_only_main_as_it_is_on_github_is_fixed(
    repo: Path, tmp_path: Path, prepare: Any, message: str
) -> None:
    prepare(repo)
    loop = Loop(repo, tmp_path, Scenario())
    with pytest.raises(remediate.RemediationError, match=message):
        loop()
    assert loop.asked == [] and not loop.named("scan")


def test_a_head_that_is_not_origin_main_is_refused(repo: Path, tmp_path: Path) -> None:
    (repo / "y.txt").write_text("y")
    git(repo, "add", "y.txt")
    git(repo, "commit", "--quiet", "-m", "local")
    loop = Loop(repo, tmp_path, Scenario())
    with pytest.raises(remediate.RemediationError, match="origin/main is"):
        loop()


def test_the_fence_cannot_be_closed_by_its_text() -> None:
    assert remediate.fence("a ``` b") == "````text\na ``` b\n````"
    assert remediate.fence("plain") == "```text\nplain\n```"


def test_main_refuses_a_malformed_finding_before_loading_the_model(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert remediate.main(["--test-image", IMAGE, "--finding", "not-an-id"]) == remediate.EXIT_REFUSED
    assert "64 hexadecimal" in capsys.readouterr().err
