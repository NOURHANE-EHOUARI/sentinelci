"""`make remediate-code`: the LLM code fixer, run on the laptop, verified like the bot's patches (ADR-0014).

For each SAST finding of origin/main (or the one named with --finding), B6's `propose_code_fix` asks the
pinned local model (B5's OllamaProvider, digest checked before any prompt) for a patch. Each proposal goes
through the same steps as the bot's `verify` job (ADR-0013), with this checkout's CLI, policies and waivers,
which are origin/main's:

1. `sentinel remediate apply` commits it on its own `sentinel/fix/...` branch of a bare copy of the
   repository (plumbing only: nothing is checked out, no hook or filter runs);
2. the patched commit is scanned like a pull request: Gitleaks on its commits; Opengrep, Syft then Grype,
   Trivy and zizmor on its tree;
3. `sentinel remediate check --test-image` builds it, runs its service's behaviour tests on the patched code,
   and the target's security test on the base code (it must fail) and on the patched code (it must pass), in
   a sandboxed container;
4. the gate is evaluated on the patched commit in pr context, the scanned commit as baseline;
5. `sentinel remediate verify` applies the verification gate: VERIFIED, REJECTED or FAILED.

Grype's database is prepared once per run in out/grype-db (`sentinel tools grype-db`, checked against its
listing's checksum): the one download besides `git fetch`. If it cannot be prepared, nothing is scanned.

A REJECTED attempt is proposed again with its diff and what rejected it, the reasons last, each new finding
named (attempts 2 and 3, B6 redacts and clips both, and keeps the end); FAILED, or a fixer that sends nothing
or has no usable answer, ends the finding. A finding no patch could verify (no behaviour tests next to its
file, no security test for its rule) is never sent to the model. The bare copy's attributes come from the
empty tree (`attr.tree`), as in the bot's verify job. Every step's evidence is kept under
out/remediate-code/<commit>/. Nothing leaves the laptop unless asked:
- `--publish` pushes each VERIFIED branch to origin and opens its pull request with the person's own `gh`
  login, as they would by hand. The bot never merges and never approves: a person reviews it.
- `--api-url` records every attempt on the platform (`sentinel upload-remediation`, token from
  SENTINEL_API_TOKEN only).

The patched code never runs outside a container (CLAUDE.md): the scanners read it, and only `remediate check`
runs its tests, in the sandbox.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[2]
REPO = "NOURHANE-EHOUARI/sentinelci"
MAIN = "refs/heads/main"
SCAN_PATH = "demo-shop"
MAX_ATTEMPTS = 3
STEP_TIMEOUT_S = 3600
OUT = Path("out") / "remediate-code"
_COMMIT = re.compile(r"[a-f0-9]{40}")
_FINDING = re.compile(r"[a-f0-9]{64}")
_BRANCH = re.compile(r"sentinel/fix/[a-z0-9][a-z0-9._-]{0,63}")
_ORIGIN = re.compile(
    rf"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/){re.escape(REPO)}(?:\.git)?/?"
)
EXIT_DONE, EXIT_REFUSED = 0, 2


class RemediationError(Exception):
    """A step that cannot be done honestly: nothing is verified, nothing is published."""


class Runner(Protocol):
    def __call__(
        self,
        args: Sequence[str],
        *,
        cwd: Path = ...,
        env: Mapping[str, str] | None = ...,
        check: bool = ...,
        capture: bool = ...,
    ) -> subprocess.CompletedProcess[str]: ...


def run_command(
    args: Sequence[str],
    *,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command; a failure with `check` is a RemediationError naming the command, never its
    environment."""
    try:
        done = subprocess.run(  # noqa: S603 (fixed commands; arguments from the checkout, the lock and the CLI)
            list(args), cwd=cwd, env=dict(env) if env is not None else None, capture_output=capture,
            text=True,
            timeout=STEP_TIMEOUT_S, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemediationError(f"{args[0]} could not run: {type(exc).__name__}") from exc
    if check and done.returncode != 0:
        last = ((done.stderr or "").strip().splitlines() or ["see the output above"])[-1]
        raise RemediationError(f"{' '.join(args[:3])} failed ({done.returncode}): {last}")
    return done


def sentinel(*args: str) -> list[str]:
    """The CLI of this checkout: origin/main's, once the preconditions hold."""
    return [sys.executable, "-m", "sentinelci.cli", *args]


def preconditions(run: Runner, *, fetch: bool) -> str:
    """The commit to fix: HEAD, which must be origin's main, with a clean working tree."""
    origin = run(["git", "config", "--get", "remote.origin.url"], check=False)
    if origin.returncode != 0 or _ORIGIN.fullmatch(origin.stdout.strip()) is None:
        raise RemediationError(f"origin is not github.com/{REPO}: fix only the reviewed repository")
    dirty = run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).stdout.splitlines()
    if dirty:
        raise RemediationError("the working tree is not clean: run this from main as it is on GitHub")
    if fetch:
        run(["git", "fetch", "--quiet", "--no-tags", "origin", f"+{MAIN}:refs/remotes/origin/main"])
    head = run(["git", "rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip()
    main = run(
        ["git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False
    ).stdout.strip()
    if not _COMMIT.fullmatch(head) or head != main:
        raise RemediationError(f"HEAD is {head}, origin/main is {main or 'unknown'}: check out main first")
    return head


def fence(text: str) -> str:
    """`text` in a code block no line of it can close: shown as text, never rendered."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}text\n{text}\n{ticks}"


def tool_versions(*documents: Path) -> list[str]:
    versions: dict[str, str] = {}
    for document in documents:
        if document.is_file():
            tools = json.loads(document.read_text(encoding="utf-8")).get("tools") or {}
            versions |= {name: str(e.get("version")) for name, e in tools.items() if e.get("version")}
    return [f"--tool-version={name}={version}" for name, version in sorted(versions.items())]


@dataclass(frozen=True)
class Settings:
    test_image: str
    tools_dir: Path
    lock: Path = ROOT / "tools.lock.toml"
    grype_db: Path = ROOT / "out" / "grype-db"  # Grype's database, prepared at the start of each run
    timeout_s: int = 600
    publish: bool = False
    api_url: str | None = None
    finding: str | None = None


@dataclass
class Attempt:
    number: int
    status: str  # "proposed", "unavailable", "not sent", or the verification outcome
    reason: str = ""
    proposal_id: str | None = None
    branch: str | None = None
    commit: str | None = None
    pull_request: str | None = None

    def record(self) -> dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value not in (None, "")}


# What B6 and B5 give (`sentinel_ai.patch.propose_code_fix`, `OllamaProvider`), injected so that tests use
# stand-ins and the script runs without the model server until it is needed.
Propose = Callable[..., Any]


@dataclass
class RemediateCode:
    settings: Settings
    propose: Propose
    provider: Any
    model: str
    model_version: str | None
    run: Runner = run_command
    fetch: bool = True
    feedback_type: Callable[..., Any] | None = None  # B6's Feedback, imported when a retry needs it
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC).replace(microsecond=0))
    out: Path = ROOT / OUT
    root: Path = ROOT  # the checkout: origin/main, whose CLI, policies and waivers judge

    # ------------------------------------------------------------ the loop

    def __call__(self) -> dict[str, list[dict[str, Any]]]:
        base = preconditions(self.run, fetch=self.fetch)
        self.work = self.out / base[:12]
        self._fresh(self.work)
        self.base = base
        self.repo = self.work / "repo.git"
        self.run(["git", "init", "--quiet", "--bare", str(self.repo)])
        # Attributes come from no tree, whatever HEAD becomes (as in the bot's verify job, #98 review).
        empty = self.run(["git", "hash-object", "-t", "tree", "/dev/null"]).stdout.strip()
        self.run(["git", "-C", str(self.repo), "config", "attr.tree", empty])
        source = ["fetch", "--quiet", "--no-tags", str(self.root), "+HEAD:refs/sentinel/base"]
        self.run(["git", "-C", str(self.repo), *source])
        if self.run(["git", "-C", str(self.repo), "rev-parse", "refs/sentinel/base"]).stdout.strip() != base:
            raise RemediationError("the bare copy is not the checked-out commit")
        self.base_tree = self._export(base, self.work / "base", whole=True)
        self.opa_manifest = self.work / "opa-manifest.json"
        self.run(sentinel("tools", "verify", "opa", "--lock", str(self.settings.lock), "--dest",
                          str(self.settings.tools_dir), "--report", str(self.opa_manifest)))  # fmt: skip
        # The dependency scans need Grype's database: the only download, checked against its listing's
        # checksum. Without it nothing is scanned, so nothing is verified.
        database = ["--db-dir", str(self.settings.grype_db), "--report", str(self.work / "grype-db.json")]
        limits = ["--timeout", str(self.settings.timeout_s), "--lock", str(self.settings.lock)]
        tools = ["--tools-dir", str(self.settings.tools_dir)]
        self.run(sentinel("tools", "grype-db", *database, *limits, *tools))
        self.before = self.work / "before.ndjson"
        self._scan(self.base_tree, base, self.work / "base-scan", self.before, git_range=None)
        findings = self._findings(self.before)
        targets = self._targets(findings)
        summary: dict[str, list[dict[str, Any]]] = {}
        for target in targets:
            summary[target.id] = [attempt.record() for attempt in self._remediate(target, findings)]
        (self.work / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return summary

    def _unverifiable(self, target: Any) -> str | None:
        """Why no patch of this finding can ever be verified, or None: no behaviour tests next to its file, or
        no security test for its rule. Neither depends on the patch, so the model is not asked at all (#100
        review); `remediate check` still decides on every patch."""
        from sentinelci.remediation.code import CodeCheckError, security_test_of, service_of

        path = target.location.path
        service = service_of(self.base_tree, path)
        if service is None:
            return f"no tests next to {path}: a code patch is never verified without them"
        try:
            test = security_test_of(target.rule_id)
        except CodeCheckError as exc:
            return str(exc)
        if not (self.base_tree / service / test).is_file():
            rule = target.rule_id
            return f"no security test {service}/{test} for {rule}: a fix is never verified without one"
        return None

    def _remediate(self, target: Any, findings: list[Any]) -> list[Attempt]:
        why = self._unverifiable(target)
        if why is not None:
            return [Attempt(1, "not verifiable", why)]
        attempts: list[Attempt] = []
        feedback = None
        for number in range(1, MAX_ATTEMPTS + 1):
            outcome = self.propose(
                target, findings, self.base_tree, self.provider, model=self.model,
                model_version=self.model_version, attempt=number, feedback=feedback, created_at=self.now(),
            )  # fmt: skip
            if outcome.status != "proposed":
                attempts.append(Attempt(number, outcome.status, outcome.reason))
                break
            work = self.work / target.id[:12] / f"attempt-{number}"
            attempt = self._verify(target, outcome.proposal, number, work)
            attempts.append(attempt)
            if attempt.status != "REJECTED" or number == MAX_ATTEMPTS:
                break
            feedback = self._feedback(outcome.proposal, attempt, work)
        return attempts

    def _verify(self, target: Any, proposal: Any, number: int, work: Path) -> Attempt:
        """One attempt through the bot's verification steps; its evidence in `work`."""
        work.mkdir(parents=True)
        path = work / "proposal.json"
        path.write_text(proposal.model_dump_json(indent=2, exclude_none=True) + "\n", encoding="utf-8")
        attempt = Attempt(number, "FAILED", proposal_id=proposal.proposal_id)
        try:
            applied = json.loads(self.run(sentinel(
                "remediate", "apply", "--proposal", str(path), "--findings", str(self.before),
                "--repo-root", str(self.repo), "--base", self.base,
            )).stdout)  # fmt: skip
            attempt.branch, attempt.commit = applied["branch"], applied["commit"]
            if not _BRANCH.fullmatch(attempt.branch) or not _COMMIT.fullmatch(attempt.commit):
                raise RemediationError("the applied branch or commit is not one apply makes")
            patched = self._export(attempt.commit, work / "patched", whole=False)
            after = work / "after.ndjson"
            status = self._scan(
                patched, attempt.commit, work / "scan", after, git_range=f"{self.base}..{attempt.commit}"
            )
            checked = self.run(sentinel(
                "remediate", "check", "--proposal", str(path), "--base-root", str(self.base_tree),
                "--patched-root", str(patched), "--findings", str(self.before),
                "--test-image", self.settings.test_image,
            ), check=False)  # fmt: skip
            if checked.returncode not in (0, 1):
                raise RemediationError("its build and tests could not be checked")
            (work / "check.json").write_text(checked.stdout, encoding="utf-8")
            check = json.loads(checked.stdout)
            scored = work / "scored.ndjson"
            self.run(sentinel("score", "--findings", str(after), "--policy-dir", str(self.root / "policies"),
                              "--out", str(scored)))  # fmt: skip
            decision = work / "decision.json"
            evaluated = self.run(sentinel(
                "evaluate", "--findings", str(scored), "--repo", REPO, "--commit", attempt.commit,
                "--context", "pr", "--ref", f"refs/heads/{attempt.branch}", "--policy-dir", "policies",
                "--opa", str(self.settings.tools_dir / "bin" / "opa"),
                *tool_versions(self.opa_manifest, status),
                "--tool-status", str(status), "--baseline", str(self.before), "--output", str(decision),
            ), check=False)  # fmt: skip
            # Run from this checkout (origin/main), so with its waivers, as the bot's verify job does.
            if evaluated.returncode not in (0, 1):
                raise RemediationError("no decision on the patched commit")
            result = work / "result.json"
            verified = self.run(sentinel(
                "remediate", "verify", "--proposal", str(path), "--before", str(self.before),
                "--after", str(scored), "--decision", str(decision), "--tool-status", str(status),
                "--build-ok" if check["build_ok"] else "--build-failed",
                "--tests-ok" if check["tests_ok"] else "--tests-failed", "--out", str(result),
            ), check=False)  # fmt: skip
            if verified.returncode not in (0, 1):
                raise RemediationError("the verification gate refused its inputs")
            attempt.status = json.loads(result.read_text(encoding="utf-8"))["outcome"]
            attempt.reason = verified.stdout.strip()
        except (RemediationError, KeyError, ValueError) as exc:
            attempt.reason = str(exc)
            return attempt
        if self.settings.api_url:
            self._upload(path, result, attempt)
        if attempt.status == "VERIFIED" and self.settings.publish:
            try:
                attempt.pull_request = self._publish(target, proposal, attempt, work)
            except RemediationError as exc:
                attempt.reason += f" (not published: {exc})"
        return attempt

    def _feedback(self, proposal: Any, attempt: Attempt, work: Path) -> Any:
        """What rejected the attempt, for the next one, redacted and clipped by B6 before the model sees it.
        B6 keeps the END of this text (where a CI log's failure is), so the reasons come last: the tests' log
        first, then the check's problems, then the verification's summary (review of #91). With a long log,
        the model still sees why it was rejected, and as much of the log as fits."""
        make = self.feedback_type
        if make is None:
            from sentinel_ai.patch import Feedback

            make = Feedback
        check = json.loads((work / "check.json").read_text(encoding="utf-8"))
        parts = [check.get("log", ""), *check.get("problems", []), *self._new_findings(work), attempt.reason]
        return make(previous_diff=proposal.diff, ci_log="\n".join(part for part in parts if part))

    def _new_findings(self, work: Path) -> list[str]:
        """Which findings the patch brought, not only how many (#100 review): tool, rule, severity and place,
        never a finding's text or evidence."""
        result, scored = work / "result.json", work / "scored.ndjson"
        if not (result.is_file() and scored.is_file()):
            return []
        new = json.loads(result.read_text(encoding="utf-8")).get("new_findings", [])
        found = {finding.id: finding for finding in self._findings(scored)}
        lines = []
        for finding_id in new:
            finding = found.get(finding_id)
            if finding is None:
                continue
            place = finding.location
            line = f":{place.start_line}" if place and place.start_line else ""
            where = f"{place.path}{line}" if place else "-"
            tool = finding.tool.name
            lines.append(f"new finding: {tool} {finding.rule_id} ({finding.severity}) at {where}")
        return lines

    # ------------------------------------------------------------ the steps

    def _fresh(self, path: Path) -> None:
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True)

    def _export(self, commit: str, destination: Path, *, whole: bool) -> Path:
        """The commit's tree (or its scan path), from the bare copy, which has no worktree: the commit's own
        .gitattributes cannot drop or rewrite a file (--worktree-attributes)."""
        archive = destination.with_suffix(".tar")
        scope = [] if whole else ["--", SCAN_PATH]
        self.run(["git", "-C", str(self.repo), "archive", "--worktree-attributes", "--format=tar",
                  f"--output={archive}", commit, *scope])  # fmt: skip
        destination.mkdir(parents=True)
        try:
            with tarfile.open(archive) as tar:
                tar.extractall(destination, filter="data")
        except (OSError, tarfile.TarError) as exc:
            raise RemediationError(f"{archive.name} could not be unpacked: {exc}") from exc
        archive.unlink()
        return destination

    def _scan(self, tree: Path, commit: str, work: Path, out: Path, *, git_range: str | None) -> Path:
        """Gitleaks (on the tree, or on the commits of `git_range`), Opengrep, Syft then Grype, Trivy and
        zizmor (every scanner the pr gate requires, policies/required_tools.rego), combined into `out`;
        returns the combined tool status. A scan that fails is not a pass: the attempt is FAILED."""
        work.mkdir(parents=True, exist_ok=True)
        audit = ["--repo", REPO, "--commit", commit, "--context", "pr", "--run-id", "local",
                 "--timeout", str(self.settings.timeout_s), "--lock", str(self.settings.lock)]  # fmt: skip
        tools = ["--tools-dir", str(self.settings.tools_dir)]  # zizmor is the CLI's own: not for its audit
        target = str(tree / SCAN_PATH)
        database = ["--db-dir", str(self.settings.grype_db)]  # prepared at the start of the run
        if git_range is None:
            secrets = ["scan", "secrets", target, "--mode", "dir", "--repo-root", str(tree), *tools]
        else:
            secrets = ["scan", "secrets", str(self.repo), "--mode", "git", "--log-opts",
                       f"{git_range} -- {SCAN_PATH}", "--repo-root", str(self.repo), *tools]  # fmt: skip
        scans = {
            "secrets": secrets,
            "sast": ["scan", "sast", target, "--repo-root", str(tree), *tools],
            "sca": ["scan", "sca", target, "--repo-root", str(tree), *database, *tools],
            "iac": ["scan", "iac", target, "--repo-root", str(tree), *tools],
            "pipelines": ["scan", "pipelines", target, "--repo-root", str(tree)],
        }
        combine = ["scan", "combine", "--out", str(out), "--tool-status-out", str(work / "status.json")]
        for name, args in scans.items():
            self.run(sentinel(*args, *audit, "--out", str(work / f"{name}.ndjson"), "--tool-status-out",
                              str(work / f"{name}-status.json")))  # fmt: skip
            combine += [
                "--findings",
                str(work / f"{name}.ndjson"),
                "--tool-status",
                str(work / f"{name}-status.json"),
            ]
        self.run(sentinel(*combine))
        return work / "status.json"

    def _findings(self, path: Path) -> list[Any]:
        from sentinelci.contracts.finding import Finding

        return [
            Finding.model_validate_json(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def _targets(self, findings: list[Any]) -> list[Any]:
        sast = [f for f in findings if f.category == "SAST" and f.location and f.location.start_line]
        if self.settings.finding is None:
            return sast
        named = [f for f in sast if f.id == self.settings.finding]
        if not named:
            raise RemediationError(
                f"{self.settings.finding} is not a SAST finding of {self.base[:12]} with a line"
            )
        return named

    def _upload(self, proposal: Path, result: Path, attempt: Attempt) -> None:
        done = self.run(sentinel(
            "upload-remediation", "--proposal", str(proposal), "--result", str(result), "--repo", REPO,
            "--api-url", str(self.settings.api_url),
        ), check=False)  # fmt: skip
        if done.returncode != 0:
            attempt.reason += " (not recorded on the platform)"

    def _publish(self, target: Any, proposal: Any, attempt: Attempt, work: Path) -> str:
        """Push the verified branch and open its pull request, with the person's own git and gh."""
        url = self.run(["git", "config", "--get", "remote.origin.url"]).stdout.strip()
        if _ORIGIN.fullmatch(url) is None:
            raise RemediationError("origin is not the reviewed repository")
        branch = attempt.branch or ""
        ref = f"refs/heads/{branch}"
        self.run(["git", "-C", str(self.repo), "push", "--quiet", url, f"{attempt.commit}:{ref}"])
        decision = json.loads((work / "decision.json").read_text(encoding="utf-8"))
        place = target.location
        check = work / "check.json"
        body = "\n\n".join([
            f"**SentinelCI remediation (llm:code, attempt {attempt.number}): VERIFIED by the tests and the "
            "scanners, not by a person.** Review it before merging; the bot never merges.",
            f"**Finding:** `{target.rule_id}` in `{place.path}` line {place.start_line} (`{target.id}`)",
            f"**Proposal:** `{proposal.proposal_id}`, model `{proposal.model.name}`",
            "**The model's rationale:**\n" + fence(proposal.rationale),
            "**The patch:**\n" + fence(proposal.diff),
            "**Tests (`sentinel remediate check`):**\n" + fence("\n".join(_test_summaries(check))),
            f"**Gate on the patched commit:** {decision.get('verdict')}",
        ])  # fmt: skip
        (work / "pull-request.md").write_text(body + "\n", encoding="utf-8")
        title = f"fix(security): {target.rule_id} in {place.path} (llm:code, verified)"
        opened = self.run(["gh", "pr", "create", "--repo", REPO, "--base", "main", "--head", branch,
                           "--title", title[:200], "--body-file", str(work / "pull-request.md")])  # fmt: skip
        return opened.stdout.strip().splitlines()[-1] if opened.stdout.strip() else branch


def _test_summaries(check: Path) -> list[str]:
    """Each test run of the check and what pytest's summary says (#100 review): the evidence a reviewer
    wants, as `$ pytest <selection> (<what>): <summary>`. From the check's `runs` (every run, whatever the log
    kept); from its clipped `log` only for a check written before `runs` existed, where a run the clip cut
    into is left out (#100 review, nit 2)."""
    from sentinelci.remediation.code import summary_of

    result = json.loads(check.read_text(encoding="utf-8"))
    if isinstance(result.get("runs"), list):
        return [
            f"$ pytest {run.get('selection')} ({run.get('label')}): {run.get('summary') or 'no summary'}"
            for run in result["runs"]
            if isinstance(run, dict)
        ] or ["(no test ran)"]
    log = result.get("log", "")
    runs = [block for block in log.split("\n$ pytest ") if block]
    lines = []
    for number, block in enumerate(runs):
        header, _, output = block.partition("\n")
        if number == 0 and not header.startswith("$ pytest "):
            continue  # the start of a log clipped to its end
        said, _ = summary_of(output)
        # The log is the patched code's output too: shown as text (fenced), like the rationale and the diff.
        lines.append(f"$ pytest {header.removeprefix('$ pytest ')}: {said or 'no summary'}")
    return lines or ["(no test log kept)"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("--test-image", required=True, help="Image of the service's tests, pinned by digest.")
    parser.add_argument("--tools-dir", type=Path, default=ROOT / ".sentinel" / "tools")
    parser.add_argument("--grype-db", type=Path, default=ROOT / "out" / "grype-db",
                        help="Where Grype's database is prepared (`sentinel tools grype-db`).")  # fmt: skip
    parser.add_argument("--finding", help="Only this SAST finding (its id).")
    parser.add_argument("--publish", action="store_true", help="Push each VERIFIED branch and open its PR.")
    parser.add_argument("--api-url", help="Record every attempt on this platform (SENTINEL_API_TOKEN).")
    parser.add_argument("--no-fetch", action="store_true", help="Do not fetch origin first.")
    args = parser.parse_args(argv)
    if args.finding is not None and not _FINDING.fullmatch(args.finding):
        print("--finding is a finding id: 64 hexadecimal characters", file=sys.stderr)
        return EXIT_REFUSED
    from sentinel_ai.patch import propose_code_fix
    from sentinel_ai.providers.ollama import OllamaProvider

    provider = OllamaProvider.from_env()
    model = provider.generation
    settings = Settings(
        test_image=args.test_image, tools_dir=args.tools_dir, publish=args.publish, api_url=args.api_url,
        finding=args.finding, grype_db=args.grype_db.resolve(),
    )  # fmt: skip
    loop = RemediateCode(
        settings, propose_code_fix, provider, model.name, model.digest, fetch=not args.no_fetch
    )
    try:
        summary = loop()
    except RemediationError as exc:
        print(f"remediate-code: {exc}\nnothing was verified or published", file=sys.stderr)
        return EXIT_REFUSED
    for finding, attempts in summary.items():
        last = attempts[-1]
        print(f"{finding[:12]}: {last['status']} after {len(attempts)} attempt(s)"
              + (f" -> {last['pull_request']}" if "pull_request" in last else ""))  # fmt: skip
    print(f"evidence: {loop.work.relative_to(ROOT) if loop.work.is_relative_to(ROOT) else loop.work}")
    return EXIT_DONE


if __name__ == "__main__":
    sys.exit(main())
