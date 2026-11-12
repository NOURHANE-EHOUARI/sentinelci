"""Build and tests of an LLM code proposal (`llm:code`, task A6, SPEC §9, ADR-0014 decision 3).

A model's patch is code nobody has run. Its build and its tests are defined here, on the trees of the base and
of the patched commit (exported, never checked out), and the patched code only ever runs in a container:

- **Build**: every edited file is Python and still parses (`ast.parse`, which runs nothing). A file of
  another language has no build defined here, so it cannot be verified (CodeCheckError).
- **Tests**, two of them (ADR-0014 decision 3, review of #91). The service is the nearest directory above the
  edited file that holds a `tests/` directory with a `test_*.py` file, below the repository root (whose
  `tests/` are SentinelCI's own).
  1. Its behaviour tests (`tests/`) pass on the patched code.
  2. The target finding's own security test, `security_tests/test_<rule>.py` (the rule id with `-` as `_`),
     fails on the base code and passes on the patched code: the weakness is gone, not only the scanner's
     sight of it (a scanner can miss a rewritten pattern).
  Each runs with `python -m pytest` in a throwaway container from an image pinned by digest: no network, a
  read-only root file system, no capability, no new privilege, as `nobody`, with memory, process and CPU
  limits and a time limit. The service is mounted read-only, and the base commit's `tests/` and
  `security_tests/` are mounted over its own: a patch never brings its own tests. A patch that edits either,
  a service without behaviour tests, or a rule without a security test fails the tests: a code patch is never
  VERIFIED without them.

Only pytest's own answer counts, and only when its summary line agrees with its exit code (review of #100):
the patched code runs inside the pytest process, so it can end that process with exit 0 before any test ran,
or skip a test. A behaviour or patched run passes with exit 0 and a summary of passed tests and nothing else
(no skip, xfail, deselection or error); the base run "fails" with exit 1 and a summary with failed tests (a
test that ran and failed: exit 2 to 5 is a broken or empty test, which proves nothing). Any other answer, the
time limit included, fails the tests, with the end of the output kept as the feedback for a retry. This raises
the bar, it is not tamper-proof: code that prints a summary line of its own before it exits still passes, and
a person reads every diff.
A container that could not run at all (no Docker, an image that is not there) is CodeCheckError: nothing is
verified, which is not the same as a failed test.
"""

import ast
import re
import shutil
import subprocess
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from sentinelci.contracts.remediation import PatchProposal

LLM_CODE = "llm:code"
TEST_TIMEOUT_S = 300
MAX_LOG_CHARS = 8000  # the end of pytest's output kept for the result and a retry's feedback
# An image named by its digest (`name@sha256:...`) or a local image id (`sha256:...`): the tests always run
# in the same image, whatever a tag points to today.
PINNED_IMAGE = re.compile(r"^(?:[a-z0-9][a-z0-9._/:-]*@)?sha256:[a-f0-9]{64}$")
SCRATCH = "/tmp:rw,noexec,nosuid,size=64m"  # noqa: S108 (a tmpfs inside the container, not a host path)
SANDBOX = (
    "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--user", "65534:65534", "--pids-limit", "256", "--memory", "1g", "--memory-swap", "1g",
    "--cpus", "2", "--tmpfs", SCRATCH,
    "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
)  # fmt: skip
PYTEST = ("python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header")
SECURITY_TESTS = "security_tests"
RULE = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")  # an Opengrep rule id of SentinelCI's (normalize/opengrep.py)
# pytest's exit when tests ran and some failed (2 to 5: interrupted, internal, usage, nothing collected)
TESTS_FAILED = 1
# pytest's last summary line under -q: "3 passed in 0.04s", "1 failed, 2 passed, 1 warning in 0.31s (0:00:01)"
SUMMARY = re.compile(r"(?:=+ )?((?:\d+ [a-z]+, )*\d+ [a-z]+) in \d+(?:\.\d+)?s(?: \([0-9:]+\))?(?: =+)?")
ONLY_PASSED = frozenset({"passed", "warning", "warnings"})
DOCKER_FAILURES = (125, 126, 127)  # docker itself, or the command in the image, could not start
TIMED_OUT = (124, 137)  # `timeout -s KILL` in the container, or the memory limit
GRACE_S = 30  # the client waits this much longer than the container's own time limit


class CodeCheckError(Exception):
    """The build and tests cannot be checked honestly: nothing is verified."""


@dataclass(frozen=True)
class Ran:
    returncode: int
    output: str
    timed_out: bool = False


Runner = Callable[[Sequence[str], int], Ran]


@dataclass(frozen=True)
class CodeChecked:
    build_ok: bool
    tests_ok: bool
    problems: list[str]  # "build: <file>: <why>", then "tests: <why>"
    log: str = ""  # the end of the tests' output ("" when they did not run)


def docker_runner(args: Sequence[str], timeout: int) -> Ran:
    """`docker <args>` with a time limit. The named container is removed even when the client is stopped,
    since stopping `docker run` does not stop its container."""
    docker = shutil.which("docker")
    if docker is None:
        raise CodeCheckError("docker is not on PATH: the tests cannot run")
    name = args[list(args).index("--name") + 1]
    try:
        done = subprocess.run(  # noqa: S603 (an argument list, no shell)
            [docker, *args], capture_output=True, encoding="utf-8", errors="replace",
            timeout=timeout + GRACE_S, check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        return Ran(returncode=-1, output=output, timed_out=True)
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=60, check=False)  # noqa: S603
    return Ran(returncode=done.returncode, output=done.stdout + done.stderr)


def _regular_file(root: Path, path: str, side: str) -> Path:
    pure = PurePosixPath(path)
    candidate = root / path
    if pure.is_absolute() or ".." in pure.parts or not candidate.is_file():
        raise CodeCheckError(f"{path} is not a regular file of the {side} tree")
    if candidate.resolve() != root.resolve() / path:
        raise CodeCheckError(f"{path} is reached through a symbolic link in the {side} tree")
    return candidate


def service_of(root: Path, path: str) -> str | None:
    """The nearest directory above `path`, below the repository root, that holds a `tests/` directory with a
    `test_*.py` file; None when there is none."""
    parts = PurePosixPath(path).parts[:-1]
    for depth in range(len(parts), 0, -1):
        tests = root.joinpath(*parts[:depth], "tests")
        if tests.is_dir() and not tests.is_symlink() and any(tests.rglob("test_*.py")):
            return "/".join(parts[:depth])
    return None


def _not_python(text: str, path: str) -> str | None:
    """Why `text` is not Python, or None."""
    try:
        ast.parse(text, filename=path)
    except SyntaxError as exc:
        return f"not valid Python any more (line {exc.lineno})"
    except (ValueError, MemoryError, RecursionError) as exc:
        return f"not valid Python any more ({type(exc).__name__})"
    return None


def _tail(text: str) -> str:
    return text if len(text) <= MAX_LOG_CHARS else "..." + text[-(MAX_LOG_CHARS - 3) :]


def summary_of(output: str) -> tuple[str, dict[str, int]]:
    """pytest's last summary line in `output` and its counts by word; ("", {}) when there is none (the
    process ended before pytest could say what ran)."""
    for line in reversed(output.splitlines()):
        found = SUMMARY.fullmatch(line.strip())
        if found:
            parts = (part.split(" ", 1) for part in found.group(1).split(", "))
            return found.group(1), {word: int(count) for count, word in parts}
    return "", {}


def _answered(counts: dict[str, int], expected: int) -> bool:
    """The summary says what the exit code says: tests failed (the base run), or passed and nothing else."""
    if expected == TESTS_FAILED:
        return counts.get("failed", 0) > 0
    return counts.get("passed", 0) > 0 and counts.keys() <= ONLY_PASSED


def _tests_failed(why: str, log: str = "") -> CodeChecked:
    return CodeChecked(build_ok=True, tests_ok=False, problems=[f"tests: {why}"], log=log)


def security_test_of(rule: str) -> str:
    """The security test of a rule, relative to its service: `security_tests/test_<rule>.py`."""
    if not RULE.fullmatch(rule):
        raise CodeCheckError(f"{rule!r} is not a rule id a security test can be named after")
    return f"{SECURITY_TESTS}/test_{rule.replace('-', '_')}.py"


def check_code(
    proposal: PatchProposal,
    base_root: Path,
    patched_root: Path,
    *,
    rule: str,
    test_image: str,
    run: Runner | None = None,
    timeout: int = TEST_TIMEOUT_S,
) -> CodeChecked:
    """Build and test an `llm:code` proposal for the finding of `rule`: its edited files parse, its service's
    behaviour tests pass on the patched code, and the rule's security test fails on the base code and passes
    on the patched code, each in a sandboxed container from `test_image`. CodeCheckError when that cannot be
    done honestly."""
    if proposal.strategy != LLM_CODE:
        raise CodeCheckError(f"{proposal.strategy} is not a code strategy")
    if not PINNED_IMAGE.match(test_image):
        raise CodeCheckError("the test image must be pinned by digest (name@sha256:..., or a sha256: id)")
    security_test = security_test_of(rule)
    build: list[str] = []
    for path in sorted(proposal.files):
        if PurePosixPath(path).suffix != ".py":
            raise CodeCheckError(f"no build is defined here for {path}: only Python is checked")
        _regular_file(base_root, path, "base")
        try:
            text = _regular_file(patched_root, path, "patched").read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            build.append(f"{path}: not UTF-8 any more")
            continue
        problem = _not_python(text, path)
        if problem:
            build.append(f"{path}: {problem}")
    if build:
        problems = [f"build: {problem}" for problem in build] + ["tests: not run, the build failed"]
        return CodeChecked(build_ok=False, tests_ok=False, problems=problems)
    services = {service_of(base_root, path) for path in proposal.files}
    service = services.pop() if len(services) == 1 else None
    if service is None:
        where = ", ".join(sorted(proposal.files))
        return _tests_failed(f"no tests next to {where}: a code patch is never verified without them")
    for kept in ("tests", SECURITY_TESTS):
        if any(path.startswith(f"{service}/{kept}/") for path in proposal.files):
            return _tests_failed(f"the patch edits its service's {kept}, which then prove nothing")
    base_security = base_root / service / security_test
    if (
        not base_security.is_file()
        or base_security.resolve() != base_root.resolve() / service / security_test
    ):
        return _tests_failed(
            f"no security test {service}/{security_test} for {rule}: a fix is never verified without one"
        )
    runs = (
        ("behaviour tests, patched code", patched_root, "tests", 0),
        # Labelled so a retry's model does not chase a failure that is not its own (#100 review).
        (f"{security_test}, base code, expected to fail", base_root, security_test, TESTS_FAILED),
        (f"{security_test}, patched code", patched_root, security_test, 0),
    )
    kept_tests = (base_root / service / "tests").resolve()
    kept_security = (base_root / service / SECURITY_TESTS).resolve()
    logs: list[str] = []
    for label, tree, selected, expected in runs:
        name = f"sentinel-tests-{uuid.uuid4().hex}"
        args = [
            "run", "--rm", "--name", name, *SANDBOX,
            "--mount", f"type=bind,source={(tree / service).resolve()},target=/srv,readonly",
            "--mount", f"type=bind,source={kept_tests},target=/srv/tests,readonly",
            "--mount", f"type=bind,source={kept_security},target=/srv/{SECURITY_TESTS},readonly",
            "--workdir", "/srv", test_image, "timeout", "-s", "KILL", str(timeout), *PYTEST, selected,
        ]  # fmt: skip
        ran = (run or docker_runner)(args, timeout)
        logs.append(f"$ pytest {selected} ({label})\n{ran.output}")
        log = _tail("\n".join(logs))
        if ran.timed_out or ran.returncode in TIMED_OUT:
            return _tests_failed(f"{label}: did not finish within {timeout} s, or ran out of memory", log)
        if ran.returncode in DOCKER_FAILURES:
            raise CodeCheckError(f"the test container could not run (docker exit {ran.returncode})")
        if ran.returncode != expected:
            why = (
                f"the {security_test} of {rule} does not fail on the base code "
                f"(pytest exit {ran.returncode}): it proves nothing about this fix"
                if expected == TESTS_FAILED
                else f"{service}/{selected} failed on the patched code (pytest exit {ran.returncode})"
            )
            return _tests_failed(why, log)
        said, counts = summary_of(ran.output)
        if not _answered(counts, expected):
            shown = f"its summary says {said}" if said else "it printed no summary"
            return _tests_failed(
                f"{label}: pytest's summary does not show that (exit {ran.returncode}, {shown}): an early "
                "exit, a skip or a deselection proves nothing",
                log,
            )
    return CodeChecked(build_ok=True, tests_ok=True, problems=[], log=_tail("\n".join(logs)))
