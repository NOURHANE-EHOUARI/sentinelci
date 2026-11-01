"""`sentinel scan sast`: Opengrep, never configured or silenced by the scanned repository (task A1).

Unit tests use a fake `opengrep` script pinned in a test lock. Integration tests use the real binary and run
only when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.opengrep import OFFLINE_ENV, escaping_links, scan_sast_with_run

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
FIXTURE = Path(__file__).resolve().parents[1] / "normalize" / "fixtures" / "opengrep" / "results.json"
SHELL = 'import subprocess\n\n\ndef f(name):\n    subprocess.run("ls " + name, shell=True)\n'


def _result(target: Path) -> dict[str, Any]:
    """A real Opengrep result (from the normalizer fixture), moved under `target`."""
    result: dict[str, Any] = json.loads(FIXTURE.read_text())[2]  # python-sql-built-from-strings
    result["path"] = str(target.resolve() / "app" / "sql.py")
    return result


def fake_opengrep(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    report: dict[str, Any] | str | None = None,
    exit_code: int = 0,
) -> tuple[Path, Path]:
    """A fake opengrep that records its call and prints `report` (JSON) on stdout."""
    record = tmp_path / "record"
    record.mkdir()
    payload = tmp_path / "report.json"
    text = (
        report
        if isinstance(report, str)
        else json.dumps(report or {"version": "1.0.0", "results": [], "errors": []})
    )
    payload.write_text(text)
    script = f"""printf '%s\\n' "$@" > {record}/argv
env > {record}/env
pwd > {record}/cwd
cat {payload}
exit {exit_code}
"""
    _, dest = install_script(tmp_path, releases, write_lock, script, tool="opengrep")
    return dest, record


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    (target / "app").mkdir(parents=True)
    (target / "app" / "sql.py").write_text("def f(cur, uid):\n    cur.execute(f'SELECT {uid}')\n")
    return target


def _scan(tmp_path: Path, dest: Path, target: Path, repo_root: Path | None = None):  # type: ignore[no-untyped-def]
    return scan_sast_with_run(
        target,
        lock=load_lock(tmp_path / "tools.lock.toml"),
        tools_dir=dest,
        repo_root=repo_root,
        platform=PLATFORM,
    )


def test_opengrep_runs_isolated_with_sentinelcis_rules_only(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("SEMGREP_RULES", "p/default")  # a SEMGREP_* variable of the job never reaches Opengrep
    target = _target(tmp_path)
    dest, record = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [], "errors": []}
    )
    scan = _scan(tmp_path, dest, target)
    argv = (record / "argv").read_text().splitlines()
    assert argv[:2] == ["scan", "--config"] and argv[2].endswith(os.path.join("configs", "opengrep"))
    assert argv[3:] == [
        "--json", "--no-rewrite-rule-ids", "--disable-nosem", "--no-git-ignore",
        "--x-ignore-semgrepignore-files", "--disable-version-check", "--max-target-bytes=0", "--timeout=0",
        "--", str(target.resolve()),
    ]  # fmt: skip
    env = dict(line.split("=", 1) for line in (record / "env").read_text().splitlines() if "=" in line)
    assert "GITHUB_TOKEN" not in env and "SEMGREP_RULES" not in env
    assert all(env.get(key) == value for key, value in OFFLINE_ENV.items())
    cwd = Path((record / "cwd").read_text().strip())
    assert not cwd.is_relative_to(target) and not cwd.exists(), "a private, empty working directory"
    assert (scan.results, scan.warnings, scan.run.stdout) == ([], [], "")


@pytest.mark.parametrize(
    ("report", "exit_code", "message"),
    [
        (None, 2, "exited with code 2"),
        ("", 0, "no `results` list"),
        ("{not json", 0, "unreadable JSON"),
        ({"version": "1.0.0", "results": {}, "errors": []}, 0, "no `results` list"),
        ({"version": "1.0.0", "results": ["x"], "errors": []}, 0, "results are not objects"),
        ({"version": "9.9.9", "results": [], "errors": []}, 0, "version '9.9.9', the lock pins 1.0.0"),
        ({"version": "1.0.0", "results": []}, 0, "no `errors` list"),
        ({"version": "1.0.0", "results": [], "errors": ["x"]}, 0, "malformed error entry"),
        ({"version": "1.0.0", "results": [],
          "errors": [{"level": "error", "type": "Fatal error", "path": "a.py"}]},
         0, "could not scan everything: Fatal error in a.py"),
        ({"version": "1.0.0", "results": [], "errors": [{"type": ["Timeout", []]}]},
         0, "could not scan everything: Timeout"),
    ],
    ids=["crash", "no-output", "unreadable", "results-not-list", "result-not-object", "other-version",
         "no-errors", "error-not-object", "fatal-error", "error-without-level"],
)  # fmt: skip
def test_unusable_runs_fail_closed(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    report: dict[str, Any] | str | None,
    exit_code: int,
    message: str,
) -> None:
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report, exit_code)
    with pytest.raises(ScannerError, match=message):
        _scan(tmp_path, dest, _target(tmp_path))


def test_a_file_parsed_only_in_part_is_a_warning(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    target = _target(tmp_path)
    error = {"level": "warn", "type": ["PartialParsing", []], "path": str(target.resolve() / "app" / "w.js")}
    dest, _ = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [], "errors": [error]}
    )
    assert _scan(tmp_path, dest, target).warnings == ["PartialParsing in app/w.js"]


@pytest.mark.parametrize(
    "case", ["file-link", "directory-link", "loop", "outside-the-root", "not-a-directory"]
)
def test_bad_targets_never_run_opengrep(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], case: str
) -> None:
    dest, record = fake_opengrep(tmp_path, releases, write_lock)
    target, root = _target(tmp_path), None
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lib.py").write_text(SHELL)
    expected = "symbolic links leave the scanned tree or loop"
    if case == "file-link":
        (target / "app" / "lib.py").symlink_to(outside / "lib.py")
    elif case == "directory-link":
        (target / "vendor").symlink_to(outside)
    elif case == "loop":
        (target / "a.py").symlink_to("b.py")
        (target / "b.py").symlink_to("a.py")
    elif case == "outside-the-root":
        root, expected = target, "outside the repository root"
        target = outside
    else:
        target, expected = target / "app" / "sql.py", "is not a directory"
    with pytest.raises(ScannerError, match=expected):
        _scan(tmp_path, dest, target, root)
    assert not (record / "argv").exists(), "the scanner must not even start"


def test_links_inside_the_tree_are_fine(tmp_path: Path) -> None:
    target = _target(tmp_path)
    (target / "alias.py").symlink_to(target / "app" / "sql.py")
    (target / "lib").symlink_to(target / "app")
    assert escaping_links(target) == []


def _cli(tmp_path: Path, dest: Path, target: Path, out: Path, repo_root: Path) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "scan", "sast", str(target), "--out", str(out), "--repo", "o/r", "--commit", "0" * 40,
            "--context", "pr", "--repo-root", str(repo_root), "--lock", str(tmp_path / "tools.lock.toml"),
            "--tools-dir", str(dest),
            "--platform", PLATFORM,
        ],
    )  # fmt: skip
    return result.exit_code, result.output


def test_cli_writes_repository_relative_sast_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    services = repo / "services"
    (services / "app").mkdir(parents=True)
    (services / "app" / "sql.py").write_text("def f(cur, uid):\n    cur.execute(f'SELECT {uid}')\n")
    warn = {"level": "warn", "type": ["PartialParsing", []], "path": str(services.resolve() / "app" / "w.js")}
    report = {"version": "1.0.0", "results": [_result(services)], "errors": [warn]}
    dest, _ = fake_opengrep(tmp_path, releases, write_lock, report)
    out = tmp_path / "out" / "sast.ndjson"
    code, output = _cli(tmp_path, dest, services, out, repo)
    assert code == 0, output
    (finding,) = [json.loads(line) for line in out.read_text().splitlines()]
    assert (finding["category"], finding["rule_id"]) == ("SAST", "python-sql-built-from-strings")
    assert finding["location"]["path"] == "services/app/sql.py"
    assert finding["tool"] == {"name": "opengrep", "version": "1.0.0"}
    assert "1 finding(s)" in output and "PartialParsing in app/w.js" in output


def test_cli_failure_leaves_no_findings(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    target = _target(tmp_path)
    dest, _ = fake_opengrep(
        tmp_path, releases, write_lock, {"version": "1.0.0", "results": [{"check_id": "x"}], "errors": []}
    )
    out = tmp_path / "sast.ndjson"
    out.write_text("stale")
    code, output = _cli(tmp_path, dest, target, out, target)
    assert code == 3 and "FAIL CLOSED" in output and "is not SentinelCI's" in output
    assert not out.exists()


# ---------------------------------------------------------------- the real Opengrep

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
@pytest.mark.integration
def test_real_opengrep_cannot_be_silenced_by_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each file below is skipped or hidden by a plain `opengrep scan`; SentinelCI reports all of them."""
    target = tmp_path / "repo"
    files = {
        "app/plain.py": SHELL,
        "app/semgrepignored.py": SHELL,
        "app/nosem.py": SHELL.replace("shell=True)", "shell=True)  # nosemgrep"),
        "app/gitignored.py": SHELL,
        "app/big.py": SHELL + "# padding\n" * 120_000,  # over Opengrep's default 1 MB limit
        "tests/test_x.py": SHELL,
        "node_modules/pkg/x.py": SHELL,
    }
    for name, text in files.items():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(text)
    (target / ".semgrepignore").write_text("app/semgrepignored.py\n")
    (target / ".gitignore").write_text("app/gitignored.py\n")
    (target / ".semgrep.yml").write_text(  # a repository rule file: never loaded
        "rules:\n  - id: their-rule\n    languages: [python]\n    severity: ERROR\n    message: x\n"
        "    pattern: def $F(...): ...\n"
    )
    monkeypatch.setenv("SEMGREP_RULES", str(target / ".semgrep.yml"))
    monkeypatch.chdir(target)  # the repository as working directory, as in CI: still ignored
    scan = scan_sast_with_run(target, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    found = {str(Path(r["path"]).relative_to(target.resolve())): r for r in scan.results}
    assert set(found) == set(files)
    assert {r["check_id"] for r in scan.results} == {"python-shell-command-from-data"}
    assert [name for name, r in found.items() if r["extra"]["is_ignored"]] == ["app/nosem.py"]
    assert scan.run.version == "1.33.1" and scan.warnings == []
