"""`sentinel scan secrets`: Gitleaks hardened against repository-controlled suppressions (task A1b).

Unit tests use a fake `gitleaks` script pinned in a test lock. Integration tests use the real binary
and run only when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
import random
import string
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.gitleaks import normalize_gitleaks
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.gitleaks import MAX_ARCHIVE_DEPTH, _repair_remerge_paths, scan_secrets
from sentinelci.scanners.lock import load_lock

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"

# A fake gitleaks that records its argv and writes a fixed report to --report-path.
FAKE_GITLEAKS = r"""
printf '%s\n' "$@" > "$SENTINEL_ARGV_FILE_PLACEHOLDER"
while [ $# -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then shift; REPORT="$1"; fi
  shift
done
echo "$REPORT" > "$SENTINEL_REPORT_PATH_PLACEHOLDER"
cat > "$REPORT" <<'JSON'
[{"RuleID": "generic-api-key", "Description": "Generic API Key", "StartLine": 3, "EndLine": 3,
  "Match": "key = \"fake-value-for-tests-only\"", "Secret": "fake-value-for-tests-only",
  "File": "app/settings.py", "Commit": "", "Tags": []}]
JSON
"""


def fake_gitleaks(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], body: str | None = None
):
    argv_file = tmp_path / "argv.txt"
    report_path_file = tmp_path / "report-path.txt"
    script = (
        (body or FAKE_GITLEAKS)
        .replace("$SENTINEL_ARGV_FILE_PLACEHOLDER", str(argv_file))
        .replace("$SENTINEL_REPORT_PATH_PLACEHOLDER", str(report_path_file))
    )
    lock, dest = install_script(tmp_path, releases, write_lock, script, tool="gitleaks")
    return lock, dest, argv_file, report_path_file


def test_hardened_flags_are_always_passed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()

    scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)

    argv = argv_file.read_text().splitlines()
    assert argv[0] == "dir"
    config = Path(argv[argv.index("--config") + 1])
    assert not config.is_relative_to(repo), "the scanned repository must not choose the scanner config"
    ignore_dir = Path(argv[argv.index("--gitleaks-ignore-path") + 1])
    assert not ignore_dir.is_relative_to(repo)
    assert "--ignore-gitleaks-allow" in argv
    assert argv[argv.index("--exit-code") + 1] == "0"
    assert argv[argv.index("--report-format") + 1] == "json"
    assert not any(arg.startswith("--redact") for arg in argv), "the normalizer hashes secrets itself"


def test_raw_report_with_secrets_is_deleted_after_the_scan(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _, report_path_file = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()

    raw = scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)

    assert raw[0]["Secret"] == "fake-value-for-tests-only"  # noqa: S105 (fixture value)
    assert not Path(report_path_file.read_text().strip()).exists()


def test_repository_ignore_file_is_refused(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # Gitleaks always loads <source>/.gitleaksignore (cmd/root.go), whatever --gitleaks-ignore-path says.
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitleaksignore").write_text("app/settings.py:generic-api-key:3\n")

    with pytest.raises(ScannerError, match=r"\.gitleaksignore .* use SentinelCI waivers"):
        scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)
    assert not argv_file.exists(), "the scanner must not even start"


def test_missing_report_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock, body="exit 0\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScannerError, match="gitleaks produced no report"):
        scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)


def test_scanner_crash_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _, _ = fake_gitleaks(
        tmp_path, releases, write_lock, body='echo "FTL bad config" >&2\nexit 1\n'
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScannerError, match="gitleaks exited with code 1"):
        scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)


def test_target_outside_repo_root_is_refused(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    (tmp_path / "repo").mkdir()
    with pytest.raises(ScannerError, match="outside the repository"):
        scan_secrets(
            tmp_path / "repo" / "..",
            lock=lock,
            tools_dir=dest,
            platform=PLATFORM,
            repo_root=tmp_path / "repo",
        )


HARDENING = "--text --no-textconv --no-ext-diff --diff-merges=remerge"


def _log_opts_passed(argv_file: Path) -> str:
    argv = argv_file.read_text().splitlines()
    return argv[argv.index("--log-opts") + 1]


@pytest.mark.parametrize(
    ("log_opts", "expected"),
    [
        (None, f"{HARDENING} --full-history --all --diff-filter=tuxdb"),
        ("1111111..2222222 -- demo-shop", f"{HARDENING} --diff-filter=tuxdb 1111111..2222222 -- demo-shop"),
        (
            "--full-history --since=2026-01-01 origin/main..HEAD",
            f"{HARDENING} --diff-filter=tuxdb --full-history --since=2026-01-01 origin/main..HEAD",
        ),
    ],
)
def test_git_mode_always_forces_text_patches(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    log_opts: str | None,
    expected: str,
) -> None:
    # A `-diff` attribute in the scanned repository's .gitattributes would otherwise turn patches into
    # "Binary files differ" and hide secrets from Gitleaks.
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()

    scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM, mode="git", log_opts=log_opts)

    assert argv_file.read_text().splitlines()[0] == "git"
    assert _log_opts_passed(argv_file) == expected


@pytest.mark.parametrize(
    "log_opts",
    [
        "--output=/tmp/pwned a..b",  # git would write a file
        "--ext-diff a..b",  # would undo --no-ext-diff
        "--textconv a..b",
        "--binary a..b",
        "-p a..b",
        "a..b --diff-filter=A -- src",
        "--no-merges a..b",  # would hide merge commits again (evil merges)
        "--first-parent a..b",  # would skip the commits of a side branch merged into the pull request
        "--diff-merges=off a..b",
    ],
)
def test_unsafe_log_options_are_refused(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], log_opts: str
) -> None:
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScannerError, match="is not allowed in --log-opts"):
        scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM, mode="git", log_opts=log_opts)
    assert not argv_file.exists(), "the scanner must not even start"


def test_log_options_after_the_separator_are_pathspecs(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()
    scan_secrets(
        repo, lock=lock, tools_dir=dest, platform=PLATFORM, mode="git", log_opts="a..b -- :(exclude)docs"
    )
    assert _log_opts_passed(argv_file).endswith("a..b -- :(exclude)docs")


def test_archives_are_opened_in_dir_mode_only(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, argv_file, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()

    scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM)
    dir_argv = argv_file.read_text().splitlines()
    scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM, mode="git")
    git_argv = argv_file.read_text().splitlines()

    assert dir_argv[dir_argv.index("--max-archive-depth") + 1] == str(MAX_ARCHIVE_DEPTH)
    assert "--max-archive-depth" not in git_argv


@pytest.mark.parametrize(
    ("existing", "reported", "expected"),
    [
        (["settings.py"], "b/settings.py", "settings.py"),  # conflicted file of a remerge diff
        (["b/settings.py", "settings.py"], "b/settings.py", "b/settings.py"),  # a real b/ directory wins
        ([], "b/settings.py", "b/settings.py"),  # nothing to map it to: left as reported
        (["app/b/x.py", "app/x.py"], "app/b/x.py", "app/b/x.py"),  # only a leading b/ is considered
        (["x.py"], "x.py", "x.py"),
    ],
)
def test_remerge_paths_are_repaired_only_when_unambiguous(
    tmp_path: Path, existing: list[str], reported: str, expected: str
) -> None:
    for name in existing:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("x\n")
    findings: list[dict[str, Any]] = [{"File": reported}]
    _repair_remerge_paths(findings, tmp_path)
    assert findings[0]["File"] == expected


def test_log_options_are_refused_in_dir_mode(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    lock, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScannerError, match="only applies to git mode"):
        scan_secrets(repo, lock=lock, tools_dir=dest, platform=PLATFORM, log_opts="a..b")


def test_cli_scan_secrets_writes_contract_valid_findings(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    finding_validator: Draft202012Validator,
) -> None:
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    lock_path = tmp_path / "tools.lock.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out" / "secrets.ndjson"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "secrets",
            str(repo),
            "--out",
            str(out),
            "--repo",
            "NOURHANE-EHOUARI/sentinelci",
            "--commit",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "--context",
            "pr",
            "--lock",
            str(lock_path),
            "--tools-dir",
            str(dest),
            "--platform",
            PLATFORM,
        ],
    )

    assert result.exit_code == 0, result.output
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    finding = json.loads(lines[0])
    assert not list(finding_validator.iter_errors(finding))
    assert finding["tool"] == {"name": "gitleaks", "version": "1.0.0"}
    assert "fake-value-for-tests-only" not in out.read_text()


def test_cli_scan_secrets_fails_closed_on_ignore_file(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitleaksignore").write_text("x\n")
    out = tmp_path / "secrets.ndjson"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "secrets",
            str(repo),
            "--out",
            str(out),
            "--repo",
            "NOURHANE-EHOUARI/sentinelci",
            "--commit",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "--context",
            "pr",
            "--lock",
            str(tmp_path / "tools.lock.toml"),
            "--tools-dir",
            str(dest),
            "--platform",
            PLATFORM,
        ],
    )

    assert result.exit_code == 3
    assert "SC-010" in result.output
    assert not out.exists()


def test_cli_scan_failure_removes_an_older_findings_file(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    _, dest, _, _ = fake_gitleaks(tmp_path, releases, write_lock, body='echo "FTL" >&2\nexit 1\n')
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "secrets.ndjson"
    out.write_text('{"stale": true}\n', encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan", "secrets", str(repo), "--out", str(out),
            "--repo", "NOURHANE-EHOUARI/sentinelci", "--commit", "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "--context", "pr", "--lock", str(tmp_path / "tools.lock.toml"), "--tools-dir", str(dest),
            "--platform", PLATFORM,
        ],
    )  # fmt: skip

    assert result.exit_code == 3
    assert not out.exists()


# ------------------------------------------------------------------ integration (real Gitleaks)

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


def _fake_github_token(seed: int) -> str:
    # Built at runtime so no token-shaped string is committed to the repository.
    rng = random.Random(seed)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


@real
@pytest.mark.integration
def test_real_gitleaks_neutralizes_author_controlled_suppressions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(f'TOKEN = "{_fake_github_token(1)}"\n')
    (repo / "inline.py").write_text(f'TOKEN = "{_fake_github_token(2)}"  # gitleaks:allow\n')
    (repo / ".gitleaks.toml").write_text(
        "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''app\\.py''']\n"
    )

    raw = scan_secrets(repo, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))

    assert sorted(item["File"] for item in raw) == ["app.py", "inline.py"]


@real
@pytest.mark.integration
def test_real_gitleaks_history_scan_finds_a_deleted_secret(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git = [
        "git",
        "-C",
        str(repo),
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ]
    subprocess.run([*git, "init", "-q"], check=True)
    (repo / "config.py").write_text(f'TOKEN = "{_fake_github_token(3)}"\n')
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "add config"], check=True)
    (repo / "config.py").write_text("TOKEN = None\n")
    subprocess.run([*git, "commit", "-qam", "remove secret"], check=True)

    raw = scan_secrets(repo, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), mode="git")

    assert len(raw) == 1
    assert raw[0]["File"] == "config.py"
    assert len(raw[0]["Commit"]) == 40


@real
@pytest.mark.integration
@pytest.mark.parametrize("attribute", ["*.py -diff", "config.py binary"])
def test_real_gitleaks_sees_through_author_gitattributes(tmp_path: Path, attribute: str) -> None:
    # Without --text, `git log -p` prints "Binary files differ" for these files and Gitleaks finds nothing
    # (reproduced with Gitleaks 8.30.1, both with a commit range and with its default full-history scan).
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run([*git, "init", "-q"], check=True)
    (repo / "app.py").write_text("print('hello')\n")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "commit", "-qm", "base"], check=True)
    head = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    base = head.stdout.strip()
    (repo / ".gitattributes").write_text(f"{attribute}\n")
    (repo / "config.py").write_text(f'TOKEN = "{_fake_github_token(4)}"\n')
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "-c", "commit.gpgsign=false", "commit", "-qm", "change"], check=True)
    lock, tools = load_lock(REPO_LOCK), Path(str(TOOLS_DIR))

    in_range = scan_secrets(repo, lock=lock, tools_dir=tools, mode="git", log_opts=f"{base}..HEAD")
    full_history = scan_secrets(repo, lock=lock, tools_dir=tools, mode="git")

    assert [item["File"] for item in in_range] == ["config.py"]
    assert [item["File"] for item in full_history] == ["config.py"]


class _Repo:
    """A throwaway git repository for real-binary tests."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str) -> str:
        base = ["git", "-C", str(self.path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        base += ["-c", "commit.gpgsign=false"]
        return subprocess.run([*base, *args], check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, files: dict[str, str], message: str) -> str:
        for name, content in files.items():
            (self.path / name).write_text(content)
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")


def _real_scan(repo: _Repo, log_opts: str | None = None) -> list[tuple[str, int]]:
    raw = scan_secrets(
        repo.path, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), mode="git", log_opts=log_opts
    )
    return sorted({(item["File"], item["StartLine"]) for item in raw})


@real
@pytest.mark.integration
def test_real_gitleaks_scans_secrets_added_in_a_merge_commit(tmp_path: Path) -> None:
    # Evil merge: `git merge --no-commit`, add a secret while "resolving", commit. Plain `git log -p` prints
    # no patch for merges, so Gitleaks 8.30.1 found nothing in the PR range or in full history.
    repo = _Repo(tmp_path / "repo")
    repo.commit({"app.py": "a\n"}, "base")
    repo.git("checkout", "-q", "-b", "feature")
    repo.commit({"feature.py": "b\n"}, "feature")
    repo.git("checkout", "-q", "main")
    base = repo.commit({"other.py": "c\n"}, "main moves on")
    repo.git("checkout", "-q", "feature")
    repo.git("merge", "-q", "--no-commit", "main")
    repo.commit({"config.py": f'TOKEN = "{_fake_github_token(5)}"\n'}, "Merge main into feature")

    assert _real_scan(repo, f"{base}..HEAD") == [("config.py", 1)]
    assert _real_scan(repo) == [("config.py", 1)]


@real
@pytest.mark.integration
def test_real_gitleaks_does_not_blame_an_honest_merge_of_the_base_branch(tmp_path: Path) -> None:
    # The base branch already has a secret; merging it into the pull request adds nothing new.
    repo = _Repo(tmp_path / "repo")
    repo.commit({"app.py": "a\n"}, "base")
    repo.git("checkout", "-q", "-b", "feature")
    repo.commit({"feature.py": "b\n"}, "feature")
    repo.git("checkout", "-q", "main")
    base = repo.commit({"leaked.py": f'TOKEN = "{_fake_github_token(6)}"\n'}, "main leaks")
    repo.git("checkout", "-q", "feature")
    repo.git("merge", "-q", "--no-edit", "main")
    repo.commit({"more.py": "c\n"}, "more")

    assert _real_scan(repo, f"{base}..HEAD") == []
    assert _real_scan(repo) == [("leaked.py", 1)]  # still found where it was introduced


@real
@pytest.mark.integration
def test_real_gitleaks_scans_a_conflict_resolution_and_reports_the_real_path(tmp_path: Path) -> None:
    repo = _Repo(tmp_path / "repo")
    repo.commit({"settings.py": "value = 1\n"}, "base")
    repo.git("checkout", "-q", "-b", "feature")
    repo.commit({"settings.py": "value = 2\n"}, "feature")
    repo.git("checkout", "-q", "main")
    base = repo.commit({"settings.py": "value = 3\n"}, "main")
    repo.git("checkout", "-q", "feature")
    subprocess.run(["git", "-C", str(repo.path), "merge", "-q", "main"], check=False, capture_output=True)
    resolved = f'value = 4\nTOKEN = "{_fake_github_token(7)}"\n'
    repo.commit({"settings.py": resolved}, "Merge main (conflict resolved)")

    # Gitleaks reads the remerge header of a conflicted file as `b/settings.py`; the adapter restores it.
    assert _real_scan(repo, f"{base}..HEAD") == [("settings.py", 2)]


@real
@pytest.mark.integration
def test_real_gitleaks_opens_archives_in_dir_mode(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with zipfile.ZipFile(repo / "backup.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("old/config.py", f'TOKEN = "{_fake_github_token(8)}"\n')

    raw = scan_secrets(repo, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))

    assert [(item["File"], item["RuleID"]) for item in raw] == [("backup.zip!old/config.py", "github-pat")]
    findings = normalize_gitleaks(
        raw,
        run=Run(
            repo="NOURHANE-EHOUARI/sentinelci",
            commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            context="pr",
        ),
        tool=Tool(name="gitleaks", version="8.30.1"),
        repo_root=repo,
    )
    assert findings[0].location is not None
    assert findings[0].location.path == "backup.zip!old/config.py"
