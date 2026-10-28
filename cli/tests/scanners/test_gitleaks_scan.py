"""`sentinel scan secrets`: Gitleaks hardened against repository-controlled suppressions (task A1b).

Unit tests use a fake `gitleaks` script pinned in a test lock. Integration tests use the real binary
and run only when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
import random
import string
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.scanners.errors import ScannerError
from sentinelci.scanners.gitleaks import scan_secrets
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
