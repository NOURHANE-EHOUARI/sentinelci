"""`sentinel scan iac`: Trivy hardened against repository-controlled configuration and network (task A1c).

Unit tests use a fake `trivy` script pinned in a test lock. Integration tests use the real binary and run only
when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.trivy import normalize_trivy_config
from sentinelci.policy.tool_status import ToolStatus
from sentinelci.scanners.errors import ScannerError, ScannerTimeout
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.scanners.trivy import _CHUNK, OFFLINE_ENV, inline_ignores, scan_iac_with_run

from .conftest import FakeReleases
from .test_runner import PLATFORM, install_script

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

REPORT = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "infra/main.tf",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AWS-0086",
                    "Title": "S3 Access block should block public ACL",
                    "Message": "No public access block so not blocking public acls",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "CauseMetadata": {"Resource": "aws_s3_bucket.shop", "StartLine": 1, "EndLine": 3},
                }
            ],
        }
    ],
}

# A fake trivy that records its argv and environment, then writes REPORT to --output.
FAKE_TRIVY = r"""
printf '%s\n' "$@" "--END-OF-CALL--" >> "$SENTINEL_ARGV_FILE_PLACEHOLDER"
env > "$SENTINEL_ENV_FILE_PLACEHOLDER"
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then shift; OUT="$1"; fi
  shift
done
cat > "$OUT" <<'JSON'
REPORT_PLACEHOLDER
JSON
"""


def fake_trivy(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], body: str | None = None
) -> tuple[Path, Path, Path]:
    argv_file, env_file = tmp_path / "argv.txt", tmp_path / "env.txt"
    script = (
        (body or FAKE_TRIVY)
        .replace("$SENTINEL_ARGV_FILE_PLACEHOLDER", str(argv_file))
        .replace("$SENTINEL_ENV_FILE_PLACEHOLDER", str(env_file))
        .replace("REPORT_PLACEHOLDER", json.dumps(REPORT))
    )
    _, dest = install_script(tmp_path, releases, write_lock, script, tool="trivy")
    return dest, argv_file, env_file


def _argv(argv_file: Path) -> list[str]:
    lines = argv_file.read_text().split("\n")
    return lines[: lines.index("--END-OF-CALL--")]


def _value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "infra").mkdir(parents=True)
    (repo / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "shop" {}\n')
    return repo


def test_repository_configuration_is_never_loaded(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    (repo / "trivy.yaml").write_text("severity: [CRITICAL]\n")
    (repo / ".trivyignore").write_text("AWS-0086\n")

    results, run = scan_iac_with_run(
        repo, lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
    )

    argv = _argv(argv_file)
    assert argv[0] == "config" and argv[-1] == "."
    assert _value(argv, "--config") == "" and _value(argv, "--ignorefile") == ""
    for flag in ("--skip-check-update", "--skip-version-check", "--disable-telemetry"):
        assert flag in argv
    assert _value(argv, "--exit-code") == "0" and _value(argv, "--format") == "json"
    for flag in ("--cache-dir", "--module-dir", "--config-data", "--output"):
        assert not Path(_value(argv, flag)).is_relative_to(repo), (
            f"{flag} must not point into the scanned tree"
        )
    assert (Path(_value(argv, "--config-data")) / "trusted-registries.yaml").is_file()
    assert results == REPORT["Results"] and run.tool == "trivy"


def test_the_scan_runs_offline_and_inherits_no_secret(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token-for-tests")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    dest, _, env_file = fake_trivy(tmp_path, releases, write_lock)

    scan_iac_with_run(
        _repo(tmp_path), lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
    )

    env = dict(line.split("=", 1) for line in env_file.read_text().splitlines() if "=" in line)
    for key, value in OFFLINE_ENV.items():
        assert env.get(key) == value, key
    assert env["GIT_ALLOW_PROTOCOL"] == "none" and env["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert "GITHUB_TOKEN" not in env


@pytest.mark.parametrize(
    "marker",
    [
        "#trivy:ignore:AWS-0086",
        "# tfsec:ignore:aws-s3-block-public-acls",
        "// TRIVY:IGNORE:AWS-0086",
        "# trivy : ignore : *",
    ],
)
def test_inline_ignores_are_refused_before_anything_runs(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], marker: str
) -> None:
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    (repo / "infra" / "main.tf").write_text(f'resource "aws_s3_bucket" "shop" {{}} {marker}\n')

    with pytest.raises(ScannerError, match=r"inline trivy:ignore .*\(infra/main\.tf\).* SentinelCI waivers"):
        scan_iac_with_run(
            repo, lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
        )
    assert not argv_file.exists(), "the scanner must not even start"


def test_the_marker_check_matches_what_trivy_reads(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "COMMIT_EDITMSG").write_text("trivy:ignore in a commit message\n")  # Trivy skips .git
    elsewhere = tmp_path / "elsewhere.tf"
    elsewhere.write_text("#trivy:ignore:AWS-0086\n")
    (root / "linked.tf").symlink_to(elsewhere)  # Trivy does not follow symbolic links
    assert inline_ignores(root) == []

    big = root / "big" / "main.tf"
    big.parent.mkdir()
    big.write_bytes(b"x" * (_CHUNK - 5) + b"#tfsec:ignore:aws-s3")  # the marker spans two read chunks
    (root / "a.yaml").write_text("ok: true\n")
    assert inline_ignores(root) == ["big/main.tf"]


@pytest.mark.parametrize(
    ("body", "error", "message"),
    [
        ("echo 'FATAL context deadline exceeded' >&2\nexit 1\n", ScannerTimeout, "timed out after"),
        ("echo 'FATAL failed to parse' >&2\nexit 1\n", ScannerError, "exited with code 1"),
        ("exit 0\n", ScannerError, "produced no report"),
    ],
    ids=["own-time-limit", "crash", "no-report"],
)
def test_failures_are_scanner_errors(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    body: str,
    error: type[Exception],
    message: str,
) -> None:
    dest, _, _ = fake_trivy(tmp_path, releases, write_lock, body=body)
    with pytest.raises(error, match=message):
        scan_iac_with_run(
            _repo(tmp_path), lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
        )


@pytest.mark.parametrize(
    "report", ["not json", '{"SchemaVersion": 1, "Results": []}', '{"SchemaVersion": 2, "Results": {}}']
)
def test_unreadable_reports_fail_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path], report: str
) -> None:
    body = FAKE_TRIVY.replace("REPORT_PLACEHOLDER", report)
    dest, _, _ = fake_trivy(tmp_path, releases, write_lock, body=body)
    with pytest.raises(ScannerError, match=r"trivy (produced an unreadable report|report)"):
        scan_iac_with_run(
            _repo(tmp_path), lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
        )


def test_a_target_outside_the_repository_is_refused(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _, _ = fake_trivy(tmp_path, releases, write_lock)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ScannerError, match="outside the repository root"):
        scan_iac_with_run(
            outside,
            lock=load_lock(tmp_path / "tools.lock.toml"),
            tools_dir=dest,
            repo_root=_repo(tmp_path),
            platform=PLATFORM,
        )


# ------------------------------------------------------------------ CLI


def _cli(tmp_path: Path, dest: Path, target: Path, repo_root: Path) -> tuple[int, str, Path, Path]:
    out, status = tmp_path / "out" / "iac.ndjson", tmp_path / "out" / "tool-status.json"
    result = CliRunner().invoke(
        app,
        [
            "scan", "iac", str(target), "--repo-root", str(repo_root), "--out", str(out),
            "--repo", "NOURHANE-EHOUARI/sentinelci", "--commit", COMMIT, "--context", "pr",
            "--lock", str(tmp_path / "tools.lock.toml"), "--tools-dir", str(dest),
            "--platform", PLATFORM, "--tool-status-out", str(status),
        ],
    )  # fmt: skip
    return result.exit_code, result.output, out, status


def test_cli_writes_repository_relative_findings_and_an_ok_status(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    finding_validator: Draft202012Validator,
) -> None:
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    (repo / "demo").mkdir()

    code, output, out, status = _cli(tmp_path, dest, repo / "demo", repo)

    assert code == 0, output
    assert _argv(argv_file)[-1] == "demo"
    (finding,) = [json.loads(line) for line in out.read_text().splitlines()]
    assert not list(finding_validator.iter_errors(finding))
    assert finding["location"] == {"path": "demo/infra/main.tf", "start_line": 1, "end_line": 3}
    assert (finding["category"], finding["tool"]) == ("IAC", {"name": "trivy", "version": "1.0.0"})
    document = json.loads(status.read_text())
    ToolStatus.model_validate(document)
    assert document["tools"]["trivy"]["status"] == "ok"


def test_cli_records_a_refused_scan_and_fails_closed(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    (repo / "infra" / "main.tf").write_text("#trivy:ignore:*\n")

    code, output, out, status = _cli(tmp_path, dest, repo, repo)

    assert code == 3 and "SC-010" in output
    assert not out.exists()
    trivy = json.loads(status.read_text())["tools"]["trivy"]
    assert trivy["status"] == "failed" and "inline trivy:ignore" in trivy["detail"]


# ------------------------------------------------------------------ integration (real Trivy)

TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)

PUBLIC_ACL = """resource "aws_s3_bucket" "shop" {
  bucket = "demo-shop-assets"
}

resource "aws_s3_bucket_public_access_block" "shop" {
  bucket                  = aws_s3_bucket.shop.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


def _real_ids(root: Path) -> set[tuple[str, str]]:
    results, run = scan_iac_with_run(root, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    run_info = Run(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr")
    findings = normalize_trivy_config(results, run=run_info, tool=Tool(name="trivy", version=run.version))
    return {(f.location.path, f.rule_id) for f in findings if f.location}


@real
@pytest.mark.integration
def test_real_trivy_ignores_repository_config_and_ignore_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(PUBLIC_ACL)
    assert ("main.tf", "AWS-0086") in _real_ids(repo)
    (repo / "trivy.yaml").write_text("severity: [CRITICAL]\nmisconfiguration:\n  scanners: [dockerfile]\n")
    (repo / ".trivyignore").write_text("AWS-0086\n")
    (repo / ".trivyignore.yaml").write_text("misconfigurations:\n  - id: AWS-0086\n")
    assert ("main.tf", "AWS-0086") in _real_ids(repo)


@real
@pytest.mark.integration
def test_the_offline_environment_stops_trivy_from_fetching_modules(tmp_path: Path) -> None:
    # A module behind a git source (file transport: no network needed for the control run).
    module = tmp_path / "module"
    module.mkdir()
    (module / "main.tf").write_text(PUBLIC_ACL)
    git = ["git", "-C", str(module), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(module)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "module"], check=True)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(f'module "assets" {{\n  source = "git::file://{module}"\n}}\n')
    args = [
        "config", "--debug", "--skip-check-update", "--skip-version-check", "--disable-telemetry",
        "--config", "", "--ignorefile", "", "--cache-dir", str(tmp_path / "cache"), "--format", "json",
        "--output", str(tmp_path / "report.json"), ".",
    ]  # fmt: skip

    def log(extra_env: dict[str, str] | None) -> str:
        run = run_verified_tool(
            "trivy",
            args,
            lock=load_lock(REPO_LOCK),
            tools_dir=Path(str(TOOLS_DIR)),
            cwd=repo,
            extra_env=extra_env,
        )
        return run.stderr

    assert "Loaded module" in log(None), "control: without the offline environment Trivy clones the module"
    blocked = log(OFFLINE_ENV)
    assert "Failed to load module" in blocked and "Loaded module" not in blocked
