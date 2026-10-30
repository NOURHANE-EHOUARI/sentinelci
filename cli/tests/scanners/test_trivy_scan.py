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
from sentinelci.scanners.trivy import (
    _CHUNK,
    OFFLINE_ENV,
    check_outside_reads,
    escaping_links,
    inline_ignores,
    outside_terraform_ignores,
    remote_modules,
    scan_iac_with_run,
)

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
    ("name", "refused"),
    [
        ("main.tf", True),
        ("values.yaml", True),
        ("Dockerfile", True),
        ("Dockerfile.prod", True),
        ("api.dockerfile", True),
        # Trivy reads these as Dockerfiles by name, whatever the extension (review of #26, repro D1).
        ("Dockerfile.txt", True),
        ("Dockerfile.sh", True),
        ("Containerfile.md", True),
        ("dockerfile.py", True),
        ("api.Containerfile", True),
        ("template", True),  # no extension: checked
        ("tfplan.bin", True),  # unknown type: checked
        ("scanner.py", False),
        ("README.md", False),
        ("app.ts", False),
    ],
)
def test_the_marker_check_skips_only_files_trivy_never_parses(
    tmp_path: Path, name: str, refused: bool
) -> None:
    # A tree whose code or documentation merely mentions the markers (a self-scan) can still be scanned.
    (tmp_path / name).write_text("# trivy:ignore:AWS-0086\n")
    assert inline_ignores(tmp_path) == ([name] if refused else [])


def test_links_that_leave_the_scanned_tree_are_refused(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # Trivy does not follow them, but Terraform and kubectl do: the content would go unscanned.
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    outside = tmp_path / "elsewhere"
    (outside / "mod").mkdir(parents=True)
    (outside / "pod.yaml").write_text("kind: Pod\n")
    (repo / "infra" / "inside.tf").symlink_to(repo / "infra" / "main.tf")  # stays inside: fine
    assert escaping_links(repo) == []
    (repo / "infra" / "pod.yaml").symlink_to(outside / "pod.yaml")
    (repo / "infra" / "modlink").symlink_to(outside / "mod")
    assert escaping_links(repo) == ["infra/modlink", "infra/pod.yaml"]

    with pytest.raises(
        ScannerError, match=r"symbolic links leave the scanned tree \(infra/modlink, infra/pod.yaml\)"
    ):
        scan_iac_with_run(
            repo, lock=load_lock(tmp_path / "tools.lock.toml"), tools_dir=dest, platform=PLATFORM
        )
    assert not argv_file.exists(), "the scanner must not even start"


def test_what_trivy_read_outside_the_scan_path_is_checked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for name in ("demo-shop", "mod", "mod2"):
        (repo / name).mkdir(parents=True)
    (repo / "mod" / "main.tf").write_text('#trivy:ignore:*\nresource "aws_s3_bucket" "a" {}\n')
    (repo / "mod2" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    clean = [{"Target": "."}, {"Target": "../mod2/main.tf"}]
    check_outside_reads(clean, repo, "demo-shop")  # a local module without ignores is fine

    with pytest.raises(ScannerError, match=r"in a module outside the scan path \(mod/main.tf\)"):
        check_outside_reads(
            [*clean, {"Target": "../mod/main.tf", "Misconfigurations": []}], repo, "demo-shop"
        )
    with pytest.raises(ScannerError, match="outside the repository"):
        check_outside_reads([{"Target": "../../etc/passwd"}], repo, "demo-shop")


def _module_chain(repo: Path, *, ignore: bool) -> None:
    """Review of #26, repro N1: the scan tree calls ../moda, which calls ../modb under a module ignore."""
    for name in ("demo-shop", "moda", "modb"):
        (repo / name).mkdir(parents=True)
    (repo / "demo-shop" / "main.tf").write_text('module "a" { source = "../moda" }\n')
    marker = "#trivy:ignore:*\n" if ignore else ""
    (repo / "moda" / "main.tf").write_text(f'{marker}module "b" {{\n  source = "../modb"\n}}\n')
    (repo / "modb" / "main.tf").write_text(PUBLIC_ACL)


def test_a_module_level_ignore_outside_the_scan_path_is_refused_before_the_run(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    # moda has no resource, so Trivy never reports it: only a check before the run can see its ignore.
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True)
    assert outside_terraform_ignores(repo / "demo-shop", repo) == ["moda/main.tf"]
    with pytest.raises(ScannerError, match=r"outside the scan path, in Terraform files .* \(moda/main\.tf\)"):
        scan_iac_with_run(
            repo / "demo-shop",
            lock=load_lock(tmp_path / "tools.lock.toml"),
            tools_dir=dest,
            repo_root=repo,
            platform=PLATFORM,
        )
    assert not argv_file.exists(), "the scanner must not even start"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("main.tf", 'module "a" { source = "../moda" }\n'),
        ("main.tf", 'module /* a comment */ "a" {\n  source = "\\u002e\\u002e/moda"\n}\n'),  # HCL escapes
        ("main.tf.json", '{"module": {"a": {"source": "../moda"}}}'),
        ("main.tf.json", '{"\\u006dodule": {"a": {"source": "../moda"}}}'),  # an escaped JSON key
        ("main.tf.json", '{"module": '),  # unparsable here: assume the worst
    ],
    ids=["hcl", "hcl-escaped-source", "json", "json-escaped-key", "json-unparsable"],
)
def test_any_module_in_the_scan_tree_makes_the_repository_terraform_checked(
    tmp_path: Path, name: str, text: str
) -> None:
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True)
    (repo / "demo-shop" / "main.tf").unlink()
    (repo / "demo-shop" / name).write_text(text)
    assert outside_terraform_ignores(repo / "demo-shop", repo) == ["moda/main.tf"]


def test_without_modules_or_outside_the_scan_tree_nothing_else_is_checked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True)
    (repo / "demo-shop" / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')  # no module any more
    assert outside_terraform_ignores(repo / "demo-shop", repo) == []
    (repo / "demo-shop" / "main.tf").write_text('module "a" { source = "../moda" }\n')
    assert outside_terraform_ignores(repo, repo) == [], (
        "the whole repository is the scan tree: checked already"
    )
    (repo / ".git").mkdir()
    (repo / ".git" / "old.tf").write_text("#trivy:ignore:*\n")  # Trivy never reads .git
    assert outside_terraform_ignores(repo / "demo-shop", repo) == ["moda/main.tf"]


def test_linked_terraform_files_outside_the_scan_tree_are_checked_through_their_target(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=False)
    (repo / "docs").mkdir()
    (repo / "docs" / "notes.md").write_text(
        "#trivy:ignore:*\n"
    )  # skipped by name, but loaded through the link
    (repo / "modb" / "extra.tf").symlink_to(repo / "docs" / "notes.md")
    assert outside_terraform_ignores(repo / "demo-shop", repo) == ["modb/extra.tf"]
    (repo / "modb" / "extra.tf").unlink()
    (tmp_path / "elsewhere.tf").write_text('resource "aws_s3_bucket" "c" {}\n')
    (repo / "modb" / "extra.tf").symlink_to(tmp_path / "elsewhere.tf")
    with pytest.raises(ScannerError, match=r"modb/extra\.tf links outside the repository"):
        outside_terraform_ignores(repo / "demo-shop", repo)


def test_remote_modules_are_listed_through_local_modules(tmp_path: Path) -> None:
    # Review of #26, nit R1: a remote module inside ../mod, and module sources in .tf.json files.
    repo = tmp_path / "repo"
    for name in ("demo-shop", "mod", "mod/nested"):
        (repo / name).mkdir(parents=True)
    (repo / "demo-shop" / "main.tf").write_text('module "a" { source = "../mod" }\n')
    (repo / "demo-shop" / "more.tf.json").write_text(
        json.dumps({"module": [{"k": {"source": "git::https://example.invalid/k.git"}}]})
    )
    (repo / "mod" / "main.tf").write_text(
        'module "r" {\n  source = "git::https://example.invalid/r.git"\n}\n'
        'module "n" {\n  source = "./nested"\n}\nmodule "back" {\n  source = "../demo-shop"\n}\n'
    )
    (repo / "mod" / "nested" / "main.tf.json").write_text(
        json.dumps({"module": {"j": {"source": "registry.example/ns/j/aws"}}})
    )
    assert remote_modules(repo / "demo-shop", repo) == [
        "git::https://example.invalid/k.git",
        "git::https://example.invalid/r.git",
        "registry.example/ns/j/aws",
    ]
    assert remote_modules(repo / "demo-shop") == ["git::https://example.invalid/k.git"], "scan tree only"


def test_remote_modules_are_listed(tmp_path: Path) -> None:
    (tmp_path / "net").mkdir()
    (tmp_path / "main.tf").write_text(
        'module "a" {\n  source = "git::https://example.invalid/net.git?ref=v1"\n}\n'
        'module "b" {\n  source  = "terraform-aws-modules/s3-bucket/aws"\n  version = "4.1.0"\n}\n'
        'module "c" {\n  source = "./net"\n}\nmodule "d" {\n  source = "../shared"\n}\n'
    )
    assert remote_modules(tmp_path) == [
        "git::https://example.invalid/net.git?ref=v1",
        "terraform-aws-modules/s3-bucket/aws",
    ]


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


@real
@pytest.mark.integration
def test_real_trivy_ignores_in_a_module_outside_the_scan_path_fail_closed(tmp_path: Path) -> None:
    # Review of #26: Trivy loads `../mod` and honours its #trivy:ignore, with an `ok` status before the fix.
    repo = tmp_path / "repo"
    for name in ("demo-shop", "mod", "mod2"):
        (repo / name).mkdir(parents=True)
    (repo / "demo-shop" / "main.tf").write_text('module "m" {\n  source = "../mod2"\n}\n')
    (repo / "mod2" / "main.tf").write_text(PUBLIC_ACL)
    results, run = scan_iac_with_run(
        repo / "demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), repo_root=repo
    )
    findings = normalize_trivy_config(
        results,
        run=Run(repo="o/r", commit=COMMIT, context="pr"),
        tool=Tool(name="trivy", version=run.version),
        scan_root="demo-shop",
    )
    assert ("mod2/main.tf", "AWS-0086") in {(f.location.path, f.rule_id) for f in findings if f.location}

    (repo / "demo-shop" / "main.tf").write_text('module "m" {\n  source = "../mod"\n}\n')
    (repo / "mod" / "main.tf").write_text(PUBLIC_ACL.replace("resource ", "#trivy:ignore:*\nresource "))
    with pytest.raises(ScannerError, match=r"outside the scan path.* \(mod/main.tf\)"):
        scan_iac_with_run(
            repo / "demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), repo_root=repo
        )


@real
@pytest.mark.integration
def test_real_trivy_module_level_ignore_in_an_outside_module_fails_closed(tmp_path: Path) -> None:
    # Review of #26, repro N1: with the real Trivy, the ignore above `module "b"` in ../moda silenced modb.
    control = tmp_path / "control"
    _module_chain(control, ignore=False)
    results, run = scan_iac_with_run(
        control / "demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), repo_root=control
    )
    findings = normalize_trivy_config(
        results,
        run=Run(repo="o/r", commit=COMMIT, context="pr"),
        tool=Tool(name="trivy", version=run.version),
        scan_root="demo-shop",
    )
    assert ("modb/main.tf", "AWS-0086") in {(f.location.path, f.rule_id) for f in findings if f.location}

    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True)
    with pytest.raises(ScannerError, match=r"\(moda/main\.tf\)"):
        scan_iac_with_run(
            repo / "demo-shop", lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)), repo_root=repo
        )


DOCKERFILE = "FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nUSER root\nEXPOSE 22\n"


@real
@pytest.mark.integration
@pytest.mark.parametrize("name", ["Dockerfile.txt", "Dockerfile.sh", "Containerfile.md"])
def test_real_trivy_reads_dockerfiles_by_name_so_their_ignores_are_refused(tmp_path: Path, name: str) -> None:
    # Review of #26, repro D1: Trivy parses these as Dockerfiles, so the marker check must not skip them.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / name).write_text(DOCKERFILE)
    assert {rule for _, rule in _real_ids(repo)} >= {"DS-0002"}, "control: Trivy reads the file"
    (repo / name).write_text("".join(f"# trivy:ignore:*\n{line}\n" for line in DOCKERFILE.splitlines()))
    with pytest.raises(ScannerError, match=rf"in the scanned tree \({name}\)"):
        _real_ids(repo)
