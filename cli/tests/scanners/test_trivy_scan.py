"""`sentinel scan iac`: Trivy hardened against repository-controlled configuration and network (task A1c).

Unit tests use a fake `trivy` script pinned in a test lock. Integration tests use the real binary and run only
when SENTINEL_TOOLS_DIR points to a `sentinel tools install` directory.
"""

import json
import os
import re
import subprocess
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding, Run, Tool
from sentinelci.normalize.trivy import normalize_trivy_config
from sentinelci.policy.tool_status import ToolStatus
from sentinelci.scanners.errors import ScannerError, ScannerTimeout
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.runner import run_verified_tool
from sentinelci.scanners.trivy import (
    _CHUNK,
    CHECK_NAMESPACE,
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
    for flag in ("--cache-dir", "--module-dir", "--config-data", "--config-check", "--output"):
        assert not Path(_value(argv, flag)).is_relative_to(repo), (
            f"{flag} must not point into the scanned tree"
        )
    assert (Path(_value(argv, "--config-data")) / "trusted-registries.yaml").is_file()
    assert (Path(_value(argv, "--config-check")) / "aws_iam_full_admin.rego").is_file()
    assert _value(argv, "--check-namespaces") == CHECK_NAMESPACE == "sentinelci"
    assert _value(argv, "--rego-error-limit") == "0"
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


def _module_chain(
    repo: Path, *, ignore: bool, scan_file: str = "main.tf", moda_file: str = "main.tf"
) -> None:
    """Review of #26, repro N1: the scan tree calls ../moda, which calls ../modb under a module ignore. The
    file names cover OpenTofu (second review of #26, repros A1 to A3)."""
    for name in ("demo-shop", "moda", "modb"):
        (repo / name).mkdir(parents=True)
    call = (
        '{"module": {"a": {"source": "../moda"}}}'
        if scan_file.endswith(".json")
        else 'module "a" { source = "../moda" }\n'
    )
    (repo / "demo-shop" / scan_file).write_text(call)
    marker = "#trivy:ignore:*\n" if ignore else ""
    (repo / "moda" / moda_file).write_text(f'{marker}module "b" {{\n  source = "../modb"\n}}\n')
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
        ("main.tf.json", '[{"module": {"a": {"source": "../moda"}}}]'),  # Trivy loads a top-level array
        ("main.tofu", 'module "a" { source = "../moda" }\n'),  # OpenTofu files are Terraform to Trivy
        ("main.tofu.json", '{"module": {"a": {"source": "../moda"}}}'),
        ("MAIN.TOFU", 'module "a" { source = "../moda" }\n'),
    ],
    ids=[
        "hcl", "hcl-escaped-source", "json", "json-escaped-key", "json-unparsable", "json-array", "tofu",
        "tofu-json", "tofu-upper-case",
    ],
)  # fmt: skip
def test_any_module_in_the_scan_tree_makes_the_repository_terraform_checked(
    tmp_path: Path, name: str, text: str
) -> None:
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True)
    (repo / "demo-shop" / "main.tf").unlink()
    (repo / "demo-shop" / name).write_text(text)
    assert outside_terraform_ignores(repo / "demo-shop", repo) == ["moda/main.tf"]


@pytest.mark.parametrize("moda_file", ["main.tofu", "main.tf.json", "main.tofu.json"])
def test_opentofu_and_json_files_outside_the_scan_tree_are_checked(tmp_path: Path, moda_file: str) -> None:
    # Second review of #26, repro A2: the module ignore sits in moda/main.tofu.
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=True, moda_file=moda_file)
    assert outside_terraform_ignores(repo / "demo-shop", repo) == [f"moda/{moda_file}"]


def test_links_leaving_the_repository_are_refused_when_a_module_may_load_them(tmp_path: Path) -> None:
    # Second review of #26, repro B1: moda is a directory link to a folder outside the repository.
    repo = tmp_path / "repo"
    _module_chain(repo, ignore=False)
    (repo / "alias").symlink_to(repo / "modb")  # stays inside: its files are checked where they are
    (repo / ".venv" / "bin").mkdir(parents=True)
    (tmp_path / "python3.13").write_text("")
    (repo / ".venv" / "bin" / "python").symlink_to(tmp_path / "python3.13")  # leaves, but no module loads it
    assert outside_terraform_ignores(repo / "demo-shop", repo) == []

    outside = tmp_path / "outside-moda"
    (repo / "moda").rename(outside)
    (outside / "main.tf").write_text('#trivy:ignore:*\nmodule "b" {\n  source = "../repo/modb"\n}\n')
    (repo / "moda").symlink_to(outside)
    with pytest.raises(ScannerError, match=r"symbolic links leave the repository \(moda\)"):
        outside_terraform_ignores(repo / "demo-shop", repo)
    (repo / "moda").unlink()
    (repo / "modb" / "extra.tofu").symlink_to(outside / "main.tf")
    with pytest.raises(ScannerError, match=r"symbolic links leave the repository \(modb/extra\.tofu\)"):
        outside_terraform_ignores(repo / "demo-shop", repo)


def test_a_terraform_named_link_to_a_device_is_never_read(
    tmp_path: Path,
    releases: FakeReleases,
    write_lock: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Second review of #26, repro C1: reading demo-shop/zero.tf -> /dev/zero never ends (MemoryError, and
    # no tool status written).
    dest, argv_file, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = tmp_path / "repo"
    (repo / "demo-shop").mkdir(parents=True)
    (repo / "demo-shop" / "main.tf").write_text(PUBLIC_ACL)
    (repo / "demo-shop" / "zero.tf").symlink_to("/dev/zero")
    read_bytes = Path.read_bytes

    def guarded(path: Path) -> bytes:
        assert path.name != "zero.tf", "a link to a device must never be read"
        return read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    assert remote_modules(repo / "demo-shop", repo) == []
    with pytest.raises(ScannerError, match=r"leave the repository \(demo-shop/zero\.tf\)"):
        outside_terraform_ignores(repo / "demo-shop", repo)  # the link counts as declaring a module
    code, output, out, status = _cli(tmp_path, dest, repo / "demo-shop", repo)
    assert code == 3 and not out.exists() and not argv_file.exists(), output
    trivy = json.loads(status.read_text())["tools"]["trivy"]
    assert trivy["status"] == "failed"
    assert "symbolic links leave the scanned tree (zero.tf)" in trivy["detail"]


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
    with pytest.raises(ScannerError, match=r"symbolic links leave the repository \(modb/extra\.tf\)"):
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


def test_only_module_sources_are_listed_as_remote_modules(tmp_path: Path) -> None:
    # Second review of #26, nit: the provider source `hashicorp/aws` was listed as a remote module.
    (tmp_path / "providers.tf").write_text(
        'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n'
        '      version = "~> 5.0"\n    }\n  }\n}\n'
    )
    (tmp_path / "main.tofu").write_text(
        'module "net" {\n  # a } in a comment, and a { in a string\n  description = "{"\n'
        '  source = "git::https://example.invalid/net.git"\n}\n'
        'resource "x" "y" {\n  source = "not-a-module"\n}\n'
    )
    (tmp_path / "more.tofu.json").write_text(
        json.dumps([{"module": {"k": {"source": "registry.example/ns/k/aws"}}}, {"terraform": {}}])
    )
    assert remote_modules(tmp_path) == ["git::https://example.invalid/net.git", "registry.example/ns/k/aws"]


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


def test_cli_warns_about_remote_modules_after_a_successful_scan(
    tmp_path: Path, releases: FakeReleases, write_lock: Callable[[str], Path]
) -> None:
    dest, _, _ = fake_trivy(tmp_path, releases, write_lock)
    repo = _repo(tmp_path)
    (repo / "infra" / "main.tf").write_text(
        'module "m" {\n  source = "git::https://example.invalid/m.git"\n}\n'
    )
    code, output, _, _ = _cli(tmp_path, dest, repo, repo)
    assert code == 0, output
    assert (
        "1 remote Terraform module(s) not fetched or evaluated: git::https://example.invalid/m.git" in output
    )


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


SENTINEL_CHECKS = files("sentinelci.scanners.configs").joinpath("trivy-checks")


def test_sentinelcis_own_checks_cannot_be_mistaken_for_trivys() -> None:
    """Every check in configs/trivy-checks is in the `sentinelci` namespace (the only one added to Trivy's)
    and has a SENTINEL-* id, so a finding names who wrote the rule and no Trivy check id is shadowed."""
    checks = [entry for entry in SENTINEL_CHECKS.iterdir() if entry.name.endswith(".rego")]
    assert checks
    for check in checks:
        text = check.read_text(encoding="utf-8")
        package = re.search(r"^package (\S+)$", text, re.MULTILINE)
        assert package and package.group(1).startswith(f"{CHECK_NAMESPACE}."), check.name
        ids = re.findall(r"^#   (?:id|avd_id): (\S+)$", text, re.MULTILINE)
        assert len(ids) == 2 and len(set(ids)) == 1 and ids[0].startswith("SENTINEL-"), check.name
        assert re.search(r"^#   severity: (LOW|MEDIUM|HIGH|CRITICAL)$", text, re.MULTILINE), check.name
        assert "#   input:\n#     selector:" in text, f"{check.name} must say which input it reads"


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
@pytest.mark.parametrize(
    ("scan_file", "moda_file"),
    [
        ("main.tf", "main.tf"),
        ("main.tofu", "main.tf"),
        ("main.tf", "main.tofu"),
        ("main.tofu.json", "main.tf"),
    ],
    ids=["terraform", "tofu-in-scan-tree", "tofu-in-module", "tofu-json-in-scan-tree"],
)
def test_real_trivy_module_level_ignore_in_an_outside_module_fails_closed(
    tmp_path: Path, scan_file: str, moda_file: str
) -> None:
    # Review of #26, repro N1: with the real Trivy, the ignore above `module "b"` in ../moda silenced modb.
    # Second review, repros A1 to A3: Trivy loads OpenTofu files too, so the same chain with .tofu files.
    control = tmp_path / "control"
    _module_chain(control, ignore=False, scan_file=scan_file, moda_file=moda_file)
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
    _module_chain(repo, ignore=True, scan_file=scan_file, moda_file=moda_file)
    with pytest.raises(ScannerError, match=rf"\(moda/{moda_file}\)"):
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


# SentinelCI's own check SENTINEL-AWS-0001 (configs/trivy-checks), where Trivy's embedded checks see nothing.
ALLOW_ALL = """jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })"""
ASSUME_ROLE = """jsonencode({
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })"""
FULL_ADMIN = {
    "jsonencode": f"""resource "aws_iam_policy" "p" {{
  name   = "p"
  policy = {ALLOW_ALL}
}}
""",
    "heredoc json, *:* and a list": """resource "aws_iam_policy" "p" {
  name   = "p"
  policy = <<-JSON
    {"Version": "2012-10-17",
     "Statement": [{"Effect": "Allow", "Action": "*:*", "Resource": ["*"]}]}
  JSON
}
""",
    "policy document": """data "aws_iam_policy_document" "d" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "p" {
  name   = "p"
  policy = data.aws_iam_policy_document.d.json
}
""",
    "role policy, second statement, mixed actions": f"""resource "aws_iam_role" "r" {{
  name               = "r"
  assume_role_policy = {ASSUME_ROLE}
}}

resource "aws_iam_role_policy" "p" {{
  name   = "p"
  role   = aws_iam_role.r.id
  policy = jsonencode({{ Version = "2012-10-17", Statement = [
    {{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }},
    {{ Effect = "Allow", Action = ["s3:GetObject", "*"], Resource = "*" }},
  ] }})
}}
""",
    "inline policy of a role": f"""resource "aws_iam_role" "r" {{
  name               = "r"
  assume_role_policy = {ASSUME_ROLE}
  inline_policy {{
    name   = "p"
    policy = {ALLOW_ALL}
  }}
}}
""",
    "user policy": f"""resource "aws_iam_user" "u" {{
  name = "u"
}}

resource "aws_iam_user_policy" "p" {{
  name   = "p"
  user   = aws_iam_user.u.name
  policy = {ALLOW_ALL}
}}
""",
    "group policy": f"""resource "aws_iam_group" "g" {{
  name = "g"
}}

resource "aws_iam_group_policy" "p" {{
  name   = "p"
  group  = aws_iam_group.g.name
  policy = {ALLOW_ALL}
}}
""",
}
ASSUME_ROLE_CFN = """      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: ec2.amazonaws.com}
            Action: sts:AssumeRole
"""
FULL_ADMIN_CLOUDFORMATION = {
    "AWS::IAM::Policy": f"""AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AdminPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: admin
      Roles: [!Ref Role]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  Role:
    Type: AWS::IAM::Role
    Properties:
{ASSUME_ROLE_CFN}""",
    "inline policy of an AWS::IAM::Role": f"""AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
{ASSUME_ROLE_CFN}      Policies:
        - PolicyName: inline-admin
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: ["*:*"]
                Resource: ["*"]
""",
}
NOT_FULL_ADMIN = {
    "one service": ("s3:*", "*", "Allow"),
    "one resource": ("*", "arn:aws:s3:::bucket/*", "Allow"),
    "deny": ("*", "*", "Deny"),
    "prefix wildcard": ("s3:Get*", "*", "Allow"),
}


@real
@pytest.mark.integration
@pytest.mark.parametrize("form", FULL_ADMIN)
def test_real_trivy_reports_full_admin_policies_with_sentinelcis_check(tmp_path: Path, form: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "iam.tf").write_text(FULL_ADMIN[form])
    assert ("iam.tf", "SENTINEL-AWS-0001") in _real_ids(repo)


@real
@pytest.mark.integration
@pytest.mark.parametrize("form", FULL_ADMIN_CLOUDFORMATION)
def test_real_trivy_reports_full_admin_cloudformation_policies(tmp_path: Path, form: str) -> None:
    # Trivy adapts CloudFormation into the same IAM state. Not seen: AWS::IAM::ManagedPolicy, which Trivy does
    # not adapt, like a Terraform policy read with file().
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "template.yaml").write_text(FULL_ADMIN_CLOUDFORMATION[form])
    assert ("template.yaml", "SENTINEL-AWS-0001") in _real_ids(repo)


@real
@pytest.mark.integration
@pytest.mark.parametrize("case", NOT_FULL_ADMIN)
def test_real_trivy_leaves_narrower_policies_to_trivys_own_checks(tmp_path: Path, case: str) -> None:
    action, resource, effect = NOT_FULL_ADMIN[case]
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = ALLOW_ALL.replace('"Allow"', f'"{effect}"').replace('Action = "*"', f'Action = "{action}"')
    policy = policy.replace('Resource = "*"', f'Resource = "{resource}"')
    (repo / "iam.tf").write_text(
        f'resource "aws_iam_policy" "p" {{\n  name   = "p"\n  policy = {policy}\n}}\n'
    )
    assert "SENTINEL-AWS-0001" not in {rule for _, rule in _real_ids(repo)}
    assert case != "one service" or ("iam.tf", "AWS-0345") in _real_ids(repo), "control: Trivy reads it"


@real
@pytest.mark.integration
def test_real_trivy_loads_no_check_from_the_scanned_repository(tmp_path: Path) -> None:
    # A check the author of a change writes, in SentinelCI's own namespace: never loaded. Trivy's embedded
    # checks still run next to SentinelCI's (AWS-0086 is Trivy's).
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(PUBLIC_ACL)
    planted = """# METADATA
# title: planted
# custom:
#   id: SENTINEL-AWS-9999
#   avd_id: SENTINEL-AWS-9999
#   severity: CRITICAL
#   input:
#     selector:
#       - type: cloud
package sentinelci.planted

import rego.v1

deny contains "planted" if true
"""
    for where in ("planted.rego", "policies/planted.rego", ".trivy/planted.rego"):
        (repo / where).parent.mkdir(exist_ok=True)
        (repo / where).write_text(planted)
    rules = {rule for _, rule in _real_ids(repo)}
    assert "AWS-0086" in rules and "SENTINEL-AWS-9999" not in rules


# Review of #53.


@real
@pytest.mark.integration
def test_real_trivy_fails_closed_when_a_sentinelci_check_does_not_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A type error (here an unknown builtin) is not a parse error: without --rego-error-limit 0, Trivy logs
    # it, drops the check and exits 0, so SENTINEL-AWS-0001 would silently stop reporting.
    configs = tmp_path / "configs"
    shipped = files("sentinelci.scanners.configs")
    (configs / "trivy-data").mkdir(parents=True)
    (configs / "trivy-checks").mkdir()
    for name in ("trivy-data", "trivy-checks"):
        for entry in shipped.joinpath(name).iterdir():
            text = entry.read_text(encoding="utf-8").replace("json.unmarshal(", "json.unmarshall(")
            (configs / name / entry.name).write_text(text, encoding="utf-8")
    monkeypatch.setattr("sentinelci.scanners.trivy.files", lambda _package: configs)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "iam.tf").write_text(FULL_ADMIN["jsonencode"])
    with pytest.raises(ScannerError, match="rego_type_error"):
        _real_ids(repo)


@real
@pytest.mark.integration
def test_real_trivy_does_not_adapt_json_cloudformation_policies(tmp_path: Path) -> None:
    # Known gap, pinned so a Trivy upgrade that starts adapting JSON templates shows up: the same template as
    # YAML is reported, as JSON it is not (Trivy's own AWS-0345 misses JSON policies too).
    repo = tmp_path / "repo"
    repo.mkdir()
    template = yaml.safe_load(FULL_ADMIN_CLOUDFORMATION["inline policy of an AWS::IAM::Role"])
    (repo / "template.json").write_text(json.dumps(template))
    assert "SENTINEL-AWS-0001" not in {rule for _, rule in _real_ids(repo)}


WILDCARD_SPELLINGS = {
    "double star": ('Action = "**"', True),
    "question mark and star": ('Action = "*:?*"', True),
    "question mark then star": ('Action = "?*"', True),
    "every resource but one": ('Action = "*", NotResource = "arn:aws:s3:::audit"', True),
    "nothing (NotResource *)": ('Action = "*", NotResource = "*"', False),
    # IAM refuses Resource and NotResource together; with one ARN in Resource it is not every resource anyway.
    "one resource, and a NotResource": (
        'Action = "*", Resource = "arn:aws:s3:::b", NotResource = "arn:aws:s3:::audit"',
        False,
    ),
    "one character": ('Action = "?"', False),
    "one verb in every service": ('Action = "*:Get*"', False),
    "every action but IAM (NotAction)": ('NotAction = "iam:*"', False),
}


@real
@pytest.mark.integration
@pytest.mark.parametrize("case", WILDCARD_SPELLINGS)
def test_real_trivy_full_admin_spellings(tmp_path: Path, case: str) -> None:
    clause, reported = WILDCARD_SPELLINGS[case]
    repo = tmp_path / "repo"
    repo.mkdir()
    statement = clause if "Resource" in clause else f'{clause}, Resource = "*"'
    (repo / "iam.tf").write_text(
        'resource "aws_iam_policy" "p" {\n  name   = "p"\n'
        '  policy = jsonencode({ Version = "2012-10-17", Statement = '
        f'[{{ Effect = "Allow", {statement} }}] }})\n}}\n'
    )
    assert (("iam.tf", "SENTINEL-AWS-0001") in _real_ids(repo)) is reported


def _real_findings(root: Path) -> list[Finding]:
    results, run = scan_iac_with_run(root, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    run_info = Run(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr")
    return normalize_trivy_config(results, run=run_info, tool=Tool(name="trivy", version=run.version))


@real
@pytest.mark.integration
def test_real_trivy_reports_full_admin_as_high_on_its_resource(tmp_path: Path) -> None:
    # One resource among others still counts as every resource; the severity is what the risk model reads.
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = ALLOW_ALL.replace('Resource = "*"', 'Resource = ["arn:aws:s3:::b", "*"]')
    (repo / "iam.tf").write_text(
        f'resource "aws_iam_policy" "admin" {{\n  name   = "p"\n  policy = {policy}\n}}\n'
    )
    found = [f for f in _real_findings(repo) if f.rule_id == "SENTINEL-AWS-0001"]
    assert [(f.severity, f.location.path if f.location else None) for f in found] == [("HIGH", "iam.tf")]
