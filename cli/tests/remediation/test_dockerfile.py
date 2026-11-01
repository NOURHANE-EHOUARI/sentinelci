"""The deterministic Dockerfile fixer (task A6, SPEC §9): only safe edits and minimal diffs, each checked
against the real Trivy (opt-in with SENTINEL_TOOLS_DIR, like the other real-tool tests)."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.remediation.dockerfile import FIXES, fix_dockerfile, propose
from sentinelci.remediation.proposal import NotFixable

from .conftest import NOW, ROOT, iac_finding

SEED_PATH = "demo-shop/services/shop-api/Dockerfile"
SEED = ROOT / SEED_PATH
GOLDEN = Path(__file__).parent / "fixtures" / "shop-api-dockerfile.diff"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)


def _seed_findings() -> list:  # type: ignore[type-arg]
    # What Trivy 0.76.1 reports on the seed (GT-IAC-006).
    return [iac_finding("DS-0002", SEED_PATH, "HIGH"), iac_finding("DS-0026", SEED_PATH, "LOW")]


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / SEED_PATH).parent.mkdir(parents=True)
    shutil.copy(SEED, repo / SEED_PATH)
    return repo


def test_the_seed_runs_as_non_root_and_nothing_else_changes(
    tmp_path: Path, proposal_validator: Draft202012Validator
) -> None:
    repo = _repo(tmp_path)
    proposal = propose(_seed_findings(), repo, created_at=NOW).proposal
    assert proposal is not None and proposal.strategy == "deterministic:dockerfile"
    assert proposal.finding_ids == [iac_finding("DS-0002", SEED_PATH).id], "DS-0026 (HEALTHCHECK) stays open"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(proposal.diff)
    assert proposal.diff == GOLDEN.read_text()
    assert "HEALTHCHECK" in proposal.rationale and "UID 10001" in proposal.rationale
    document = json.loads(proposal.model_dump_json(exclude_none=True))
    assert not [e.message for e in proposal_validator.iter_errors(document)]
    git = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "seed"], check=True)
    (tmp_path / "p.diff").write_text(proposal.diff)
    subprocess.run([*git, "apply", str(tmp_path / "p.diff")], check=True)
    assert (repo / SEED_PATH).read_text().splitlines()[-2:] == [
        "USER 10001:10001",
        'CMD ["python", "-m", "app"]',
    ]


@pytest.mark.parametrize(
    ("dockerfile", "expected"),
    [
        ("FROM a\nRUN make\nUSER root\nCMD x\n", "FROM a\nRUN make\nUSER 10001:10001\nCMD x\n"),
        ("FROM a\nuser 0:0  # as root\nCMD x\n", "FROM a\nuser 10001:10001\nCMD x\n"),
        ("FROM a\nUSER app\nCMD x\n", "FROM a\nUSER app\nCMD x\n"),
        ("FROM a\nRUN make\n", "FROM a\nRUN make\nUSER 10001:10001\n"),
        ("FROM b AS build\nUSER root\nRUN make\nFROM a\nCOPY --from=build /x /x\nENTRYPOINT [\"/x\"]\n",
         "FROM b AS build\nUSER root\nRUN make\nFROM a\nCOPY --from=build /x /x\nUSER 10001:10001\n"
         "ENTRYPOINT [\"/x\"]\n"),
    ],
    ids=["user-root", "user-zero-lowercase", "already-non-root", "no-cmd", "multi-stage"],
)  # fmt: skip
def test_the_final_stage_runs_as_non_root(dockerfile: str, expected: str) -> None:
    assert fix_dockerfile(dockerfile, ["DS-0002"]).text == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ADD app.py /app/\n", "COPY app.py /app/\n"),
        ("add --chown=10001 src/ /src/\n", "copy --chown=10001 src/ /src/\n"),
        ("ADD https://example.com/x.sh /x.sh\n", None),
        ("ADD vendor.tar.gz /opt/\n", None),
        ("ADD --checksum=sha256:00 https://example.com/x /x\n", None),
        ("ADD git@github.com:o/r.git /r\n", None),
        ("ADD --unpack=true dist /opt/\n", None),  # an ADD-only flag on a local source
    ],
    ids=[
        "local-file",
        "lowercase-with-chown",
        "url",
        "archive-extracted",
        "checksum-flag",
        "git-source",
        "add-only-flag",
    ],
)
def test_add_becomes_copy_only_where_it_does_nothing_more(line: str, expected: str | None) -> None:
    dockerfile = f"FROM a\n{line}CMD x\n"
    assert fix_dockerfile(dockerfile, ["DS-0005"]).text == f"FROM a\n{expected or line}CMD x\n"


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        ("RUN apt-get update && apt-get install -y curl\n",
         "RUN apt-get update && apt-get install --no-install-recommends -y curl\n"),
        ("RUN apt-get -y install curl \\\n    gcc && rm -rf /var/lib/apt/lists/*\n",
         "RUN apt-get -y install --no-install-recommends curl \\\n    gcc && rm -rf /var/lib/apt/lists/*\n"),
        ("RUN apt-get install -y \\\n    --no-install-recommends curl\n", None),
        ("RUN apt-get install -y a && apt-get install -y b\n",
         "RUN apt-get install --no-install-recommends -y a"
         " && apt-get install --no-install-recommends -y b\n"),
    ],
    ids=["one-line", "continuation", "flag-on-a-later-line", "two-installs"],
)  # fmt: skip
def test_apt_get_installs_no_recommended_packages(run: str, expected: str | None) -> None:
    dockerfile = f"FROM a\n{run}CMD x\n"
    assert fix_dockerfile(dockerfile, ["DS-0029"]).text == f"FROM a\n{expected or run}CMD x\n"


@pytest.mark.parametrize(
    ("dockerfile", "reason"),
    [
        ("# escape=`\nFROM a\nRUN x `\n  y\n", "escape"),
        ("FROM a\nRUN <<EOF\napt-get install -y x\nEOF\n", "heredoc"),
        ("FROM a\nCMD x", "newline"),
    ],
    ids=["escape-directive", "heredoc", "no-final-newline"],
)
def test_a_file_that_cannot_be_edited_safely_is_left_alone(dockerfile: str, reason: str) -> None:
    with pytest.raises(NotFixable, match=reason):
        fix_dockerfile(dockerfile, ["DS-0002"])


@pytest.mark.parametrize(
    ("name", "selected"),
    [("Dockerfile", True), ("Dockerfile.prod", True), ("api.dockerfile", True), ("Containerfile", True),
     ("docker-compose.yml", False), ("Dockerfile.md", True)],
)  # fmt: skip
def test_the_files_trivy_reads_as_dockerfiles_are_the_ones_fixed(
    tmp_path: Path, name: str, selected: bool
) -> None:
    (tmp_path / name).write_text("FROM a\nCMD x\n")
    plan = propose([iac_finding("DS-0002", name, "HIGH")], tmp_path, created_at=NOW)
    assert (plan.proposal is not None) == selected


def test_cli_proposes_the_seed_fix(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    findings = tmp_path / "findings.ndjson"
    findings.write_text(dumps_ndjson(_seed_findings()))
    out = tmp_path / "proposal.json"
    args = [
        "remediate",
        "dockerfile",
        "--findings",
        str(findings),
        "--repo-root",
        str(repo),
        "--out",
        str(out),
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0 and "1 finding(s) in 1 file(s)" in result.output, result.output
    assert PatchProposal.model_validate_json(out.read_bytes()).strategy == "deterministic:dockerfile"


# ---------------------------------------------------------------- the real Trivy

RICH = """\
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y gcc \\
    make
ADD src/ /src/
FROM python:3.12-slim
ADD app.py /app/app.py
RUN apt-get update && apt-get -y install curl && rm -rf /var/lib/apt/lists/*
USER root
CMD ["python", "/app/app.py"]
"""


def _trivy(directory: Path, cache: Path) -> dict[str, set[str]]:
    args = ["config", "--skip-check-update", "--disable-telemetry", "--config", "", "--ignorefile", "",
            "--format", "json", "--quiet", "--cache-dir", str(cache), str(directory)]  # fmt: skip
    run = subprocess.run(
        [str(Path(str(TOOLS_DIR)) / "bin" / "trivy"), *args], capture_output=True, text=True, check=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(cache), "HTTPS_PROXY": "http://127.0.0.1:9"},
    )  # fmt: skip
    found: dict[str, set[str]] = {}
    for result in json.loads(run.stdout).get("Results", []):
        found.setdefault(Path(result["Target"]).parent.name, set()).update(
            m["ID"] for m in result.get("Misconfigurations") or []
        )
    return found


@real
@pytest.mark.integration
def test_real_trivy_each_edit_resolves_its_rule_and_adds_none(tmp_path: Path) -> None:
    sources = {"rich": RICH, "seed": SEED.read_text()}
    for name, text in sources.items():
        (tmp_path / "before" / name).mkdir(parents=True)
        (tmp_path / "before" / name / "Dockerfile").write_text(text)
    before = _trivy(tmp_path / "before", tmp_path / "cache")
    assert before["seed"] == {"DS-0002", "DS-0026"}, "the seed's findings changed: update _seed_findings"
    cases = [(name, rule) for name in sources for rule in sorted(before[name] & FIXES.keys())]
    assert {rule for _, rule in cases} == set(FIXES), "every rule the fixer knows is checked"
    for name, rule in cases:
        (tmp_path / "after" / f"{name}-{rule}").mkdir(parents=True)
        (tmp_path / "after" / f"{name}-{rule}" / "Dockerfile").write_text(
            fix_dockerfile(sources[name], [rule]).text
        )
    after = _trivy(tmp_path / "after", tmp_path / "cache")
    for name, rule in cases:
        reported = after.get(f"{name}-{rule}", set())
        assert rule not in reported, f"{rule} still reported on {name}"
        assert reported <= before[name], f"{rule} on {name} added {reported - before[name]}"
