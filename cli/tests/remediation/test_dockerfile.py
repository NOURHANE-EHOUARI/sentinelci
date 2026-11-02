"""The deterministic Dockerfile fixer (task A6, SPEC §9): only safe edits and minimal diffs, each checked
against the real Trivy (opt-in with SENTINEL_TOOLS_DIR, like the other real-tool tests)."""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding, Location
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.remediation.dockerfile import FIXES, fix_dockerfile, propose
from sentinelci.remediation.proposal import FixContext, NotFixable

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
        ("FROM a\nRUN make\nUSER root\nCMD x\n", "FROM a\nRUN make\nUSER root\nUSER 10001:10001\nCMD x\n"),
        ("FROM a\nuser 0:0\nCMD x\n", "FROM a\nuser 0:0\nUSER 10001:10001\nCMD x\n"),
        ("FROM a\nUSER\troot\nCMD x\n", "FROM a\nUSER\troot\nUSER 10001:10001\nCMD x\n"),
        # #42 review, should fix 1: every RUN keeps running as the user it ran as.
        ("FROM a\nUSER root\nRUN mkdir /srv\nCMD x\n",
         "FROM a\nUSER root\nRUN mkdir /srv\nUSER 10001:10001\nCMD x\n"),
        ("FROM a\nCMD x\nRUN make\n", "FROM a\nCMD x\nRUN make\nUSER 10001:10001\n"),
        ("FROM a\nRUN make\nCMD x\nUSER root\n", "FROM a\nRUN make\nCMD x\nUSER root\nUSER 10001:10001\n"),
        ("FROM a\nUSER app\nCMD x\n", "FROM a\nUSER app\nCMD x\n"),
        ("FROM a\nRUN make\n", "FROM a\nRUN make\nUSER 10001:10001\n"),
        ("FROM b AS build\nUSER root\nRUN make\nFROM a\nCOPY --from=build /x /x\nENTRYPOINT [\"/x\"]\n",
         "FROM b AS build\nUSER root\nRUN make\nFROM a\nCOPY --from=build /x /x\nUSER 10001:10001\n"
         "ENTRYPOINT [\"/x\"]\n"),
    ],
    ids=["user-root", "user-zero-lowercase", "user-tab", "run-after-user-root", "run-after-cmd",
         "user-root-after-cmd", "already-non-root", "no-cmd", "multi-stage"],
)  # fmt: skip
def test_the_final_stage_runs_as_non_root(dockerfile: str, expected: str) -> None:
    assert fix_dockerfile(dockerfile, ["DS-0002"]).text == expected


def _context(root: Path) -> FixContext:
    """A build context with every kind of ADD source: ADD unpacks a local tar by its content (#42 review)."""
    (root / "app.py").write_text("print('x')\n")
    (root / "src").mkdir()
    (root / "data").write_text("x")
    for name in ("vendor.tar.gz", "vendor"):  # a tar is a tar whatever its name
        with tarfile.open(root / name, "w:gz" if name.endswith(".gz") else "w") as archive:
            archive.add(root / "data", arcname="data")
    (root / "notes.gz").write_bytes(gzip.compress(b"not a tar"))
    with zipfile.ZipFile(root / "config.zip", "w") as archive:  # ADD never unpacks a zip
        archive.writestr("a", "b")
    return FixContext(path="Dockerfile", repo_root=root, others=[])


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ADD app.py /app/\n", "COPY app.py /app/\n"),
        ("add --chown=10001 src/ /src/\n", "copy --chown=10001 src/ /src/\n"),
        ("ADD --exclude=*.md . /app\n", "COPY --exclude=*.md . /app\n"),
        ("ADD config.zip /opt/\n", "COPY config.zip /opt/\n"),
        ("ADD https://example.com/x.sh /x.sh\n", None),
        ("ADD vendor.tar.gz /opt/\n", None),
        ("ADD vendor /opt/\n", None),
        ("ADD notes.gz /opt/\n", None),
        ("ADD missing.txt /opt/\n", None),
        ("ADD *.py /app/\n", None),
        ("ADD $SRC /app/\n", None),
        ("ADD --checksum=sha256:00 https://example.com/x /x\n", None),
        ("ADD git@github.com:o/r.git /r\n", None),
        ("ADD --unpack=true src /opt/\n", None),  # an ADD-only flag on a local source
        ("ADD app.py vendor /opt/\n", None),  # one source is a tar
    ],
    ids=[
        "local-file", "lowercase-with-chown", "exclude-flag", "zip", "url", "archive-by-name",
        "archive-by-content", "compressed", "missing", "glob", "variable", "checksum-flag", "git-source",
        "add-only-flag", "one-source-a-tar",
    ],
)  # fmt: skip
def test_add_becomes_copy_only_where_it_does_nothing_more(
    tmp_path: Path, line: str, expected: str | None
) -> None:
    dockerfile = f"FROM a\n{line}CMD x\n"
    fixed = fix_dockerfile(dockerfile, ["DS-0005"], _context(tmp_path))
    assert fixed.text == f"FROM a\n{expected or line}CMD x\n"
    assert (("DS-0005", 2) in fixed.left_open) is (expected is None), "what stays ADD is not claimed"


def test_without_a_context_no_add_source_can_be_checked() -> None:
    assert fix_dockerfile("FROM a\nADD app.py /app/\nCMD x\n", ["DS-0005"]).text.count("ADD") == 1


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
        case = tmp_path / "after" / f"{name}-{rule}"
        (case / "src").mkdir(parents=True)
        (case / "app.py").write_text("print('x')\n")  # RICH's ADD sources: plain local files
        context = FixContext(path="Dockerfile", repo_root=case, others=[])
        (case / "Dockerfile").write_text(fix_dockerfile(sources[name], [rule], context).text)
    after = _trivy(tmp_path / "after", tmp_path / "cache")
    for name, rule in cases:
        reported = after.get(f"{name}-{rule}", set())
        assert rule not in reported, f"{rule} still reported on {name}"
        assert reported <= before[name], f"{rule} on {name} added {reported - before[name]}"


# ---------------------------------------------------------------- #42 review: claim only what is resolved


def _at(rule: str, line: int, path: str = "svc/Dockerfile", severity: str = "MEDIUM") -> Finding:
    """A Trivy finding on one line; its id differs per line, as #26's do (the resource is the line's text)."""
    base = iac_finding(rule, path, severity)
    identity = hashlib.sha256(f"{rule}|{path}|{line}".encode()).hexdigest()
    return base.model_copy(
        update={"id": identity, "location": Location(path=path, start_line=line, end_line=line)}
    )


def _service(tmp_path: Path, dockerfile: str) -> Path:
    service = tmp_path / "svc"
    service.mkdir()
    (service / "Dockerfile").write_text(dockerfile)
    (service / "app.py").write_text("print('x')\n")
    (service / "data").write_text("x")
    with tarfile.open(service / "vendor", "w") as archive:  # ADD unpacks it by content; COPY would not
        archive.add(service / "data", arcname="data")
    return tmp_path


def test_a_tar_without_an_archive_name_stays_added(tmp_path: Path) -> None:
    """#42 review, blocking 1."""
    repo = _service(tmp_path, "FROM a\nADD vendor /opt/\nADD app.py /app/\nUSER app\nCMD x\n")
    findings = [_at("DS-0005", 2), _at("DS-0005", 3)]
    plan = propose(findings, repo, created_at=NOW)
    assert plan.proposal is not None
    assert "+COPY vendor" not in plan.proposal.diff and "+COPY app.py /app/" in plan.proposal.diff
    assert plan.proposal.finding_ids == [findings[1].id], "the ADD left as it is is not claimed"


def test_a_run_that_carries_another_finding_is_left_alone(tmp_path: Path) -> None:
    """#42 review, should fix 2: Trivy names a finding by its RUN's text, so the edit would rename DS-0021."""
    repo = _service(tmp_path, "FROM a\nRUN apt-get update && apt-get install curl\nUSER app\nCMD x\n")
    plan = propose([_at("DS-0029", 2), _at("DS-0021", 2, severity="HIGH")], repo, created_at=NOW)
    assert plan.proposal is None and plan.skipped["svc/Dockerfile"] == "nothing this fixer can resolve"


def test_only_the_resolved_findings_are_claimed(tmp_path: Path) -> None:
    """#42 review, should fix 3: one RUN is held by another finding, the other is fixed."""
    dockerfile = "FROM a\nRUN sudo apt-get install -y x\nRUN apt-get install -y y\nUSER root\nCMD x\n"
    repo = _service(tmp_path, dockerfile)
    held, fixed, root = _at("DS-0029", 2), _at("DS-0029", 3), _at("DS-0002", 4, severity="HIGH")
    plan = propose([held, fixed, root, _at("DS-0010", 2, severity="CRITICAL")], repo, created_at=NOW)
    assert plan.proposal is not None and plan.proposal.finding_ids == sorted([fixed.id, root.id])
    assert "-RUN sudo" not in plan.proposal.diff and "+RUN apt-get install --no-install-recommends -y y" in (
        plan.proposal.diff
    )


def test_a_crlf_dockerfile_is_left_alone(tmp_path: Path) -> None:
    """#42 review, should fix 4: a diff of the LF text would not apply."""
    (tmp_path / "Dockerfile").write_bytes(b'FROM alpine:3.20\r\nRUN echo hi\r\nCMD ["sh"]\r\n')
    plan = propose([iac_finding("DS-0002", "Dockerfile", "HIGH")], tmp_path, created_at=NOW)
    assert plan.proposal is None and "CRLF" in plan.skipped["Dockerfile"]


@pytest.mark.parametrize(
    ("line", "heredoc"),
    [('RUN echo "a << b"\n', True), ("RUN echo $((1 << 3))\n", False), ("RUN <<EOF\n", True),
     ("COPY <<-'X' /a\n", True)],
)  # fmt: skip
def test_only_a_heredoc_marker_counts_as_a_heredoc(line: str, heredoc: bool) -> None:
    """#42 review, nit 2 (still conservative: `<< b` in a string looks like one)."""
    text = f"FROM a\n{line}CMD x\n"
    if heredoc:
        with pytest.raises(NotFixable, match="heredoc"):
            fix_dockerfile(text, ["DS-0002"])
    else:
        assert "USER 10001:10001" in fix_dockerfile(text, ["DS-0002"]).text


def test_an_add_that_carries_another_finding_is_left_alone(tmp_path: Path) -> None:
    """#42 review, should fix 2, for ADD: the other finding would be renamed by the edit."""
    repo = _service(tmp_path, "FROM a\nADD app.py /app/\nUSER app\nCMD x\n")
    plan = propose([_at("DS-0005", 2), _at("DS-0013", 2)], repo, created_at=NOW)
    assert plan.proposal is None and plan.skipped["svc/Dockerfile"] == "nothing this fixer can resolve"


@pytest.mark.parametrize("source", ["$SRC", "app*.py", "../outside.txt"])
def test_a_source_that_is_not_one_plain_file_of_the_repository_stays_added(
    tmp_path: Path, source: str
) -> None:
    """A variable or a glob is expanded by the build (to a tar, maybe), even when a file has that name; a
    source outside the repository is not ours to judge."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.txt").write_text("x")
    if not source.startswith("../"):
        (repo / source).write_text("x")  # a file with that very name exists
    text = f"FROM a\nADD {source} /app/\nCMD x\n"
    context = FixContext(path="Dockerfile", repo_root=repo, others=[])
    assert fix_dockerfile(text, ["DS-0005"], context).text == text


@pytest.mark.parametrize("tar_at", ["svc/vendor", "vendor"], ids=["next-to-it", "at-the-root"])
@pytest.mark.parametrize("link", [False, True], ids=["file", "symlink"])
def test_add_stays_when_any_place_the_source_could_be_is_a_tar(
    tmp_path: Path, tar_at: str, link: bool
) -> None:
    """The build context may be the Dockerfile's directory or the repository root: a tar in either one is
    unpacked by ADD (Docker follows a symbolic link), so ADD stays when either place holds one."""
    (tmp_path / "svc").mkdir()
    (tmp_path / "data").write_text("x")
    with tarfile.open(tmp_path / "archive.tar", "w") as archive:
        archive.add(tmp_path / "data", arcname="data")
    for place in ("svc/vendor", "vendor"):
        target = tmp_path / place
        if place != tar_at:
            target.write_text("plain\n")
        elif link:
            target.symlink_to(tmp_path / "archive.tar")
        else:
            shutil.copy(tmp_path / "archive.tar", target)
    context = FixContext(path="svc/Dockerfile", repo_root=tmp_path, others=[])
    fixed = fix_dockerfile("FROM a\nADD vendor /opt/\nUSER app\nCMD x\n", {"DS-0005"}, context)
    assert "ADD vendor /opt/" in fixed.text and ("DS-0005", 2) in fixed.left_open


@pytest.mark.parametrize("where", ["svc/vendor", "vendor"], ids=["next-to-it", "at-the-root"])
def test_a_plain_source_in_either_place_becomes_copy(tmp_path: Path, where: str) -> None:
    """Control: one plain file, in either place, and nothing elsewhere."""
    (tmp_path / "svc").mkdir()
    (tmp_path / where).write_text("plain\n")
    context = FixContext(path="svc/Dockerfile", repo_root=tmp_path, others=[])
    fixed = fix_dockerfile("FROM a\nADD vendor /opt/\nUSER app\nCMD x\n", {"DS-0005"}, context)
    assert "COPY vendor /opt/" in fixed.text and not fixed.left_open


def test_a_dangling_link_where_the_source_could_be_keeps_add(tmp_path: Path) -> None:
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "vendor").write_text("plain\n")
    (tmp_path / "vendor").symlink_to(tmp_path / "missing.tar")
    context = FixContext(path="svc/Dockerfile", repo_root=tmp_path, others=[])
    fixed = fix_dockerfile("FROM a\nADD vendor /opt/\nUSER app\nCMD x\n", {"DS-0005"}, context)
    assert "ADD vendor /opt/" in fixed.text


def test_a_merged_finding_with_a_held_place_is_not_claimed(tmp_path: Path) -> None:
    """#42 review, nit 1: #26 merges two identical RUNs into one finding with `other_locations`. When one of
    them is held by another finding, the merged finding stays reported, so it is not claimed."""
    run = "RUN apt-get update && apt-get install -y curl"
    repo = _service(tmp_path, f"FROM a\n{run}\nUSER app\n{run}\nCMD x\n")
    merged = _at("DS-0029", 2).model_copy(
        update={"other_locations": [Location(path="svc/Dockerfile", start_line=4, end_line=4)]}
    )
    plan = propose([merged, _at("DS-0021", 4, severity="HIGH")], repo, created_at=NOW)
    assert plan.proposal is None and plan.skipped["svc/Dockerfile"] == "nothing this fixer can resolve"
