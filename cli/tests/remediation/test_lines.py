"""Lines as git and the scanners count them (task A6): split on line feeds only.

`str.splitlines` also splits on a form feed, U+0085, U+2028 and other separators. A fixer that split that way
would edit other lines than the findings name, and its diff's line counts would not be git's, so `git apply`
would refuse the proposal (Hiba's note on #81). Each case here is applied with the real `git apply` and must
give exactly the new bytes.
"""

import subprocess
from pathlib import Path

import pytest

from sentinelci.contracts.finding import Location
from sentinelci.remediation.check import check_iac
from sentinelci.remediation.dockerfile import propose as propose_dockerfile
from sentinelci.remediation.proposal import lines_of, unified_diff

from .conftest import NOW, iac_finding

SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


def git_apply(root: Path, diff: str) -> None:
    (root / "proposal.diff").write_text(diff, encoding="utf-8")
    subprocess.run(["git", "apply", "proposal.diff"], cwd=root, check=True, capture_output=True)
    (root / "proposal.diff").unlink()


@pytest.mark.parametrize("separator", SEPARATORS, ids=[f"U+{ord(s):04X}" for s in SEPARATORS])
def test_only_a_line_feed_ends_a_line(separator: str) -> None:
    text = f"a{separator}b\nc\n"
    assert lines_of(text) == [f"a{separator}b\n", "c\n"]
    assert lines_of("a\nb") == ["a\n", "b"] and lines_of("") == [] and lines_of("\n\n") == ["\n", "\n"]


@pytest.mark.parametrize("separator", SEPARATORS, ids=[f"U+{ord(s):04X}" for s in SEPARATORS])
def test_a_diff_of_a_line_holding_a_separator_applies(tmp_path: Path, separator: str) -> None:
    old = f"one\ntwo {separator} still two\nthree\nfour\n"
    new = old.replace("three", "THREE")
    (tmp_path / "f.txt").write_bytes(old.encode())
    diff = unified_diff("f.txt", old, new)
    assert "@@ -1,4 +1,4 @@" in diff, "four lines on each side, as git counts them"
    git_apply(tmp_path, diff)
    assert (tmp_path / "f.txt").read_bytes() == new.encode()


@pytest.mark.parametrize(
    ("old", "new"),
    [("a\nb", "a\nB"), ("a\nb", "a\nb\n"), ("a\nb\n", "a\nb"), ("x\n" * 5 + "y", "x\n" * 5 + "z")],
    ids=["changed-last-line", "line-feed-added", "line-feed-removed", "far-last-line"],
)
def test_a_last_line_without_a_line_feed_carries_gits_marker(tmp_path: Path, old: str, new: str) -> None:
    (tmp_path / "f.txt").write_bytes(old.encode())
    diff = unified_diff("f.txt", old, new)
    assert "\\ No newline at end of file\n" in diff
    git_apply(tmp_path, diff)
    assert (tmp_path / "f.txt").read_bytes() == new.encode()


def test_the_dockerfile_fixer_edits_the_lines_the_findings_name(tmp_path: Path) -> None:
    """A form feed and U+2028 before the ADD: the finding's line 5 is the ADD as git counts, and the line of
    another finding (the RUN, line 6) is still held."""
    text = (
        "# build \x0c notes\n"
        "FROM debian:12\n"
        'LABEL note="a\u2028b"\n'
        "WORKDIR /app\n"
        "ADD app.py /app/\n"
        "RUN apt-get update && apt-get install -y curl\n"
        'CMD ["/app/app.py"]\n'
    )
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "Dockerfile").write_text(text, encoding="utf-8")
    (tmp_path / "svc" / "app.py").write_text("print('x')\n", encoding="utf-8")
    add = iac_finding("DS-0005", "svc/Dockerfile")
    add = add.model_copy(update={"location": Location(path="svc/Dockerfile", start_line=5, end_line=5)})
    other = iac_finding("DS-0099", "svc/Dockerfile")
    other = other.model_copy(update={"location": Location(path="svc/Dockerfile", start_line=6, end_line=6)})
    recommends = iac_finding("DS-0029", "svc/Dockerfile")
    recommends = recommends.model_copy(
        update={"location": Location(path="svc/Dockerfile", start_line=6, end_line=6)}
    )
    findings = [add, other, recommends]
    proposal = propose_dockerfile(findings, tmp_path, created_at=NOW).proposal
    assert proposal is not None and proposal.finding_ids == [add.id], "the RUN is held by DS-0099"
    base = tmp_path / "base"
    base.mkdir()
    subprocess.run(["cp", "-r", str(tmp_path / "svc"), str(base)], check=True)
    patched = tmp_path / "patched"
    subprocess.run(["cp", "-r", str(base), str(patched)], check=True)
    git_apply(patched, proposal.diff)
    assert (patched / "svc" / "Dockerfile").read_text(encoding="utf-8") == text.replace(
        "ADD app.py", "COPY app.py"
    )
    checked = check_iac(proposal, base, patched, findings)
    assert (checked.build_ok, checked.tests_ok, checked.problems) == (True, True, [])
