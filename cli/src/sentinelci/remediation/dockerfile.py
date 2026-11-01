"""Deterministic Dockerfile fixer (task A6, SPEC §9 strategy `deterministic:dockerfile`).

It fixes the Trivy findings it knows how to resolve without changing what the image does, and only those, each
rule id mapped to one edit checked against the pinned Trivy:

- DS-0002 (the image runs as root): the final stage runs as `USER 10001:10001`. A last `USER root` / `USER 0`
  is replaced; without any USER, it is added right before the stage's CMD or ENTRYPOINT, so every RUN before
  still runs as root;
- DS-0005 (ADD for a local file): `COPY`, unless ADD does something COPY does not: a URL, a git source, an
  archive ADD would extract, or an ADD-only flag;
- DS-0029 (apt-get without --no-install-recommends): the flag is added to each `apt-get install` lacking it.

Left alone, because the right fix depends on the application or on the network: the base image's tag or digest
(a registry lookup), a missing HEALTHCHECK, a script piped to a shell. Those findings stay open.

Only the lines of the edited instructions change. A file the fixer cannot edit safely (a parser `escape`
directive, a heredoc) is left alone rather than guessed at.
"""

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sentinelci.contracts.finding import Finding
from sentinelci.remediation.proposal import Fixed, NotFixable, Plan, propose_fixes

NON_ROOT_USER = "10001:10001"
DOCKERFILE_NAMES = re.compile(r"(?i)^(dockerfile|containerfile)(\..+)?$|.+\.(dockerfile|containerfile)$")
_DIRECTIVE = re.compile(r"^#\s*(escape|syntax)\s*=", re.IGNORECASE)
_ARCHIVE = re.compile(r"(?i)\.(tar|tgz|tbz2?|txz|tzst|zip|gz|bz2|xz|zst)$")
_APT_INSTALL = re.compile(r"\bapt-get\b(?:(?!&&|\|\||;|\|).)*?\binstall\b", re.DOTALL)
_COMMAND_END = re.compile(r"&&|\|\||;|\|")


@dataclass
class Instruction:
    start: int  # index of its first physical line
    end: int  # index after its last physical line
    keyword: str  # upper case


def _instructions(lines: list[str]) -> list[Instruction]:
    """The instructions of a Dockerfile and their physical lines (continuations joined, comments skipped)."""
    found: list[Instruction] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        start = index
        while lines[index].rstrip("\n").rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
        found.append(Instruction(start=start, end=index + 1, keyword=stripped.split(None, 1)[0].upper()))
        index += 1
    return found


def _check(lines: list[str]) -> None:
    if not lines or not lines[-1].endswith("\n"):
        raise NotFixable("the file does not end with a newline")
    for line in lines:
        if line.strip() and not line.strip().startswith("#"):
            break  # parser directives only come first
        if _DIRECTIVE.match(line.strip()) and "escape" in line.lower():
            raise NotFixable("an `escape` parser directive changes how lines continue")
    if any("<<" in line for line in lines if not line.lstrip().startswith("#")):
        raise NotFixable("a heredoc: its lines cannot be told apart from instructions safely")


def _non_root_user(lines: list[str], instructions: list[Instruction]) -> None:
    starts = [i for i, ins in enumerate(instructions) if ins.keyword == "FROM"]
    final = instructions[starts[-1] :] if starts else instructions
    users = [ins for ins in final if ins.keyword == "USER"]
    if users:
        last = users[-1]
        line = lines[last.start]
        keyword, _, rest = line.lstrip().partition(" ")
        tokens = rest.split()
        user = tokens[0].split(":", 1)[0] if tokens else ""
        if user in ("root", "0"):
            indent = line[: len(line) - len(line.lstrip())]
            lines[last.start] = f"{indent}{keyword} {NON_ROOT_USER}\n"
        return
    run_points = [ins.start for ins in final if ins.keyword in ("CMD", "ENTRYPOINT")]
    if run_points:
        lines.insert(min(run_points), f"USER {NON_ROOT_USER}\n")
    else:
        lines.append(f"USER {NON_ROOT_USER}\n")


def _copy_not_add(lines: list[str], instructions: list[Instruction]) -> None:
    for ins in (ins for ins in instructions if ins.keyword == "ADD"):
        text = " ".join(line.strip().rstrip("\\") for line in lines[ins.start : ins.end])
        words = text.split()[1:]
        if any(
            word.startswith("--") and not word.startswith(("--chown", "--chmod", "--link")) for word in words
        ):
            continue  # --checksum, --keep-git-dir, ...: only ADD has them
        sources = [w.strip('[]",') for w in words if not w.startswith("--")][:-1]
        if not sources or any("://" in s or s.startswith("git@") or _ARCHIVE.search(s) for s in sources):
            continue
        line = lines[ins.start]
        position = len(line) - len(line.lstrip())
        keyword = line[position : position + 3]
        lines[ins.start] = line[:position] + ("COPY" if keyword.isupper() else "copy") + line[position + 3 :]


def _no_recommends(lines: list[str], instructions: list[Instruction]) -> None:
    for ins in (ins for ins in instructions if ins.keyword == "RUN"):
        text = "".join(lines[ins.start : ins.end])
        edits: list[int] = []
        for match in _APT_INSTALL.finditer(text):
            end = _COMMAND_END.search(text, match.end())
            command = text[match.start() : end.start() if end else len(text)]
            if "--no-install-recommends" not in command:
                edits.append(match.end())
        for offset in reversed(edits):
            text = text[:offset] + " --no-install-recommends" + text[offset:]
        if edits:  # text is inserted within lines: the line count, so every instruction's place, is kept
            lines[ins.start : ins.end] = text.splitlines(keepends=True)


Edit = Callable[[list[str], list[Instruction]], None]
FIXES: dict[str, tuple[str, Edit]] = {
    "DS-0002": (f"USER {NON_ROOT_USER} in the final stage", _non_root_user),
    "DS-0005": ("COPY instead of ADD for local files", _copy_not_add),
    "DS-0029": ("apt-get install --no-install-recommends", _no_recommends),
}


def fix_dockerfile(text: str, rule_ids: Iterable[str]) -> Fixed:
    """Apply the edits of `rule_ids` (those this fixer knows) to a Dockerfile."""
    lines = text.splitlines(keepends=True)
    _check(lines)
    changes: list[str] = []
    for rule in sorted(set(rule_ids) & FIXES.keys()):
        label, edit = FIXES[rule]
        edit(lines, _instructions(lines))
        changes.append(label)
    return Fixed(text="".join(lines), changes=changes)


def _fixable(finding: Finding) -> bool:
    return (
        finding.category == "IAC"
        and finding.tool.name == "trivy"
        and finding.rule_id in FIXES
        and finding.location is not None
        and DOCKERFILE_NAMES.match(Path(finding.location.path).name) is not None
    )


def _rationale(files: int, labels: list[str]) -> str:
    return (
        f"Harden {files} Dockerfile(s): {'; '.join(labels)}. Left as they are: what depends on the "
        "application or a registry (the base image's tag or digest, a HEALTHCHECK, a script piped to a "
        "shell); their findings stay open. The image now runs as a non-root user: files it writes at run "
        "time must be writable by UID 10001."
    )


def propose(findings: Sequence[Finding], repo_root: Path, *, attempt: int = 1, created_at: datetime) -> Plan:
    """One proposal for every Dockerfile finding of `findings` this fixer resolves."""
    return propose_fixes(
        findings,
        repo_root,
        select=_fixable,
        fix=fix_dockerfile,
        strategy="deterministic:dockerfile",
        rationale=_rationale,
        attempt=attempt,
        created_at=created_at,
    )
