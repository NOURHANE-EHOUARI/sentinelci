"""Deterministic Dockerfile fixer (task A6, SPEC §9 strategy `deterministic:dockerfile`).

It fixes the Trivy findings it knows how to resolve, and only those, each rule id mapped to one edit checked
against the pinned Trivy, and it claims only the findings an edit resolved:

- DS-0005 (ADD for a local file): `COPY`, only when ADD would do nothing more. ADD unpacks a local tar
  archive by its content, not its name, and the build context may be the Dockerfile's directory or the
  repository root, so every source must be found, and every place it could be (next to the Dockerfile, at
  the repository root) must hold nothing or a plain directory or regular file inside the repository: no
  symbolic link, tar or compressed file. A URL, a git or SSH source (`user@host:path`), a glob, a variable,
  a path with `..`, a quoted or escaped word, a JSON form that is not a list of plain names, a missing
  source and an ADD-only flag keep ADD: BuildKit could read each of them otherwise;
- DS-0029 (apt-get without --no-install-recommends): the flag is added to each `apt-get install` lacking it;
- DS-0002 (the image runs as root): `USER 10001:10001` is added to the final stage (the last FROM) after its
  last RUN and USER, so every RUN still runs as the user it ran as: before the next CMD or ENTRYPOINT, or at
  the end. A USER line is never rewritten.

An edit never touches an instruction that carries a finding it does not resolve: Trivy names a Dockerfile
finding by its instruction's text, so editing that line would give the other finding a new fingerprint, which
the gate counts as new. The line-preserving edits run first, so the findings' line numbers still hold.

The USER change can still change what the image does: files the image writes at run time must be writable by
UID 10001, and an image that needs root at run time breaks. The rationale says so. Left alone, because the
right fix depends on the application or on the network: the base image's tag or digest (a registry lookup),
a missing HEALTHCHECK, a script piped to a shell. Those findings stay open.

Only the lines of the edited instructions change. A file the fixer cannot edit safely (a parser `escape`
directive, a heredoc) is left alone rather than guessed at.
"""

import json
import re
import tarfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from sentinelci.contracts.finding import Finding
from sentinelci.remediation.proposal import FixContext, Fixed, NotFixable, Plan, propose_fixes
from sentinelci.scanners.runner import is_within

NON_ROOT_USER = "10001:10001"
DOCKERFILE_NAMES = re.compile(r"(?i)^(dockerfile|containerfile)(\..+)?$|.+\.(dockerfile|containerfile)$")
_DIRECTIVE = re.compile(r"^#\s*(escape|syntax)\s*=", re.IGNORECASE)
_HEREDOC = re.compile(r"<<-?\s*[\"']?[A-Za-z_]\w*")
_APT_INSTALL = re.compile(r"\bapt-get\b(?:(?!&&|\|\||;|\|).)*?\binstall\b", re.DOTALL)
_COMMAND_END = re.compile(r"&&|\|\||;|\|")
_COPY_FLAGS = ("--chown", "--chmod", "--link", "--exclude")  # flags COPY takes too
# gzip, bzip2, xz, zstd: ADD may unpack a compressed tar whatever its name.
_COMPRESSED = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")


@dataclass
class Instruction:
    start: int  # index of its first physical line
    end: int  # index after its last physical line
    keyword: str  # upper case

    def lines(self) -> range:
        """Its 1-based line numbers, as findings name them."""
        return range(self.start + 1, self.end + 1)


def parse_instructions(lines: list[str]) -> list[Instruction]:
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


def check_editable(lines: list[str]) -> None:
    """Raise NotFixable for a file the fixer never edits, as its instructions cannot be told apart safely: no
    final newline, a byte-order mark, an `escape` parser directive, a heredoc. `sentinel remediate check` asks
    the same."""
    if not lines or not lines[-1].endswith("\n"):
        raise NotFixable("the file does not end with a newline")
    if lines[0].startswith("\ufeff"):  # #85 review: BuildKit drops it and reads `# escape=` after it
        raise NotFixable("a byte-order mark: Docker reads the parser directives after it")
    for line in lines:
        if line.strip() and not line.strip().startswith("#"):
            break  # parser directives only come first
        if _DIRECTIVE.match(line.strip()) and "escape" in line.lower():
            raise NotFixable("an `escape` parser directive changes how lines continue")
    if any(_HEREDOC.search(line) for line in lines if not line.lstrip().startswith("#")):
        raise NotFixable("a heredoc: its lines cannot be told apart from instructions safely")


@dataclass
class _Edit:
    """One edit's view of the file: its lines, the lines other findings are on, and what it left open."""

    lines: list[str]
    held: set[int]  # 1-based lines carrying a finding this run does not resolve
    context: FixContext | None
    left_open: set[tuple[str, int | None]]

    def free(self, instruction: Instruction) -> bool:
        return not self.held.intersection(instruction.lines())

    def leave(self, rule: str, instruction: Instruction | None) -> None:
        if instruction is None:
            self.left_open.add((rule, None))
        else:
            self.left_open.update((rule, line) for line in instruction.lines())


def _non_root_user(edit: _Edit, instructions: list[Instruction]) -> None:
    starts = [i for i, ins in enumerate(instructions) if ins.keyword == "FROM"]
    final = instructions[starts[-1] :] if starts else instructions
    users = [ins for ins in final if ins.keyword == "USER"]
    if users:
        tokens = edit.lines[users[-1].start].split(None, 1)
        user = tokens[1].split()[0].split(":", 1)[0] if len(tokens) > 1 and tokens[1].split() else ""
        if user not in ("root", "0"):
            edit.leave("DS-0002", None)  # it does not run as root as far as this file says: nothing to do
            return
    stage_start = final[0].end if final else 0
    after = max((ins.end for ins in final if ins.keyword in ("RUN", "USER")), default=stage_start)
    run_points = [ins.start for ins in final if ins.keyword in ("CMD", "ENTRYPOINT") and ins.start >= after]
    edit.lines.insert(min(run_points, default=len(edit.lines)), f"USER {NON_ROOT_USER}\n")


def _plain_local_source(source: str, context: FixContext | None) -> bool:
    """A source ADD only copies, wherever the build context puts it.

    The context may be the Dockerfile's directory or the repository root (`docker build -f svc/Dockerfile .`),
    so every place the source could be is checked. A place where nothing is found is skipped; any place that
    holds a symbolic link (Docker follows it, and unpacks a tar it points to), something outside the
    repository, a tar, something compressed, or anything but a directory or a regular file keeps ADD. ADD
    becomes COPY only when the source was found and every place that holds it is plain.

    A source BuildKit may read otherwise keeps ADD too: a URL or a git source (`://`, or any `user@host:path`,
    which it fetches over SSH), and a path with `..`, which it cleans into the context (`../app.py` from
    `svc/` is `svc/app.py` there), so the places checked here would not be the ones it reads.
    """
    if context is None or not source or any(c in source for c in "*?[$:@"):
        return False
    if ".." in PurePosixPath(source).parts:
        return False
    root = context.repo_root
    found = False
    for base in (root / context.path).parent, root:
        candidate = base / source.lstrip("/")
        if not candidate.is_symlink() and not candidate.exists():
            continue  # nothing there, not even a dangling link
        found = True
        if candidate.is_symlink() or not is_within(candidate, root):
            return False
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            return False
        with candidate.open("rb") as file:
            head = file.read(6)
        if head.startswith(_COMPRESSED) or tarfile.is_tarfile(candidate):
            return False
    return found


def add_only_copies(lines: list[str], ins: Instruction, context: FixContext | None) -> bool:
    """This ADD does nothing COPY would not: only flags COPY takes too, and every source a plain local file or
    directory wherever the build context puts it (`_plain_local_source`). The fixer turns only such an ADD
    into COPY, and `sentinel remediate check` accepts only that edit."""
    text = " ".join(line.strip().rstrip("\\") for line in lines[ins.start : ins.end])
    words = text.split()[1:]
    flags_ok = all(not w.startswith("--") or w.startswith(_COPY_FLAGS) for w in words)
    args = [w for w in words if not w.startswith("--")]
    if args and args[0].startswith("["):  # the JSON form: read as BuildKit reads it, or not at all
        try:
            parsed = json.loads(" ".join(args))
        except ValueError:
            return False
        if not (isinstance(parsed, list) and all(isinstance(a, str) and a.split() == [a] for a in parsed)):
            return False  # not a list of strings, or a name with a space in it
        args = parsed
    elif any(c in word for word in args for c in "\"'\\"):
        return False  # a quote or an escape: the shell form's words are not these
    sources = args[:-1]
    return bool(sources) and flags_ok and all(_plain_local_source(source, context) for source in sources)


def _copy_not_add(edit: _Edit, instructions: list[Instruction]) -> None:
    for ins in (ins for ins in instructions if ins.keyword == "ADD"):
        if not (add_only_copies(edit.lines, ins, edit.context) and edit.free(ins)):
            edit.leave("DS-0005", ins)  # ADD does more here, or editing it would rename another finding
            continue
        line = edit.lines[ins.start]
        position = len(line) - len(line.lstrip())
        keyword = line[position : position + 3]
        edit.lines[ins.start] = (
            line[:position] + ("COPY" if keyword.isupper() else "copy") + line[position + 3 :]
        )


def _no_recommends(edit: _Edit, instructions: list[Instruction]) -> None:
    for ins in (ins for ins in instructions if ins.keyword == "RUN"):
        text = "".join(edit.lines[ins.start : ins.end])
        edits: list[int] = []
        for match in _APT_INSTALL.finditer(text):
            end = _COMMAND_END.search(text, match.end())
            command = text[match.start() : end.start() if end else len(text)]
            if "--no-install-recommends" not in command:
                edits.append(match.end())
        if edits and not edit.free(ins):
            edit.leave("DS-0029", ins)  # another finding is named by this RUN's text
            continue
        for offset in reversed(edits):
            text = text[:offset] + " --no-install-recommends" + text[offset:]
        if edits:  # text is inserted within lines: the line count, so every instruction's place, is kept
            edit.lines[ins.start : ins.end] = text.splitlines(keepends=True)


EditFunction = Callable[[_Edit, list[Instruction]], None]
# In the order they run: the edits that keep the line count first, so findings' lines still hold for them.
FIXES: dict[str, tuple[str, EditFunction]] = {
    "DS-0005": ("COPY instead of ADD for plain local files", _copy_not_add),
    "DS-0029": ("apt-get install --no-install-recommends", _no_recommends),
    "DS-0002": (f"USER {NON_ROOT_USER} at the end of the final stage", _non_root_user),
}


def _held_lines(others: Sequence[Finding], path: str) -> set[int]:
    """The lines of `path` the other findings are on."""
    held: set[int] = set()
    for finding in others:
        for place in [finding.location, *(finding.other_locations or [])]:
            if place is not None and place.path == path and place.start_line is not None:
                held.update(range(place.start_line, (place.end_line or place.start_line) + 1))
    return held


def fix_dockerfile(text: str, rule_ids: Iterable[str], context: FixContext | None = None) -> Fixed:
    """Apply the edits of `rule_ids` (those this fixer knows) to a Dockerfile. Without a context, no ADD
    source can be checked, so ADD stays."""
    lines = text.splitlines(keepends=True)
    check_editable(lines)
    held = _held_lines(context.others, context.path) if context else set()
    edit = _Edit(lines=lines, held=held, context=context, left_open=set())
    changes: list[str] = []
    wanted = set(rule_ids)
    for rule, (label, function) in FIXES.items():
        if rule in wanted:
            before = "".join(edit.lines)
            function(edit, parse_instructions(edit.lines))
            if "".join(edit.lines) != before:
                changes.append(label)
    return Fixed(text="".join(edit.lines), changes=changes, left_open=frozenset(edit.left_open))


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
        "shell); their findings stay open. Check before merging: the image now runs as a non-root user, so "
        "files it writes at run time must be writable by UID 10001, and an image that needs root at run time "
        "breaks; the build and tests do not run it."
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
