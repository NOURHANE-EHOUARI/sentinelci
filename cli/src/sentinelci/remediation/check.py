"""Build and tests of an infrastructure-as-code proposal (task A6, SPEC §9 verification gate).

A Kubernetes manifest or a Dockerfile has no compiler and no unit test of its own, and the demo's are never
built. For the deterministic IaC strategies, the verification run therefore defines both, on the trees of the
base and of the patched commit (exported with `git archive`, never checked out):

- **Build**: every edited file still parses as what it was, into the same resources. A manifest keeps its
  documents, each with the same apiVersion, kind, name and namespace. A Dockerfile keeps its stages (the same
  FROM lines, in order) and holds only Dockerfile instructions. Without this check, a patch that broke a file
  would make its findings "gone": a scanner reports nothing in a file it cannot parse.
- **Tests**: the patch changes only what its strategy may change.
  - A manifest, read as data, is the same once the settings the Kubernetes fixer sets are removed from both
    sides: the pod's and every container's `securityContext`, and the pod's host namespaces.
  - A Dockerfile is the same, line for line, once the `USER 10001:10001` lines the patch added are skipped,
    except that an ADD may have become COPY (on the ADD's first line, and only where the fixer makes that
    edit: COPY's flags only, and every source a plain local file or directory of the base tree, never a URL,
    an archive or a link) and an `apt-get install` may have gained `--no-install-recommends`. An added USER
    line is an instruction of its own in the final stage, with no RUN after it: every RUN still runs as the
    user it ran as.

  Whether the new settings are right is the scanners' part: a weaker one is a new finding, which the gate
  counts.

Manifests are read with a safe loader that refuses aliases (an alias can make a small file a huge value) and
duplicate keys (a parser that keeps the first one would read another manifest than this one). What cannot be
checked honestly raises CheckError, and nothing is verified: a strategy with no build or tests defined here
(an LLM code fix, B6, will be built and tested with the application), a file that is not a regular file of
both trees, or a base file this check cannot read.
"""

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.dockerfile import NON_ROOT_USER, Instruction, add_only_copies, parse_instructions
from sentinelci.remediation.kubernetes import POD_SPEC_PATHS
from sentinelci.remediation.proposal import FixContext
from sentinelci.scanners.runner import is_within

KUBERNETES = "deterministic:kubernetes"
DOCKERFILE = "deterministic:dockerfile"
MAX_FILE_BYTES = 1024 * 1024
HOST_NAMESPACES = ("hostNetwork", "hostPID", "hostIPC")
DOCKERFILE_INSTRUCTIONS = frozenset({
    "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "HEALTHCHECK", "LABEL", "MAINTAINER",
    "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER", "VOLUME", "WORKDIR",
})  # fmt: skip
_ADDED_USER = f"USER {NON_ROOT_USER}\n"
_NO_RECOMMENDS = " --no-install-recommends"


class CheckError(Exception):
    """The build and tests cannot be checked honestly: nothing is verified."""


@dataclass(frozen=True)
class Checked:
    build_ok: bool
    tests_ok: bool
    problems: list[str]  # "build: <file>: <why>" and "tests: <file>: <why>", in file order


# ---------------------------------------------------------------- reading the trees


def _read(root: Path, path: str, side: str) -> bytes:
    pure = PurePosixPath(path)
    candidate = root / path
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or candidate.is_symlink()
        or not candidate.is_file()
        or not is_within(candidate, root)
    ):
        raise CheckError(f"{path} is not a regular file of the {side} tree")
    if candidate.stat().st_size > MAX_FILE_BYTES:
        raise CheckError(f"{path} is larger than {MAX_FILE_BYTES} bytes in the {side} tree")
    return candidate.read_bytes()


# ---------------------------------------------------------------- Kubernetes manifests


class _ManifestLoader(yaml.SafeLoader):
    """SafeLoader without aliases (so without merge keys) or duplicate keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if isinstance(self.peek_event(), yaml.AliasEvent):  # type: ignore[no-untyped-call]
            raise yaml.YAMLError("aliases are not read by this check")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: list[Any] = []
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
            seen.append(key)
        return super().construct_mapping(node, deep=deep)


def _documents(text: str) -> list[Any]:
    return list(yaml.load_all(text, Loader=_ManifestLoader))  # a restricted SafeLoader


def _identity(document: Any) -> tuple[Any, ...]:
    if not isinstance(document, dict):
        return (type(document).__name__,)
    metadata = document.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    return (document.get("apiVersion"), document.get("kind"), metadata.get("name"), metadata.get("namespace"))


def _without_security_settings(document: Any) -> Any:
    """The document without what the Kubernetes fixer may set."""
    copy = deepcopy(document)
    kind = copy.get("kind") if isinstance(copy, dict) else None
    if not isinstance(kind, str) or kind not in POD_SPEC_PATHS:
        return copy
    pod: Any = copy
    for key in POD_SPEC_PATHS[kind]:
        pod = pod.get(key) if isinstance(pod, dict) else None
    if isinstance(pod, dict):
        for key in ("securityContext", *HOST_NAMESPACES):
            pod.pop(key, None)
        for field in ("initContainers", "containers"):
            containers = pod.get(field)
            for container in containers if isinstance(containers, list) else []:
                if isinstance(container, dict):
                    container.pop("securityContext", None)
    return copy


def _check_manifest(
    path: str, before_text: str, after_text: str, _base_root: Path
) -> tuple[list[str], list[str]]:
    try:
        before = _documents(before_text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise CheckError(f"{path} at the base is not a manifest this check reads: {exc}") from exc
    try:
        after = _documents(after_text)
    except (yaml.YAMLError, RecursionError) as exc:
        return [f"{path}: not a valid manifest any more ({type(exc).__name__}: {str(exc)[:200]})"], []
    if [_identity(document) for document in after] != [_identity(document) for document in before]:
        return [f"{path}: its documents changed (their number, or a kind, name or namespace)"], []
    return [], [
        f"{path}: document {number} changes more than the pod's and containers' security settings"
        for number, (old, new) in enumerate(zip(before, after, strict=True), start=1)
        if _without_security_settings(old) != _without_security_settings(new)
    ]


# ---------------------------------------------------------------- Dockerfiles


def _dockerfile_build(path: str, before: list[str], after: list[str]) -> list[str]:
    old, new = parse_instructions(before), parse_instructions(after)
    unknown = sorted({i.keyword for i in old} - DOCKERFILE_INSTRUCTIONS)
    if unknown:
        raise CheckError(f"{path} at the base holds lines that are not instructions: {unknown}")
    problems = []
    if after and after[-1].rstrip("\n").rstrip().endswith("\\"):
        problems.append(f"{path}: its last instruction continues past the end of the file")
    added = sorted({i.keyword for i in new} - DOCKERFILE_INSTRUCTIONS)
    if added:
        problems.append(f"{path}: not a Dockerfile any more (no such instruction: {', '.join(added)})")

    def stages(lines: list[str], instructions: list[Instruction]) -> list[str]:
        return ["".join(lines[i.start : i.end]) for i in instructions if i.keyword == "FROM"]

    if stages(after, new) != stages(before, old):
        problems.append(f"{path}: its stages changed (the FROM lines)")
    return problems


def _allowed_line_edit(old: str, new: str, *, add_start: bool, in_run: bool) -> bool:
    """ADD → COPY on the first line of an ADD, or `--no-install-recommends` added within a RUN."""
    if add_start:
        keyword = old.lstrip()[:3]
        indent = old[: len(old) - len(old.lstrip())]
        rest = old.lstrip()[3:]
        if keyword.upper() == "ADD" and new in (indent + "COPY" + rest, indent + "copy" + rest):
            return True
    return (
        in_run
        and new.replace(_NO_RECOMMENDS, "") == old.replace(_NO_RECOMMENDS, "")
        and new.count(_NO_RECOMMENDS) > old.count(_NO_RECOMMENDS)
    )


def _dockerfile_tests(path: str, before: list[str], after: list[str], base_root: Path) -> list[str]:
    old = parse_instructions(before)
    # An ADD may become COPY only where the fixer would make it COPY: judged on the base tree, as it was.
    context = FixContext(path=path, repo_root=base_root, others=())
    add_starts = {i.start for i in old if i.keyword == "ADD" and add_only_copies(before, i, context)}
    run_lines = {line for i in old if i.keyword == "RUN" for line in range(i.start, i.end)}
    added_users: list[int] = []
    i = j = 0
    while j < len(after):
        if i < len(before) and after[j] == before[i]:
            i, j = i + 1, j + 1
        elif after[j] == _ADDED_USER:
            added_users.append(j)
            j += 1
        elif i < len(before) and _allowed_line_edit(
            before[i], after[j], add_start=i in add_starts, in_run=i in run_lines
        ):
            i, j = i + 1, j + 1
        else:
            return [f"{path}: line {j + 1} is not a change the Dockerfile fixer makes"]
    if i < len(before):
        return [f"{path}: line {i + 1} of the base is gone"]
    new = parse_instructions(after)
    for line in added_users:
        (position,) = [k for k, ins in enumerate(new) if ins.start <= line < ins.end]
        later = {ins.keyword for ins in new[position + 1 :]}
        if new[position].start != line or new[position].keyword != "USER" or later & {"RUN", "FROM"}:
            return [
                f"{path}: the USER line added at line {line + 1} is not an instruction of its own after the "
                "last RUN of the final stage"
            ]
    return []


def _check_dockerfile(
    path: str, before_text: str, after_text: str, base_root: Path
) -> tuple[list[str], list[str]]:
    before, after = before_text.splitlines(keepends=True), after_text.splitlines(keepends=True)
    build = _dockerfile_build(path, before, after)
    return build, ([] if build else _dockerfile_tests(path, before, after, base_root))


# ---------------------------------------------------------------- the check


CHECKS: dict[str, Callable[[str, str, str, Path], tuple[list[str], list[str]]]] = {
    KUBERNETES: _check_manifest,
    DOCKERFILE: _check_dockerfile,
}


def check_iac(proposal: PatchProposal, base_root: Path, patched_root: Path) -> Checked:
    """Build and test the proposal's files: `base_root` holds the base commit's tree, `patched_root` the
    patched commit's. CheckError when it cannot be done honestly."""
    check = CHECKS.get(proposal.strategy)
    if check is None:
        raise CheckError(f"no build or tests are defined here for strategy {proposal.strategy}")
    build: list[str] = []
    tests: list[str] = []
    for path in sorted(proposal.files):
        try:
            before = _read(base_root, path, "base").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CheckError(f"{path} at the base is not UTF-8") from exc
        try:
            after = _read(patched_root, path, "patched").decode("utf-8")
        except UnicodeDecodeError:
            failed, failed_tests = [f"{path}: not UTF-8 any more"], list[str]()
        else:
            failed, failed_tests = check(path, before, after, base_root)
        build += failed
        tests += [f"{path}: not run, the build failed"] if failed else failed_tests
    return Checked(
        build_ok=not build,
        tests_ok=not tests,
        problems=[f"build: {problem}" for problem in build] + [f"tests: {problem}" for problem in tests],
    )
