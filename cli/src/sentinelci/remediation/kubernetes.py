"""Deterministic Kubernetes fixer (task A6, SPEC §9 strategy `deterministic:kubernetes`).

It hardens the workloads of a manifest for the Trivy findings it knows how to resolve, and only those: each
rule id maps to one edit, checked against the pinned Trivy (the edit makes that rule's finding disappear and
adds none). What changes what the application does is never touched (a hostPath volume, an image tag,
resource limits, an added capability): those findings stay, and the verification gate rejects a proposal
that claims them.

Manifests are edited with a round-trip YAML parser, so comments, key order and quoting stay as they were and
the diff shows only the hardening. A file whose layout the parser cannot reproduce exactly is left alone
(reported as not fixable) rather than reformatted.
"""

import io
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from sentinelci.contracts.finding import Finding
from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.proposal import build_proposal
from sentinelci.scanners.runner import is_within

NON_ROOT_ID = 10001  # above 10000 (KSV-0020, KSV-0021), so no collision with a host account
_INDENTS = ((2, 4, 2), (2, 2, 0), (4, 4, 2), (4, 6, 4), (2, 4, 0))  # (mapping, sequence, offset) styles

Edit = Callable[[CommentedMap, CommentedMap], None]  # (pod spec, container) -> None


def _context(node: CommentedMap) -> CommentedMap:
    if not isinstance(node.get("securityContext"), dict):
        node["securityContext"] = CommentedMap()
    context: CommentedMap = node["securityContext"]
    return context


def _drop_all(pod: CommentedMap, container: CommentedMap) -> None:
    context = _context(container)
    if not isinstance(context.get("capabilities"), dict):
        context["capabilities"] = CommentedMap()
    capabilities = context["capabilities"]
    if not isinstance(capabilities.get("drop"), list):
        capabilities["drop"] = []
    if "ALL" not in capabilities["drop"]:
        capabilities["drop"].append("ALL")


def _non_root(pod: CommentedMap, container: CommentedMap) -> None:
    context = _context(container)
    context["runAsNonRoot"] = True
    if context.get("runAsUser") == 0 or (
        _context_of(pod).get("runAsUser") == 0 and "runAsUser" not in context
    ):
        context["runAsUser"] = NON_ROOT_ID  # runAsNonRoot with UID 0 would stop the pod from starting


def _context_of(node: CommentedMap) -> dict[str, Any]:
    context = node.get("securityContext")
    return context if isinstance(context, dict) else {}


def _pod_non_root(pod: CommentedMap, container: CommentedMap) -> None:
    _context(pod)["runAsNonRoot"] = True
    if _context_of(container).get("runAsUser") == 0:
        _context(container)["runAsUser"] = NON_ROOT_ID


def _set(key: str, value: Any) -> Edit:
    def edit(pod: CommentedMap, container: CommentedMap) -> None:
        _context(container)[key] = value

    return edit


def _seccomp(pod: CommentedMap, container: CommentedMap) -> None:
    _context(container)["seccompProfile"] = CommentedMap(type="RuntimeDefault")


def _no_host(key: str) -> Edit:
    def edit(pod: CommentedMap, container: CommentedMap) -> None:
        if pod.get(key) is True:
            pod[key] = False

    return edit


def _not_privileged(pod: CommentedMap, container: CommentedMap) -> None:
    if _context_of(container).get("privileged") is True:
        _context(container)["privileged"] = False


# Trivy (0.76.1) rule id -> the edit that resolves it. Each pair is checked with the real Trivy in the tests.
FIXES: dict[str, tuple[str, Edit]] = {
    "KSV-0001": ("allowPrivilegeEscalation: false", _set("allowPrivilegeEscalation", False)),
    "KSV-0003": ("drop ALL capabilities", _drop_all),
    "KSV-0004": ("drop ALL capabilities", _drop_all),
    "KSV-0106": ("drop ALL capabilities", _drop_all),
    "KSV-0012": ("runAsNonRoot: true", _non_root),
    "KSV-0014": ("readOnlyRootFilesystem: true", _set("readOnlyRootFilesystem", True)),
    "KSV-0017": ("privileged: false", _not_privileged),
    "KSV-0020": (f"runAsUser: {NON_ROOT_ID}", _set("runAsUser", NON_ROOT_ID)),
    "KSV-0105": (f"runAsUser: {NON_ROOT_ID}", _set("runAsUser", NON_ROOT_ID)),
    "KSV-0021": (f"runAsGroup: {NON_ROOT_ID}", _set("runAsGroup", NON_ROOT_ID)),
    "KSV-0030": ("seccompProfile RuntimeDefault", _seccomp),
    "KSV-0104": ("seccompProfile RuntimeDefault", _seccomp),
    "KSV-0118": ("pod securityContext runAsNonRoot: true", _pod_non_root),
    "KSV-0009": ("hostNetwork: false", _no_host("hostNetwork")),
    "KSV-0010": ("hostPID: false", _no_host("hostPID")),
    "KSV-0008": ("hostIPC: false", _no_host("hostIPC")),
}


class NotFixable(Exception):
    """The file cannot be edited minimally (unparsable, or a layout the parser would rewrite)."""


@dataclass(frozen=True)
class FixedManifest:
    text: str
    changes: list[str]  # what was hardened, for the proposal's rationale


def _yaml(mapping: int, sequence: int, offset: int) -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.indent(mapping=mapping, sequence=sequence, offset=offset)
    yaml.width = 4096
    return yaml


def _round_trip(text: str) -> tuple[YAML, list[Any]]:
    """The parser settings that reproduce `text` exactly, with its documents."""
    if not text.endswith("\n"):
        raise NotFixable("the file does not end with a newline")
    for style in _INDENTS:
        yaml = _yaml(*style)
        try:
            documents = list(yaml.load_all(text))
        except YAMLError as exc:
            raise NotFixable(f"not valid YAML: {type(exc).__name__}") from exc
        out = io.StringIO()
        yaml.dump_all(documents, out)
        if out.getvalue() == text:
            return yaml, documents
    raise NotFixable("its layout cannot be kept exactly (comments, indentation or quoting would change)")


def _pod_specs(document: Any) -> list[Any]:
    """The pod specs of a workload: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job or CronJob."""
    if not isinstance(document, dict):
        return []
    kind, spec = document.get("kind"), document.get("spec")
    paths = {
        "Pod": (),
        "Deployment": ("template", "spec"), "StatefulSet": ("template", "spec"),
        "DaemonSet": ("template", "spec"), "ReplicaSet": ("template", "spec"), "Job": ("template", "spec"),
        "CronJob": ("jobTemplate", "spec", "template", "spec"),
    }  # fmt: skip
    if kind not in paths or not isinstance(spec, dict):
        return []
    node: Any = spec
    for key in paths[kind]:
        node = node.get(key) if isinstance(node, dict) else None
    return [node] if isinstance(node, dict) else []


def fix_manifest(text: str, rule_ids: Iterable[str]) -> FixedManifest:
    """Apply the edits of `rule_ids` (those this fixer knows) to every workload container of the manifest."""
    edits: dict[str, Edit] = {}
    for rule in sorted(set(rule_ids) & FIXES.keys()):
        label, edit = FIXES[rule]
        edits.setdefault(label, edit)  # one edit can resolve several rules
    yaml, documents = _round_trip(text)
    for pod in (pod for document in documents for pod in _pod_specs(document)):
        containers = [*(pod.get("initContainers") or []), *(pod.get("containers") or [])]
        for container in (c for c in containers if isinstance(c, CommentedMap)):
            for edit in edits.values():
                edit(pod, container)
    out = io.StringIO()
    yaml.dump_all(documents, out)
    return FixedManifest(text=out.getvalue(), changes=sorted(edits))


@dataclass(frozen=True)
class KubernetesPlan:
    proposal: PatchProposal | None  # None: nothing this fixer can resolve
    skipped: dict[str, str]  # path -> why it was left alone


def _fixable(finding: Finding) -> bool:
    return (
        finding.category == "IAC"
        and finding.tool.name == "trivy"
        and finding.rule_id in FIXES
        and finding.location is not None
        and finding.location.path.lower().endswith((".yaml", ".yml"))
    )


def propose(
    findings: Sequence[Finding], repo_root: Path, *, attempt: int = 1, created_at: datetime
) -> KubernetesPlan:
    """One proposal for every Kubernetes finding of `findings` this fixer resolves, across their manifests."""
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if _fixable(finding) and finding.location is not None:
            by_path[finding.location.path].append(finding)
    changes: dict[str, tuple[str, str]] = {}
    fixed_ids: list[str] = []
    labels: set[str] = set()
    skipped: dict[str, str] = {}
    for path, flagged in sorted(by_path.items()):
        file = repo_root / path
        if file.is_symlink() or not file.is_file() or not is_within(file, repo_root):
            skipped[path] = "not a regular file inside the repository"
            continue
        try:
            old = file.read_text(encoding="utf-8")
            fixed = fix_manifest(old, {f.rule_id for f in flagged})
        except UnicodeDecodeError:
            skipped[path] = "not UTF-8 text"
            continue
        except NotFixable as exc:
            skipped[path] = str(exc)
            continue
        if fixed.text == old:
            skipped[path] = "already hardened: the findings are stale"
            continue
        changes[path] = (old, fixed.text)
        fixed_ids += [f.id for f in flagged]
        labels.update(fixed.changes)
    if not changes:
        return KubernetesPlan(proposal=None, skipped=skipped)
    rationale = (
        f"Harden the workloads of {len(changes)} manifest(s): {'; '.join(sorted(labels))}. Left as they are: "
        "changes to what the application does (hostPath volumes, image tags, resource limits, added "
        "capabilities); their findings stay open."
    )
    proposal = build_proposal(
        strategy="deterministic:kubernetes",
        finding_ids=fixed_ids,
        changes=changes,
        flagged_paths=set(by_path),
        rationale=rationale,
        attempt=attempt,
        created_at=created_at,
    )
    return KubernetesPlan(proposal=proposal, skipped=skipped)
