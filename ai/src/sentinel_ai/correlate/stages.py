"""Stages 1 and 2 of the correlator (task A7, SPEC section 8): one run's findings become root-cause groups.

- **Stage 1, dedup.** One alert per fingerprint: the same risk reported by two tools (Grype and Trivy give a
  package finding the same id) is one alert.
- **Stage 2a, structural.** Alerts of the same category that share a fix key are one group: the same package
  (one upgrade fixes all its advisories), the same advisory under any of its ids (CVE, GHSA, aliases: one
  vulnerable code base, such as lodash and lodash-es), or the same rule in the same file (one pattern
  repeated). Keys join groups transitively. A package in an image and the same package in a lockfile are two
  groups: one needs an image rebuild, the other a lockfile bump. Secrets are never grouped (each one is
  rotated on its own). Deterministic, no model.
- **Stage 2b, embedding.** Groups of the same category whose texts are close are merged: average linkage over
  the embeddings of their alerts, with a similarity threshold; a merged group records the linkage of its last
  merge (`similarity`). Secrets are never merged. The embedder is injected (`LLMProvider.embed`, a local model
  by default); without one, this stage is skipped. An embedder that fails, or returns non-finite or zero
  vectors, is an `EmbedderError`, and `correlate_run` then falls back to stages 1 and 2a and records the stage
  as `skipped`, with the failure: advice degrades, it never vanishes, and an outage never reads as a choice.

Labels are templates (`labelled_by: template`): what the members share, and a fix only when one change
resolves every member (each a package with known fixed versions). Stage 3 (a model labels the groups it is
given; it never forms them) comes later. Everything here is advisory: the release gate never reads it, and the
same findings in any order give the same groups.

`DEFAULT_THRESHOLD` is provisional: it is calibrated on a labelled set other than demo-shop (SPEC section 17),
then committed with the embedding model's digest before the demo-shop run.
"""

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import TypeAdapter, ValidationError

from sentinel_ai.correlate.models import (
    MAX_KEY,
    Correlation,
    Correlator,
    EmbeddingModel,
    OneLine,
    RootCauseGroup,
    Skipped,
    Stage,
    group_id,
)

Finding = Mapping[str, Any]
Embedder = Callable[[list[str]], list[list[float]]]
DEFAULT_THRESHOLD = 0.8  # provisional: see the module docstring
CORRELATOR_VERSION = "0.1.0"
PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
LOCATED_CATEGORIES = frozenset({"SAST", "IAC", "PIPELINE"})
_FINGERPRINT = re.compile(r"[a-f0-9]{64}")


class CorrelationError(Exception):
    """The findings cannot be correlated (one without a fingerprint): nothing is grouped."""


class EmbedderError(CorrelationError):
    """The embedder failed or answered nonsense: stage 2b cannot run."""


def _one_line(text: str, limit: int) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3].rstrip() + "..."


def purl_base(purl: str) -> str:
    """The package without version, qualifiers or subpath: the same rule as the fingerprints (SPEC 13.1)."""
    head = purl.partition("#")[0].partition("?")[0]
    name_start = head.rfind("/") + 1
    at = head.rfind("@")
    return head[:at] if at >= name_start else head


@dataclass(frozen=True)
class Alert:
    """One fingerprint: the findings that report it (one per tool)."""

    id: str
    findings: tuple[Finding, ...]

    @property
    def first(self) -> Finding:
        return self.findings[0]

    @property
    def category(self) -> str:
        return str(self.first.get("category", ""))

    @property
    def rule_id(self) -> str:
        return str(self.first.get("rule_id", ""))

    @property
    def title(self) -> str:
        return str(self.first.get("title") or self.rule_id)

    @property
    def path(self) -> str | None:
        location = self.first.get("location")
        return str(location["path"]) if isinstance(location, dict) and location.get("path") else None

    @property
    def package(self) -> Mapping[str, Any] | None:
        package = self.first.get("package")
        return package if isinstance(package, dict) and package.get("purl") else None

    def advisories(self) -> set[str]:
        """Every id of the advisory, across the tools that reported it."""
        ids = set()
        for finding in self.findings:
            ids.add(str(finding.get("rule_id", "")))
            for field in ("cve", "aliases"):
                ids.update(str(value) for value in finding.get(field) or [])
        return {value for value in ids if value}

    def text(self) -> str:
        """What the embedder reads: category, rule, title, package and file."""
        parts = [self.category, self.rule_id, self.title]
        if self.package is not None:
            parts.append(f"{self.package.get('name')} {self.package.get('version')}")
        if self.path is not None:
            parts.append(f"({self.path})")
        return " ".join(part for part in parts if part)


def dedup(findings: Iterable[Finding]) -> list[Alert]:
    """Stage 1: one alert per fingerprint, sorted by id; each alert's findings in a fixed order."""
    by_id: dict[str, list[Finding]] = {}
    for index, finding in enumerate(findings):
        fingerprint = finding.get("id") if isinstance(finding, Mapping) else None
        if not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None:
            raise CorrelationError(f"finding {index} has no fingerprint (id)")
        by_id.setdefault(fingerprint, []).append(finding)
    return [
        Alert(fingerprint, tuple(sorted(by_id[fingerprint], key=lambda f: json.dumps(f, sort_keys=True))))
        for fingerprint in sorted(by_id)
    ]


def structural_keys(alert: Alert) -> list[str]:
    """The fix keys of an alert: what, when shared, makes two alerts one root cause."""
    if alert.category in PACKAGE_CATEGORIES and alert.package is not None:
        keys = [f"package:{purl_base(str(alert.package['purl']))}"]
        return keys + [f"advisory:{advisory}" for advisory in sorted(alert.advisories())]
    if alert.category in LOCATED_CATEGORIES and alert.path is not None:
        return [f"rule:{alert.rule_id}@{alert.path}"]
    return []


class _Partition:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[max(root_a, root_b)] = min(root_a, root_b)

    def classes(self) -> list[list[int]]:
        classes: dict[int, list[int]] = {}
        for item in range(len(self.parent)):
            classes.setdefault(self.find(item), []).append(item)
        return [classes[root] for root in sorted(classes)]


def structural_groups(alerts: Sequence[Alert]) -> list[list[Alert]]:
    """Stage 2a: alerts of one category sharing any fix key, transitively."""
    partition = _Partition(len(alerts))
    first_with: dict[tuple[str, str], int] = {}
    for index, alert in enumerate(alerts):
        for key in structural_keys(alert):
            partition.union(first_with.setdefault((alert.category, key), index), index)
    return [[alerts[i] for i in members] for members in partition.classes()]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return sum(x * y for x, y in zip(a, b, strict=True)) / norm if norm else 0.0


def embedding_groups(
    groups: Sequence[Sequence[Alert]], embed: Embedder, threshold: float = DEFAULT_THRESHOLD
) -> list[tuple[list[int], float | None]]:
    """Stage 2b: indices of `groups` merged by average linkage over their alerts' embeddings, within one
    category (never secrets), while the closest pair is at least `threshold` similar, each with the linkage
    of its last merge (None when nothing merged into it). Ties go to the earliest pair."""
    alerts = [alert for group in groups for alert in group]
    try:
        vectors = embed([alert.text() for alert in alerts])
    except Exception as exc:  # the provider is down or refused: stage 2b did not run
        raise EmbedderError(f"the embedder failed: {type(exc).__name__}") from exc
    if (
        len(vectors) != len(alerts)
        or any(len(v) != len(vectors[0]) for v in vectors)
        or not all(math.isfinite(x) for v in vectors for x in v)
        or not all(any(v) for v in vectors)  # an empty or zero vector has no direction: every cosine is 0
    ):
        raise EmbedderError("the embedder must return one finite vector per text, all of one size, none zero")
    offsets, start = [], 0
    for group in groups:
        offsets.append(list(range(start, start + len(group))))
        start += len(group)
    similarity = [[_cosine(vectors[i], vectors[j]) for j in range(len(alerts))] for i in range(len(alerts))]
    clusters = [[index] for index in range(len(groups))]
    merged_at: list[float | None] = [None] * len(groups)
    category = [group[0].category for group in groups]

    def linkage(a: list[int], b: list[int]) -> float:
        pairs = [(i, j) for ga in a for gb in b for i in offsets[ga] for j in offsets[gb]]
        return sum(similarity[i][j] for i, j in pairs) / len(pairs)

    while True:
        best: tuple[float, int, int] | None = None
        for x in range(len(clusters)):
            for y in range(x + 1, len(clusters)):
                kind = category[clusters[x][0]]
                if kind == "SECRET" or kind != category[clusters[y][0]]:  # each secret is rotated alone
                    continue
                score = linkage(clusters[x], clusters[y])
                if score >= threshold and (best is None or score > best[0]):
                    best = (score, x, y)
        if best is None:
            return list(zip(clusters, merged_at, strict=True))
        score, x, y = best
        clusters[x] = sorted(clusters[x] + clusters[y])
        merged_at[x] = round(score, 6)
        del clusters[y], merged_at[y]


def _fix(members: Sequence[Alert]) -> str | None:
    """One change that resolves every member: an upgrade of each package past its known fixed versions."""
    fixed: dict[str, tuple[str, set[str]]] = {}
    for alert in members:
        versions = alert.package.get("fixed_versions") if alert.package is not None else None
        if alert.package is None or not versions:
            return None
        name = str(alert.package.get("name"))
        fixed.setdefault(purl_base(str(alert.package["purl"])), (name, set()))[1].update(map(str, versions))
    parts = []
    for _, (name, versions) in sorted(fixed.items()):
        listed = ", ".join(sorted(versions, key=_version_order))
        parts.append(
            f"{name} to {listed} or later" if len(versions) == 1 else f"{name} past every fix ({listed})"
        )  # versions in version order: 4.17.9 before 4.17.10
    return _one_line("Upgrade " + "; ".join(parts) + ".", 1000)


def _version_order(version: str) -> list[tuple[int, int | str]]:
    """Digits compare as numbers: 4.17.9 < 4.17.10."""
    return [(0, int(part)) if part.isdigit() else (1, part) for part in re.split(r"(\d+)", version) if part]


_ONE_LINE = TypeAdapter(OneLine)


def _expressible(key: str | None) -> str | None:
    """The key, or None when the contract cannot hold it (a line break in an alias, a very long path): the
    title still names what the members share."""
    if key is None or len(key) > MAX_KEY:
        return None
    try:
        _ONE_LINE.validate_python(key)
    except ValidationError:
        return None
    return key


def _labels(members: Sequence[Alert], stage: Stage) -> tuple[str, str, str | None, str | None]:
    """(title, root cause, single fix, shared key) for a group."""
    fix = _fix(members)
    if len(members) == 1:
        alert = members[0]
        message = alert.first.get("message") or alert.title
        return _one_line(alert.title, 200), _one_line(str(message), 2000), fix, None
    shared = set(structural_keys(members[0])).intersection(*(structural_keys(a) for a in members[1:]))
    key = min(shared) if shared else None
    count = len(members)
    if key is not None and key.startswith("package:"):
        package = members[0].package or {}
        versions = sorted({str(a.package.get("version")) for a in members if a.package}, key=_version_order)
        named = f"{package.get('name')} {', '.join(versions)}"
        advisories = sorted({a.rule_id for a in members})
        title = f"{named}: {count} advisories"
        cause = f"{named} is affected by {', '.join(advisories)}."
    elif key is not None and key.startswith("advisory:"):
        names = sorted({f"{a.package.get('name')} {a.package.get('version')}" for a in members if a.package})
        title = f"{key.removeprefix('advisory:')} in {count} packages"
        cause = f"The same advisory, {key.removeprefix('advisory:')}, affects {', '.join(names)}."
    elif key is not None and key.startswith("rule:"):
        path = members[0].path
        title = f"{members[0].rule_id}: {count} findings in {path}"
        cause = f"The same pattern ({members[0].title}) appears {count} times in {path}."
    elif stage == "structural":
        title = f"{count} related findings: {members[0].title}"
        cause = "They share packages or advisories: " + ", ".join(
            sorted({k for a in members for k in structural_keys(a)})
        ) + "."  # fmt: skip
    else:
        title = f"{count} similar findings: {members[0].title}"
        cause = "Their descriptions are close (embedding similarity); a model labels them in stage 3."
    return _one_line(title, 200), _one_line(cause, 2000), fix, _expressible(key)


def correlate(
    findings: Iterable[Finding],
    *,
    structural: bool = True,
    embed: Embedder | None = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> list[RootCauseGroup]:
    """The root-cause groups of one run's findings: every finding in exactly one group, sorted by group id.
    `structural=False` and `embed=None` turn stages off (ablation). EmbedderError when the embedder fails."""
    if not -1 <= threshold <= 1:
        raise CorrelationError(f"the similarity threshold {threshold} is not a cosine similarity (-1 to 1)")
    alerts = dedup(findings)
    groups: list[list[Alert]] = structural_groups(alerts) if structural else [[alert] for alert in alerts]
    stages: list[Stage] = ["structural" if len(group) > 1 else "dedup" for group in groups]
    similarities: list[float | None] = [None] * len(groups)
    if embed is not None and groups:
        clusters = embedding_groups(groups, embed, threshold)
        stages = [stages[c[0]] if len(c) == 1 else "embedding" for c, _ in clusters]
        similarities = [score for _, score in clusters]
        groups = [[alert for index in cluster for alert in groups[index]] for cluster, _ in clusters]
    result = []
    for members, stage, score in zip(groups, stages, similarities, strict=True):
        ids = sorted(alert.id for alert in members)
        title, cause, fix, key = _labels(sorted(members, key=lambda a: a.id), stage)
        result.append(
            RootCauseGroup(
                schema_version="1.0", group_id=group_id(ids), finding_ids=ids, stage=stage,
                labelled_by="template", similarity=score, key=key, title=title, root_cause=cause,
                single_fix=fix,
            )
        )  # fmt: skip
    return sorted(result, key=lambda group: group.group_id)


def correlate_run(
    findings_data: bytes,
    *,
    structural: bool = True,
    embed: Embedder | None = None,
    embedding_model: EmbeddingModel | None = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> Correlation:
    """The correlation document of one findings NDJSON file (the bytes B1 recorded, served at
    `GET /runs/{id}/findings`): its groups, its sha256 (what ties them to a run) and the stages that ran. If
    the embedder fails, stages 1 and 2a are kept and the embedding stage is recorded as skipped, with the
    failure. With no findings, the embedder is not called, and the stage is neither run nor skipped."""
    if (embed is None) != (embedding_model is None):
        raise CorrelationError("an embedder comes with the embedding model that names it, and only then")
    try:
        # NDJSON lines end with "\n" only, as the gate and B1 split them: str.splitlines() would also split on
        # U+2028, U+2029 and U+0085, which stay raw inside JSON strings (the CLI writes ensure_ascii=False).
        lines = findings_data.decode("utf-8").split("\n")
        findings = [json.loads(line) for line in lines if line.strip()]
    except (UnicodeDecodeError, ValueError) as exc:
        raise CorrelationError(f"the findings are not NDJSON: {exc}") from exc
    ran, skipped = embed is not None and bool(findings), None
    try:
        groups = correlate(findings, structural=structural, embed=embed if ran else None, threshold=threshold)
    except EmbedderError as exc:  # its message is the correlator's own, never the provider's text
        groups = correlate(findings, structural=structural, threshold=threshold)
        ran, skipped = False, [Skipped(stage="embedding", reason=str(exc))]
    stages: list[Stage] = ["dedup"]
    if structural:
        stages.append("structural")
    if ran:
        stages.append("embedding")
    correlator = Correlator(
        version=CORRELATOR_VERSION,
        stages=stages,
        threshold=threshold if ran else None,
        embedding_model=embedding_model if ran else None,
        skipped=skipped,
    )
    return Correlation(
        schema_version="1.0",
        findings_sha256=hashlib.sha256(findings_data).hexdigest(),
        correlator=correlator,
        groups=groups,
    )
