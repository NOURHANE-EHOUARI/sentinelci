"""How the correlator is measured (task A7 acceptance, SPEC sections 3 and 17): each stage on its own
(ablation), the ARI against the stage 2b threshold, and the threshold's calibration.

- **Truth.** A labelled set maps finding ids to their true root cause (a ground-truth seed). Findings with
  no label are left out of the ARI and listed (`Score.unlabelled`), never guessed.
- **ARI** compares the correlator's groups with the true root causes, over the labelled findings.
- **Alert reduction** compares the raw tool reports (`out/raw/`, so that stage 1 merges the tools) with the
  groups: without that count, it compares the findings given, which already hold one finding per
  fingerprint, so stage 1 alone reduces nothing.
- **Calibration** picks the threshold with the best ARI on a labelled set that is not the one it is tested on
  (on demo-shop, the calibration half of a split of its seeds fixed before any score, SPEC section 17); a tie
  goes to the highest threshold, which merges least. It is committed with the embedding model's digest before
  the test half is measured, where the curve (`sweep`) is reported as sensitivity only.

The embedder is called once per text whatever the number of thresholds tried (`cached`).
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sentinel_ai.correlate.metrics import adjusted_rand_index, alert_reduction, labels_of
from sentinel_ai.correlate.stages import DEFAULT_THRESHOLD, CorrelationError, Embedder, correlate

Finding = Mapping[str, Any]

# The stages each ablation runs, after stage 1 (dedup), which always runs.
CONFIGURATIONS: dict[str, tuple[bool, bool]] = {
    "dedup": (False, False),
    "dedup+structural": (True, False),
    "dedup+embedding": (False, True),
    "dedup+structural+embedding": (True, True),
}


@dataclass(frozen=True)
class Score:
    """One configuration of the correlator on one labelled set."""

    configuration: str
    threshold: float | None  # stage 2b's, when it ran
    alerts: int  # what alert reduction counts from: raw tool reports, or the findings given
    groups: int
    ari: float
    alert_reduction: float
    unlabelled: tuple[str, ...]  # finding ids with no true root cause: not in the ARI


def cached(embed: Embedder) -> Embedder:
    """The embedder, called once per distinct text: a sweep reuses every vector."""
    vectors: dict[str, list[float]] = {}

    def embed_once(texts: list[str]) -> list[list[float]]:
        missing = sorted({text for text in texts if text not in vectors})
        if missing:
            answered = embed(missing)
            if len(answered) != len(missing):  # stage 2b refuses it too; the cache must not misalign first
                raise CorrelationError("the embedder must return one vector per text")
            vectors.update(zip(missing, answered, strict=True))
        return [vectors[text] for text in texts]

    return embed_once


def score(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    *,
    configuration: str = "dedup+structural+embedding",
    embed: Embedder | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    raw_alerts: int | None = None,
) -> Score:
    """One configuration's ARI and alert reduction. `truth` maps finding ids to their true root cause."""
    if configuration not in CONFIGURATIONS:
        raise CorrelationError(f"unknown configuration {configuration!r}: one of {sorted(CONFIGURATIONS)}")
    structural, embedding = CONFIGURATIONS[configuration]
    if embedding and embed is None:
        raise CorrelationError(f"{configuration} needs an embedder")
    groups = correlate(
        findings, structural=structural, embed=embed if embedding else None, threshold=threshold
    )
    ids = sorted({finding_id for group in groups for finding_id in group.finding_ids})
    labelled = [finding_id for finding_id in ids if finding_id in truth]
    if len(labelled) < 2:
        raise CorrelationError("the ARI needs at least two labelled findings")
    alerts = len(findings) if raw_alerts is None else raw_alerts
    if alerts < len(ids):
        raise CorrelationError(f"{alerts} raw alerts cannot hold {len(ids)} distinct findings")
    return Score(
        configuration=configuration,
        threshold=threshold if embedding else None,
        alerts=alerts,
        groups=len(groups),
        ari=round(adjusted_rand_index([truth[i] for i in labelled], labels_of(groups, labelled)), 6),
        alert_reduction=round(alert_reduction(alerts, len(groups)), 6),
        unlabelled=tuple(finding_id for finding_id in ids if finding_id not in truth),
    )


def ablation(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    *,
    embed: Embedder | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    raw_alerts: int | None = None,
) -> list[Score]:
    """Every configuration, so each stage is measured on its own; the embedding ones only with an embedder."""
    embed = cached(embed) if embed is not None else None
    return [
        score(findings, truth, configuration=name, embed=embed, threshold=threshold, raw_alerts=raw_alerts)
        for name, (_, embedding) in CONFIGURATIONS.items()
        if embed is not None or not embedding
    ]


def sweep(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    embed: Embedder,
    thresholds: Iterable[float],
    *,
    structural: bool = True,
    raw_alerts: int | None = None,
) -> list[Score]:
    """The ARI and alert reduction at each threshold, stage 2b on (with or without stage 2a)."""
    configuration = "dedup+structural+embedding" if structural else "dedup+embedding"
    embed = cached(embed)
    return [
        score(findings, truth, configuration=configuration, embed=embed, threshold=t, raw_alerts=raw_alerts)
        for t in sorted(set(thresholds))
    ]


def calibrate(
    findings: Sequence[Finding],
    truth: Mapping[str, str],
    embed: Embedder,
    thresholds: Iterable[float],
    *,
    structural: bool = True,
    raw_alerts: int | None = None,
) -> Score:
    """The threshold with the best ARI on a labelled set (never the one it is tested on); a tie goes to the
    highest."""
    scores = sweep(findings, truth, embed, thresholds, structural=structural, raw_alerts=raw_alerts)
    if not scores:
        raise CorrelationError("calibration needs at least one threshold")
    return max(scores, key=lambda s: (s.ari, s.threshold or 0.0))


def grid(start: float = 0.5, stop: float = 0.95, step: float = 0.05) -> list[float]:
    """Thresholds from `start` to `stop` included, rounded so that 0.1 + 0.2 is 0.3."""
    if step <= 0 or stop < start:
        raise CorrelationError("a grid needs a positive step and stop >= start")
    count = round((stop - start) / step)
    return [round(start + i * step, 6) for i in range(count + 1)]


Labeller = Callable[[Finding], str | None]


def truth_of(findings: Iterable[Finding], label: Labeller) -> dict[str, str]:
    """finding id -> true root cause, from a function that knows the labelled set (the ground-truth seeds);
    a finding it returns None for stays unlabelled. Two findings with one id must agree."""
    truth: dict[str, str] = {}
    for finding in findings:
        root = label(finding)
        if root is None:
            continue
        finding_id = str(finding.get("id"))
        if truth.setdefault(finding_id, root) != root:
            raise CorrelationError(
                f"finding {finding_id} has two true root causes: {truth[finding_id]}, {root}"
            )
    return truth
