"""Alert correlation: dedup, embedding clustering and root-cause labels (task A7, Track A).

Advisory only: the release gate never imports this package (import contract), and a group never changes a
verdict. See `stages` for stages 1 and 2, `labels` for stage 3 (a model writes the labels of the groups it is
given), `metrics` for the ARI and alert reduction, and `evaluation` for how each stage is measured.
"""

from sentinel_ai.correlate.labels import GroupLabel, Outcome, label_groups, redact
from sentinel_ai.correlate.metrics import adjusted_rand_index, alert_reduction, labels_of
from sentinel_ai.correlate.models import Correlation, EmbeddingModel, RootCauseGroup, group_id
from sentinel_ai.correlate.stages import (
    CorrelationError,
    EmbedderError,
    correlate,
    correlate_run,
    dedup,
    structural_groups,
    structural_keys,
)

__all__ = [
    "Correlation",
    "CorrelationError",
    "EmbedderError",
    "EmbeddingModel",
    "GroupLabel",
    "Outcome",
    "RootCauseGroup",
    "adjusted_rand_index",
    "alert_reduction",
    "correlate",
    "correlate_run",
    "dedup",
    "group_id",
    "label_groups",
    "labels_of",
    "redact",
    "structural_groups",
    "structural_keys",
]
