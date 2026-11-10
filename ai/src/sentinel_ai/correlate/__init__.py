"""Alert correlation: dedup, embedding clustering and root-cause labels (task A7, Track A).

Advisory only: the release gate never imports this package (import contract), and a group never changes a
verdict. See `stages` for the stages and `metrics` for how they are measured.
"""

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
    "RootCauseGroup",
    "adjusted_rand_index",
    "alert_reduction",
    "correlate",
    "correlate_run",
    "dedup",
    "group_id",
    "labels_of",
    "structural_groups",
    "structural_keys",
]
