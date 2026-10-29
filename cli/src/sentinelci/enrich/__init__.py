"""Enrichment: EPSS, KEV, OSV, reachability and service context (task B2, Track B).

Must never import sentinel_ai: deterministic decides, AI advises.
"""

from sentinelci.enrich.apply import enrich_finding
from sentinelci.enrich.models import (
    EnrichmentError,
    ServiceContext,
    Snapshot,
    load_service_context,
    load_snapshot,
)

__all__ = [
    "EnrichmentError",
    "ServiceContext",
    "Snapshot",
    "enrich_finding",
    "load_service_context",
    "load_snapshot",
]
