"""OPA policy evaluation, decision records and replay (task B4, Track B).

Must never import sentinel_ai: deterministic decides, AI advises.
"""

from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.decision import Subject, evaluate, load_findings
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.opa import OpaError, OpaRunner
from sentinelci.policy.replay import ReplayError, ReplayResult, replay
from sentinelci.policy.store import EvidenceStore, StoreError
from sentinelci.policy.tool_status import load_tool_status
from sentinelci.policy.waivers import load_waivers

__all__ = [
    "EvaluationError",
    "EvidenceStore",
    "OpaError",
    "OpaRunner",
    "PolicyBundle",
    "ReplayError",
    "ReplayResult",
    "StoreError",
    "Subject",
    "evaluate",
    "load_findings",
    "load_tool_status",
    "load_waivers",
    "replay",
]
