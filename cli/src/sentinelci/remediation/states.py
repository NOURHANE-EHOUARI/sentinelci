"""The remediation states (SPEC §9) and the only transitions between them.

PROPOSED → PATCH_READY → PR_OPEN → VERIFYING → VERIFIED | REJECTED | FAILED; a REJECTED patch goes back to
PATCH_READY for a retry with CI feedback while attempts are left; any state but a terminal one can fail.
"""

from typing import Literal

from sentinelci.contracts.remediation import MAX_ATTEMPTS, VerificationResult
from sentinelci.remediation.proposal import RemediationError

State = Literal["PROPOSED", "PATCH_READY", "PR_OPEN", "VERIFYING", "VERIFIED", "REJECTED", "FAILED"]
TERMINAL: frozenset[State] = frozenset({"VERIFIED", "FAILED"})
TRANSITIONS: dict[State, frozenset[State]] = {
    "PROPOSED": frozenset({"PATCH_READY", "FAILED"}),
    "PATCH_READY": frozenset({"PR_OPEN", "FAILED"}),
    "PR_OPEN": frozenset({"VERIFYING", "FAILED"}),
    "VERIFYING": frozenset({"VERIFIED", "REJECTED", "FAILED"}),
    "REJECTED": frozenset({"PATCH_READY", "FAILED"}),
    "VERIFIED": frozenset(),
    "FAILED": frozenset(),
}


def advance(current: State, target: State, *, attempt: int) -> State:
    """The next state, or RemediationError: an illegal transition never happens silently."""
    if current in TERMINAL:
        raise RemediationError(f"a remediation that is {current} is over")
    if target not in TRANSITIONS[current]:
        raise RemediationError(f"a remediation cannot go from {current} to {target}")
    if current == "REJECTED" and target == "PATCH_READY" and attempt >= MAX_ATTEMPTS:
        raise RemediationError(f"no retry left after attempt {attempt} of {MAX_ATTEMPTS}")
    return target


def after_verification(result: VerificationResult) -> State:
    """The state a verification leads to (its outcome: VERIFIED, REJECTED or FAILED)."""
    return advance("VERIFYING", result.outcome, attempt=result.attempt)
