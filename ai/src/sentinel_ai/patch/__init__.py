"""Patch proposals written by a model (task B6, Track B): the LLM code fixer for SAST findings.

Advisory only: a proposal is a pull request that the verification gate and a human review decide on. The
release gate never imports this package (import contract). See `code` for the guardrails.
"""

from sentinel_ai.patch.code import (
    MAX_LINES_SENT,
    PROMPT_SHA256,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    CodeFix,
    Feedback,
    LineEdit,
    Outcome,
    propose_code_fix,
)

__all__ = [
    "MAX_LINES_SENT",
    "PROMPT_SHA256",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT",
    "CodeFix",
    "Feedback",
    "LineEdit",
    "Outcome",
    "propose_code_fix",
]
