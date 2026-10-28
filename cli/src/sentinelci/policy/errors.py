"""Errors of the release gate."""


class EvaluationError(Exception):
    """The gate could not produce a decision. Callers must fail closed."""
