"""Errors raised by normalizers.

A NormalizationError means the scanner output cannot be trusted or interpreted. Callers must treat it as a
scanner failure: the gate turns it into rule SC-010 (fail closed), never into an empty pass.
"""


class NormalizationError(Exception):
    """Scanner output is malformed, incomplete or unsafe to process."""
