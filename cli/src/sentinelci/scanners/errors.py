"""Errors of the tool-integrity layer.

A ToolIntegrityError means a security tool cannot be trusted: it is missing, unpinned, or its bytes do not
match the hashes in tools.lock.toml. Callers must fail closed: the gate reports rule SC-010 and blocks.
"""


class ToolIntegrityError(Exception):
    """A pinned tool is missing, misconfigured or does not match its lock entry."""
