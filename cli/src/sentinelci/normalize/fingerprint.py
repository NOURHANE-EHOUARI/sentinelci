"""Stable finding fingerprints (SPEC section 13.1).

A fingerprint identifies the same risk across runs, line shifts and tools, so that PR gating can tell new
findings from existing ones and the remediation loop can tell when a finding is gone.
"""

import hashlib

_SEP = "|"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def secret_fingerprint(rule_id: str, secret_value: str) -> str:
    """SECRET: sha256(rule id | sha256(secret value)). The location is deliberately not part of it."""
    return sha256_hex(_SEP.join((rule_id, sha256_hex(secret_value))))


def purl_without_version(purl: str) -> str:
    """Drop the `@version` part of a package URL, keeping qualifiers and subpath."""
    head, hash_sep, subpath = purl.partition("#")
    head, query_sep, qualifiers = head.partition("?")
    base = head.rsplit("@", 1)[0] if "@" in head else head
    return f"{base}{query_sep}{qualifiers}{hash_sep}{subpath}"


def package_fingerprint(category: str, vuln_id: str, purl: str) -> str:
    """SCA / CONTAINER: sha256(category | vuln id | purl without version) — a version bump fixes it."""
    return sha256_hex(_SEP.join((category, vuln_id, purl_without_version(purl))))


def normalize_snippet(snippet: str) -> str:
    """Whitespace-insensitive form of a code snippet (blank lines and indentation ignored)."""
    lines = (" ".join(line.split()) for line in snippet.splitlines())
    return "\n".join(line for line in lines if line)


def sast_fingerprint(rule_id: str, path: str, snippet: str) -> str:
    """SAST: sha256(rule id | path | sha256(normalized snippet)) — survives line shifts."""
    return sha256_hex(_SEP.join((rule_id, path, sha256_hex(normalize_snippet(snippet)))))


def config_fingerprint(rule_id: str, path: str, resource: str) -> str:
    """IAC / PIPELINE: sha256(rule id | path | resource or job identifier)."""
    return sha256_hex(_SEP.join((rule_id, path, resource)))
