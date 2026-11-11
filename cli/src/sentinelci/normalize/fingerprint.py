"""Stable finding fingerprints (SPEC section 13.1).

A fingerprint identifies the same risk across runs, line shifts and tools, so that PR gating can tell new
findings from existing ones and the remediation loop can tell when a finding is gone.
"""

import hashlib
import re

_SEP = "|"
_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def secret_fingerprint(rule_id: str, secret_value: str) -> str:
    """SECRET: sha256(rule id | sha256(secret value)). The location is deliberately not part of it."""
    return sha256_hex(_SEP.join((rule_id, sha256_hex(secret_value))))


def purl_base(purl: str) -> str:
    """Package identity used in fingerprints and waivers: the purl without version, qualifiers or subpath.

    Same definition as `purl_base` in policies/gate.rego, so fingerprints and waiver matching always agree.
    Qualifiers (arch, distro, ...) describe the environment, not the package: keeping them would make every
    OS-package finding look new after a base-image point release and would break Grype/Trivy dedup.
    Only an "@" after the last "/" starts the version, so non-canonical purls with an unencoded scope
    (pkg:npm/@scope/name) keep their namespace.
    """
    head = purl.partition("#")[0].partition("?")[0]
    name_start = head.rfind("/") + 1
    at = head.rfind("@")
    return head[:at] if at >= name_start else head


def package_fingerprint(category: str, vuln_id: str, purl: str) -> str:
    """SCA / CONTAINER: sha256(category | vuln id | purl base) — a version bump fixes it."""
    return sha256_hex(_SEP.join((category, vuln_id, purl_base(purl))))


def normalize_snippet(snippet: str) -> str:
    """Whitespace-insensitive form of a code snippet (blank lines and indentation ignored)."""
    lines = (" ".join(line.split()) for line in snippet.splitlines())
    return "\n".join(line for line in lines if line)


def sast_fingerprint(rule_id: str, path: str, snippet: str) -> str:
    """SAST: sha256(rule id | path | sha256(normalized snippet)) — survives line shifts."""
    return sha256_hex(_SEP.join((rule_id, path, sha256_hex(normalize_snippet(snippet)))))


def config_fingerprint(rule_id: str, path: str, resource: str) -> str:
    """IAC, and PIPELINE at job or workflow level: sha256(rule id | path | resource or job identifier)."""
    return sha256_hex(_SEP.join((rule_id, path, resource)))


def normalize_expressions(code: str) -> str:
    """GitHub expressions with the spaces inside their braces dropped: `${{x}}` is `${{ x }}`."""
    return _EXPRESSION.sub(lambda match: "${{ " + match.group(1) + " }}", code)


def pipeline_fingerprint(rule_id: str, path: str, resource: str, code: str | None) -> str:
    """PIPELINE: sha256(rule id | path | resource | sha256(normalized code)), where the resource is the job
    (`jobs.<id>`) or the top-level key, and the code is the source text the finding is about (an action
    reference, the line of a `run:` script that holds the expression, a trigger, a permission), normalized
    like a SAST snippet with its expressions' inner spaces dropped. A job holds many steps, so the job alone
    is too coarse: a new expression in a job that already had one must be a new finding. Line moves, added
    steps and edits to other lines keep it. Without code (a finding about a whole job or file, one per job or
    file by nature), this is `config_fingerprint`."""
    if code is None:
        return config_fingerprint(rule_id, path, resource)
    normalized = normalize_snippet(normalize_expressions(code))
    return sha256_hex(_SEP.join((rule_id, path, resource, sha256_hex(normalized))))
