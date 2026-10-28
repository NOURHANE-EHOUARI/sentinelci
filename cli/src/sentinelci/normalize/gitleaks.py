"""Gitleaks JSON report (`--report-format json`) -> Finding v1.

Security notes:
- The raw report contains real secret values. This normalizer hashes each secret, redacts the snippet
  and drops author / e-mail metadata. The raw report must never be uploaded as an artifact or stored
  in the evidence bundle.
- A report produced with `--redact` cannot be fingerprinted (the secret is gone), so it is rejected
  (fail closed).
"""

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sentinelci.contracts.finding import Evidence, Finding, Location, Run, Severity, Tool
from sentinelci.normalize.errors import NormalizationError
from sentinelci.normalize.fingerprint import secret_fingerprint, sha256_hex
from sentinelci.normalize.paths import to_repo_relative

REDACTED = "[REDACTED]"
HARDCODED_CREDENTIALS_CWE = "CWE-798"
# Placeholder Gitleaks writes when run with `--redact` (a marker, not a credential).
_GITLEAKS_REDACTION_MARKER = "REDACTED"
# Gitleaks has no native severity; the risk model treats secrets as directly exploitable.
DEFAULT_SEVERITY: Severity = "HIGH"
MAX_SNIPPET = 300
_REQUIRED = ("RuleID", "Secret", "File", "StartLine")


def load_gitleaks_report(path: Path) -> list[dict[str, Any]]:
    """Read a Gitleaks JSON report; an empty scan is `[]`."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"cannot read Gitleaks report {path}: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise NormalizationError("Gitleaks report must be a JSON list of objects")
    return data


def _is_redacted(secret: str) -> bool:
    # `--redact` replaces the value with "REDACTED"; `--redact=N` keeps a prefix followed by "...".
    return secret == _GITLEAKS_REDACTION_MARKER or secret.endswith("...")


def _validate(item: Mapping[str, Any], index: int) -> None:
    missing = [key for key in _REQUIRED if key not in item or item[key] in (None, "")]
    if missing:
        raise NormalizationError(f"Gitleaks finding #{index} is missing {', '.join(missing)}")
    if not isinstance(item["StartLine"], int) or item["StartLine"] < 1:
        raise NormalizationError(f"Gitleaks finding #{index} has an invalid StartLine")
    if _is_redacted(str(item["Secret"])):
        raise NormalizationError(
            "Gitleaks report is redacted: run Gitleaks without --redact inside the scan job "
            "(the normalizer hashes and redacts secrets itself)"
        )


def _redact(text: str, secret: str) -> str:
    redacted = text.replace(secret, REDACTED)
    return redacted if len(redacted) <= MAX_SNIPPET else redacted[: MAX_SNIPPET - 1] + "…"


def normalize_gitleaks(
    report: Sequence[Mapping[str, Any]],
    *,
    run: Run,
    tool: Tool,
    repo_root: Path | None = None,
) -> list[Finding]:
    """Convert a Gitleaks report into one Finding per distinct (rule, secret) pair."""
    occurrences: dict[str, list[tuple[str, int, int, Mapping[str, Any]]]] = defaultdict(list)
    for index, item in enumerate(report):
        _validate(item, index)
        path = to_repo_relative(str(item["File"]), repo_root)
        start = int(item["StartLine"])
        end = max(start, int(item.get("EndLine") or start))
        fingerprint = secret_fingerprint(str(item["RuleID"]), str(item["Secret"]))
        occurrences[fingerprint].append((path, start, end, item))

    findings: list[Finding] = []
    for fingerprint, hits in occurrences.items():
        hits.sort(key=lambda hit: (hit[0], hit[1], str(hit[3].get("Commit") or "")))
        path, start, end, item = hits[0]
        secret = str(item["Secret"])
        rule_id = str(item["RuleID"])

        notes: list[str] = []
        if len(hits) > 1:
            places = ", ".join(f"{p}:{s}" for p, s, _, _ in hits)
            notes.append(f"Same secret found in {len(hits)} locations: {places}")
        commit = str(item.get("Commit") or "")
        if commit:
            notes.append(f"Found in git history at commit {commit[:12]}.")

        findings.append(
            Finding(
                id=fingerprint,
                tool=tool,
                rule_id=rule_id,
                category="SECRET",
                title=str(item.get("Description") or f"Secret detected by rule {rule_id}"),
                message=" ".join(notes) or None,
                severity=DEFAULT_SEVERITY,
                severity_source="none",
                cwe=[HARDCODED_CREDENTIALS_CWE],
                location=Location(path=path, start_line=start, end_line=end),
                evidence=Evidence(
                    snippet=_redact(str(item.get("Match") or ""), secret) or None,
                    secret_hash=sha256_hex(secret),
                ),
                run=run,
            )
        )
    return sorted(findings, key=lambda f: f.id)
