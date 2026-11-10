"""Shared helpers: Trivy-like IAC findings for a manifest, and contract validators."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.fingerprint import config_fingerprint

ROOT = Path(__file__).resolve().parents[3]
SEED = ROOT / "demo-shop" / "infra" / "k8s" / "shop-api.yaml"
SEED_PATH = "demo-shop/infra/k8s/shop-api.yaml"
RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")
NOW = datetime(2026, 11, 10, 10, 0, tzinfo=UTC)
# What Trivy 0.76.1 reports on the seed (GT-IAC-005), rule id -> severity.
SEED_RULES = {
    "KSV-0001": "MEDIUM", "KSV-0003": "LOW", "KSV-0004": "LOW", "KSV-0009": "HIGH", "KSV-0011": "LOW",
    "KSV-0012": "MEDIUM", "KSV-0013": "MEDIUM", "KSV-0014": "HIGH", "KSV-0015": "LOW", "KSV-0016": "LOW",
    "KSV-0017": "HIGH", "KSV-0018": "LOW", "KSV-0020": "LOW", "KSV-0021": "LOW", "KSV-0023": "MEDIUM",
    "KSV-0030": "LOW", "KSV-0104": "MEDIUM", "KSV-0105": "LOW", "KSV-0106": "LOW", "KSV-0118": "HIGH",
    "KSV-0121": "HIGH", "KSV-0125": "MEDIUM",
}  # fmt: skip


def iac_finding(rule: str, path: str = SEED_PATH, severity: str = "MEDIUM", tool: str = "trivy") -> Finding:
    return Finding(
        id=config_fingerprint(rule, path, "Deployment/shop-api"),
        tool=Tool(name=tool, version="0.76.1"),
        rule_id=rule,
        category="IAC",
        title=rule,
        severity=severity,  # type: ignore[arg-type]
        location=Location(path=path, start_line=20, end_line=20),
        run=RUN,
    )


def seed_findings() -> list[Finding]:
    return [iac_finding(rule, severity=severity) for rule, severity in SEED_RULES.items()]


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / f"{name}.v1.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture(scope="session")
def proposal_validator() -> Draft202012Validator:
    return _validator("patch-proposal")


@pytest.fixture(scope="session")
def result_validator() -> Draft202012Validator:
    return _validator("verification-result")
