"""Shared release inputs for the attestation tests: an image, its findings, SBOM, decision and run."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
FINDINGS = ROOT / "schemas" / "fixtures" / "finding" / "valid"
REPO = "NOURHANE-EHOUARI/sentinelci"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
IMAGE_HEX = "5c3e1f0a9b8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e"
IMAGE = f"registry.local/demo-shop/shop-api@sha256:{IMAGE_HEX}"
OTHER_IMAGE_HEX = "a" * 64
BUILDER = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/heads/main"
SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
GITHUB_ENV = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": REPO,
    "GITHUB_SHA": COMMIT,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/release.yml@refs/heads/main",
    "GITHUB_RUN_ID": "1234567890",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY_ID": "987654321",
    "GITHUB_REPOSITORY_OWNER_ID": "123456",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def findings_bytes() -> bytes:
    lines = [
        json.dumps(json.loads((FINDINGS / name).read_text(encoding="utf-8")), sort_keys=True)
        for name in ("container-os-package.json", "sca-enriched-and-scored.json", "secret-in-config.json")
    ]
    return "".join(f"{line}\n" for line in lines).encode()


def sbom_bytes(serial: str | None = SERIAL) -> bytes:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": "shop-api"}},
        "components": [
            {"type": "library", "name": "flask", "version": "3.1.0", "purl": "pkg:pypi/flask@3.1.0"}
        ],
    }
    if serial is not None:
        document["serialNumber"] = serial
    return json.dumps(document, indent=2).encode()


def decision_dict(**changes: Any) -> dict[str, Any]:
    decision: dict[str, Any] = {
        "schema_version": "1.1",
        "decision_id": "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9f",
        "evaluated_at": "2026-11-10T10:00:00Z",
        "subject": {
            "repo": REPO,
            "ref": "refs/heads/main",
            "commit": COMMIT,
            "image_digest": f"sha256:{IMAGE_HEX}",
            "context": "release",
        },
        "verdict": "WARN",
        "violations": [
            {"rule": "SC-006", "effect": "WARN", "finding_ids": ["c" * 64], "message": "P1 finding"}
        ],
        "waivers_applied": [],
        "inputs": {
            "findings_digest": sha(findings_bytes()),
            "sbom_digest": sha(sbom_bytes()),
            "enrichment_snapshot_digest": "sha256:" + "3" * 64,
            "policy_bundle_digest": "sha256:" + "4" * 64,
            "waivers_digest": "sha256:" + "5" * 64,
            "risk_model_version": "1.0.0",
            "tool_versions": {"gitleaks": "8.30.1", "grype": "0.121.0", "trivy": "0.76.1"},
        },
        "engine_version": "0.1.0",
    }
    for path, value in changes.items():
        *parents, leaf = path.split("__")
        node = decision
        for parent in parents:
            node = node[parent]
        node[leaf] = value
    return decision


def decision_bytes(**changes: Any) -> bytes:
    return json.dumps(decision_dict(**changes), indent=2).encode()


@pytest.fixture
def github_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for name, value in GITHUB_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    return dict(GITHUB_ENV)
