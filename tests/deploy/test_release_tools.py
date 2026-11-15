"""`make release` with the pinned tools (task A4c, ADR-0011): the key pair Cosign makes and checks, the
signing step with crane, `sentinel attest`, `sentinel verify` and `cosign save`, and whole releases on a
throwaway repository with the real scanners, `sentinel score` and `sentinel evaluate`.

Opt-in: SENTINEL_TOOLS_DIR (cosign, crane, gitleaks, opengrep, trivy, syft, grype, opa). The build is the
stand-in of release_support (no Docker daemon). Grype's database is never downloaded here: without
SENTINEL_GRYPE_DB_DIR the image scan fails and the gate blocks (SC-010), which is the BLOCK release this
checks; with it, the BLOCK comes from the seeded pyyaml (SC-002), and the release that passes is signed too.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _support() -> ModuleType:
    name = "release_support"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("release_support.py"))
        assert spec is not None and spec.loader is not None
        sys.modules[name] = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sys.modules[name])
    return sys.modules[name]


support = _support()
release = support.release
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
GRYPE_DB = os.environ.get("SENTINEL_GRYPE_DB_DIR")
PASSWORD = "release-test-password"  # noqa: S105 (a throwaway key's, made per test)
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
    ),
]


def tools_dir() -> Path:
    return Path(str(TOOLS_DIR)).resolve()


def cosign() -> Path:
    return Path(release.verified_tool("cosign", tools_dir(), support.ROOT / "tools.lock.toml"))


def environ() -> dict[str, str]:
    """This process's environment, without what would make `sentinel attest` refuse or Cosign read a key."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_") and k != "COSIGN_PASSWORD"}


def make_key(directory: Path, public_key: Path, password: str = PASSWORD) -> Path:
    key = directory / "release.key"
    release.make_key(key, public_key=public_key, cosign=cosign, ask_password=lambda prompt: password)
    return key


# ---------------------------------------------------------------- the key pair


def test_the_key_cosign_made_is_the_pair_of_the_public_key_it_wrote(tmp_path: Path) -> None:
    public = tmp_path / "repo" / "deploy" / "keys" / "release.pub"
    key = make_key(tmp_path / "home" / ".sentinelci", public)
    assert key.stat().st_mode & 0o777 == 0o600 and public.read_bytes() == key.with_suffix(".pub").read_bytes()
    run = release.run_command
    release.check_key_pair(key, public, PASSWORD, cosign(), run, tmp_path / "cosign-home")
    with pytest.raises(release.ReleaseError, match="wrong password"):
        release.check_key_pair(key, public, "not the password", cosign(), run, tmp_path / "cosign-home")
    other = make_key(tmp_path / "other", tmp_path / "other.pub", "another-password")
    with pytest.raises(release.ReleaseError, match="is not the pair of"):
        release.check_key_pair(other, public, "another-password", cosign(), run, tmp_path / "cosign-home")


# ---------------------------------------------------------------- signing


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_decided_image_is_signed_verified_and_saved_as_a_bundle(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "deploy" / "keys").mkdir(parents=True)
    shutil.copyfile(support.ROOT / "tools.lock.toml", root / "tools.lock.toml")
    key = make_key(tmp_path / "keys", root / "deploy" / "keys" / "release.pub")
    settings = release.Settings(root=root, tools_dir=tools_dir(), grype_db=tmp_path / "grype-db")
    paths = release.Paths(tmp_path / "out")
    release.fresh_work(paths)
    digest = support.oci_archive(paths.archive, {"app/main.py": b"print('release')\n"})
    release.extract(paths.archive, paths.layout)
    run = release.run_command
    run(release.sentinel(
        "sbom", str(paths.archive), "--name", release.IMAGE_NAME, "--source", "oci-archive", "--image-digest",
        digest, "--cyclonedx", str(paths.sbom), "--spdx", str(paths.evidence / "sbom.spdx.json"),
        *settings.tool_args(),
    ))  # fmt: skip
    paths.findings.write_text("")
    commit = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    decision = {
        "schema_version": "1.1", "decision_id": "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9f",
        "evaluated_at": "2026-11-11T10:00:00Z",
        "subject": {"repo": release.REPO, "ref": release.MAIN, "commit": commit, "image_digest": digest,
                    "context": "release"},
        "verdict": "PASS", "violations": [], "waivers_applied": [],
        "inputs": {
            "findings_digest": sha256(paths.findings), "sbom_digest": sha256(paths.sbom),
            "enrichment_snapshot_digest": "sha256:" + "3" * 64, "policy_bundle_digest": "sha256:" + "4" * 64,
            "waivers_digest": "sha256:" + "5" * 64, "risk_model_version": "1.0.0",
            "tool_versions": {"gitleaks": "8.30.1"},
        },
        "engine_version": "0.1.0",
    }  # fmt: skip
    paths.decision.write_text(json.dumps(decision, indent=2))
    signed = release.sign(
        release.Decided("PASS", digest), key=key, password=PASSWORD, paths=paths, settings=settings, run=run,
        environ=environ(), tool=lambda name: release.verified_tool(name, tools_dir(), settings.lock),
    )  # fmt: skip
    assert release.bundle_digest(paths.bundle) == digest
    assert "TRUSTED: 16/16 checks passed" in signed.trust_report  # registry mode, as Kyverno checks
    assert "TRUSTED: 15/15 checks passed" in signed.trust_report  # the evidence bundles, offline
    assert f"builder {release.builder_id()}" in signed.trust_report
    assert sorted(p.name for p in (paths.evidence / "attestations").iterdir()) == [
        "decision.sigstore.json", "provenance.sigstore.json", "sbom.sigstore.json", "vuln.sigstore.json",
    ]  # fmt: skip


# ---------------------------------------------------------------- whole releases


def release_repo(tmp_path: Path) -> Path:
    """A release repository with this checkout's lock and policies, and a key pair whose public key it
    holds."""
    dockerfile = 'FROM scratch\nCOPY app/ /app/\nUSER 10001:10001\nCMD ["app"]\n'
    repo = support.make_repo(tmp_path / "repo", {f"{support.SERVICE}/Dockerfile.release": dockerfile})
    shutil.copytree(support.ROOT / "policies", repo / "policies")
    shutil.copyfile(support.ROOT / "tools.lock.toml", repo / "tools.lock.toml")
    make_key(tmp_path / "keys", repo / "deploy" / "keys" / "release.pub")
    support.git(repo, "add", "-A")
    support.git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "pipeline")
    support.git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo


def whole_release(repo: Path, tmp_path: Path, **changes: Any) -> tuple[int, Any]:
    recorder = support.Recorder(repo, real=True)
    # Never a download in a test: the database is SENTINEL_GRYPE_DB_DIR's, or there is none.
    recorder.fakes["sentinel tools grype-db"] = lambda call: support.done(returncode=0 if GRYPE_DB else 3)
    settings = release.Settings(
        root=repo, tools_dir=tools_dir(), grype_db=Path(GRYPE_DB) if GRYPE_DB else tmp_path / "no-grype-db"
    )
    made = release.Release(
        key=tmp_path / "keys" / "release.key", out=repo / "out" / "release", settings=settings, fetch=False,
        run=recorder, ask_password=lambda prompt: PASSWORD, environ=environ(), **changes,
    )  # fmt: skip
    return made(), recorder


def decision(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def test_the_block_image_is_blocked_and_nothing_is_signed(tmp_path: Path) -> None:
    repo = release_repo(tmp_path)
    status, recorder = whole_release(repo, tmp_path, expect_block=True, requirements="requirements.block.txt")
    assert status == release.EXIT_RELEASED
    out = repo / "out" / "release"
    made = decision(out / "block-evidence" / "decision.v1.json")
    assert made["verdict"] == "BLOCK" and made["subject"]["context"] == "release"
    assert made["subject"]["image_digest"] == release.layout_digest(out / "block-image")
    rules = {v["rule"] for v in made["violations"] if v["effect"] == "BLOCK"}
    assert rules == ({"SC-002"} if GRYPE_DB else {"SC-010"}), made["violations"]
    tools = json.loads((out / "block-evidence" / "tool-status.json").read_text())["tools"]
    assert {"gitleaks", "opengrep", "trivy", "zizmor", "syft", "grype"} <= set(tools)
    assert recorder.named("sentinel attest") == [] and not (out / "bundle").exists()


@pytest.mark.skipif(not GRYPE_DB, reason="set SENTINEL_GRYPE_DB_DIR: without a database every release blocks")
def test_a_release_that_passes_the_gate_is_signed_end_to_end(tmp_path: Path) -> None:
    repo = release_repo(tmp_path)
    status, _ = whole_release(repo, tmp_path)
    assert status == release.EXIT_RELEASED
    out = repo / "out" / "release"
    assert decision(out / "evidence" / "decision.v1.json")["verdict"] in {"PASS", "WARN"}
    assert (
        release.bundle_digest(out / "bundle")
        == decision(out / "evidence" / "decision.v1.json")["subject"]["image_digest"]
    )
    assert "TRUSTED: 16/16 checks passed" in (out / "evidence" / "trust-report.txt").read_text()
