"""`sentinel replay` (SPEC section 6.5): re-evaluate a decision from its recorded input digests.

The evidence store holds every input by content (`sha256/<hex>`), the policy bundle as its manifest plus
files, and decisions by id. Replay reads only the store: the policy directory and live files may have changed
since.
"""

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.decision import decision_id_of
from sentinelci.policy.replay import differences
from sentinelci.policy.store import EvidenceStore, StoreError

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
FIXTURES = ROOT / "schemas" / "fixtures"
SECRET = json.loads((FIXTURES / "finding" / "valid" / "secret-in-config.json").read_text(encoding="utf-8"))
TOOLS_TIMEOUT = (FIXTURES / "tool-status" / "valid" / "one-timeout.json").read_bytes()
TOOLS_OK = (FIXTURES / "tool-status" / "valid" / "all-ok.json").read_bytes()
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
WAIVERS_YAML = f"""\
version: 1
waivers:
  - id: waiver-2026-001
    finding_id: {SECRET["id"]}
    owner: "@Hiba-elouazi"
    justification: Fake demo credential listed in the ground truth.
    expires_at: 2026-12-31T00:00:00Z
"""


def ndjson(*findings: dict[str, Any]) -> bytes:
    return "".join(json.dumps(f) + "\n" for f in findings).encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- the store


def test_blobs_are_stored_by_content(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    digest = store.put(b"hello\n")
    assert digest == sha256(b"hello\n")
    assert (tmp_path / "store" / "sha256" / digest.removeprefix("sha256:")).read_bytes() == b"hello\n"
    assert store.get(digest) == b"hello\n"
    assert store.put(b"hello\n") == digest  # idempotent


def test_a_tampered_blob_is_refused(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    digest = store.put(b"findings")
    (tmp_path / "sha256" / digest.removeprefix("sha256:")).write_bytes(b"other findings")
    with pytest.raises(StoreError, match="integrity"):
        store.get(digest)


def test_a_corrupt_blob_is_repaired_on_put(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    digest = store.put(b"findings")
    (tmp_path / "sha256" / digest.removeprefix("sha256:")).write_bytes(b"garbage")
    store.put(b"findings")
    assert store.get(digest) == b"findings"


def test_a_missing_blob_is_refused(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="not in the evidence store"):
        EvidenceStore(tmp_path).get(sha256(b"never stored"))


@pytest.mark.parametrize(
    "digest",
    ["sha256:../../etc/passwd", "md5:" + "a" * 32, "sha256:" + "A" * 64, "a" * 64, "sha256:" + "a" * 63],
)
def test_malformed_digests_are_refused(tmp_path: Path, digest: str) -> None:
    with pytest.raises(StoreError, match="digest"):
        EvidenceStore(tmp_path).get(digest)


def test_a_policy_bundle_round_trips_by_its_digest(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    bundle = PolicyBundle.load(POLICIES)
    assert store.put_bundle(bundle) == bundle.digest
    restored = store.extract_bundle(bundle.digest, tmp_path / "restored")
    assert restored.digest == bundle.digest
    assert restored.files == bundle.files


@pytest.mark.parametrize("path", ["../evil.rego", "/etc/evil.rego", "a/../../evil.rego", "a\\..\\evil.rego"])
def test_a_bundle_manifest_cannot_write_outside_its_directory(tmp_path: Path, path: str) -> None:
    store = EvidenceStore(tmp_path / "store")
    rego = store.put(b"package evil\n")
    manifest = f"{rego.removeprefix('sha256:')}  {path}\n".encode()
    with pytest.raises(StoreError, match="path"):
        store.extract_bundle(store.put(manifest), tmp_path / "restored")
    assert not (tmp_path / "evil.rego").exists()


def test_a_manifest_that_does_not_reproduce_its_digest_is_refused(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    bundle = PolicyBundle.load(POLICIES)
    store.put_bundle(bundle)
    unsorted = "".join(reversed(bundle.manifest.splitlines(keepends=True)))
    with pytest.raises(StoreError, match="does not reproduce"):
        store.extract_bundle(store.put(unsorted.encode()), tmp_path / "restored")


def test_a_bundle_with_a_missing_file_is_refused(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "store")
    manifest = f"{'b' * 64}  gate.rego\n".encode()
    with pytest.raises(StoreError, match="not in the evidence store"):
        store.extract_bundle(store.put(manifest), tmp_path / "restored")


@pytest.mark.parametrize("decision_id", ["../x", "not-a-uuid", "5B1C6A0E-3F0D-4C8E-9A51-8D3E2F6B7C40"])
def test_decision_ids_are_checked_before_use_as_file_names(tmp_path: Path, decision_id: str) -> None:
    with pytest.raises(StoreError, match="decision id"):
        EvidenceStore(tmp_path).decision_path(decision_id)


@pytest.mark.parametrize(
    ("recorded", "replayed", "expected"),
    [
        ({"a": 1}, {"a": 1}, []),
        ({"a": True}, {"a": 1}, ["a: true -> 1"]),
        ({"a": 1.0}, {"a": 1}, ["a: 1.0 -> 1"]),
        ({"a": [1, 2]}, {"a": [1, 3]}, ["a[1]: 2 -> 3"]),
        ({"a": [1]}, {"a": [1, 2]}, ["a: [1] -> [1, 2]"]),
        ({"a": {"b": 1}}, {"a": {}}, ["a.b: 1 -> (absent)"]),
        ({}, {"c": "x"}, ['c: (absent) -> "x"']),
    ],
)
def test_differences_are_listed_by_field(recorded: Any, replayed: Any, expected: list[str]) -> None:
    assert differences(recorded, replayed) == expected


def test_a_digest_with_a_trailing_newline_is_not_a_digest(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    digest = store.put(b"findings")
    with pytest.raises(StoreError, match="not a sha256"):
        store.get(digest + "\n")


def test_a_decision_id_with_a_trailing_newline_is_not_an_id(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="decision id"):
        EvidenceStore(tmp_path).decision_path("5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40\n")


def test_a_bundle_file_name_with_an_unusual_separator_round_trips(tmp_path: Path) -> None:
    # str.splitlines() also splits on \v, \f, \x1c-\x1e, \x85, U+2028/9; the manifest is "\n"-separated only.
    policies = Path(shutil.copytree(POLICIES, tmp_path / "policies"))
    (policies / "odd\x0bname.rego").write_text("package odd\n", encoding="utf-8")
    bundle = PolicyBundle.load(policies)
    store = EvidenceStore(tmp_path / "store")
    store.put_bundle(bundle)
    assert store.extract_bundle(bundle.digest, tmp_path / "restored").digest == bundle.digest


# ---------------------------------------------------------------- sentinel evaluate --store, sentinel replay


def evaluate(
    tmp_path: Path,
    opa_binary: Path,
    findings: bytes,
    *extra: str,
    policies: Path = POLICIES,
    context: str = "pr",
    **files: bytes,
) -> tuple[int, str, dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings.ndjson").write_bytes(findings)
    args = []
    for option, data in files.items():
        (tmp_path / option).write_bytes(data)
        args += [f"--{option.replace('_', '-')}", str(tmp_path / option)]
    output = tmp_path / "decision.json"
    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "--findings", str(tmp_path / "findings.ndjson"),
            "--repo", "NOURHANE-EHOUARI/sentinelci",
            "--commit", COMMIT,
            "--context", context,
            "--evaluated-at", "2026-11-10T10:00:00Z",
            "--policy-dir", str(policies),
            "--output", str(output),
            "--store", str(tmp_path / "store"),
            "--opa", str(opa_binary),
            *args,
            *extra,
        ],
    )  # fmt: skip
    assert result.exit_code in (0, 1), result.output
    return result.exit_code, result.output, json.loads(output.read_text(encoding="utf-8"))


def replay(tmp_path: Path, opa_binary: Path, decision: str) -> tuple[int, str]:
    result = CliRunner().invoke(
        app, ["replay", decision, "--store", str(tmp_path / "store"), "--opa", str(opa_binary)]
    )
    return result.exit_code, result.output


def test_evaluate_stores_every_input_and_the_decision(tmp_path: Path, opa_binary: Path) -> None:
    _, _, decision = evaluate(tmp_path, opa_binary, ndjson(SECRET))
    store = EvidenceStore(tmp_path / "store")
    inputs = decision["inputs"]
    assert store.get(inputs["findings_digest"]) == ndjson(SECRET)
    assert store.get(inputs["waivers_digest"]) == b""
    assert store.get(inputs["enrichment_snapshot_digest"]) == b"{}"
    assert store.get(inputs["policy_bundle_digest"])  # the bundle manifest
    stored = store.decision_path(decision["decision_id"]).read_text(encoding="utf-8")
    assert stored == (tmp_path / "decision.json").read_text(encoding="utf-8")


def test_replay_by_id_is_identical(tmp_path: Path, opa_binary: Path) -> None:
    code, _, decision = evaluate(tmp_path, opa_binary, ndjson(SECRET))
    assert code == 1  # BLOCK, SC-001
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 0, out
    assert f"Replay identical: decision {decision['decision_id']} (BLOCK)" in out


def test_replay_of_a_decision_file_is_identical(tmp_path: Path, opa_binary: Path) -> None:
    evaluate(tmp_path, opa_binary, ndjson(SECRET))
    code, out = replay(tmp_path, opa_binary, str(tmp_path / "decision.json"))
    assert code == 0, out


def test_replay_covers_waivers_baseline_tool_status_and_sbom(tmp_path: Path, opa_binary: Path) -> None:
    code, _, decision = evaluate(
        tmp_path,
        opa_binary,
        ndjson(SECRET),
        "--tool-version", "syft=1.33.0",
        waivers=WAIVERS_YAML.encode("utf-8"),
        baseline=ndjson(SECRET),
        tool_status=TOOLS_TIMEOUT,
        sbom=b'{"bomFormat": "CycloneDX"}',
        enrichment_snapshot=b'{"epss": {}}',
    )  # fmt: skip
    assert code == 1  # the scanner timeout blocks
    assert decision["schema_version"] == "1.2"
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 0, out


def test_several_versions_of_one_tool_replay_identically(tmp_path: Path, opa_binary: Path) -> None:
    older = {**SECRET, "tool": {"name": "gitleaks", "version": "8.29.0"}}
    other = {**SECRET, "id": "c" * 64, "tool": {"name": "gitleaks", "version": "8.30.1"}}
    _, _, decision = evaluate(tmp_path, opa_binary, ndjson(older, other), context="release")
    assert decision["inputs"]["tool_versions"]["gitleaks"] == "8.29.0, 8.30.1"
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 0, out


def test_replay_uses_the_stored_policy_not_the_current_directory(tmp_path: Path, opa_binary: Path) -> None:
    policies = tmp_path / "policies"
    shutil.copytree(POLICIES, policies)
    _, _, decision = evaluate(tmp_path, opa_binary, ndjson(SECRET), policies=policies)
    shutil.rmtree(policies)
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 0, out


def test_a_changed_record_is_reported_field_by_field(tmp_path: Path, opa_binary: Path) -> None:
    evaluate(tmp_path, opa_binary, ndjson(SECRET))
    path = tmp_path / "decision.json"
    recorded = json.loads(path.read_text(encoding="utf-8"))
    recorded["violations"][0]["message"] = "edited after the fact"
    path.write_text(json.dumps(recorded), encoding="utf-8")
    code, out = replay(tmp_path, opa_binary, str(path))
    assert code == 1, out
    assert "Replay differs" in out
    assert "violations[0].message" in out


def test_another_engine_version_is_reported(
    tmp_path: Path, opa_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, decision = evaluate(tmp_path, opa_binary, ndjson(SECRET))
    monkeypatch.setattr("sentinelci.policy.decision.__version__", "99.0.0")
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 1, out
    assert "engine_version" in out
    assert "decision_id" in out


def test_a_tampered_input_means_no_replay(tmp_path: Path, opa_binary: Path) -> None:
    _, _, decision = evaluate(tmp_path, opa_binary, ndjson(SECRET))
    blob = decision["inputs"]["findings_digest"].removeprefix("sha256:")
    (tmp_path / "store" / "sha256" / blob).write_bytes(b"")
    code, out = replay(tmp_path, opa_binary, decision["decision_id"])
    assert code == 3, out
    assert "integrity" in out


def test_an_unknown_decision_means_no_replay(tmp_path: Path, opa_binary: Path) -> None:
    code, out = replay(tmp_path, opa_binary, "5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40")
    assert code == 3, out


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d.update(schema_version="1.0") or d["inputs"].pop("waivers_digest"),
        lambda d: d["inputs"].pop("findings_digest"),
        lambda d: d.update(subject={"repo": "x"}),
        lambda d: d.update(evaluated_at=None),
    ],
    ids=["v1.0-without-waivers-digest", "no-findings-digest", "bad-subject", "no-evaluated-at"],
)
def test_a_record_that_cannot_be_replayed_means_no_replay(
    tmp_path: Path, opa_binary: Path, edit: Any
) -> None:
    evaluate(tmp_path, opa_binary, ndjson(SECRET))
    path = tmp_path / "decision.json"
    recorded = json.loads(path.read_text(encoding="utf-8"))
    edit(recorded)
    path.write_text(json.dumps(recorded), encoding="utf-8")
    code, out = replay(tmp_path, opa_binary, str(path))
    assert code == 3, out


# ---------------------------------------------------------------- sentinel replay --all (the nightly job)


def replay_all(tmp_path: Path, opa_binary: Path, *extra: str) -> tuple[int, str]:
    result = CliRunner().invoke(
        app, ["replay", "--all", "--store", str(tmp_path / "store"), "--opa", str(opa_binary), *extra]
    )
    return result.exit_code, result.output


def stored(tmp_path: Path, decision_id: str) -> Path:
    return EvidenceStore(tmp_path / "store").decision_path(decision_id)


def edit_stored(path: Path, edit: Any) -> None:
    """Edit a stored decision after the fact (its decision_id no longer matches what it holds)."""
    record = json.loads(path.read_text(encoding="utf-8"))
    edit(record)
    path.write_text(json.dumps(record), encoding="utf-8")


def as_recorded_by(tmp_path: Path, decision_id: str, edit: Any) -> str:
    """A consistent record of another run (e.g. another engine): edited, then given its new id and file."""
    old = stored(tmp_path, decision_id)
    record = json.loads(old.read_text(encoding="utf-8"))
    edit(record)
    record["decision_id"] = decision_id_of(
        record["subject"], record["evaluated_at"], record["inputs"], record["engine_version"]
    )
    old.unlink()
    stored(tmp_path, record["decision_id"]).write_text(json.dumps(record), encoding="utf-8")
    return str(record["decision_id"])


def record_two(tmp_path: Path, opa_binary: Path) -> tuple[str, str]:
    _, _, blocked = evaluate(tmp_path / "a", opa_binary, ndjson(SECRET), "--store", str(tmp_path / "store"))
    _, _, passed = evaluate(
        tmp_path / "b", opa_binary, b"", "--store", str(tmp_path / "store"), tool_status=TOOLS_OK
    )
    return blocked["decision_id"], passed["decision_id"]


def test_replay_all_replays_every_stored_decision(tmp_path: Path, opa_binary: Path) -> None:
    first, second = record_two(tmp_path, opa_binary)
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 0, out
    assert f"identical  {first} (BLOCK)" in out
    assert f"identical  {second} (PASS)" in out
    assert "2 identical, 0 skipped, 0 differ, 0 cannot replay" in out


def test_replay_all_fails_when_one_decision_differs(tmp_path: Path, opa_binary: Path) -> None:
    first, second = record_two(tmp_path, opa_binary)
    edit_stored(stored(tmp_path, first), lambda d: d.update(verdict="PASS"))
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 1, out
    assert f"differs    {first}" in out
    assert 'verdict: "PASS" -> "BLOCK"' in out
    assert f"identical  {second} (PASS)" in out


def test_replay_all_fails_closed_when_evidence_is_missing(tmp_path: Path, opa_binary: Path) -> None:
    first, _ = record_two(tmp_path, opa_binary)
    first = as_recorded_by(tmp_path, first, lambda d: d["inputs"].update(sbom_digest=sha256(b"never stored")))
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 3, out
    assert f"cannot replay {first}" in out
    assert "decision_id does not match" not in out, "a consistent record fails on the missing blob"


@pytest.mark.parametrize(
    ("edit", "reason"),
    [
        (lambda d: d.update(engine_version="0.0.1"), "recorded with engine 0.0.1"),
        (lambda d: d["inputs"]["tool_versions"].update(opa="0.1.0"), "recorded with OPA 0.1.0"),
    ],
    ids=["other-engine", "other-opa"],
)
def test_replay_all_skips_decisions_of_another_engine_or_opa(
    tmp_path: Path, opa_binary: Path, edit: Any, reason: str
) -> None:
    first, _ = record_two(tmp_path, opa_binary)
    first = as_recorded_by(tmp_path, first, edit)
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 0, out
    assert f"skipped    {first} ({reason})" in out
    assert "1 identical, 1 skipped" in out


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d.update(engine_version="0.0.1"),
        lambda d: d["inputs"]["tool_versions"].update(opa="0.1.0"),
        lambda d: d["inputs"].update(findings_digest=sha256(b"other findings")),
        lambda d: d["subject"].update(commit="f" * 40),
        lambda d: d.update(evaluated_at="2027-01-01T00:00:00Z"),
        lambda d: d.pop("engine_version"),
    ],
    ids=["engine", "opa", "inputs", "subject", "time", "no-engine-version"],
)
def test_an_edited_record_cannot_be_skipped_nor_replayed(tmp_path: Path, opa_binary: Path, edit: Any) -> None:
    # Nourhane's idea in the review of #13: editing engine_version turned "differs" into "skipped".
    first, _ = record_two(tmp_path, opa_binary)
    edit_stored(stored(tmp_path, first), edit)
    for extra in ((), ("--allow-all-skipped",)):
        code, out = replay_all(tmp_path, opa_binary, *extra)
        assert code == 3, out
        assert f"cannot replay {first}: " in out and ("does not match" in out or "lacks" in out), out
    code, out = replay(tmp_path, opa_binary, first)
    assert code == 3, out


def test_replay_all_that_compared_nothing_is_not_a_success(tmp_path: Path, opa_binary: Path) -> None:
    # Found by Nourhane in the review of #13: after an engine bump, every decision is skipped.
    first, second = record_two(tmp_path, opa_binary)
    for decision_id in (first, second):
        as_recorded_by(tmp_path, decision_id, lambda d: d.update(engine_version="0.0.1"))

    code, out = replay_all(tmp_path, opa_binary)
    assert code == 3, out
    assert "0 identical, 2 skipped, 0 differ, 0 cannot replay" in out
    assert "nothing compared" in out

    code, out = replay_all(tmp_path, opa_binary, "--allow-all-skipped")
    assert code == 0, out
    assert "nothing compared: every decision was skipped (allowed by --allow-all-skipped)" in out


def test_allow_all_skipped_never_hides_a_difference(tmp_path: Path, opa_binary: Path) -> None:
    first, second = record_two(tmp_path, opa_binary)
    as_recorded_by(tmp_path, first, lambda d: d.update(engine_version="0.0.1"))
    edit_stored(stored(tmp_path, second), lambda d: d.update(verdict="BLOCK"))
    code, out = replay_all(tmp_path, opa_binary, "--allow-all-skipped")
    assert code == 1, out


def test_allow_all_skipped_needs_all(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["replay", "5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40", "--allow-all-skipped", "--store", str(tmp_path)],
    )
    assert result.exit_code == 2, result.output


def test_replay_all_with_nothing_to_replay_fails_closed(tmp_path: Path, opa_binary: Path) -> None:
    (tmp_path / "store").mkdir()
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 3, out
    assert "no decision" in out


def test_a_decision_file_that_is_not_its_id_is_refused(tmp_path: Path, opa_binary: Path) -> None:
    first, second = record_two(tmp_path, opa_binary)
    shutil.copy(stored(tmp_path, first), stored(tmp_path, second))
    code, out = replay_all(tmp_path, opa_binary)
    assert code == 3, out
    assert f"cannot replay {second}" in out


@pytest.mark.parametrize(
    "args", [[], ["--all", "5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40"]], ids=["none", "both"]
)
def test_replay_needs_exactly_one_of_a_decision_or_all(args: list[str]) -> None:
    result = CliRunner().invoke(app, ["replay", *args])
    assert result.exit_code == 2, result.output
