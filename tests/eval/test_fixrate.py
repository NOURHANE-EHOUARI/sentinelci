"""B8's verified fix rate (eval/fixrate/run.py): which seeds are attempted, what the gate said, the rate.

The strategies, `remediate check` and `remediate verify` are scripted stand-ins (`Scripted`); the real
engine's glue is tested with a runner that answers each command as the CLI would (`Commands`). Nothing here
scans, starts a container or asks a model.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentinelci.contracts.remediation import PatchProposal
from sentinelci.remediation.proposal import proposal_id_of, unified_diff

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    name = "sentinel_eval_fixrate_run"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "eval" / "fixrate" / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


run = _load()
K8S, DOCKER, CODE, BUMP = run.KUBERNETES, run.DOCKERFILE, run.CODE, run.BUMP


# ---------------------------------------------------------------- synthetic ground truth and findings


def seed(
    seed_id: str, category: str, path: str, *detections: tuple[str, str], **extra: Any
) -> dict[str, Any]:
    return {
        "id": seed_id,
        "category": category,
        "title": f"{seed_id} title",
        "location": {"path": path, "line": 3},
        "expected": {"detections": [{"tool": tool, "rule": rule} for tool, rule in detections]},
        **extra,
    }


SEEDS = [
    seed("GT-SAST-001", "SAST", "services/api/app/main.py", ("opengrep", "python-sql")),
    seed("GT-SAST-002", "SAST", "services/api/app/main.py", ("opengrep", "python-shell")),
    seed("GT-SAST-003", "SAST", "services/api/app/main.py", ("opengrep", "python-eval")),
    seed("GT-SAST-004", "SAST", "services/api/app/main.py", ("opengrep", "python-debug")),  # not detected
    seed("GT-IAC-001", "IAC", "infra/k8s/api.yaml", ("trivy", "KSV-0017"), ("trivy", "KSV-0023")),
    seed("GT-IAC-002", "IAC", "services/api/Dockerfile", ("trivy", "DS-0002")),
    seed("GT-IAC-003", "IAC", "infra/terraform/net.tf", ("trivy", "AWS-0107")),
    seed("GT-SECRET-001", "SECRET", "config/settings.yaml", ("gitleaks", "github-pat")),
    seed("GT-PIPELINE-001", "PIPELINE", "examples/bad.yml", ("zizmor", "dangerous-triggers")),
    seed(
        "GT-SCA-001",
        "SCA",
        "services/api/requirements.txt",
        ("grype", "GHSA-aaaa"),
        package="pkg:pypi/pyyaml@5.3.1",
    ),
]


def truth(seeds: Sequence[dict[str, Any]] = SEEDS) -> dict[str, Any]:
    return {"version": 1, "seeds": list(seeds), "controls": []}


def fid(name: str) -> str:
    """A finding id (64 hex digits) named after a short tag."""
    return (name.encode().hex() + "0" * 64)[:64]


def found(
    name: str, category: str, tool: str, rule: str, path: str, line: int = 3, **extra: Any
) -> dict[str, Any]:
    return {
        "id": fid(name),
        "category": category,
        "tool": {"name": tool, "version": "1"},
        "rule_id": rule,
        "location": {"path": "demo-shop/" + path, "start_line": line, "end_line": line},
        **extra,
    }


BASE = [
    found("sql", "SAST", "opengrep", "python-sql", "services/api/app/main.py"),
    found("sh", "SAST", "opengrep", "python-shell", "services/api/app/main.py", 9),
    found("ev", "SAST", "opengrep", "python-eval", "services/api/app/main.py", 12),
    found("priv", "IAC", "trivy", "KSV-0017", "infra/k8s/api.yaml"),
    found("hostpath", "IAC", "trivy", "KSV-0023", "infra/k8s/api.yaml"),
    found("root", "IAC", "trivy", "DS-0002", "services/api/Dockerfile"),
    found("ssh", "IAC", "trivy", "AWS-0107", "infra/terraform/net.tf"),
    found("pat", "SECRET", "gitleaks", "github-pat", "config/settings.yaml"),
    found("pwn", "PIPELINE", "zizmor", "dangerous-triggers", "examples/bad.yml"),
    found(
        "yaml",
        "SCA",
        "grype",
        "GHSA-aaaa",
        "services/api/requirements.txt",
        package={"purl": "pkg:pypi/pyyaml@5.3.1", "fixed_versions": ["5.4"]},
    ),
]


def gate(number: int, outcome: str, *failed: str) -> Any:
    return run.Attempt(number, outcome, failed=tuple(failed), proposal_id=f"p-{number}")


def made(strategy: str, claimed: Sequence[str], *attempts: Any, **extra: Any) -> Any:
    return run.Run(strategy, frozenset(fid(c) for c in claimed), tuple(attempts), **extra)


@dataclass
class Scripted:
    """The engine, scripted: each strategy's run and each code target's run, or why it could not run."""

    deterministic_runs: dict[str, Any] = field(default_factory=dict)
    code_runs: dict[str, Any] = field(default_factory=dict)
    unavailable_because: dict[str, str] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=lambda: list(BASE))
    prepare_fails: str | None = None
    calls: list[str] = field(default_factory=list)

    def prepare(self) -> list[dict[str, Any]]:
        self.calls.append("prepare")
        if self.prepare_fails:
            raise run.NotMeasured(self.prepare_fails)
        return self.findings

    def unavailable(self, strategy: str) -> str | None:
        return self.unavailable_because.get(strategy)

    def deterministic(self, strategy: str) -> Any:
        self.calls.append(strategy)
        answer = self.deterministic_runs[strategy]
        if isinstance(answer, str):
            raise run.NotMeasured(answer)
        return answer

    def code(self, finding_id: str) -> Any:
        self.calls.append(f"code {finding_id}")
        answer = self.code_runs[finding_id]
        if isinstance(answer, str):
            raise run.NotMeasured(answer)
        return answer

    def evidence(self) -> dict[str, Any]:
        return {"tools": {"trivy": "0.76.1"}}


def all_verified() -> Scripted:
    return Scripted(
        deterministic_runs={
            K8S: made(K8S, ["priv", "hostpath"], gate(1, "VERIFIED")),
            DOCKER: made(DOCKER, ["root"], gate(1, "VERIFIED")),
        },
        code_runs={
            fid("sql"): made(CODE, ["sql"], gate(1, "VERIFIED")),
            fid("sh"): made(CODE, ["sh"], gate(1, "VERIFIED")),
            fid("ev"): made(CODE, ["ev"], gate(1, "VERIFIED")),
        },
    )


def measured(engine: Scripted, seeds: Sequence[dict[str, Any]] = SEEDS, **kwargs: Any) -> dict[str, Any]:
    data: dict[str, Any] = run.measure(truth(seeds), engine, **kwargs)
    return data


def rows(data: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in data["seeds"]}


# ---------------------------------------------------------------- which seeds a strategy takes


@pytest.mark.parametrize(
    ("index", "strategy"),
    [(0, CODE), (4, K8S), (5, DOCKER), (6, None), (7, None), (8, None), (9, BUMP)],
    ids=["sast", "kubernetes", "dockerfile", "terraform", "secret", "pipeline", "sca"],
)
def test_each_seed_gets_the_strategy_of_section_9(index: int, strategy: str | None) -> None:
    got, why = run.strategy_of(SEEDS[index])
    assert got == strategy
    assert bool(why) == (strategy is None), "a seed without a strategy says why"


def test_a_container_seed_is_a_dependency_bump_and_a_mixed_iac_seed_has_no_strategy() -> None:
    container = seed(
        "GT-CONTAINER-001", "CONTAINER", "services/api/requirements.block.txt", ("grype", "GHSA-a")
    )
    assert run.strategy_of(container)[0] == BUMP
    mixed = seed("GT-IAC-009", "IAC", "infra/k8s/api.yaml", ("trivy", "KSV-0017"), ("trivy", "DS-0002"))
    assert run.strategy_of(mixed)[0] is None


# ---------------------------------------------------------------- the rate and its denominator


def test_the_rate_is_verified_over_attempted() -> None:
    engine = all_verified()
    engine.deterministic_runs[K8S] = made(K8S, ["priv"], gate(1, "VERIFIED"))  # hostPath left open
    engine.code_runs[fid("sh")] = made(CODE, ["sh"], gate(1, "REJECTED", "tests pass"), gate(2, "VERIFIED"))
    engine.code_runs[fid("ev")] = made(
        CODE, ["ev"], gate(1, "REJECTED", "tests pass"), gate(2, "REJECTED", "tests pass"),
        gate(3, "FAILED", "target fingerprint gone"),
    )  # fmt: skip
    data = measured(engine)
    headline = data["summary"]["headline"]
    # Attempted: GT-SAST-001..003, GT-IAC-001 (k8s), GT-IAC-002 (Dockerfile). Verified: SAST-001, SAST-002 on
    # its retry, IAC-002. IAC-001 is PARTIAL, SAST-003 FAILED.
    assert (headline["verified"], headline["attempted"]) == (3, 5)
    assert headline["rate"] == 0.6 and headline["target"] == 0.6 and headline["met"] is True
    assert data["summary"]["measured"] is True and data["summary"]["reason"] is None


def test_the_target_is_not_met_below_60_percent() -> None:
    engine = all_verified()
    engine.code_runs[fid("sql")] = made(CODE, [], run.Attempt(1, "NO PROPOSAL", reason="unavailable: x"))
    engine.code_runs[fid("sh")] = made(CODE, [], run.Attempt(1, "NO PROPOSAL", reason="not sent: secret"))
    headline = measured(engine)["summary"]["headline"]
    assert (headline["verified"], headline["attempted"], headline["rate"]) == (3, 5, 0.6)
    engine.code_runs[fid("ev")] = made(CODE, ["ev"], gate(1, "REJECTED", "tests pass"))
    headline = measured(engine)["summary"]["headline"]
    assert (headline["verified"], headline["attempted"], headline["rate"], headline["met"]) == (
        2,
        5,
        0.4,
        False,
    )


def test_seeds_without_a_strategy_are_listed_and_never_counted() -> None:
    data = measured(all_verified())
    by_id = rows(data)
    for seed_id in ("GT-IAC-003", "GT-SECRET-001", "GT-PIPELINE-001"):
        assert by_id[seed_id]["status"] == "not attempted" and by_id[seed_id]["outcome"] is None
        assert by_id[seed_id]["strategy"] is None and "no strategy in SPEC section 9" in by_id[seed_id]["why"]
    sca = by_id["GT-SCA-001"]
    assert (sca["status"], sca["strategy"]) == ("not attempted", BUMP)
    assert "not implemented" in sca["why"] and sca["fixed_versions"] == ["5.4"]
    undetected = by_id["GT-SAST-004"]
    assert undetected["status"] == "not attempted" and "not detected" in undetected["why"]
    summary = data["summary"]
    assert summary["headline"]["attempted"] == 5 and summary["headline"]["verified"] == 5
    assert sorted(summary["not_attempted"]) == [
        "GT-IAC-003", "GT-PIPELINE-001", "GT-SAST-004", "GT-SCA-001", "GT-SECRET-001",
    ]  # fmt: skip
    assert len(data["seeds"]) == len(SEEDS), "every seed is listed"


def test_a_strategy_that_proposes_nothing_for_a_seed_still_counts_it_as_attempted() -> None:
    engine = all_verified()
    engine.deterministic_runs[DOCKER] = made(
        DOCKER, [], reason="nothing to propose", left_open={"demo-shop/services/api/Dockerfile": "CRLF"}
    )
    data = measured(engine)
    row = rows(data)["GT-IAC-002"]
    assert (row["status"], row["outcome"]) == ("attempted", "NO PROPOSAL")
    assert "CRLF" in row["findings"][0]["reason"]
    assert data["summary"]["headline"]["attempted"] == 5 and data["summary"]["headline"]["verified"] == 4


# ---------------------------------------------------------------- each outcome


def test_each_outcome_is_counted_once_with_its_failed_conditions() -> None:
    engine = all_verified()
    engine.deterministic_runs[K8S] = made(K8S, ["priv", "hostpath"], gate(1, "REJECTED", "verdict != BLOCK"))
    engine.code_runs[fid("sh")] = made(
        CODE, ["sh"], gate(1, "REJECTED", "tests pass"), gate(2, "REJECTED", "build OK"),
        gate(3, "FAILED", "no new finding >= MEDIUM (1 new)"),
    )  # fmt: skip
    # A retry the model could not answer: the last word of the gate stands.
    engine.code_runs[fid("ev")] = made(
        CODE, ["ev"], gate(1, "REJECTED", "target fingerprint gone"),
        run.Attempt(2, "NO PROPOSAL", reason="unavailable: not a valid code fix"),
    )  # fmt: skip
    data = measured(engine)
    by_id = rows(data)
    assert by_id["GT-IAC-001"]["outcome"] == "REJECTED"
    assert by_id["GT-IAC-001"]["failed"] == ["verdict != BLOCK"]
    assert by_id["GT-SAST-002"]["outcome"] == "FAILED"
    assert by_id["GT-SAST-002"]["failed"] == ["no new finding >= MEDIUM (1 new)"]
    assert by_id["GT-SAST-003"]["outcome"] == "REJECTED"
    assert by_id["GT-SAST-003"]["failed"] == ["target fingerprint gone"]
    assert len(by_id["GT-SAST-003"]["findings"][0]["attempts"]) == 2
    outcomes = data["summary"]["outcomes"]
    assert outcomes == {"VERIFIED": 2, "REJECTED": 2, "FAILED": 1, "PARTIAL": 0, "NO PROPOSAL": 0}
    assert sum(outcomes.values()) == data["summary"]["headline"]["attempted"]


def test_a_verified_proposal_that_leaves_one_of_the_seeds_findings_open_is_partial() -> None:
    engine = all_verified()
    engine.deterministic_runs[K8S] = made(K8S, ["priv"], gate(1, "VERIFIED"))
    row = rows(measured(engine))["GT-IAC-001"]
    assert (row["status"], row["outcome"]) == ("attempted", "PARTIAL")
    assert {f["id"]: f["outcome"] for f in row["findings"]} == {
        fid("hostpath"): "NO PROPOSAL", fid("priv"): "VERIFIED",
    }  # fmt: skip


@pytest.mark.parametrize(
    ("outcomes", "combined"),
    [
        (["VERIFIED", "VERIFIED"], "VERIFIED"),
        (["VERIFIED", "REJECTED"], "PARTIAL"),
        (["VERIFIED", "NO PROPOSAL"], "PARTIAL"),
        (["REJECTED", "FAILED"], "FAILED"),
        (["NO PROPOSAL", "REJECTED"], "REJECTED"),
        (["NO PROPOSAL"], "NO PROPOSAL"),
        (["VERIFIED", "NOT MEASURED"], "NOT MEASURED"),
    ],
)
def test_a_seeds_outcome_combines_its_findings(outcomes: list[str], combined: str) -> None:
    assert run.combine(outcomes) == combined


# ---------------------------------------------------------------- fail closed


def test_a_step_that_cannot_run_gives_no_headline_and_exit_2(tmp_path: Path) -> None:
    engine = all_verified()
    engine.unavailable_because[CODE] = "no test image (TEST_IMAGE=)"
    data = measured(engine)
    summary = data["summary"]
    assert summary["measured"] is False and summary["headline"] is None
    assert "no test image" in summary["reason"]
    by_id = rows(data)
    assert (
        by_id["GT-SAST-001"]["status"] == "not measured" and by_id["GT-SAST-001"]["outcome"] == "NOT MEASURED"
    )
    assert not [call for call in engine.calls if call.startswith("code")], (
        "nothing is asked of a missing step"
    )
    assert summary["strategies"][CODE]["rate"] is None and summary["strategies"][K8S]["rate"] == 1.0
    assert run.exit_code(data) == 2
    text = run.markdown(data)
    assert "**Verified fix rate: not measured.**" in text and "attempted fixable seeds (" not in text


def test_a_step_that_fails_midway_stops_the_strategy_and_gives_exit_2() -> None:
    engine = all_verified()
    # Targets run in finding-id order: ev, sh, sql. The first one's model server fails.
    engine.code_runs[fid("ev")] = "the model server failed on attempt 1: the provider failed: ProviderError"
    data = measured(engine)
    assert data["summary"]["headline"] is None and run.exit_code(data) == 2
    by_id = rows(data)
    assert {by_id[s]["status"] for s in ("GT-SAST-001", "GT-SAST-002", "GT-SAST-003")} == {"not measured"}
    assert "ProviderError" in by_id["GT-SAST-003"]["why"]
    assert "not run" in by_id["GT-SAST-002"]["findings"][0]["reason"]
    assert [c for c in engine.calls if c.startswith("code")] == [f"code {fid('ev')}"], (
        "the next targets are not run once a step failed"
    )


def test_a_deterministic_strategy_that_cannot_run_is_not_measured() -> None:
    engine = all_verified()
    engine.deterministic_runs[DOCKER] = "the verification did not reach the gate: scan sca failed (2)"
    data = measured(engine)
    row = rows(data)["GT-IAC-002"]
    assert (row["status"], row["outcome"]) == ("not measured", "NOT MEASURED")
    assert "scan sca failed" in row["findings"][0]["reason"]
    assert run.exit_code(data) == 2


def test_a_base_scan_that_cannot_run_measures_nothing() -> None:
    data = measured(Scripted(prepare_fails="Grype's database could not be prepared"))
    assert data["summary"]["headline"] is None and run.exit_code(data) == 2
    assert "Grype's database" in data["summary"]["reason"]
    by_id = rows(data)
    assert by_id["GT-SAST-001"]["status"] == "not measured"
    assert by_id["GT-SECRET-001"]["status"] == "not attempted", "a seed without a strategy is still listed"


def test_no_attempted_seed_gives_no_rate() -> None:
    data = measured(all_verified(), seeds=[s for s in SEEDS if s["category"] in ("SECRET", "SCA")])
    assert data["summary"]["headline"] is None and run.exit_code(data) == 2
    assert "no fixable seed" in data["summary"]["reason"]


def test_a_measured_report_exits_0_whatever_the_rate() -> None:
    engine = all_verified()
    for target in ("sql", "sh", "ev"):
        engine.code_runs[fid(target)] = made(CODE, [target], gate(1, "REJECTED", "tests pass"))
    data = measured(engine)
    assert data["summary"]["headline"]["met"] is False and run.exit_code(data) == 0


# ---------------------------------------------------------------- the per-strategy table


def test_the_per_strategy_table_counts_each_strategys_seeds() -> None:
    engine = all_verified()
    engine.code_runs[fid("ev")] = made(CODE, ["ev"], gate(1, "REJECTED", "tests pass"))
    data = measured(engine)
    strategies = data["summary"]["strategies"]
    code = strategies[CODE]
    assert (code["seeds"], code["attempted"], code["verified"], code["rejected"], code["not_attempted"]) == (
        4, 3, 2, 1, 1,
    )  # fmt: skip
    assert code["rate"] == round(2 / 3, 4)
    engine.code_runs[fid("sh")] = made(CODE, ["sh"], *(gate(n, "REJECTED", "build OK") for n in (1, 2)),
                                       gate(3, "FAILED", "build OK"))  # fmt: skip
    failed = measured(engine)["summary"]["strategies"][CODE]
    assert (failed["verified"], failed["rejected"], failed["failed"]) == (1, 1, 1)
    assert strategies[K8S]["attempted"] == 1 and strategies[K8S]["rate"] == 1.0
    assert (
        strategies[BUMP]["seeds"] == 1
        and strategies[BUMP]["attempted"] == 0
        and strategies[BUMP]["rate"] is None
    )
    assert strategies["none"]["seeds"] == 3 and strategies["none"]["attempted"] == 0
    assert sum(entry["seeds"] for entry in strategies.values()) == len(SEEDS)
    text = run.markdown(data)
    assert f"| {CODE} | 4 | 3 | 2 | 1 | 0 | 0 | 0 | 1 | 0 | 66.7% |" in text


def test_no_proposal_is_counted_by_whose_it_is() -> None:
    """How much of NO PROPOSAL is the model's and how much the harness's, per strategy (#159 review)."""
    engine = all_verified()
    no = run.Attempt(1, "NO PROPOSAL", reason="x")
    engine.code_runs[fid("sql")] = made(CODE, [], no, kind=run.NO_ANSWER)
    engine.code_runs[fid("sh")] = made(CODE, [], no, kind=run.NOT_SENT)
    engine.deterministic_runs[K8S] = made(K8S, [], reason="the fixer proposed nothing")
    data = measured(engine)
    strategies = data["summary"]["strategies"]
    assert strategies[CODE]["no_proposal_why"] == {run.NO_ANSWER: 1, run.NOT_SENT: 1}
    assert strategies[K8S]["no_proposal_why"] == {run.LEFT_OPEN: 1}
    assert strategies[DOCKER]["no_proposal_why"] == {}
    assert rows(data)["GT-IAC-001"]["no_proposal"] == run.LEFT_OPEN
    text = run.markdown(data)
    assert f"| {CODE} | 4 | 3 | 1 | 0 | 0 | 0 | 2 (1 no usable answer, 1 not sent) | 1 | 0 | 33.3% |" in text


def test_the_target_is_met_by_the_exact_rate_not_the_rounded_one() -> None:
    """59,999 of 100,000 rounds to 0.6 but is below it: not met (#159 review)."""
    row = {"strategy": CODE, "make_eval_detected": None, "findings": [], "id": "s"}
    verified = [row | {"status": "attempted", "outcome": "VERIFIED"}] * 59_999
    others = [row | {"status": "attempted", "outcome": "REJECTED"}] * 40_001
    headline = run.summarize([*verified, *others])["headline"]
    assert headline["rate"] == 0.6 and headline["met"] is False
    headline = run.summarize([*verified, verified[0], *others[1:]])["headline"]
    assert headline["rate"] == 0.6 and headline["met"] is True


def test_the_markdown_states_the_headline_and_the_definition() -> None:
    text = run.markdown(measured(all_verified()))
    assert "**Verified fix rate: 5 of 5 attempted fixable seeds (100.0%)**" in text
    assert "SPEC section 3 target: >= 60%: met" in text
    assert "Attempted" in text and "GT-SECRET-001" in text


# ---------------------------------------------------------------- the inputs and their digests


def test_the_inputs_are_named_by_their_digests(tmp_path: Path) -> None:
    findings = tmp_path / "findings"
    findings.mkdir()
    for tool in ("gitleaks", "trivy"):
        (findings / f"{tool}.ndjson").write_bytes(f'{{"tool": "{tool}"}}\n'.encode())
    (tmp_path / "detection.json").write_bytes(b'{"inputs": {"demo_shop_tree": "abc"}}\n')
    recorded, inputs = run.recorded_inputs(findings, tree=lambda: "abc")
    assert inputs["findings_sha256"] == {
        "gitleaks": run.sha256(b'{"tool": "gitleaks"}\n'), "trivy": run.sha256(b'{"tool": "trivy"}\n'),
    }  # fmt: skip
    assert inputs["detection_sha256"] == run.sha256(b'{"inputs": {"demo_shop_tree": "abc"}}\n')
    assert inputs["demo_shop_tree"] == "abc" and len(recorded) == 2
    data = run.measure(truth(), all_verified(), recorded=recorded, inputs=inputs, truth_bytes=b"truth")
    assert data["inputs"]["ground_truth_sha256"] == run.sha256(b"truth")
    assert data["inputs"]["findings_sha256"] == inputs["findings_sha256"]
    assert data["evidence"] == {"tools": {"trivy": "0.76.1"}}


def test_a_tree_other_than_the_one_make_eval_scanned_is_refused(tmp_path: Path) -> None:
    (tmp_path / "findings").mkdir()
    with pytest.raises(run.NotMeasured, match="run `make eval` first"):
        run.recorded_inputs(tmp_path / "findings", tree=lambda: "abc")
    (tmp_path / "detection.json").write_text('{"inputs": {"demo_shop_tree": "abc"}}', encoding="utf-8")
    with pytest.raises(run.NotMeasured, match="but `make eval` scanned"):
        run.recorded_inputs(tmp_path / "findings", tree=lambda: "def")
    with pytest.raises(run.NotMeasured, match="not a clean checkout"):
        run.recorded_inputs(tmp_path / "findings", tree=lambda: None)


def test_a_seed_make_eval_detected_otherwise_is_flagged() -> None:
    recorded = [f for f in BASE if f["id"] != fid("root")]
    data = measured(all_verified(), recorded=recorded)
    assert data["summary"]["detection_differs"] == ["GT-IAC-002"]
    assert rows(data)["GT-IAC-002"]["make_eval_detected"] is False


def test_the_report_is_the_same_byte_for_byte() -> None:
    first = json.dumps(measured(all_verified()), sort_keys=True)
    second = json.dumps(measured(all_verified()), sort_keys=True)
    assert first == second and run.markdown(json.loads(first)) == run.markdown(json.loads(second))


# ---------------------------------------------------------------- the gate's result, read honestly


def result(outcome: str, **fields: Any) -> dict[str, Any]:
    ok = outcome == "VERIFIED"
    return {
        "proposal_id": "p", "outcome": outcome, "build_ok": True, "tests_ok": True, "target_resolved": True,
        "new_findings": [], "verdict": "PASS" if ok else "BLOCK", **fields,
    }  # fmt: skip


def test_the_failed_conditions_are_read_from_the_result() -> None:
    attempt = run.gate_attempt(2, result("REJECTED", tests_ok=False, new_findings=["a", "b"]), "p", "diff")
    assert attempt.outcome == "REJECTED" and attempt.number == 2
    assert attempt.failed == ("tests pass", "no new finding >= MEDIUM (2 new)", "verdict != BLOCK")
    assert attempt.diff_sha256 == run.sha256(b"diff")
    assert run.gate_attempt(1, result("VERIFIED"), "p", "diff").failed == ()


@pytest.mark.parametrize(
    "bad",
    [
        result("VERIFIED", tests_ok=False),  # VERIFIED with a failed condition
        result("REJECTED", verdict="PASS"),  # REJECTED with none
        result("MAYBE"),
        result("VERIFIED", proposal_id="other"),
    ],
    ids=["verified-but-failed", "rejected-for-nothing", "unknown-outcome", "another-proposal"],
)
def test_a_result_that_breaks_the_gates_invariant_is_not_measured(bad: dict[str, Any]) -> None:
    with pytest.raises(run.NotMeasured):
        run.gate_attempt(1, bad, "p", "diff")


def test_code_attempts_map_to_outcomes() -> None:
    results = {1: (result("REJECTED", tests_ok=False), {"proposal_id": "p", "diff": "d"})}
    results[2] = (result("VERIFIED"), {"proposal_id": "p", "diff": "d"})
    records = [{"number": 1, "status": "REJECTED"}, {"number": 2, "status": "VERIFIED"}]
    made_run = run.code_run(fid("sql"), records, results.get)
    assert made_run.claimed == {fid("sql")} and made_run.outcome == "VERIFIED"
    assert [a.outcome for a in made_run.attempts] == ["REJECTED", "VERIFIED"]
    nothing = run.code_run(
        fid("sql"), [{"number": 1, "status": "not verifiable", "reason": "no tests"}], {}.get
    )
    assert (
        nothing.claimed == frozenset() and nothing.outcome == "NO PROPOSAL" and "no tests" in nothing.reason
    )


@pytest.mark.parametrize(
    ("records", "said"),
    [
        # The cause decides, never the reason's words (#159 review): these words say nothing of a provider.
        ([{"number": 1, "status": "unavailable", "reason": "connection refused", "cause": "provider"}],
         "the model server failed"),
        # A record without a cause (an older loop) is not measured: it withholds the rate, never lowers it.
        ([{"number": 1, "status": "unavailable", "reason": "the provider failed: ProviderError"}],
         "no usable cause"),
        ([{"number": 1, "status": "FAILED", "reason": "its build and tests could not be checked"}],
         "did not reach the gate"),  # no result
        ([{"number": 1, "status": "proposed"}], "which no step reports"),
    ],
    ids=["model-server-down", "no-cause", "never-reached-the-gate", "unknown-status"],
)  # fmt: skip
def test_a_code_attempt_that_could_not_run_is_not_measured(records: list[dict[str, Any]], said: str) -> None:
    with pytest.raises(run.NotMeasured, match=said):
        judged = (result("VERIFIED"), {"proposal_id": "p", "diff": "d"})
        run.code_run(fid("sql"), records, lambda n: None if records[0]["status"] == "FAILED" else judged)


@pytest.mark.parametrize(
    ("status", "cause", "kind"),
    [("unavailable", "answer", run.NO_ANSWER), ("not sent", None, run.NOT_SENT),
     ("not verifiable", None, run.NOT_VERIFIABLE)],
    ids=["no-usable-answer", "not-sent", "not-verifiable"],
)  # fmt: skip
def test_a_code_attempt_with_no_proposal_says_whose_it_is(status: str, cause: str | None, kind: str) -> None:
    """An answer that was not usable is an attempt that failed, whatever the reason's words say."""
    record = {"number": 1, "status": status, "reason": "the provider failed, says the text"}
    made_run = run.code_run(fid("sql"), [record | ({"cause": cause} if cause else {})], {}.get)
    assert made_run.outcome == "NO PROPOSAL" and made_run.kind == kind


# ---------------------------------------------------------------- the real engine's IaC steps, as the bot


OLD = "FROM python:3.12\nRUN pip install x\n"
NEW = "FROM python:3.12\nRUN pip install x\nUSER 10001:10001\n"
DOCKERFILE_PATH = "demo-shop/services/api/Dockerfile"


def proposal() -> PatchProposal:
    diff = unified_diff(DOCKERFILE_PATH, OLD, NEW)
    return PatchProposal(
        schema_version="1.0", proposal_id=proposal_id_of(DOCKER, 1, [fid("root")], diff),
        finding_ids=[fid("root")], strategy=DOCKER, diff=diff, files=[DOCKERFILE_PATH],
        rationale="Run as 10001.", attempt=1,
        created_at="2026-11-15T00:00:00+00:00",  # type: ignore[arg-type]
    )  # fmt: skip


@dataclass
class Commands:
    """Answers each command as the CLI would; `calls` holds them all."""

    gate_outcome: str = "REJECTED"
    propose: bool = True
    scan_fails: str | None = None
    calls: list[list[str]] = field(default_factory=list)

    def __call__(
        self, args: Sequence[str], *, cwd: Path = ROOT, env: Mapping[str, str] | None = None,
        check: bool = True, capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:  # fmt: skip
        args = list(args)
        self.calls.append(args)
        done = self.answer(args[3:] if args[1:3] == ["-m", "sentinelci.cli"] else args)
        if check and done.returncode != 0:
            raise run.rc.RemediationError(f"{' '.join(args[:3])} failed ({done.returncode})")
        return done

    @staticmethod
    def option(args: list[str], name: str) -> Path:
        return Path(args[args.index(name) + 1])

    def answer(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        def ok(stdout: str = "", code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args, code, stdout, stderr)

        if args[0] == "git" and "archive" in args:
            output = next(a for a in args if a.startswith("--output=")).removeprefix("--output=")
            with tarfile.open(output, "w") as tar:
                data = NEW.encode()
                info = tarfile.TarInfo(DOCKERFILE_PATH)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            return ok()
        if args[:2] == ["remediate", "dockerfile"]:
            if self.propose:
                self.option(args, "--out").write_text(proposal().model_dump_json(), encoding="utf-8")
            return ok(stderr="warning: demo-shop/services/web/Dockerfile left alone: CRLF line endings\n")
        if args[:2] == ["remediate", "apply"]:
            return ok(json.dumps({"branch": "sentinel/fix/abc", "commit": "c" * 40}))
        if args[0] == "scan" and args[1] != "combine":
            if args[1] == self.scan_fails:
                return ok(code=2)
            self.option(args, "--out").write_text("", encoding="utf-8")
            self.option(args, "--tool-status-out").write_text('{"tools": {}}', encoding="utf-8")
            return ok()
        if args[:2] == ["scan", "combine"]:
            self.option(args, "--out").write_text("", encoding="utf-8")
            self.option(args, "--tool-status-out").write_text('{"tools": {"trivy": {"version": "1"}}}')
            return ok()
        if args[:2] == ["remediate", "check"]:
            return ok(json.dumps({"build_ok": True, "tests_ok": True, "problems": []}))
        if args[0] == "score":
            self.option(args, "--out").write_text("", encoding="utf-8")
            return ok()
        if args[0] == "evaluate":
            self.option(args, "--output").write_text('{"verdict": "BLOCK"}', encoding="utf-8")
            return ok(code=1)
        if args[:2] == ["remediate", "verify"]:
            body = result(self.gate_outcome, proposal_id=proposal().proposal_id)
            self.option(args, "--out").write_text(json.dumps(body), encoding="utf-8")
            return ok(code=0 if self.gate_outcome == "VERIFIED" else 1)
        raise AssertionError(f"unexpected command {args}")


def engine_with(commands: Commands, tmp_path: Path) -> Any:
    engine = run.RealEngine(
        run.rc.Settings(test_image="", tools_dir=tmp_path / "tools", grype_db=tmp_path / "db"),
        provider=None, out=tmp_path / "out", runner=commands,
    )  # fmt: skip
    loop = engine.loop
    loop.work = tmp_path / "work"
    loop.base, loop.repo, loop.base_tree = (
        "b" * 40,
        tmp_path / "work" / "repo.git",
        tmp_path / "work" / "base",
    )
    loop.before, loop.opa_manifest = loop.work / "before.ndjson", loop.work / "opa.json"
    (loop.work / "base-scan").mkdir(parents=True)
    return engine


def test_the_real_engine_verifies_an_iac_proposal_as_the_bots_verify_job(tmp_path: Path) -> None:
    commands = Commands(gate_outcome="REJECTED")
    made_run = engine_with(commands, tmp_path).deterministic(DOCKER)
    assert made_run.claimed == {fid("root")} and made_run.outcome == "REJECTED"
    assert made_run.attempts[0].failed == ("verdict != BLOCK",)
    assert made_run.left_open == {"demo-shop/services/web/Dockerfile": "CRLF line endings"}
    names = [c[3:5] for c in commands.calls if c[1:3] == ["-m", "sentinelci.cli"]]
    assert names[:2] == [["remediate", "dockerfile"], ["remediate", "apply"]]
    assert names[-4:] == [["remediate", "check"], ["score", "--findings"], ["evaluate", "--findings"],
                          ["remediate", "verify"]]  # fmt: skip
    base_iac = str(tmp_path / "work" / "base-scan" / "iac.ndjson")
    (propose,) = [c for c in commands.calls if c[3:5] == ["remediate", "dockerfile"]]
    (check,) = [c for c in commands.calls if c[3:5] == ["remediate", "check"]]
    assert str(Commands.option(propose, "--findings")) == base_iac, "proposed from the base IaC findings"
    assert str(Commands.option(check, "--findings")) == base_iac, "the fixer is re-run on the same findings"
    assert "--test-image" not in check
    (evaluate,) = [c for c in commands.calls if c[3:4] == ["evaluate"]]
    assert evaluate[evaluate.index("--context") + 1] == "pr"
    assert str(Commands.option(evaluate, "--baseline")).endswith("before.ndjson")
    archive = next(c for c in commands.calls if "archive" in c)
    assert "--" not in archive, "the patched commit is exported whole, as the bot does"


def test_the_real_engine_reports_a_fixer_that_proposes_nothing(tmp_path: Path) -> None:
    made_run = engine_with(Commands(propose=False), tmp_path).deterministic(DOCKER)
    assert made_run.claimed == frozenset() and made_run.outcome == "NO PROPOSAL"
    assert "CRLF" in made_run.reason


def test_the_real_engine_does_not_measure_a_scan_that_fails(tmp_path: Path) -> None:
    with pytest.raises(run.NotMeasured, match="did not reach the gate"):
        engine_with(Commands(scan_fails="sca"), tmp_path).deterministic(DOCKER)


def test_the_code_fixer_cannot_run_without_a_pinned_test_image(tmp_path: Path) -> None:
    engine = engine_with(Commands(), tmp_path)
    assert "test image" in (engine.unavailable(CODE) or "")
    assert engine.unavailable(DOCKER) is None
    engine.loop.settings = run.rc.Settings(test_image="python:3.12", tools_dir=tmp_path, grype_db=tmp_path)
    assert "pinned by digest" in (engine.unavailable(CODE) or "")


def test_a_strategy_partly_measured_has_no_rate() -> None:
    engine = all_verified()
    # Targets run in finding-id order: ev, sh, sql. The last one cannot run.
    engine.code_runs[fid("sql")] = (
        "attempt 1 did not reach the gate: its build and tests could not be checked"
    )
    data = measured(engine)
    code = data["summary"]["strategies"][CODE]
    assert (code["attempted"], code["verified"], code["not_measured"], code["not_attempted"]) == (2, 2, 1, 1)
    assert code["rate"] is None and data["summary"]["headline"] is None
    assert data["summary"]["not_measured"] == ["GT-SAST-001"]


def test_a_deterministic_strategy_that_cannot_run_here_is_not_asked() -> None:
    engine = all_verified()
    engine.unavailable_because[DOCKER] = "the Dockerfile fixer is not available"
    data = measured(engine)
    assert DOCKER not in engine.calls and K8S in engine.calls
    row = rows(data)["GT-IAC-002"]
    assert (row["status"], row["why"]) == ("not measured", "the Dockerfile fixer is not available")
