"""SC-011's list (policies/exposing.rego) as Python reads it is the list the gate evaluates."""

from pathlib import Path

from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.exposing import exposing_rule_ids
from sentinelci.policy.opa import OpaRunner

POLICIES = Path(__file__).resolve().parents[2] / "policies"


def test_python_reads_the_ids_opa_evaluates(opa_binary: Path) -> None:
    bundle = PolicyBundle.load(POLICIES)
    evaluated = OpaRunner.locate(opa_binary).eval("data.sentinel.exposing.rule_ids", bundle.rego_files, {})
    assert exposing_rule_ids(POLICIES) == frozenset(evaluated)
    assert len(evaluated) == 20


def test_the_list_is_part_of_the_policy_bundle() -> None:
    """It is read from the base commit with the policies, and covered by the bundle digest."""
    assert "exposing.rego" in {p.name for p in PolicyBundle.load(POLICIES).rego_files}
