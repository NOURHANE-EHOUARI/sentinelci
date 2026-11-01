"""The deterministic Kubernetes fixer (task A6, SPEC §9): only safe hardening and minimal diffs, every edit
checked against the real Trivy (opt-in with SENTINEL_TOOLS_DIR, like the other real-tool tests)."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from sentinelci.remediation.kubernetes import FIXES, NotFixable, fix_manifest, propose

from .conftest import NOW, SEED, SEED_PATH, SEED_RULES, iac_finding, seed_findings

FIXABLE = sorted(set(SEED_RULES) & FIXES.keys())
LEFT_ALONE = sorted(set(SEED_RULES) - FIXES.keys())
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)

GOLDEN = Path(__file__).parent / "fixtures" / "shop-api.diff"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "demo-shop" / "infra" / "k8s").mkdir(parents=True)
    shutil.copy(SEED, repo / SEED_PATH)
    return repo


def test_the_seed_gets_only_safe_hardening(tmp_path: Path, proposal_validator: Draft202012Validator) -> None:
    plan = propose(seed_findings(), _repo(tmp_path), created_at=NOW)
    proposal = plan.proposal
    assert proposal is not None and plan.skipped == {}
    assert proposal.strategy == "deterministic:kubernetes" and proposal.files == [SEED_PATH]
    assert sorted(proposal.finding_ids) == sorted(iac_finding(rule).id for rule in FIXABLE)
    assert len(FIXABLE) == 14 and LEFT_ALONE == [
        "KSV-0011", "KSV-0013", "KSV-0015", "KSV-0016", "KSV-0018", "KSV-0023", "KSV-0121", "KSV-0125",
    ]  # fmt: skip
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(proposal.diff)
    assert proposal.diff == GOLDEN.read_text(), "only the hardening lines change (see fixtures/shop-api.diff)"
    assert "hostPath volumes" in proposal.rationale and "stay open" in proposal.rationale
    errors = [
        e.message
        for e in proposal_validator.iter_errors(json.loads(proposal.model_dump_json(exclude_none=True)))
    ]
    assert not errors, errors


def test_the_diff_applies_with_git_and_gives_the_fixed_manifest(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    proposal = propose(seed_findings(), repo, created_at=NOW).proposal
    assert proposal is not None
    git = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "seed"], check=True)
    patch = tmp_path / "proposal.diff"
    patch.write_text(proposal.diff)
    subprocess.run([*git, "apply", "--check", str(patch)], check=True)
    subprocess.run([*git, "apply", str(patch)], check=True)
    assert (repo / SEED_PATH).read_text() == fix_manifest(SEED.read_text(), FIXABLE).text


def test_the_same_inputs_give_the_same_proposal_and_a_retry_another_id(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = propose(seed_findings(), repo, created_at=NOW).proposal
    again = propose(list(reversed(seed_findings())), repo, created_at=NOW).proposal
    retry = propose(seed_findings(), repo, attempt=2, created_at=NOW).proposal
    assert first is not None and again is not None and retry is not None
    assert first == again and retry.proposal_id != first.proposal_id and retry.attempt == 2


def test_nothing_to_propose_when_no_finding_is_fixable(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    others = [
        iac_finding("KSV-0023"),  # a hostPath volume: never removed
        iac_finding("KSV-0017", tool="checkov"),  # another scanner's rule ids are not this fixer's
        iac_finding("KSV-0017", path="demo-shop/infra/terraform/main.tf"),
    ]
    assert propose(others, repo, created_at=NOW).proposal is None


def _link(file: Path) -> None:
    """A link to another manifest inside the repository: a patch must name the real file."""
    file.rename(file.with_name("real.yaml"))
    file.symlink_to("real.yaml")


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (None, "not a regular file"),
        (_link, "not a regular file"),
        (b"apiVersion: v1\nkind:   Pod\n", "layout cannot be kept"),
        (b"kind: Pod\nspec: [unclosed\n", "not valid YAML"),
        (b"kind: Pod\nspec: {}", "does not end with a newline"),
        (b"kind: \xff\n", "not UTF-8"),
        (b"kind: Pod\nspec:\n  containers: []\n", "nothing this fixer can resolve"),
        (b"kind: Pod\r\nspec:\r\n  hostPID: true\r\n  containers: []\r\n", "CRLF"),
        (
            b"kind: Deployment\nspec: {}\n---\nkind: Unknown\nspec:\n  containers: []\n",
            "kind Unknown is not supported",
        ),
    ],
    ids=[
        "missing",
        "symlink",
        "odd-spacing",
        "invalid-yaml",
        "no-final-newline",
        "not-utf8",
        "stale-findings",
        "crlf",
        "unsupported-kind",
    ],
)
def test_a_file_that_cannot_be_edited_minimally_is_left_alone(
    tmp_path: Path, content: object, reason: str
) -> None:
    repo = _repo(tmp_path)
    file = repo / SEED_PATH
    if content is None:
        file.unlink()
    elif isinstance(content, bytes):
        file.write_bytes(content)
    else:
        content(file)  # type: ignore[operator]
    plan = propose(seed_findings(), repo, created_at=NOW)
    assert plan.proposal is None and reason in plan.skipped[SEED_PATH]


COMPACT = """\
# A CronJob in the compact list style, with an init container and the pod running as root.
apiVersion: batch/v1
kind: CronJob
metadata:
  name: report
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsUser: 0
          hostPID: true
          initContainers:
          - name: migrate
            image: registry.local/demo-shop/migrate@sha256:aaaa
          containers:
          - name: report
            image: registry.local/demo-shop/report@sha256:bbbb  # pinned by digest
          restartPolicy: Never
---
apiVersion: v1
kind: Service
metadata:
  name: report
spec:
  ports:
  - port: 80
"""


def test_every_workload_kind_and_layout_is_hardened_minimally() -> None:
    fixed = fix_manifest(COMPACT, ["KSV-0012", "KSV-0010", "KSV-0001"])
    assert fixed.changes == ["allowPrivilegeEscalation: false", "hostPID: false", "runAsNonRoot: true"]
    text = fixed.text
    assert "# pinned by digest" in text and 'schedule: "0 3 * * *"' in text, "comments and quotes are kept"
    assert "hostPID: false" in text and text.count("allowPrivilegeEscalation: false") == 2
    # The pod runs as UID 0: runAsNonRoot alone would stop it, so each container gets a non-root UID.
    assert text.count("runAsUser: 10001") == 2 and text.count("runAsNonRoot: true") == 2
    assert text.split("---")[1] == COMPACT.split("---")[1], "the Service is untouched"
    unchanged = [line for line in COMPACT.splitlines() if line not in text.splitlines()]
    assert unchanged == ["          hostPID: true"], "only the flagged line changes; everything else is added"


SAFE = """\
kind: Pod
spec:
  hostNetwork: false
  containers:
    - name: a
      securityContext:
        privileged: false
"""


def test_a_setting_that_is_already_safe_is_not_rewritten() -> None:
    manifest = SAFE
    assert fix_manifest(manifest, ["KSV-0009", "KSV-0017"]).text == manifest
    with pytest.raises(NotFixable):
        fix_manifest("kind: Pod\n  bad: indent\n", ["KSV-0009"])


# ---------------------------------------------------------------- the real Trivy

TRIVY_ARGS = [
    "config", "--skip-check-update", "--disable-telemetry", "--config", "", "--ignorefile", "",
    "--format", "json", "--quiet",
]  # fmt: skip
EXTRA = """\
apiVersion: v1
kind: Pod
metadata:
  name: tools
spec:
  hostPID: true
  hostIPC: true
  containers:
    - name: tools
      image: registry.local/demo-shop/tools@sha256:cccc
"""


def _trivy(directory: Path, cache: Path) -> dict[str, set[str]]:
    """Rule ids Trivy reports, per file name."""
    run = subprocess.run(
        [str(Path(str(TOOLS_DIR)) / "bin" / "trivy"), *TRIVY_ARGS, "--cache-dir", str(cache), str(directory)],
        capture_output=True, text=True, check=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(cache), "HTTPS_PROXY": "http://127.0.0.1:9"},
    )  # fmt: skip
    found: dict[str, set[str]] = {}
    for result in json.loads(run.stdout).get("Results", []):
        found.setdefault(Path(result["Target"]).name, set()).update(
            m["ID"] for m in result.get("Misconfigurations") or []
        )
    return found


@real
@pytest.mark.integration
def test_real_trivy_each_edit_resolves_its_rule_and_adds_none(tmp_path: Path) -> None:
    """One file per (manifest, rule): the edit for that rule alone, then one Trivy run over all of them."""
    sources = {"seed": SEED.read_text(), "extra": EXTRA}
    before_dir = tmp_path / "before"
    before_dir.mkdir()
    for name, text in sources.items():
        (before_dir / f"{name}.yaml").write_text(text)
    before = _trivy(before_dir, tmp_path / "cache")
    assert set(before["seed.yaml"]) == set(SEED_RULES), "the seed's findings changed: update SEED_RULES"
    after_dir = tmp_path / "after"
    after_dir.mkdir()
    cases = [(name, rule) for name in sources for rule in sorted(before[f"{name}.yaml"] & FIXES.keys())]
    assert {rule for _, rule in cases} == set(FIXES), "every rule the fixer knows is checked"
    for name, rule in cases:
        (after_dir / f"{name}-{rule}.yaml").write_text(fix_manifest(sources[name], [rule]).text)
    after = _trivy(after_dir, tmp_path / "cache")
    for name, rule in cases:
        reported = after.get(f"{name}-{rule}.yaml", set())
        assert rule not in reported, f"{rule} still reported on {name}"
        assert reported <= before[f"{name}.yaml"], (
            f"{rule} on {name} added {reported - before[f'{name}.yaml']}"
        )


@real
@pytest.mark.integration
def test_real_trivy_after_the_proposal_only_the_left_alone_findings_remain(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    proposal = propose(seed_findings(), repo, created_at=NOW).proposal
    assert proposal is not None
    (repo / SEED_PATH).write_text(fix_manifest(SEED.read_text(), FIXABLE).text)
    assert _trivy(repo / "demo-shop" / "infra" / "k8s", tmp_path / "cache")["shop-api.yaml"] == set(
        LEFT_ALONE
    )


POD = """\
kind: {kind}
spec:
  template:
    spec:
      containers:
        - name: a
          securityContext:
            capabilities:
              add:
                - NET_BIND_SERVICE
"""


def test_drop_all_keeps_the_added_capabilities() -> None:
    """#41 review, nit 2."""
    text = fix_manifest(POD.format(kind="Deployment"), ["KSV-0003"]).text
    assert "- NET_BIND_SERVICE" in text and "- ALL" in text


@pytest.mark.parametrize(
    "kind", ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"]
)
def test_every_template_workload_is_hardened(kind: str) -> None:
    assert "allowPrivilegeEscalation: false" in fix_manifest(POD.format(kind=kind), ["KSV-0001"]).text


def test_a_pod_template_is_hardened() -> None:
    template = "kind: PodTemplate\ntemplate:\n  spec:\n    containers:\n      - name: a\n"
    assert "allowPrivilegeEscalation: false" in fix_manifest(template, ["KSV-0001"]).text


@pytest.mark.parametrize(("value", "kept"), [(20000, True), (10001, True), (10000, False), (0, False)])
def test_a_uid_above_the_host_range_is_kept(value: int, kept: bool) -> None:
    """#41 review, should fix 1: files in the image may belong to the UID the workload already uses."""
    manifest = (
        "kind: Pod\nspec:\n  containers:\n    - name: a\n      securityContext:\n"
        f"        runAsUser: {value}\n        runAsGroup: {value}\n"
    )
    text = fix_manifest(manifest, ["KSV-0020", "KSV-0021"]).text
    assert (f"runAsUser: {value}" in text and f"runAsGroup: {value}" in text) is kept
    assert ("runAsUser: 10001" in text) is (kept is False or value == 10001)


@pytest.mark.parametrize(("start", "end"), [("---\n", ""), ("", "...\n"), ("---\n", "...\n")])
def test_document_markers_are_kept(start: str, end: str) -> None:
    """#41 review, nit 1: many manifests start with --- (and some end with ...)."""
    manifest = f"{start}kind: Pod\nspec:\n  hostPID: true\n  containers:\n    - name: a\n{end}"
    text = fix_manifest(manifest, ["KSV-0010"]).text
    assert text == manifest.replace("hostPID: true", "hostPID: false")
