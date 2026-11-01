"""The correlator, stages 1 and 2 (task A7, SPEC section 8), and its metrics.

The findings are Finding v1 records shaped like the demo-shop seeds; every group is checked against
schemas/root-cause-group.v1.json. Stage 2b runs with a deterministic embedder, so the tests say what the
clustering does, not how good a model is: that is measured with the real model in the evaluation (B8).
"""

import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from sentinel_ai.correlate import (
    Correlation,
    CorrelationError,
    EmbeddingModel,
    RootCauseGroup,
    adjusted_rand_index,
    alert_reduction,
    correlate,
    correlate_run,
    dedup,
    group_id,
    labels_of,
    structural_keys,
)
from sentinel_ai.correlate.stages import embedding_groups, purl_base

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas" / "root-cause-group.v1.json").read_text("utf-8")))


def fid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def sca(advisory: str, purl: str, *, tool: str = "grype", fixed: list[str] | None = None, cve: str = "",
        category: str = "SCA") -> dict[str, Any]:  # fmt: skip
    name, _, version = purl.split("/")[-1].partition("@")
    package: dict[str, Any] = {
        "purl": purl,
        "name": name,
        "version": version,
        "ecosystem": purl[4:].split("/")[0],
    }
    if fixed is not None:
        package["fixed_versions"] = fixed
    return {
        "id": fid(category, advisory, purl_base(purl)), "tool": {"name": tool, "version": "1"},
        "rule_id": advisory, "category": category, "title": f"{name} {version}: {advisory}",
        "message": f"{advisory} affects {name}", "severity": "HIGH", "cve": [cve] if cve else [],
        "aliases": [], "location": {"path": "package-lock.json"}, "package": package,
    }  # fmt: skip


def located(category: str, rule: str, path: str, line: int, title: str = "") -> dict[str, Any]:
    return {
        "id": fid(category, rule, path, str(line)), "tool": {"name": "t", "version": "1"}, "rule_id": rule,
        "category": category, "title": title or f"{rule} in {path}", "message": "m", "severity": "MEDIUM",
        "location": {"path": path, "start_line": line, "end_line": line},
    }  # fmt: skip


def secret(rule: str, path: str) -> dict[str, Any]:
    return located("SECRET", rule, path, 1) | {"title": f"{rule} in {path}"}


LODASH = "pkg:npm/lodash@4.17.20"
LODASH_ES = "pkg:npm/lodash-es@4.17.20"
FINDINGS = [
    sca("GHSA-35jh-r3h4-6jhm", LODASH, fixed=["4.17.21"], cve="CVE-2021-23337"),
    sca("GHSA-29mw-wpgm-hmr9", LODASH, fixed=["4.17.21"], cve="CVE-2020-28500"),
    sca("GHSA-35jh-r3h4-6jhm", LODASH_ES, fixed=["4.17.21"], cve="CVE-2021-23337"),
    sca("GHSA-xvch-5gv4-984h", "pkg:npm/minimist@1.2.5", fixed=["1.2.6"]),
    sca("GHSA-8q59-q68h-6hv4", "pkg:pypi/pyyaml@5.3.1", fixed=["5.4"]),
    located("IAC", "KSV-0014", "infra/k8s/shop-api.yaml", 20),
    located("IAC", "KSV-0014", "infra/k8s/shop-api.yaml", 41),
    located("IAC", "KSV-0014", "infra/k8s/web.yaml", 12),
    secret("github-pat", "services/shop-api/config/settings.yaml"),
    secret("npm-access-token", "services/web/.npmrc"),
]


def _by_members(groups: list[RootCauseGroup]) -> dict[frozenset[str], RootCauseGroup]:
    return {frozenset(group.finding_ids): group for group in groups}


def test_every_group_satisfies_the_contract_and_every_finding_is_in_exactly_one() -> None:
    groups = correlate(FINDINGS)
    for group in groups:
        assert not [e.message for e in SCHEMA.iter_errors(group.document())]
        assert group.group_id == group_id(group.finding_ids) and group.finding_ids == sorted(
            group.finding_ids
        )
    members = [finding for group in groups for finding in group.finding_ids]
    assert sorted(members) == sorted({f["id"] for f in FINDINGS})


def test_stage_1_one_alert_per_fingerprint_across_tools() -> None:
    """Grype and Trivy give the same package finding the same id: one alert, both reports kept."""
    grype, trivy = (
        sca("GHSA-xvch-5gv4-984h", "pkg:npm/minimist@1.2.5"),
        sca("GHSA-xvch-5gv4-984h", "pkg:npm/minimist@1.2.5", tool="trivy"),
    )
    (alert,) = dedup([trivy, grype])
    assert alert.id == grype["id"] and {f["tool"]["name"] for f in alert.findings} == {"grype", "trivy"}
    (group,) = correlate([grype, trivy])
    assert group.stage == "dedup" and len(group.finding_ids) == 1


def test_stage_2a_one_upgrade_one_advisory_one_repeated_pattern() -> None:
    groups = _by_members(correlate(FINDINGS))
    ids = [f["id"] for f in FINDINGS]
    lodash = groups[frozenset(ids[0:3])]  # two lodash advisories, and lodash-es under one of them
    assert lodash.stage == "structural"
    assert lodash.single_fix == "Upgrade lodash to 4.17.21 or later; lodash-es to 4.17.21 or later."
    repeated = groups[frozenset(ids[5:7])]  # the same rule twice in one manifest
    assert repeated.key == "rule:KSV-0014@infra/k8s/shop-api.yaml" and repeated.single_fix is None
    assert repeated.title == "KSV-0014: 2 findings in infra/k8s/shop-api.yaml"
    for alone in (ids[3], ids[4], ids[7], ids[8], ids[9]):  # another file, another package, secrets
        assert groups[frozenset([alone])].stage == "dedup"
    assert len(groups) == 7 and alert_reduction(len(FINDINGS), len(groups)) == pytest.approx(0.3)


def test_a_shared_key_names_the_group() -> None:
    package = _by_members(correlate(FINDINGS[:2]))[frozenset([FINDINGS[0]["id"], FINDINGS[1]["id"]])]
    assert package.key == "package:pkg:npm/lodash" and package.title == "lodash 4.17.20: 2 advisories"
    assert package.root_cause == "lodash 4.17.20 is affected by GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm."
    advisory = _by_members(correlate([FINDINGS[0], FINDINGS[2]]))[
        frozenset([FINDINGS[0]["id"], FINDINGS[2]["id"]])
    ]
    assert advisory.key == "advisory:CVE-2021-23337" and advisory.title == "CVE-2021-23337 in 2 packages"


def test_the_same_advisory_under_another_id_is_one_root_cause() -> None:
    """Grype reports the GHSA, Trivy the CVE: different fingerprints, one advisory (its CVE alias)."""
    grype = sca("GHSA-35jh-r3h4-6jhm", LODASH, cve="CVE-2021-23337")
    trivy = sca("CVE-2021-23337", LODASH, tool="trivy")
    (group,) = correlate([grype, trivy])
    assert group.stage == "structural" and len(group.finding_ids) == 2


@pytest.mark.parametrize(
    ("members", "fix"),
    [
        ([sca("A-1", LODASH, fixed=["4.17.21"]), sca("A-2", LODASH, fixed=["4.17.19", "4.17.21"])],
         "Upgrade lodash past every fix (4.17.19, 4.17.21)."),
        ([sca("A-1", LODASH, fixed=["4.17.21"]), sca("A-2", LODASH)], None),  # one advisory has no fix
        ([located("IAC", "KSV-0014", "a.yaml", 1)], None),
        ([sca("A-1", LODASH, fixed=["4.17.21"])], "Upgrade lodash to 4.17.21 or later."),
    ],
    ids=["two-fixed-versions", "one-without-fix", "not-a-package", "single"],
)  # fmt: skip
def test_a_fix_is_proposed_only_when_one_change_resolves_every_member(
    members: list[dict[str, Any]], fix: str | None
) -> None:
    (group,) = correlate(members)
    assert group.single_fix == fix


def test_ablation_switches_stages_off() -> None:
    assert {g.stage for g in correlate(FINDINGS, structural=False)} == {"dedup"}
    assert len(correlate(FINDINGS, structural=False)) == len(FINDINGS)


def test_the_same_findings_in_any_order_give_the_same_groups() -> None:
    expected = correlate(FINDINGS)
    for seed in range(5):
        shuffled = list(FINDINGS)
        random.Random(seed).shuffle(shuffled)
        assert correlate(shuffled) == expected


@pytest.mark.parametrize("finding", [{"category": "SCA"}, {"id": "not-a-fingerprint"}, ["a", "list"]])
def test_a_finding_without_a_fingerprint_is_refused(finding: Any) -> None:
    with pytest.raises(CorrelationError, match="finding 1 has no fingerprint"):
        correlate([FINDINGS[0], finding])


def test_secrets_never_share_a_structural_key() -> None:
    """Each secret is rotated on its own: no key joins two of them, whatever their files."""
    assert structural_keys(dedup([secret("github-pat", "a.yaml")])[0]) == []


# ---------------------------------------------------------------- stage 2b, with a deterministic embedder

TOPICS = {"sql": [1.0, 0.0, 0.0], "root": [0.0, 1.0, 0.0], "token": [0.0, 0.0, 1.0]}


def keyword_embedder(texts: list[str]) -> list[list[float]]:
    """A vector per text from the topics it mentions: close texts share a topic."""
    vectors = []
    for text in texts:
        lowered = text.lower()
        vector = [sum(v[i] for word, v in TOPICS.items() if word in lowered) for i in range(3)]
        vectors.append([x + 0.01 for x in vector])
    return vectors


SIMILAR = [
    located("SAST", "python-sql-built-from-strings", "app/db.py", 10, "SQL built from strings in get_user"),
    located("SAST", "python-sql-concatenation", "app/orders.py", 22, "SQL statement concatenated in orders"),
    located("SAST", "python-sql-format", "app/reports.py", 5, "user input formatted into SQL"),
    located("IAC", "DS-0002", "services/web/Dockerfile", 1, "image runs as root"),
    located("IAC", "CKV_DOCKER_3", "services/shop-api/Dockerfile", 1, "container runs as root user"),
    located("SAST", "python-debug-mode-enabled", "app/main.py", 3, "debug mode with a token in logs"),
]


def test_stage_2b_merges_close_groups_of_one_category() -> None:
    groups = correlate(SIMILAR, embed=keyword_embedder, threshold=0.9)
    by_members = _by_members(groups)
    sql = frozenset(f["id"] for f in SIMILAR[:3])
    assert by_members[sql].stage == "embedding" and by_members[sql].single_fix is None
    assert by_members[frozenset(f["id"] for f in SIMILAR[3:5])].stage == "embedding"
    assert by_members[frozenset([SIMILAR[5]["id"]])].stage == "dedup"
    truth = ["sql", "sql", "sql", "root", "root", "token"]
    predicted = labels_of(groups, [f["id"] for f in SIMILAR])
    assert adjusted_rand_index(truth, predicted) == 1.0


def test_stage_2b_never_merges_across_categories_or_below_the_threshold() -> None:
    mixed = [SIMILAR[0], located("IAC", "sql-in-a-config", "x.yaml", 1, "SQL in a config file")]
    assert len(correlate(mixed, embed=keyword_embedder, threshold=0.5)) == 2, "SAST and IAC stay apart"
    orthogonal = lambda texts: [[float(i == j) for j in range(len(texts))] for i in range(len(texts))]  # noqa: E731
    assert len(correlate(SIMILAR, embed=orthogonal, threshold=0.5)) == len(SIMILAR), "below the threshold"


@pytest.mark.parametrize("threshold", [1.01, -1.5, math.nan])
def test_a_threshold_that_is_not_a_cosine_similarity_is_refused(threshold: float) -> None:
    """#47 review, nit 3: -5 merged every group of a category."""
    with pytest.raises(CorrelationError, match="not a cosine similarity"):
        correlate(SIMILAR, embed=keyword_embedder, threshold=threshold)


def test_an_embedder_that_does_not_answer_one_vector_per_text_is_refused() -> None:
    with pytest.raises(CorrelationError, match="one finite vector per text"):
        embedding_groups([dedup(SIMILAR[:2])], lambda texts: [[1.0]], 0.5)


# ---------------------------------------------------------------- metrics


@pytest.mark.parametrize(
    ("truth", "predicted", "ari"),
    [
        ([0, 0, 1, 1], [0, 0, 1, 1], 1.0),
        ([0, 0, 1, 1], [1, 1, 0, 0], 1.0),  # names do not matter
        ([0, 0, 1, 1], [0, 1, 0, 1], -0.5),
        ([0, 0, 1, 2], [0, 0, 1, 1], 4 / 7),
        ([0, 0, 0, 0], [0, 1, 2, 3], 0.0),
        ([0, 0, 0], [5, 5, 5], 1.0),
    ],
)
def test_adjusted_rand_index(truth: list[int], predicted: list[int], ari: float) -> None:
    assert adjusted_rand_index(truth, predicted) == pytest.approx(ari)


def test_metrics_refuse_mismatched_inputs() -> None:
    with pytest.raises(ValueError, match="same items"):
        adjusted_rand_index([0, 1], [0])
    assert alert_reduction(0, 0) == 0.0 and alert_reduction(10, 6) == pytest.approx(0.4)


FIXTURES = ROOT / "schemas" / "fixtures" / "root-cause-group"


@pytest.mark.parametrize("path", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_the_model_accepts_every_valid_fixture(path: Path) -> None:
    document = json.loads(path.read_text("utf-8"))
    assert RootCauseGroup.model_validate(document).document() == document


@pytest.mark.parametrize("path", sorted((FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_the_model_refuses_every_invalid_fixture(path: Path) -> None:
    with pytest.raises(ValueError):
        RootCauseGroup.model_validate(json.loads(path.read_text("utf-8")))


def _marker_embedder(texts: list[str]) -> list[list[float]]:
    return [[1.0, 0.0] if "alpha" in text else [0.0, 1.0] for text in texts]


def test_the_threshold_is_inclusive() -> None:
    pair = [located("SAST", "r1", "a.py", 1, "alpha one"), located("SAST", "r2", "b.py", 1, "alpha two")]
    assert len(correlate(pair, embed=_marker_embedder, threshold=1.0)) == 1


def test_groups_merge_on_their_average_similarity_not_their_closest_members() -> None:
    """Average linkage: one close member does not pull a whole group in (single linkage would chain)."""
    group = [located("SAST", "r1", "a.py", 1, "alpha"), located("SAST", "r1", "a.py", 9, "beta")]
    close_to_one = located("SAST", "r2", "b.py", 1, "alpha")
    assert len(correlate([*group, close_to_one], embed=_marker_embedder, threshold=0.9)) == 2
    assert len(correlate([*group, close_to_one], embed=_marker_embedder, threshold=0.5)) == 1


# ---------------------------------------------------------------- #47 review


@pytest.mark.parametrize("path", ["infra/k8s/my app.yaml", "a/" * 300 + "m.yaml"], ids=["space", "long"])
def test_every_group_satisfies_the_contract_whatever_the_path(path: str) -> None:
    (group,) = correlate([located("IAC", "KSV-0014", path, 20), located("IAC", "KSV-0014", path, 41)])
    assert not [e.message for e in SCHEMA.iter_errors(group.document())]
    assert group.key == f"rule:KSV-0014@{path}"


def test_a_key_the_contract_cannot_hold_is_dropped_and_the_title_still_names_it() -> None:
    first, second = (
        sca("GHSA-a", "pkg:npm/a@1", fixed=["2"]) | {"aliases": ["OSV\nX"]},
        sca("GHSA-b", "pkg:npm/b@1", fixed=["2"]) | {"aliases": ["OSV\nX"]},
    )
    (group,) = correlate([first, second])
    assert group.key is None and "OSV" in group.title
    assert not [e.message for e in SCHEMA.iter_errors(group.document())]


def test_stage_2b_never_merges_secrets() -> None:
    """Each secret is rotated on its own, in stage 2b as in stage 2a."""
    two = [secret("github-pat", "services/a/settings.yaml"), secret("github-pat", "services/b/settings.yaml")]
    assert len(correlate(two, embed=lambda texts: [[1.0, 0.0] for _ in texts], threshold=0.5)) == 2


def _down(texts: list[str]) -> list[list[float]]:
    raise ConnectionError("connection refused")


def _nan(texts: list[str]) -> list[list[float]]:
    return [[math.nan, 1.0] for _ in texts]


@pytest.mark.parametrize("embed", [_down, _nan], ids=["down", "nan"])
def test_an_embedder_failure_is_a_correlation_error(embed: Any) -> None:
    with pytest.raises(CorrelationError, match="embedder"):
        correlate(FINDINGS, embed=embed, threshold=0.0)


def test_the_model_refuses_members_out_of_order_or_a_foreign_group_id() -> None:
    (group,) = correlate(FINDINGS[:2])
    document = group.document()
    for change in ({"finding_ids": document["finding_ids"][::-1]}, {"group_id": "0" * 64}):
        with pytest.raises(ValueError, match="sha256 of them"):
            RootCauseGroup.model_validate(document | change)


def test_two_reports_of_one_fingerprint_give_the_same_labels_in_any_order() -> None:
    first = located("SAST", "r1", "a.py", 1, "SQL built from strings")
    other = first | {"tool": {"name": "other", "version": "1"}, "title": "String-built SQL"}
    assert correlate([first, other]) == correlate([other, first])


def test_an_embedding_group_records_its_similarity_and_only_it() -> None:
    groups = correlate(SIMILAR, embed=keyword_embedder, threshold=0.5)
    merged = [g for g in groups if g.stage == "embedding"]
    assert merged and all(g.similarity is not None and 0.5 <= g.similarity <= 1 for g in merged)
    assert all(g.similarity is None for g in groups if g.stage != "embedding")
    assert all(not [e.message for e in SCHEMA.iter_errors(g.document())] for g in groups)


def test_a_package_in_an_image_and_in_a_lockfile_are_two_root_causes() -> None:
    """Nit 5: one needs an image rebuild, the other a lockfile bump."""
    lockfile = sca("GHSA-35jh-r3h4-6jhm", LODASH, fixed=["4.17.21"])
    image = sca("GHSA-35jh-r3h4-6jhm", LODASH, fixed=["4.17.21"], category="CONTAINER")
    assert len(correlate([lockfile, image])) == 2


def test_versions_are_listed_in_version_order() -> None:
    """Nit 5: 4.17.9 before 4.17.10, and every version of the package in the title."""
    old = sca("GHSA-a", "pkg:npm/lodash@4.17.9", fixed=["4.17.10"])
    new = sca("GHSA-b", "pkg:npm/lodash@4.17.10", fixed=["4.17.9", "4.17.11"])
    (group,) = correlate([old, new])
    assert group.title.startswith("lodash 4.17.9, 4.17.10: 2 advisories")
    assert group.single_fix == "Upgrade lodash past every fix (4.17.9, 4.17.10, 4.17.11)."


# ---------------------------------------------------------------- the run document (correlation.v1.json)

CONTRACTS = {
    name: json.loads((ROOT / "schemas" / name).read_text("utf-8"))
    for name in ("correlation.v1.json", "root-cause-group.v1.json")
}
RUN_SCHEMA = Draft202012Validator(
    CONTRACTS["correlation.v1.json"],
    registry=Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in CONTRACTS.values()),
)
MODEL = EmbeddingModel(provider="ollama", name="qwen3-embedding:0.6b", digest="sha256:" + "8" * 64)


def _ndjson(findings: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(f, sort_keys=True) + "\n" for f in findings).encode()


def test_the_run_document_ties_the_groups_to_their_findings() -> None:
    data = _ndjson(FINDINGS)
    run = correlate_run(data)
    document = run.document()
    assert not [e.message for e in RUN_SCHEMA.iter_errors(document)]
    assert run.findings_sha256 == hashlib.sha256(data).hexdigest()
    assert run.correlator.stages == ["dedup", "structural"] and run.correlator.threshold is None
    assert sorted(i for g in run.groups for i in g.finding_ids) == sorted({f["id"] for f in FINDINGS})


def test_the_run_document_records_the_embedding_stage_and_its_model() -> None:
    run = correlate_run(_ndjson(SIMILAR), embed=keyword_embedder, embedding_model=MODEL, threshold=0.5)
    assert run.correlator.stages == ["dedup", "structural", "embedding"]
    assert (run.correlator.threshold, run.correlator.embedding_model) == (0.5, MODEL)
    assert not [e.message for e in RUN_SCHEMA.iter_errors(run.document())]


@pytest.mark.parametrize("embed", [_down, _nan], ids=["down", "nan"])
def test_an_embedder_failure_keeps_stages_1_and_2a_and_says_so(embed: Any) -> None:
    """Should fix 4: advice degrades, it never vanishes, and the document says which stages ran."""
    run = correlate_run(_ndjson(FINDINGS), embed=embed, embedding_model=MODEL)
    assert run.correlator.stages == ["dedup", "structural"] and run.correlator.embedding_model is None
    assert run.groups == correlate(FINDINGS)


def test_an_embedder_comes_with_its_model() -> None:
    with pytest.raises(CorrelationError, match="embedding model"):
        correlate_run(_ndjson(FINDINGS), embed=keyword_embedder)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d | {"groups": d["groups"][::-1]},
        lambda d: d | {"groups": [*d["groups"], d["groups"][0]]},
        lambda d: d | {"correlator": {"version": "0.1.0", "stages": ["dedup"]}},
    ],
    ids=["unsorted", "a-finding-twice", "a-stage-that-did-not-run"],
)
def test_the_run_model_refuses_what_the_schema_cannot_express(change: Any) -> None:
    document = correlate_run(_ndjson(FINDINGS)).document()
    with pytest.raises(ValueError, match=r"sorted|two groups|did not run"):
        Correlation.model_validate(change(document))


def test_an_embedding_group_records_the_linkage_of_its_merge() -> None:
    pair = [located("SAST", "r1", "a.py", 1), located("SAST", "r2", "b.py", 1)]
    vectors = {pair[0]["rule_id"]: [1.0, 0.0], pair[1]["rule_id"]: [0.8, 0.6]}
    embed = lambda texts: [vectors[text.split()[1]] for text in texts]  # noqa: E731 (keyed by rule id)
    (group,) = correlate(pair, embed=embed, threshold=0.5)
    assert (group.stage, group.similarity) == ("embedding", 0.8)


def test_a_key_longer_than_the_contract_allows_is_dropped() -> None:
    path = "a/" * 1100 + "m.yaml"
    (group,) = correlate([located("IAC", "KSV-0014", path, 20), located("IAC", "KSV-0014", path, 41)])
    assert group.key is None and not [e.message for e in SCHEMA.iter_errors(group.document())]


def test_the_run_model_refuses_a_finding_in_two_groups() -> None:
    x, y = "1" * 64, "2" * 64
    single = {"schema_version": "1.0", "group_id": group_id([x]), "finding_ids": [x], "stage": "dedup",
              "labelled_by": "template", "title": "t", "root_cause": "r", "single_fix": None}  # fmt: skip
    pair = single | {"group_id": group_id([x, y]), "finding_ids": [x, y], "stage": "structural"}
    groups = sorted([single, pair], key=lambda g: g["group_id"])
    correlator = {"version": "0.1.0", "stages": ["dedup", "structural"]}
    document = {
        "schema_version": "1.0",
        "findings_sha256": "7" * 64,
        "correlator": correlator,
        "groups": groups,
    }
    with pytest.raises(ValueError, match="in two groups"):
        Correlation.model_validate(document)
