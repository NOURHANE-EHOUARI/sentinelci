"""Snapshot fetchers (task B2, SPEC section 6.1): OSV, FIRST EPSS and CISA KEV, tested without a network.

Responses mirror the real APIs' shapes (checked against the live services); ids are fake.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.enrich import EnrichmentError, enrich_finding, load_snapshot
from sentinelci.enrich.cvss import base_score
from sentinelci.enrich.fetch import (
    EPSS_URL,
    KEV_URL,
    MIN_KEV_ENTRIES,
    OSV_URL,
    build_snapshot,
    dumps_snapshot,
)
from sentinelci.enrich.transport import (
    HttpTransport,
    RecordingTransport,
    ReplayTransport,
    TransportError,
)
from sentinelci.risk.model import RiskModel, score_finding

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "schemas" / "fixtures"
SCA = {
    k: v
    for k, v in json.loads(
        (FIXTURES / "finding" / "valid" / "sca-enriched-and-scored.json").read_text("utf-8")
    ).items()
    if k not in ("enrichment", "risk")
}
SECRET = json.loads((FIXTURES / "finding" / "valid" / "secret-in-config.json").read_text("utf-8"))

# A GHSA-only finding: CVSS and fixes come from OSV, EPSS and KEV through the CVE alias OSV reveals.
FINDING = {**SCA, "rule_id": "GHSA-aaaa-bbbb-cccc", "cve": [], "aliases": ["PYSEC-2099-7"]}
OSV_GHSA = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "modified": "2026-11-09T12:00:00.123456Z",
    "aliases": ["CVE-2099-1001"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H"}],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-lib", "purl": "pkg:pypi/example-lib"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]},
                {
                    "type": "GIT",
                    "repo": "https://example.invalid/r",
                    "events": [{"introduced": "0"}, {"fixed": "abc123"}],
                },
            ],
        },
        {
            "package": {"ecosystem": "npm", "name": "example-lib"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
        },
    ],
}
OSV_PYSEC = {
    "id": "PYSEC-2099-7",
    "modified": "2026-11-08T00:00:00Z",
    "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2099-1001"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "Example_Lib"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.2.4"}, {"introduced": "1.3"}],
                }
            ],
        }
    ],
}
EPSS = {
    "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
    "total": 1, "offset": 0, "limit": 100,
    "data": [
        {"cve": "CVE-2099-1001", "epss": "0.410000000", "percentile": "0.950000000", "date": "2026-11-10"},
    ],
}  # fmt: skip
# The real catalogue holds well over MIN_KEV_ENTRIES entries; filler entries make the fixture that size.
KEV_ENTRIES = [
    {"cveID": "CVE-2099-1001", "dateAdded": "2026-10-01"},
    {"cveID": "CVE-2099-9999", "dateAdded": "2026-10-02"},
    *({"cveID": f"CVE-2000-{n:05d}", "dateAdded": "2020-01-01"} for n in range(MIN_KEV_ENTRIES)),
]
KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.09",
    "dateReleased": "2026-11-09T19:00:04.8077Z",
    "count": len(KEV_ENTRIES),
    "vulnerabilities": KEV_ENTRIES,
}


class FakeTransport:
    """Answers from a table; any request it does not know is a 404. Records every request it gets."""

    def __init__(self, table: dict[tuple[str, str, bytes | None], tuple[int, Any]]) -> None:
        self.table = table
        self.requests: list[tuple[str, str, bytes | None]] = []

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        self.requests.append((method, url, body))
        status, payload = self.table.get((method, url, body), (404, {"code": 5, "message": "Not Found"}))
        if isinstance(payload, Exception):
            raise payload
        return status, payload if isinstance(payload, bytes) else json.dumps(payload).encode()


def feeds(**override: tuple[int, Any]) -> FakeTransport:
    table: dict[tuple[str, str, bytes | None], tuple[int, Any]] = {
        ("GET", f"{OSV_URL}/GHSA-aaaa-bbbb-cccc", None): (200, OSV_GHSA),
        ("GET", f"{OSV_URL}/PYSEC-2099-7", None): (200, OSV_PYSEC),
        ("GET", f"{EPSS_URL}?cve=CVE-2099-1001", None): (200, EPSS),
        ("GET", KEV_URL, None): (200, KEV),
    }
    for name, value in override.items():
        key = {
            "epss": ("GET", f"{EPSS_URL}?cve=CVE-2099-1001", None),
            "kev": ("GET", KEV_URL, None),
            "osv": ("GET", f"{OSV_URL}/GHSA-aaaa-bbbb-cccc", None),
        }[name]
        table[key] = value
    return FakeTransport(table)


def snapshot(transport: FakeTransport, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    result, _ = build_snapshot(findings if findings is not None else [FINDING], transport)
    return result


# ---------------------------------------------------------------- CVSS base score from a vector


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:O", 10.0),  # temporal metrics ignored
    ],
)
def test_cvss3_base_scores(vector: str, score: float) -> None:
    assert base_score(vector) == (vector[5:8], score)


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/Au:N/C:P/I:P/A:P",  # CVSS 2: not computed
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # CVSS 4: not computed
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # a base metric missing
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # repeated metric
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n",
    ],
)
def test_vectors_that_cannot_be_scored_give_nothing(vector: str) -> None:
    assert base_score(vector) is None


# ---------------------------------------------------------------- the snapshot


def test_a_snapshot_from_every_feed() -> None:
    assert snapshot(feeds()) == {
        "schema_version": "1.0",
        "sources": {
            "epss": {"date": "2026-11-10"},
            "kev": {
                "catalog_version": "2026.11.09",
                "cves": ["CVE-2099-1001"],  # what the KEV lookup covered
                "date_released": "2026-11-09T19:00:04.8077Z",
            },
            "osv": {"date": "2026-11-09"},
        },
        "vulnerabilities": {
            "CVE-2099-1001": {
                "epss": {"score": 0.41, "percentile": 0.95},
                "kev": {"date_added": "2026-10-01"},
            },
            "GHSA-aaaa-bbbb-cccc": {
                "aliases": ["CVE-2099-1001"],
                "cvss": {
                    "version": "3.1",
                    "score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H",
                },
                "fixed_versions": {"pkg:npm/example-lib": ["2.0.1"], "pkg:pypi/example-lib": ["1.2.4"]},
            },
            "PYSEC-2099-7": {
                "aliases": ["CVE-2099-1001", "GHSA-aaaa-bbbb-cccc"],
                "fixed_versions": {"pkg:pypi/example-lib": ["1.2.4"]},
            },
        },
    }


def test_the_snapshot_satisfies_the_contract() -> None:
    document = snapshot(feeds())
    schema = json.loads((ROOT / "schemas" / "enrichment-snapshot.v1.json").read_text(encoding="utf-8"))
    assert not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
    load_snapshot(dumps_snapshot(document))


def test_the_snapshot_enriches_the_finding_end_to_end() -> None:
    enriched = enrich_finding(FINDING, load_snapshot(dumps_snapshot(snapshot(feeds()))), None)["enrichment"]
    assert enriched["epss"] == {"score": 0.41, "percentile": 0.95, "date": "2026-11-10"}
    assert enriched["kev"] == {"listed": True, "date_added": "2026-10-01"}
    assert (enriched["cvss"]["score"], enriched["fix_available"]) == (9.8, True)


def test_the_same_feeds_give_the_same_bytes() -> None:
    assert dumps_snapshot(snapshot(feeds())) == dumps_snapshot(snapshot(feeds()))


def test_only_package_findings_are_looked_up() -> None:
    transport = feeds()
    assert snapshot(transport, [SECRET]) == {"schema_version": "1.0", "sources": {}, "vulnerabilities": {}}
    assert transport.requests == []


def test_ids_that_are_not_vulnerability_ids_are_never_sent() -> None:
    odd = {**SCA, "rule_id": "../../admin?x=1", "cve": ["CVE-2099-1001\n"], "aliases": []}
    transport = feeds()
    snapshot(transport, [odd])
    assert all("admin" not in url and "\n" not in url for _, url, _ in transport.requests)


def test_epss_is_asked_in_batches_of_100_in_a_stable_order() -> None:
    many = {
        **SCA,
        "rule_id": "CVE-2099-0001",
        "cve": [f"CVE-2099-{n:04d}" for n in range(1, 151)],
        "aliases": [],
    }

    class AnswersEveryEpssBatch(FakeTransport):
        def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
            if url.startswith(EPSS_URL):
                self.requests.append((method, url, body))
                return 200, json.dumps({"status": "OK", "data": []}).encode()
            return super().request(method, url, body)

    transport = AnswersEveryEpssBatch({("GET", KEV_URL, None): (200, KEV)})
    snapshot(transport, [many])
    epss_urls = [url for _, url, _ in transport.requests if url.startswith(EPSS_URL)]
    assert [len(url.split("=", 1)[1].split(",")) for url in epss_urls] == [100, 50]
    assert epss_urls[0].split("=", 1)[1].split(",")[:2] == ["CVE-2099-0001", "CVE-2099-0002"]


# ---------------------------------------------------------------- a failed feed is left out, never guessed


@pytest.mark.parametrize(
    ("feed", "response"),
    [
        ("epss", (500, {"error": "down"})),
        ("epss", (200, {"status": "OK", "data": "not a list"})),
        ("epss", (200, b"<html>maintenance</html>")),
        ("epss", (200, TransportError("timed out"))),
        ("kev", (200, {"title": "no catalogVersion"})),
        ("kev", (503, b"")),
        ("osv", (500, b"")),
        ("osv", (200, {"id": "GHSA-aaaa-bbbb-cccc", "modified": "not a date", "affected": []})),
    ],
)
def test_a_failed_feed_is_left_out_with_a_warning(feed: str, response: tuple[int, Any]) -> None:
    result, warnings = build_snapshot([FINDING], feeds(**{feed: response}))
    assert feed not in result["sources"]
    assert any(feed.upper() in w for w in warnings)
    load_snapshot(dumps_snapshot(result))  # still a valid snapshot
    others = {"epss", "kev", "osv"} - {feed}
    if feed == "osv":
        others -= {"epss", "kev"}  # without OSV the CVE alias is never learnt
    if feed == "kev":
        others -= {"epss"}  # EPSS without KEV would lower the risk of a listed vulnerability
    assert others <= set(result["sources"])


def test_an_unknown_id_is_not_an_osv_failure() -> None:
    result, warnings = build_snapshot(
        [{**SCA, "rule_id": "GHSA-zzzz-zzzz-zzzz", "cve": [], "aliases": []}], feeds()
    )
    assert warnings == []
    assert "osv" not in result["sources"]  # OSV knew nothing: no date to give, nothing to say


# ---------------------------------------------------------------- transports


def test_http_transport_only_talks_to_the_three_feeds() -> None:
    transport = HttpTransport()
    for url in [
        "http://api.osv.dev/v1/vulns/X",
        "https://evil.example/v1",
        "https://api.osv.dev.evil.example/v1",
    ]:
        with pytest.raises(TransportError, match="not an allowed feed"):
            transport.request("GET", url)


def test_recording_then_replaying_gives_the_same_snapshot(tmp_path: Path) -> None:
    recorded = snapshot(RecordingTransport(feeds(), tmp_path / "rec"))  # type: ignore[arg-type]
    replayed, warnings = build_snapshot([FINDING], ReplayTransport(tmp_path / "rec"))
    assert (replayed, warnings) == (recorded, [])


def test_replay_without_a_recording_fails_like_a_feed_outage(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    result, warnings = build_snapshot([FINDING], ReplayTransport(tmp_path / "empty"))
    assert result["sources"] == {}
    assert warnings


# ---------------------------------------------------------------- sentinel snapshot


def test_cli_builds_a_snapshot_offline(tmp_path: Path) -> None:
    snapshot(RecordingTransport(feeds(), tmp_path / "rec"))  # type: ignore[arg-type]
    (tmp_path / "findings.ndjson").write_text(json.dumps(FINDING) + "\n", encoding="utf-8")
    out = tmp_path / "snapshot.json"
    result = CliRunner().invoke(
        app,
        [
            "snapshot",
            "--findings",
            str(tmp_path / "findings.ndjson"),
            "--out",
            str(out),
            "--offline",
            str(tmp_path / "rec"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.read_bytes() == dumps_snapshot(snapshot(feeds()))
    assert "sources: epss, kev, osv" in result.output


def test_cli_fails_closed_on_unreadable_findings(tmp_path: Path) -> None:
    (tmp_path / "findings.ndjson").write_text("{broken\n", encoding="utf-8")
    out = tmp_path / "snapshot.json"
    out.write_text("stale", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "snapshot",
            "--findings",
            str(tmp_path / "findings.ndjson"),
            "--out",
            str(out),
            "--offline",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 3
    assert not out.exists()


# ---------------------------------------------------------------- details the main cases do not reach


def test_the_alias_round_finds_the_cvss_a_pysec_record_lacks() -> None:
    pysec_only = {**SCA, "rule_id": "PYSEC-2099-7", "cve": [], "aliases": []}
    result = snapshot(feeds(), [pysec_only])
    assert result["vulnerabilities"]["GHSA-aaaa-bbbb-cccc"]["cvss"]["score"] == 9.8
    enriched = enrich_finding(pysec_only, load_snapshot(dumps_snapshot(result)), None)
    assert enriched["enrichment"]["cvss"]["score"] == 9.8


def test_an_epss_answer_about_a_cve_nobody_asked_for_is_refused() -> None:
    unasked = {"cve": "CVE-2099-7777", "epss": "0.9", "percentile": "0.9", "date": "2026-11-10"}
    extra = {**EPSS, "data": [*EPSS["data"], unasked]}
    result, warnings = build_snapshot([FINDING], feeds(epss=(200, extra)))
    assert "epss" not in result["sources"]
    assert any("EPSS" in w for w in warnings)


def test_the_highest_of_several_cvss_vectors_is_kept() -> None:
    two = {**OSV_GHSA, "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
    ]}  # fmt: skip
    result = snapshot(feeds(osv=(200, two)))
    assert result["vulnerabilities"]["GHSA-aaaa-bbbb-cccc"]["cvss"]["score"] == 9.8


def test_a_snapshot_that_breaks_the_contract_is_never_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinelci.enrich.fetch as fetch

    bad = {"GHSA-aaaa-bbbb-cccc": {"fixed_versions": {"pkg:pypi/example-lib@1.2.0": ["1.2.4"]}}}
    monkeypatch.setattr(fetch, "_osv", lambda ids, transport: (bad, None))
    with pytest.raises(EnrichmentError):
        build_snapshot([FINDING], feeds())


def test_cli_writes_nothing_when_the_snapshot_breaks_the_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.enrich.fetch as fetch

    bad = {"GHSA-aaaa-bbbb-cccc": {"fixed_versions": {"pkg:pypi/example-lib@1.2.0": ["1.2.4"]}}}
    snapshot(RecordingTransport(feeds(), tmp_path / "rec"))  # type: ignore[arg-type]
    monkeypatch.setattr(fetch, "_osv", lambda ids, transport: (bad, None))
    (tmp_path / "findings.ndjson").write_text(json.dumps(FINDING) + "\n", encoding="utf-8")
    out = tmp_path / "snapshot.json"
    out.write_text("stale", encoding="utf-8")
    args = ["snapshot", "--findings", str(tmp_path / "findings.ndjson"), "--out", str(out)]
    result = CliRunner().invoke(app, [*args, "--offline", str(tmp_path / "rec")])
    assert result.exit_code == 3
    assert not out.exists()


def test_a_kev_release_time_without_an_offset_is_dropped_not_fatal() -> None:
    naive = {**KEV, "dateReleased": "2026-11-09T19:00:04"}
    result = snapshot(feeds(kev=(200, naive)))
    assert "date_released" not in result["sources"]["kev"]
    assert result["sources"]["kev"]["cves"] == ["CVE-2099-1001"]


def test_cli_snapshot_refuses_to_overwrite_its_input(tmp_path: Path) -> None:
    findings = tmp_path / "findings.ndjson"
    findings.write_text(json.dumps(FINDING) + "\n", encoding="utf-8")
    args = ["snapshot", "--findings", str(findings), "--out", str(findings), "--offline", str(tmp_path)]
    assert CliRunner().invoke(app, args).exit_code == 3
    assert json.loads(findings.read_text(encoding="utf-8")) == FINDING


# ---------------------------------------------------------------- a feed problem never lowers risk (#18)


def test_without_kev_epss_is_left_out_too_and_the_finding_keeps_the_worst_case() -> None:
    # Nourhane's repro: KEV answers 403 while EPSS is up. EPSS alone would give E = 0.46 instead of 1.0 (#16).
    result, warnings = build_snapshot([FINDING], feeds(kev=(403, b"Forbidden")))
    assert set(result["sources"]) == {"osv"}
    assert any(w.startswith("EPSS left out") and "KEV" in w for w in warnings)
    enriched = enrich_finding(FINDING, load_snapshot(dumps_snapshot(result)), None)["enrichment"]
    assert "epss" not in enriched and "kev" not in enriched  # E = 1.0 in the risk engine


def kev_with(entries: list[Any], **fields: Any) -> dict[str, Any]:
    return {**KEV, "vulnerabilities": entries, "count": len(entries), **fields}


@pytest.mark.parametrize(
    "catalogue",
    [
        kev_with([*KEV_ENTRIES, "not an object"]),
        kev_with([*KEV_ENTRIES, {"cveId": "CVE-2099-1001", "dateAdded": "2026-10-01"}]),
        kev_with([*KEV_ENTRIES, {"cveID": "cve-2099-1002", "dateAdded": "2026-10-01"}]),
        kev_with([*KEV_ENTRIES, {"cveID": "CVE-2099-1002 ", "dateAdded": "2026-10-01"}]),
        kev_with([*KEV_ENTRIES, {"cveID": "CVE-2099-1002\n", "dateAdded": "2026-10-01"}]),
        kev_with([*KEV_ENTRIES, {"cveID": ["CVE-2099-1002"], "dateAdded": "2026-10-01"}]),
        kev_with([*KEV_ENTRIES, {"cveID": "CVE-2099-1002", "dateAdded": "20261001"}]),
        kev_with([*KEV_ENTRIES, {"cveID": "CVE-2099-1002"}]),
        kev_with([]),
        kev_with(KEV_ENTRIES[:2] + [{"cveID": f"CVE-2000-{n:05d}", "dateAdded": "2020-01-01"}
                                    for n in range(997)]),
        {**KEV, "count": len(KEV_ENTRIES) + 1},
        {**KEV, "count": str(len(KEV_ENTRIES))},
        {k: v for k, v in KEV.items() if k != "count"},
        {**KEV, "catalogVersion": ""},
        {**KEV, "catalogVersion": 2026},
    ],
    ids=["entry-not-object", "renamed-cveID", "lowercase-cve", "trailing-space", "trailing-newline",
         "cveID-list", "basic-date", "no-dateAdded", "empty", "too-small", "count-mismatch",
         "count-string", "no-count", "empty-catalogVersion", "numeric-catalogVersion"],
)  # fmt: skip
def test_a_kev_catalogue_is_trusted_whole_or_not_at_all(catalogue: dict[str, Any]) -> None:
    result, warnings = build_snapshot([FINDING], feeds(kev=(200, catalogue)))
    assert "kev" not in result["sources"] and "epss" not in result["sources"]
    assert any(w.startswith("KEV left out") for w in warnings)


def test_a_catalogue_of_exactly_1000_entries_is_trusted() -> None:
    """The bound is pinned by literals (999 refused above, 1,000 here), not derived from MIN_KEV_ENTRIES."""
    filler = [{"cveID": f"CVE-2000-{n:05d}", "dateAdded": "2020-01-01"} for n in range(999)]
    result, warnings = build_snapshot([FINDING], feeds(kev=(200, kev_with([KEV_ENTRIES[0], *filler]))))
    assert "kev" in result["sources"], warnings
    assert MIN_KEV_ENTRIES == 1000


def test_kev_covers_a_cve_it_does_not_list() -> None:
    """A covered, unlisted CVE is the one case where the snapshot says "not listed" (E < 1 is allowed)."""
    unlisted = {**SCA, "rule_id": "CVE-2099-5555", "cve": ["CVE-2099-5555"], "aliases": []}
    result, warnings = build_snapshot([unlisted], feeds())
    assert "CVE-2099-5555" in result["sources"]["kev"]["cves"], warnings
    enriched = enrich_finding(unlisted, load_snapshot(dumps_snapshot(result)), None)["enrichment"]
    assert enriched["kev"] == {"listed": False}


@pytest.mark.parametrize(
    ("released", "kept"),
    [
        ("2026-11-09T19:00:04.8077Z", True),
        ("2026-11-09T19:00:04+02:00", True),
        ("2026-11-09T19:00:04", False),
        ("2026-11-09", False),
        ("2026-W45", False),
        ("2026-11-09T25:00:04Z", False),
        (20261109, False),
    ],
)
def test_kev_release_time_is_kept_only_as_rfc3339_with_an_offset(released: Any, kept: bool) -> None:
    result = snapshot(feeds(kev=(200, {**KEV, "dateReleased": released})))
    assert ("date_released" in result["sources"]["kev"]) is kept


@pytest.mark.parametrize(
    "osv",
    [
        {**OSV_GHSA, "aliases": 7},
        {**OSV_GHSA, "severity": 7},
        {**OSV_GHSA, "affected": [{"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": 7}]},
        {**OSV_GHSA, "affected": ["not an object"]},
        {**OSV_GHSA, "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [7]}]}]},
        {**OSV_GHSA, "id": "GHSA-zzzz-zzzz-zzzz"},
    ],
    ids=["aliases-int", "severity-int", "ranges-int", "affected-entry-str", "event-int", "another-id"],
)
def test_malformed_osv_data_leaves_osv_out_instead_of_crashing(osv: dict[str, Any]) -> None:
    result, warnings = build_snapshot([FINDING], feeds(osv=(200, osv)))
    assert "osv" not in result["sources"]
    [warning] = [w for w in warnings if w.startswith("OSV left out")]
    assert any(word in warning for word in ("is not a list", "is not an object", "another record")), warning


def test_a_body_nested_too_deep_is_a_feed_failure() -> None:
    result, warnings = build_snapshot([FINDING], feeds(osv=(200, b"[" * 100_000 + b"]" * 100_000)))
    assert "osv" not in result["sources"]
    assert any("did not answer JSON" in w for w in warnings)


def test_any_other_error_while_reading_a_feed_is_a_feed_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinelci.enrich.fetch as fetch

    def broken(*args: Any) -> Any:
        raise KeyError("an unforeseen shape")

    monkeypatch.setattr(fetch, "_osv_entry", broken)
    result, warnings = build_snapshot([{**FINDING, "cve": ["CVE-2099-1001"]}], feeds())
    assert result["sources"] == {}  # OSV out, so KEV and EPSS too (an alias may be the listed CVE)
    assert any(w.startswith("OSV left out") for w in warnings)

    monkeypatch.undo()
    monkeypatch.setattr(fetch, "_number", broken)
    result, warnings = build_snapshot([FINDING], feeds())
    assert set(result["sources"]) == {"osv", "kev"}  # EPSS alone is left out
    assert any(w.startswith("EPSS left out") for w in warnings)


def test_epss_answers_from_two_days_are_refused() -> None:
    two = {**SCA, "rule_id": "CVE-2099-1001", "cve": ["CVE-2099-1001", "CVE-2099-1002"], "aliases": []}
    rows = [{**EPSS["data"][0]}, {**EPSS["data"][0], "cve": "CVE-2099-1002", "date": "2026-11-09"}]
    transport = feeds()
    transport.table[("GET", f"{EPSS_URL}?cve=CVE-2099-1001,CVE-2099-1002", None)] = (
        200,
        {**EPSS, "data": rows},
    )
    result, warnings = build_snapshot([two], transport)
    assert "epss" not in result["sources"]
    assert any("several days" in w for w in warnings)


@pytest.mark.parametrize("status", [401, 403, 410, 429, 500])
def test_an_error_status_is_a_feed_failure_even_with_a_valid_body(status: int) -> None:
    for feed, body in (("osv", OSV_GHSA), ("kev", KEV), ("epss", EPSS)):
        result, warnings = build_snapshot([FINDING], feeds(**{feed: (status, body)}))
        assert feed not in result["sources"], (feed, status)
        assert any(f"HTTP {status}" in w for w in warnings)


@pytest.mark.parametrize(
    "row",
    [
        {"cve": "CVE-2099-1001", "epss": True, "percentile": "0.5", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": " 0.5 ", "percentile": "0.5", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": "0.0_1", "percentile": "0.5", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": "1.5", "percentile": "0.5", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": "0.5", "percentile": "-0.1", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": "nan", "percentile": "0.5", "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": "0.5", "percentile": "0.5", "date": "20261110"},
        {"cve": "CVE-2099-1001", "epss": -0.1, "percentile": 0.5, "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": float("nan"), "percentile": 0.5, "date": "2026-11-10"},
        {"cve": "CVE-2099-1001", "epss": 0.5, "percentile": float("inf"), "date": "2026-11-10"},
    ],
    ids=[
        "bool",
        "padded",
        "underscore",
        "above-one",
        "negative",
        "nan",
        "basic-date",
        "json-negative",
        "json-NaN",
        "json-Infinity",
    ],
)
def test_epss_values_are_read_strictly(row: dict[str, Any]) -> None:
    result, warnings = build_snapshot([FINDING], feeds(epss=(200, {**EPSS, "data": [row]})))
    assert "epss" not in result["sources"]
    assert any(w.startswith("EPSS left out") for w in warnings)


def test_conflicting_epss_rows_are_refused_and_identical_ones_accepted() -> None:
    row = EPSS["data"][0]
    same = snapshot(feeds(epss=(200, {**EPSS, "data": [row, dict(row)]})))
    assert "epss" in same["sources"]
    other = {**row, "epss": "0.9"}
    result, _ = build_snapshot([FINDING], feeds(epss=(200, {**EPSS, "data": [row, other]})))
    assert "epss" not in result["sources"]


def test_a_withdrawn_osv_record_gives_nothing() -> None:
    result = snapshot(feeds(osv=(200, {**OSV_GHSA, "withdrawn": "2026-11-01T00:00:00Z"})))
    assert "GHSA-aaaa-bbbb-cccc" not in result["vulnerabilities"]


def test_a_lowercase_cve_rule_id_still_reaches_epss_and_kev() -> None:
    lower = {**SCA, "rule_id": "cve-2099-1001", "cve": [], "aliases": []}
    result = snapshot(feeds(), [lower])
    assert result["vulnerabilities"]["CVE-2099-1001"]["epss"]["percentile"] == 0.95
    assert enrich_finding(lower, load_snapshot(dumps_snapshot(result)), None)["enrichment"]["kev"]["listed"]


def test_the_alias_closure_reaches_a_kev_listed_cve_two_levels_away() -> None:
    # PYSEC -> GHSA -> CVE (Nourhane's S4): apply follows the closure the fetcher resolved.
    pysec_only = {**SCA, "rule_id": "PYSEC-2099-7", "cve": [], "aliases": []}
    transport = feeds()
    transport.table[("GET", f"{OSV_URL}/PYSEC-2099-7", None)] = (
        200,
        {**OSV_PYSEC, "aliases": ["GHSA-aaaa-bbbb-cccc"]},
    )
    result = snapshot(transport, [pysec_only])
    assert result["vulnerabilities"]["PYSEC-2099-7"]["aliases"] == ["GHSA-aaaa-bbbb-cccc"]  # two levels
    enriched = enrich_finding(pysec_only, load_snapshot(dumps_snapshot(result)), None)["enrichment"]
    assert enriched["kev"] == {"listed": True, "date_added": "2026-10-01"}
    assert enriched["epss"]["percentile"] == 0.95


@pytest.mark.parametrize(
    "affected",
    [
        [{"package": {"ecosystem": "Maven", "name": "org.example:lib"},
          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
        [{"package": {"purl": "pkg:pypi/example-lib"},
          "ranges": [{"type": "GIT", "repo": "https://example.invalid/r", "events": [{"fixed": "abc123"}]}]}],
    ],
    ids=["fix-on-an-unmapped-package", "fix-only-as-a-commit"],
)  # fmt: skip
def test_a_fix_that_cannot_be_tied_to_a_version_keeps_fix_availability_unknown(affected: list[Any]) -> None:
    record = {**OSV_GHSA, "affected": [*OSV_GHSA["affected"], *affected]}
    result = snapshot(feeds(osv=(200, record)))
    assert "fixed_versions" not in result["vulnerabilities"].get("GHSA-aaaa-bbbb-cccc", {})


# ---------------------------------------------------------------- an OSV outage never lowers risk (#18)

OUTAGE_FINDING = {**SCA, "rule_id": "GHSA-aaaa-bbbb-cccc", "cve": ["CVE-2099-0001"], "aliases": []}


def outage_feeds(osv: tuple[int, Any]) -> FakeTransport:
    """Nourhane's repro: KEV lists only CVE-2099-0002, which only OSV links to the finding."""
    both = "CVE-2099-0001,CVE-2099-0002"
    rows = [
        {"cve": "CVE-2099-0001", "epss": "0.01", "percentile": "0.10", "date": "2026-11-10"},
        {"cve": "CVE-2099-0002", "epss": "0.90", "percentile": "0.99", "date": "2026-11-10"},
    ]
    entries = [{"cveID": "CVE-2099-0002", "dateAdded": "2026-10-01"}, *KEV_ENTRIES[2:]]
    return FakeTransport(
        {
            ("GET", f"{OSV_URL}/GHSA-aaaa-bbbb-cccc", None): osv,
            ("GET", f"{EPSS_URL}?cve={both}", None): (200, {**EPSS, "total": 2, "data": rows}),
            ("GET", f"{EPSS_URL}?cve=CVE-2099-0001", None): (200, {**EPSS, "data": rows[:1]}),
            ("GET", KEV_URL, None): (200, {**KEV, "count": len(entries), "vulnerabilities": entries}),
        }
    )


def scored(transport: FakeTransport) -> tuple[dict[str, Any], list[str]]:
    result, warnings = build_snapshot([OUTAGE_FINDING], transport)
    enriched = enrich_finding(OUTAGE_FINDING, load_snapshot(dumps_snapshot(result)), None)
    return score_finding(enriched, RiskModel.load(ROOT / "policies" / "risk-model.yaml")), warnings


def test_with_osv_the_listed_alias_is_found() -> None:
    record = {**OSV_GHSA, "aliases": ["CVE-2099-0001", "CVE-2099-0002"]}
    finding, warnings = scored(outage_feeds((200, record)))
    assert warnings == []
    assert finding["enrichment"]["kev"] == {"listed": True, "date_added": "2026-10-01"}
    assert finding["risk"]["factors"]["E"] == 1.0


@pytest.mark.parametrize("osv", [(503, b""), (200, TransportError("timed out"))], ids=["503", "timeout"])
def test_without_osv_kev_and_epss_are_left_out_too(osv: tuple[int, Any]) -> None:
    """KEV covered the finding's own CVE, but the listed one was only reachable through OSV: without OSV,
    `listed: false` and EPSS 0.10 would score 46 P2 instead of the worst case."""
    finding, warnings = scored(outage_feeds(osv))
    assert "kev" not in finding.get("enrichment", {}) and "epss" not in finding.get("enrichment", {})
    assert finding["risk"]["factors"]["E"] == 1.0
    assert any(w.startswith("KEV and EPSS left out") and "OSV" in w for w in warnings)


# ---------------------------------------------------------------- a bad --out exits 3, no traceback (#18)


def command_line(command: str, tmp_path: Path, out: Path) -> list[str]:
    findings = tmp_path / "findings.ndjson"
    findings.write_text(json.dumps(FINDING) + "\n", encoding="utf-8")
    extra = ["--offline", str(tmp_path)] if command == "snapshot" else []  # no recordings: an outage
    if command == "score":
        extra = ["--policy-dir", str(ROOT / "policies")]
    return [command, "--findings", str(findings), "--out", str(out), *extra]


@pytest.mark.parametrize("command", ["snapshot", "enrich", "score"])
def test_an_out_path_below_a_file_exits_3(tmp_path: Path, command: str) -> None:
    (tmp_path / "afile").write_text("not a directory", encoding="utf-8")
    result = CliRunner().invoke(app, command_line(command, tmp_path, tmp_path / "afile" / "out.json"))
    assert result.exit_code == 3, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "--out" in result.output


@pytest.mark.parametrize("command", ["snapshot", "enrich", "score"])
def test_a_failed_write_exits_3_and_leaves_nothing(
    tmp_path: Path, command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinelci.cli as cli

    def no_space(*args: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli.os, "replace", no_space)
    out = tmp_path / "out.json"
    result = CliRunner().invoke(app, command_line(command, tmp_path, out))
    assert result.exit_code == 3, result.output
    assert "No space left" in result.output
    assert not out.exists() and not list(tmp_path.glob(".out.json.*"))


@pytest.mark.parametrize("value", [10**400, "1" + "0" * 400], ids=["json-integer", "string"])
def test_an_epss_number_too_large_for_a_float_leaves_only_epss_out(value: Any) -> None:
    """#18 nit: float(10**400) raises OverflowError, which lost the whole snapshot."""
    row = {"cve": "CVE-2099-1001", "epss": value, "percentile": "0.95", "date": "2026-11-10"}
    result, warnings = build_snapshot([FINDING], feeds(epss=(200, {**EPSS, "data": [row]})))
    assert set(result["sources"]) == {"osv", "kev"}
    assert any(w.startswith("EPSS left out") for w in warnings)
