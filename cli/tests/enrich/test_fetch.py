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
from sentinelci.enrich.fetch import EPSS_URL, KEV_URL, OSV_URL, build_snapshot, dumps_snapshot
from sentinelci.enrich.transport import (
    HttpTransport,
    RecordingTransport,
    ReplayTransport,
    TransportError,
)

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
KEV = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.09",
    "dateReleased": "2026-11-09T19:00:04.8077Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2099-1001", "dateAdded": "2026-10-01"},
        {"cveID": "CVE-2099-9999", "dateAdded": "2026-10-02"},
    ],
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

    transport = AnswersEveryEpssBatch({})
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
