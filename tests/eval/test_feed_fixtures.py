"""The offline feed fixtures (eval/feeds/) stay consistent, complete and small, with no network."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding
from sentinelci.enrich.transport import ReplayTransport, _key
from sentinelci.normalize.ndjson import dumps_ndjson

FEEDS = Path(__file__).resolve().parents[2] / "eval" / "feeds"
MAX_FIXTURE_BYTES = 1024 * 1024


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("feed_fixtures", FEEDS / "refresh.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["feed_fixtures"] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


FIXTURES = _load()


def test_the_offline_replay_rebuilds_the_committed_snapshot_byte_for_byte() -> None:
    assert FIXTURES.replay() == (FEEDS / "snapshot.json").read_bytes()


def test_the_fixtures_still_cover_what_they_exist_for() -> None:
    assert FIXTURES.check_coverage((FEEDS / "snapshot.json").read_bytes()) == []


def test_the_committed_findings_are_the_cases() -> None:
    expected = dumps_ndjson(Finding.model_validate(f) for f in FIXTURES.findings())
    assert (FEEDS / "findings.ndjson").read_text(encoding="utf-8") == expected


def test_every_recording_is_used_and_none_is_missing() -> None:
    used: set[Path] = set()
    original = ReplayTransport.request

    def recorded(
        self: ReplayTransport, method: str, url: str, body: bytes | None = None
    ) -> tuple[int, bytes]:
        used.add(self.directory / f"{_key(method, url, body)}.json")  # the exact file this request reads
        return original(self, method, url, body)

    ReplayTransport.request = recorded  # type: ignore[method-assign]
    try:
        FIXTURES.replay()
    finally:
        ReplayTransport.request = original  # type: ignore[method-assign]
    assert used == set((FEEDS / "recordings").glob("*.json")), "a stale recording was left behind"


def test_the_fixtures_stay_small() -> None:
    size = sum(p.stat().st_size for p in FEEDS.rglob("*") if p.is_file())
    assert size < MAX_FIXTURE_BYTES, f"{size} bytes: keep recordings compressed and the finding set small"


def test_cli_enriches_the_fixture_findings_offline(tmp_path: Path) -> None:
    out = tmp_path / "enriched.ndjson"
    args = [
        "enrich",
        "--findings",
        str(FEEDS / "findings.ndjson"),
        "--snapshot",
        str(FEEDS / "snapshot.json"),
    ]
    result = CliRunner().invoke(app, [*args, "--out", str(out)])
    assert result.exit_code == 0, result.output
    by_rule = {
        f["rule_id"]: f.get("enrichment", {}) for f in map(json.loads, out.read_text("utf-8").splitlines())
    }
    assert by_rule["GHSA-jfh8-c2jp-5v3q"]["kev"]["listed"] is True
    assert by_rule["GHSA-jfh8-c2jp-5v3q"]["cvss"]["score"] == 10.0
    assert by_rule["GHSA-8q59-q68h-6hv4"]["kev"] == {"listed": False}
    assert by_rule["GHSA-j8r2-6x86-q33q"]["fix_available"] is True


class _Down:
    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        return 503, b""


def test_a_failed_refresh_changes_nothing(tmp_path: Path) -> None:
    """#21 nit: the recordings are staged and swapped in only when every feed answered."""
    (tmp_path / "recordings").mkdir()
    (tmp_path / "recordings" / "kept.json").write_text("{}", encoding="utf-8")
    try:
        FIXTURES.refresh(_Down(), here=tmp_path)
    except SystemExit as exc:
        assert "fixtures not refreshed" in str(exc)
    else:
        raise AssertionError("a failed refresh must stop")
    assert sorted(p.name for p in tmp_path.rglob("*")) == ["kept.json", "recordings"]


def test_a_successful_refresh_replaces_the_whole_set(tmp_path: Path) -> None:
    (tmp_path / "recordings").mkdir()
    (tmp_path / "recordings" / "stale.json").write_text("{}", encoding="utf-8")
    FIXTURES.refresh(ReplayTransport(FEEDS / "recordings"), here=tmp_path)
    assert (tmp_path / "snapshot.json").read_bytes() == (FEEDS / "snapshot.json").read_bytes()
    assert (tmp_path / "findings.ndjson").read_bytes() == (FEEDS / "findings.ndjson").read_bytes()
    recorded = sorted(p.name for p in (tmp_path / "recordings").iterdir())
    assert recorded == sorted(p.name for p in (FEEDS / "recordings").iterdir())
    assert not (tmp_path / "recordings.new").exists() and not (tmp_path / "recordings.old").exists()
