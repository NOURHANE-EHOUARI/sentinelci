"""`sentinel upload --decision` (A3e) against the real API (B1, #79), over HTTP: the decision the gate
made, recorded byte for byte after the run's findings. The real OPA makes the decision, the API is served by
uvicorn on a loopback port, and PostgreSQL is real. Each side is tested on its own elsewhere; this is the
contract between them.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from typer.testing import CliRunner

from sentinel_api.config import Settings
from sentinel_api.main import create_app
from sentinelci.cli import app as cli
from sentinelci.policy.opa import OpaError, OpaRunner

from .conftest import TOKEN

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
REPO, COMMIT = "acme/shop", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
RUN = {"repo": REPO, "commit": COMMIT, "context": "pr"}


@pytest.fixture
def opa() -> Path:
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")


@pytest.fixture
def live_api(database_url: str) -> Iterator[str]:
    """The API served by uvicorn on a free loopback port, as `make up` serves it."""
    settings = Settings(
        database_url=database_url, token_sha256=frozenset({hashlib.sha256(TOKEN.encode()).hexdigest()})
    )
    server = uvicorn.Server(
        uvicorn.Config(create_app(settings), host="127.0.0.1", port=0, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            pytest.fail("the API did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    server.should_exit = True
    thread.join(timeout=10)


def gate(tmp_path: Path, opa: Path) -> tuple[Path, Path, dict[str, Any]]:
    """Findings of one run and the decision the real gate makes on them."""
    lines = []
    for name in ("secret-in-config.json", "sca-enriched-and-scored.json"):
        document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
        lines.append(json.dumps(document | {"run": RUN}, sort_keys=True))
    findings = tmp_path / "findings.ndjson"
    findings.write_text("\n".join(lines) + "\n", encoding="utf-8")
    decision = tmp_path / "decision.json"
    done = CliRunner().invoke(cli, [
        "evaluate", "--findings", str(findings), "--repo", REPO, "--commit", COMMIT, "--context", "pr",
        "--evaluated-at", "2026-11-11T22:00:00Z", "--policy-dir", str(ROOT / "policies"), "--opa", str(opa),
        "--output", str(decision),
    ])  # fmt: skip
    assert done.exit_code in (0, 1), done.output  # PASS/WARN or BLOCK: a decision either way
    return findings, decision, json.loads(decision.read_text(encoding="utf-8"))


def upload(api: str, findings: Path, decision: Path, *extra: str) -> Any:
    return CliRunner().invoke(
        cli,
        ["upload", "--findings", str(findings), "--api-url", api, "--repo", REPO, "--commit", COMMIT,
         "--context", "pr", "--decision", str(decision), *extra],
        env={"SENTINEL_API_TOKEN": TOKEN},
    )  # fmt: skip


def test_the_gates_decision_is_recorded_after_the_runs_findings(
    live_api: str, opa: Path, tmp_path: Path
) -> None:
    findings, decision, document = gate(tmp_path, opa)
    done = upload(live_api, findings, decision)
    assert done.exit_code == 0, done.output
    uploaded = json.loads(done.stdout)
    data = decision.read_bytes()
    assert uploaded["decision_sha256"] == hashlib.sha256(data).hexdigest()
    assert uploaded["decision_already_recorded"] is False
    request = urllib.request.Request(  # noqa: S310 (the loopback http:// URL the fixture made)
        f"{live_api}/api/v1/runs/{uploaded['run_id']}/decision", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as response:
        served = response.read()
    assert served == data, "kept byte for byte"
    assert json.loads(served)["verdict"] == document["verdict"]

    again = upload(live_api, findings, decision, "--resume", uploaded["run_id"])
    assert again.exit_code == 0, again.output
    assert json.loads(again.stdout)["decision_already_recorded"] is True, "the same bytes: recorded already"


def test_a_decision_made_on_other_findings_is_never_sent(live_api: str, opa: Path, tmp_path: Path) -> None:
    findings, decision, _ = gate(tmp_path, opa)
    findings.write_text(findings.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
    done = upload(live_api, findings, decision)
    assert done.exit_code == 4 and "other findings" in done.stderr
    assert TOKEN not in done.output
