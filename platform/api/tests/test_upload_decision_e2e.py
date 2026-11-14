"""`sentinel upload --decision` end to end: the real gate (`sentinel score`, then `sentinel evaluate` with
OPA), the CLI's own HTTP client, and the real API on the loopback with a real PostgreSQL.

The decision is accepted only with the findings it was made on: the scored ones the gate evaluated. With the
scan's findings the CLI refuses before anything is sent, so the platform is never left with a run whose
decision it would refuse.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
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

ROOT = Path(__file__).resolve().parents[3]
VALID = ROOT / "schemas" / "fixtures" / "finding" / "valid"
TOKEN = "e2e-token-" + "y" * 32  # a fake, for this test's platform
RUN = {"repo": "acme/shop", "commit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "context": "pr",
       "ref": "refs/pull/12/merge", "run_id": "42/1"}  # fmt: skip


@pytest.fixture
def opa() -> Path:
    try:
        return OpaRunner.locate().binary
    except OpaError:
        if os.environ.get("SENTINEL_REQUIRE_OPA"):
            pytest.fail("SENTINEL_REQUIRE_OPA is set but no OPA binary was found")
        pytest.skip("OPA binary not installed (set SENTINEL_OPA or put opa on PATH)")


@pytest.fixture
def platform(database_url: str) -> Iterator[str]:
    """The API served by uvicorn on 127.0.0.1, in this process."""
    settings = Settings(
        database_url=database_url, token_sha256=frozenset({hashlib.sha256(TOKEN.encode()).hexdigest()})
    )
    server = uvicorn.Server(uvicorn.Config(create_app(settings), log_level="warning"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started:
        assert time.monotonic() < deadline and thread.is_alive(), "the API did not start"
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(30)
        sock.close()


def scan_findings(path: Path) -> bytes:
    """Two findings as a scan writes them (no risk score yet)."""
    lines = []
    for name in ("secret-in-config.json", "container-os-package.json"):
        finding: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
        finding.pop("risk", None)
        lines.append(json.dumps(finding | {"run": RUN}, sort_keys=True))
    data = "".join(line + "\n" for line in lines).encode("utf-8")
    path.write_bytes(data)
    return data


def get(url: str) -> tuple[int, dict[str, str], bytes]:
    """A plain read of the API, never through a proxy (the API is on the loopback)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response:  # http://127.0.0.1 only
        return response.status, dict(response.headers), response.read()


def sentinel(*args: str) -> Any:
    return CliRunner(env={"SENTINEL_API_TOKEN": TOKEN}).invoke(cli, list(args))


def test_the_gates_decision_is_recorded_with_the_scored_findings_and_refused_with_the_scans(
    tmp_path: Path, opa: Path, platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # no default waivers or sentinel.yaml
    scanned, scored, decision = (
        tmp_path / "scan.ndjson",
        tmp_path / "scored.ndjson",
        tmp_path / "decision.json",
    )
    scan_findings(scanned)
    policies = str(ROOT / "policies")
    result = sentinel("score", "--findings", str(scanned), "--policy-dir", policies, "--out", str(scored))
    assert result.exit_code == 0, result.output
    assert scored.read_bytes() != scanned.read_bytes(), "scoring adds each finding's risk"
    result = sentinel(
        "evaluate", "--findings", str(scored), "--repo", RUN["repo"], "--commit", RUN["commit"],
        "--context", RUN["context"], "--ref", RUN["ref"], "--evaluated-at", "2026-11-11T10:00:00Z",
        "--tool-version", "gitleaks=8.30.1", "--policy-dir", policies, "--opa", str(opa),
        "--output", str(decision),
    )  # fmt: skip
    assert result.exit_code in (0, 1), result.output  # PASS/WARN or BLOCK: a decision either way
    verdict = json.loads(decision.read_text(encoding="utf-8"))["verdict"]
    run_args = ["--api-url", platform, "--repo", RUN["repo"], "--commit", RUN["commit"],
                "--context", RUN["context"], "--ref", RUN["ref"], "--run-id", RUN["run_id"]]  # fmt: skip

    # The scan's findings: not the ones the decision was made on. Refused locally: no run is created.
    refused = sentinel("upload", "--findings", str(scanned), "--decision", str(decision), *run_args)
    assert refused.exit_code == 4
    assert "made on other findings than --findings" in refused.output
    assert json.loads(get(f"{platform}/api/v1/runs")[2])["total"] == 0

    # The scored findings: the run, its findings, then its decision, byte for byte.
    uploaded = sentinel("upload", "--findings", str(scored), "--decision", str(decision), *run_args)
    assert uploaded.exit_code == 0, uploaded.output
    printed = json.loads(uploaded.output)
    assert printed["verdict"] == verdict and not printed["decision_already_recorded"]
    status, headers, served = get(f"{platform}/api/v1/runs/{printed['run_id']}/decision")
    assert status == 200 and served == decision.read_bytes()
    assert headers["etag"] == f'"{hashlib.sha256(served).hexdigest()}"'
    assert json.loads(get(f"{platform}/api/v1/runs/{printed['run_id']}")[2])["verdict"] == verdict

    # The same step again (a re-run of the upload step of the same CI run): recorded already, not twice.
    again = sentinel("upload", "--findings", str(scored), "--decision", str(decision), *run_args)
    assert again.exit_code == 0, again.output
    printed_again = json.loads(again.output)
    assert printed_again["run_id"] == printed["run_id"]
    assert printed_again["already_recorded"] and printed_again["decision_already_recorded"]

    # --resume confirms it too, without creating a run (what a local run, with no --run-id, is finished with).
    resumed = sentinel("upload", "--findings", str(scored), "--decision", str(decision), *run_args,
                       "--resume", printed["run_id"])  # fmt: skip
    assert resumed.exit_code == 0, resumed.output
    assert json.loads(resumed.output)["decision_already_recorded"] is True
    assert json.loads(get(f"{platform}/api/v1/runs")[2])["total"] == 1
    assert TOKEN not in uploaded.output + again.output + refused.output + resumed.output
