"""SentinelCI's own clients against the real API, over HTTP: `sentinel upload` (M1) records a run and its
findings, then `sentinel-ai correlate` (A7) reads them back and stores the run's correlation (B1's endpoint,
#73). Each side is tested on its own elsewhere; this is the contract between them, with a real server on the
loopback and a real PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from typer.testing import CliRunner

from sentinel_ai.cli import app as ai_app
from sentinel_api.config import Settings
from sentinel_api.main import create_app
from sentinelci.report.upload import Platform, RunInfo, upload

from .conftest import TOKEN

VALID = Path(__file__).resolve().parents[3] / "schemas" / "fixtures" / "finding" / "valid"
RUN = RunInfo(repo="acme/shop", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")


def findings() -> bytes:
    lines = []
    for name in ("secret-in-config.json", "sca-enriched-and-scored.json", "container-os-package.json"):
        document: dict[str, Any] = json.loads((VALID / name).read_text(encoding="utf-8"))
        lines.append(json.dumps(document | {"run": RUN.body()}, sort_keys=True))
    return ("\n".join(lines) + "\n").encode()


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
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def correlate(api: str, run_id: str) -> Any:
    return CliRunner().invoke(
        ai_app, ["correlate", "--run", run_id, "--api-url", api], env={"SENTINEL_API_TOKEN": TOKEN}
    )


def test_upload_then_correlate_against_the_real_api(live_api: str) -> None:
    platform = Platform(base_url=live_api, token=TOKEN)
    data = findings()
    uploaded = upload(data, RUN, platform)
    assert (uploaded.finding_count, uploaded.findings_sha256) == (3, hashlib.sha256(data).hexdigest())

    done = correlate(live_api, uploaded.run_id)
    assert done.exit_code == 0, done.output
    stored = json.loads(done.stdout)
    assert stored["run_id"] == uploaded.run_id and stored["already_recorded"] is False
    served = platform.get_bytes(f"/api/v1/runs/{uploaded.run_id}/correlations", limit=1 << 20)
    assert hashlib.sha256(served).hexdigest() == stored["sha256"], "kept byte for byte, named by its sha256"
    document = json.loads(served)
    assert document["findings_sha256"] == uploaded.findings_sha256
    assert sorted(i for g in document["groups"] for i in g["finding_ids"]) == sorted(
        json.loads(line)["id"] for line in data.decode().splitlines()
    ), "each of the run's findings in exactly one group"

    again = correlate(live_api, uploaded.run_id)
    assert again.exit_code == 0, again.output
    assert json.loads(again.stdout) | {"already_recorded": False} == stored, (
        "the same bytes: the same version"
    )
    assert json.loads(again.stdout)["already_recorded"] is True


def test_a_run_without_findings_is_not_correlated(live_api: str) -> None:
    platform = Platform(base_url=live_api, token=TOKEN)
    run_id, _ = platform.create_run(RUN)
    done = correlate(live_api, run_id)
    assert done.exit_code == 4 and "the correlation was not stored" in done.stderr
    assert TOKEN not in done.output


def test_a_wrong_token_stores_nothing_and_is_never_printed(live_api: str) -> None:
    platform = Platform(base_url=live_api, token=TOKEN)
    uploaded = upload(findings(), RUN, platform)
    wrong = "wrong-token-" + "y" * 32
    done = CliRunner().invoke(
        ai_app, ["correlate", "--run", uploaded.run_id, "--api-url", live_api],
        env={"SENTINEL_API_TOKEN": wrong},
    )  # fmt: skip
    assert done.exit_code == 4 and wrong not in done.output
