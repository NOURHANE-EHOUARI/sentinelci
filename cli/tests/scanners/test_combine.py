"""`sentinel scan combine`: one findings file and one tool status for the gate, or nothing (fail closed)."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sentinelci.cli import app
from sentinelci.contracts.finding import Finding, Location, Run, Tool
from sentinelci.normalize.ndjson import dumps_ndjson
from sentinelci.policy.tool_status import ToolStatus
from sentinelci.scanners.combine import CombineError, combine_findings, combine_tool_statuses

RUN = Run(repo="NOURHANE-EHOUARI/sentinelci", commit="4b825dc642cb6eb9a060e54bf8d69288fbee4904", context="pr")
LOCK = "1" * 64


def finding(seed: str, tool: str, category: str = "IAC", title: str = "x") -> Finding:
    return Finding(
        id=seed * 64,
        tool=Tool(name=tool, version="1.0.0"),
        rule_id="R-1",
        category=category,  # type: ignore[arg-type]
        title=title,
        severity="HIGH",
        run=RUN,
        location=Location(path="infra/main.tf", start_line=1),
    )


def status(
    tool: str, *, ok: bool = True, lock: str = LOCK, platform: str | None = "linux-amd64"
) -> dict[str, Any]:
    entry: dict[str, Any] = {"version": "1.0.0", "status": "ok", "binary_sha256": "2" * 64}
    if not ok:
        entry = {"version": "1.0.0", "status": "failed", "detail": f"{tool} crashed"}
    document: dict[str, Any] = {"schema_version": 1, "lock_sha256": lock, "tools": {tool: entry}}
    if platform:
        document["platform"] = platform
    return document


def write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def test_findings_are_merged_and_sorted(tmp_path: Path) -> None:
    secrets = write(tmp_path / "secrets.ndjson", dumps_ndjson([finding("b", "gitleaks", "SECRET")]))
    iac = write(tmp_path / "iac.ndjson", dumps_ndjson([finding("c", "trivy"), finding("a", "trivy")]))
    empty = write(tmp_path / "failed-scan.ndjson", "")  # what a failed scan leaves behind
    combined = combine_findings([secrets, iac, empty])
    assert sorted(f.id[0] for f in combined) == ["a", "b", "c"]
    assert [json.loads(line)["id"][0] for line in dumps_ndjson(combined).splitlines()] == ["a", "b", "c"]


def test_a_repeated_finding_is_refused(tmp_path: Path) -> None:
    one = write(tmp_path / "one.ndjson", dumps_ndjson([finding("a", "trivy")]))
    with pytest.raises(CombineError, match="appears twice"):
        combine_findings([one, one])


@pytest.mark.parametrize("line", ['{"id": "x"}', "not json", '{"schema_version": "9.9"}'])
def test_a_line_that_is_not_a_finding_is_refused(tmp_path: Path, line: str) -> None:
    bad = write(tmp_path / "bad.ndjson", dumps_ndjson([finding("a", "trivy")]) + line + "\n")
    with pytest.raises(CombineError, match="line 2 is not a Finding v1"):
        combine_findings([bad])


def test_a_line_separator_inside_a_string_does_not_split_a_finding(tmp_path: Path) -> None:
    raw = write(tmp_path / "raw.ndjson", dumps_ndjson([finding("a", "trivy", title="before\u2028after")]))
    (only,) = combine_findings([raw])
    assert only.title == "before\u2028after"


def test_tool_statuses_are_merged(tmp_path: Path) -> None:
    gitleaks = write(tmp_path / "gitleaks.json", json.dumps(status("gitleaks")))
    trivy = write(tmp_path / "trivy.json", json.dumps(status("trivy", ok=False)))
    combined = combine_tool_statuses([trivy, gitleaks])
    ToolStatus.model_validate(combined)
    assert list(combined["tools"]) == ["gitleaks", "trivy"]
    assert combined["tools"]["trivy"]["status"] == "failed"
    assert (combined["lock_sha256"], combined["platform"]) == (LOCK, "linux-amd64")


@pytest.mark.parametrize(
    ("second", "message"),
    [
        (status("trivy", lock="3" * 64), "another lock"),
        (status("gitleaks"), "more than one tool status"),
        (status("trivy", platform="darwin-arm64"), "different platforms"),
        ({"schema_version": 1, "lock_sha256": LOCK, "tools": {}}, "not a tool-status v1"),
    ],
    ids=["other-lock", "same-tool-twice", "other-platform", "invalid"],
)
def test_inconsistent_tool_statuses_are_refused(tmp_path: Path, second: dict[str, Any], message: str) -> None:
    first = write(tmp_path / "gitleaks.json", json.dumps(status("gitleaks")))
    other = write(tmp_path / "other.json", json.dumps(second))
    with pytest.raises(CombineError, match=message):
        combine_tool_statuses([first, other])


def test_a_status_without_platform_combines_with_one_that_has_it(tmp_path: Path) -> None:
    first = write(tmp_path / "gitleaks.json", json.dumps(status("gitleaks")))
    second = write(tmp_path / "trivy.json", json.dumps(status("trivy", ok=False, platform=None)))
    assert combine_tool_statuses([first, second])["platform"] == "linux-amd64"


def _cli(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, ["scan", "combine", *args])
    return result.exit_code, result.output


def test_cli_skips_missing_statuses_so_the_gate_reports_the_scanner(tmp_path: Path) -> None:
    secrets = write(tmp_path / "secrets.ndjson", dumps_ndjson([finding("b", "gitleaks", "SECRET")]))
    gitleaks = write(tmp_path / "gitleaks.json", json.dumps(status("gitleaks")))
    out, status_out = tmp_path / "out" / "findings.ndjson", tmp_path / "out" / "tool-status.json"

    code, output = _cli(
        "--findings", str(secrets),
        "--tool-status", str(gitleaks), "--tool-status", str(tmp_path / "none.json"),
        "--out", str(out), "--tool-status-out", str(status_out),
    )  # fmt: skip

    assert code == 0, output
    assert out.read_text() == secrets.read_text()
    assert list(json.loads(status_out.read_text())["tools"]) == ["gitleaks"]


def test_cli_writes_no_status_when_no_scanner_wrote_one(tmp_path: Path) -> None:
    secrets = write(tmp_path / "secrets.ndjson", "")
    out, status_out = tmp_path / "findings.ndjson", write(tmp_path / "tool-status.json", "stale")
    code, _ = _cli(
        "--findings", str(secrets), "--tool-status", str(tmp_path / "none.json"),
        "--out", str(out), "--tool-status-out", str(status_out),
    )  # fmt: skip
    assert code == 0
    assert out.read_text() == "" and not status_out.exists(), "the gate then reports the tool status missing"


def test_cli_fails_closed_and_leaves_nothing_behind(tmp_path: Path) -> None:
    one = write(tmp_path / "one.ndjson", dumps_ndjson([finding("a", "trivy")]))
    out = write(tmp_path / "findings.ndjson", "stale\n")
    status_out = write(tmp_path / "tool-status.json", "stale")
    code, output = _cli(
        "--findings",
        str(one),
        "--findings",
        str(one),
        "--out",
        str(out),
        "--tool-status-out",
        str(status_out),
    )
    assert code == 3 and "SC-010" in output
    assert not out.exists() and not status_out.exists()
