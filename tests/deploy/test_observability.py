"""Prometheus and Grafana as code (SPEC section 10, task A8): what they scrape and show.

Neither runs here (their images cannot be pulled in every environment): the files are checked against the
API's metrics contract, SPEC §10, whose names and labels are read from the SPEC itself.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "compose"
PROMETHEUS = COMPOSE / "prometheus" / "prometheus.yml"
PROVISIONING = COMPOSE / "grafana" / "provisioning"
DASHBOARDS = sorted((PROVISIONING / "dashboards").glob("*.json"))
HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")


def spec_metrics() -> dict[str, set[str]]:
    section = (ROOT / "docs" / "spec" / "SPEC.md").read_text(encoding="utf-8").split("## 10.", 1)[1]
    section = section.split("\n## ", 1)[0]
    listed = dict(re.findall(r"`(sentinel_[a-z_]+)\{([a-z_,]+)\}`", section))
    assert len(listed) == 10, listed  # SPEC section 10 names ten metrics
    return {name: set(labels.split(",")) for name, labels in listed.items()}


def compose() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((COMPOSE / "compose.yaml").read_text(encoding="utf-8"))
    return loaded


def dashboard(path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def queries(document: dict[str, Any]) -> list[str]:
    return [target["expr"] for panel in document["panels"] for target in panel.get("targets", [])]


# ---------------------------------------------------------------- Prometheus


def test_prometheus_scrapes_the_api_metrics_where_compose_serves_them() -> None:
    config = yaml.safe_load(PROMETHEUS.read_text(encoding="utf-8"))
    (job,) = [job for job in config["scrape_configs"] if job["job_name"] == "sentinel-api"]
    assert job["metrics_path"] == "/metrics"
    ((target,),) = [static["targets"] for static in job["static_configs"]]
    host, port = target.split(":")
    api = compose()["services"]["api"]
    assert host == "api" and any(mapping.endswith(f":{port}") for mapping in api["ports"])
    volumes = compose()["services"]["prometheus"]["volumes"]
    assert "./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" in volumes


# ---------------------------------------------------------------- Grafana


def test_dashboards_are_provisioned_read_only_from_the_mounted_directory() -> None:
    (provider,) = yaml.safe_load((PROVISIONING / "dashboards" / "sentinelci.yaml").read_text())["providers"]
    assert provider["type"] == "file" and provider["allowUiUpdates"] is False
    assert (
        "./grafana/provisioning:/etc/grafana/provisioning:ro" in compose()["services"]["grafana"]["volumes"]
    )
    assert provider["options"]["path"] == "/etc/grafana/provisioning/dashboards"
    assert DASHBOARDS, "a provider with no dashboard"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_every_panel_reads_the_provisioned_prometheus(path: Path) -> None:
    (datasource,) = yaml.safe_load((PROVISIONING / "datasources" / "prometheus.yaml").read_text())[
        "datasources"
    ]
    document = dashboard(path)
    assert document["editable"] is False and document["uid"]
    ids = [panel["id"] for panel in document["panels"]]
    assert len(ids) == len(set(ids)), "panel ids are unique"
    for panel in document["panels"]:
        if panel["type"] == "row":
            continue
        assert panel["datasource"] == {"type": "prometheus", "uid": datasource["uid"]}, panel["title"]
        assert panel["targets"] and all(t["datasource"]["uid"] == datasource["uid"] for t in panel["targets"])
        grid = panel["gridPos"]
        assert grid["x"] >= 0 and grid["x"] + grid["w"] <= 24, panel["title"]


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_queries_use_only_spec_names_and_their_labels(path: Path) -> None:
    metrics = spec_metrics()
    for expr in queries(dashboard(path)):
        names = re.findall(r"\b(sentinel_[a-z_]+)", expr)
        assert names, expr
        used: set[str] = set()
        for name in names:
            base = next(
                (name.removesuffix(s) for s in HISTOGRAM_SUFFIXES if name.removesuffix(s) in metrics), name
            )
            assert base in metrics, f"{name} is not a SPEC section 10 metric: {expr}"
            used |= metrics[base] | ({"le"} if name.endswith("_bucket") else set())
        selected = {
            key for block in re.findall(r"\{([^}]*)\}", expr) for key in re.findall(r"(\w+)\s*=~?", block)
        }
        grouped = {
            key.strip() for clause in re.findall(r"\bby \(([^)]*)\)", expr) for key in clause.split(",")
        }
        assert selected | grouped <= used, f"a label SPEC section 10 does not give these metrics: {expr}"


def test_every_spec_metric_has_a_panel() -> None:
    shown = {
        name.removesuffix("_bucket")
        for path in DASHBOARDS
        for expr in queries(dashboard(path))
        for name in re.findall(r"\b(sentinel_[a-z_]+)", expr)
    }
    assert shown == set(spec_metrics())
