"""Render the demo-shop chart as Helm would, without Helm: the tests' helper (not a test module).

Helm merges the chart's values.yaml with the value files given, validates the result against
values.schema.json, then renders the templates with Go's text/template. Here the merge and the schema are
done in Python (jsonschema, draft-07 as in Helm), and the templates are rendered by Go's own text/template
(helm_render.go, standard library only, `go run`), with the one Helm function the chart uses.

The cluster renders the chart with Argo CD's Helm; this is what the tests can run without a cluster.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "demo-shop"
HARNESS = Path(__file__).with_name("helm_render.go")
GO = shutil.which("go")


class RenderError(Exception):
    """Helm would not render the chart with these values."""


def merged(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Helm's coalescing of value files: maps merge key by key, anything else is replaced."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merged(result[key], value)
        else:
            result[key] = value
    return result


def values(*overrides: dict[str, Any], chart: Path = CHART) -> dict[str, Any]:
    result = yaml.safe_load((chart / "values.yaml").read_text(encoding="utf-8"))
    for override in overrides:
        result = merged(result, override)
    return result  # type: ignore[no-any-return]


def schema_errors(data: dict[str, Any], chart: Path = CHART) -> list[str]:
    schema = json.loads((chart / "values.schema.json").read_text(encoding="utf-8"))
    return sorted(error.message for error in Draft7Validator(schema).iter_errors(data))


def render(
    *overrides: dict[str, Any], chart: Path = CHART, namespace: str = "demo-shop"
) -> list[dict[str, Any]]:
    """The manifests `helm template` would print, parsed; RenderError if Helm would refuse the values."""
    data = values(*overrides, chart=chart)
    errors = schema_errors(data, chart)
    if errors:
        raise RenderError(f"values.schema.json: {'; '.join(errors)}")
    meta = yaml.safe_load((chart / "Chart.yaml").read_text(encoding="utf-8"))
    document = {
        "values": data,
        "release": {"Name": meta["name"], "Namespace": namespace, "Service": "Helm"},
        "chart": {"Name": meta["name"], "Version": meta["version"]},
    }
    assert GO is not None, "the chart tests need Go (they skip without it)"
    home = os.environ.get("HOME") or tempfile.gettempdir()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "GOCACHE": os.environ.get("GOCACHE", str(Path(home) / ".cache" / "go-build")),
        "GOTOOLCHAIN": "local",  # never download a toolchain
        "GOPROXY": "off",  # nor a module: the harness is standard library only
        "GOFLAGS": "-mod=mod",
        "GO111MODULE": "on",
    }
    done = subprocess.run(
        [GO, "run", str(HARNESS), str(chart)],
        input=json.dumps(document), capture_output=True, text=True, timeout=300, check=False, env=env,
        cwd=ROOT,
    )  # fmt: skip
    if done.returncode != 0:
        raise RenderError(done.stderr.strip())
    return [doc for doc in yaml.safe_load_all(done.stdout) if doc]
