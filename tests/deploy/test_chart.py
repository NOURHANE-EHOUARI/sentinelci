"""The demo-shop Helm chart (deploy/helm/demo-shop, task A5b): what it renders, and what it refuses.

Rendered as Helm renders it (tests/deploy/chart_render.py: the values merged and checked against
values.schema.json, the templates run by Go's text/template), so it needs Go. That its Deployment is admitted
for a release and denied for an unsigned image is tested with the real Kyverno CLI in
cli/tests/supplychain/test_admission.py, and on kind in test_kind_demo.py.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DIGEST = "sha256:" + "0123456789abcdef" * 4


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("chart_render", HERE / "chart_render.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


chart = _load()
pytestmark = pytest.mark.skipif(
    chart.GO is None, reason="renders the chart with Go's text/template: needs Go"
)


def release(**changes: Any) -> dict[str, Any]:
    return chart.merged({"image": {"digest": DIGEST}}, changes)


@pytest.fixture(scope="module")
def manifests() -> dict[str, dict[str, Any]]:
    return {document["kind"]: document for document in chart.render(release())}


def test_it_renders_the_three_resources_argo_cd_may_create(manifests: dict[str, dict[str, Any]]) -> None:
    assert sorted(manifests) == ["Deployment", "Service", "ServiceAccount"]
    project = yaml.safe_load((ROOT / "deploy" / "argocd" / "project.yaml").read_text("utf-8"))
    allowed = {(entry["group"], entry["kind"]) for entry in project["spec"]["namespaceResourceWhitelist"]}
    rendered = {(d["apiVersion"].rpartition("/")[0], d["kind"]) for d in manifests.values()}
    assert rendered == allowed, "the AppProject allows exactly what the chart renders"
    assert all("namespace" not in d["metadata"] for d in manifests.values()), "Argo CD sets the namespace"


def test_the_image_is_the_release_by_digest_only(manifests: dict[str, dict[str, Any]]) -> None:
    (container,) = manifests["Deployment"]["spec"]["template"]["spec"]["containers"]
    assert container["image"] == f"kind-registry:5000/demo-shop/shop-api@{DIGEST}"
    assert container["image"].startswith("kind-registry:5000/demo-shop/"), "the admission policy's prefix"


def test_the_pod_meets_the_restricted_pod_security_profile(manifests: dict[str, dict[str, Any]]) -> None:
    """The fields Pod Security "restricted" checks, which the demo-shop namespace enforces."""
    spec = manifests["Deployment"]["spec"]["template"]["spec"]
    pod = spec["securityContext"]
    assert pod["runAsNonRoot"] is True and pod["runAsUser"] == 10001 and pod["runAsGroup"] == 10001
    assert pod["seccompProfile"] == {"type": "RuntimeDefault"}
    assert not {"hostNetwork", "hostPID", "hostIPC"} & set(spec)
    assert all(set(volume) <= {"name", "emptyDir"} for volume in spec["volumes"]), (
        "no hostPath or other volume"
    )
    for container in spec["containers"]:
        security = container["securityContext"]
        assert security == {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }  # fmt: skip
        assert "hostPort" not in json.dumps(container["ports"])
    assert spec["automountServiceAccountToken"] is False
    assert manifests["ServiceAccount"]["automountServiceAccountToken"] is False


def test_the_release_image_contract(manifests: dict[str, dict[str, Any]]) -> None:
    """ADR-0011 decision 6: port 8080, health at GET /healthz, writes only to /tmp."""
    spec = manifests["Deployment"]["spec"]["template"]["spec"]
    (container,) = spec["containers"]
    assert container["ports"] == [{"name": "http", "containerPort": 8080}]
    for probe in ("readinessProbe", "livenessProbe"):
        assert container[probe]["httpGet"] == {"path": "/healthz", "port": "http"}
    assert container["volumeMounts"] == [{"name": "tmp", "mountPath": "/tmp"}]  # noqa: S108 (the Pod's)
    assert spec["volumes"] == [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}]
    assert "memory" in container["resources"]["limits"]
    service = manifests["Service"]["spec"]
    assert service["type"] == "ClusterIP" and service["ports"] == [
        {"name": "http", "port": 80, "targetPort": "http"}
    ]
    assert service["selector"] == manifests["Deployment"]["spec"]["selector"]["matchLabels"]


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({}, "does not match"),
        ({"image": {"digest": "latest"}}, "does not match"),
        ({"image": {"digest": "sha256:" + "A" * 64}}, "does not match"),
        ({"image": {"digest": "sha512:" + "a" * 128}}, "does not match"),
        ({"image": {"repository": "kind-registry:5000/demo-shop/shop-api:v1"}}, "does not match"),
        ({"replicas": 0}, "less than the minimum"),
        ({"port": 80}, "less than the minimum"),
        ({"debug": True}, "Additional properties"),
    ],
    ids=[
        "no-digest",
        "a-tag",
        "upper-case",
        "not-sha256",
        "repository-with-tag",
        "no-replica",
        "low-port",
        "unknown",
    ],
)
def test_values_helm_refuses(values: dict[str, Any], message: str) -> None:
    with pytest.raises(chart.RenderError, match=message):
        chart.render(chart.merged(release(), values) if values else {})


def test_the_template_refuses_an_empty_digest_even_past_the_schema(tmp_path: Path) -> None:
    """Two guards: the schema in Helm, and the template's `required` wherever the chart is rendered without
    the schema."""
    copy = tmp_path / "demo-shop"
    copy.mkdir()
    for path in chart.CHART.rglob("*"):
        if path.is_file() and path.name != "values.schema.json":
            target = copy / path.relative_to(chart.CHART)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    (copy / "values.schema.json").write_text("{}", encoding="utf-8")
    with pytest.raises(chart.RenderError, match=r"image\.digest is set by make demo-release"):
        chart.render(chart=copy)


def test_a_template_with_a_function_the_render_does_not_prove_fails(tmp_path: Path) -> None:
    copy = tmp_path / "demo-shop"
    (copy / "templates").mkdir(parents=True)
    for name in ("Chart.yaml", "values.yaml", "values.schema.json"):
        (copy / name).write_bytes((chart.CHART / name).read_bytes())
    (copy / "templates" / "x.yaml").write_text("a: {{ .Values.port | toYaml }}\n", encoding="utf-8")
    with pytest.raises(chart.RenderError, match='function "toYaml" not defined'):
        chart.render(release(), chart=copy)
