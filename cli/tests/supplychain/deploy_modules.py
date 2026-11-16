"""deploy/kind's scripts and tests/deploy's chart renderer, for the supply-chain tests that run them with the
real tools. They are scripts, not packages, so they are loaded by path; each is loaded once per session, so
`cluster.ClusterError` is one class wherever it is caught."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # demo.py imports cluster by name; dataclasses resolve annotations through it
    spec.loader.exec_module(module)
    return module


cluster = _load("cluster", ROOT / "deploy" / "kind" / "cluster.py")
demo = _load("demo", ROOT / "deploy" / "kind" / "demo.py")
chart_render = _load("chart_render", ROOT / "tests" / "deploy" / "chart_render.py")
