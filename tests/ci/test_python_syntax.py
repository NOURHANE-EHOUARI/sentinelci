"""Python syntax that SentinelCI's own SAST can read (A10, self-gate).

Opengrep 1.33.1 cannot parse PEP 695 type parameters. A file that holds one is analysed only in part: the
function and what follows it go unanalysed (`sentinel-sast-not-analysed`, P1 in the self-gate), and the
partial parse can mislead the rules on the lines around it (a constant `text("SET TRANSACTION ...")` was
reported as SQL built from strings). So the tree uses TypeVars, and ruff's UP040, UP046 and UP047 are off.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def python_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8")
    files = [ROOT / name for name in listed.split("\0") if name]
    return [path for path in files if path.parts[len(ROOT.parts)] != "demo-shop" and path.is_file()]


def pep695(source: str, name: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source, filename=name)):
        if isinstance(node, ast.TypeAlias):
            found.append(f"{name}:{node.lineno}: `type` statement")
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and node.type_params:
            found.append(f"{name}:{node.lineno}: type parameters on `{node.name}`")
    return found


def test_no_python_file_uses_type_parameters_opengrep_cannot_parse() -> None:
    files = python_files()
    assert len(files) > 100, "git ls-files found the tree"
    found = [
        hit for path in files for hit in pep695(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
    ]
    assert not found, "use a TypeVar: " + "; ".join(found)


def test_the_check_sees_each_form() -> None:
    assert pep695("def f[T](x: T) -> T:\n    return x\n", "f.py") == ["f.py:1: type parameters on `f`"]
    assert pep695("async def f[T](x: T) -> T:\n    return x\n", "f.py") == ["f.py:1: type parameters on `f`"]
    assert pep695("class C[T]:\n    pass\n", "c.py") == ["c.py:1: type parameters on `C`"]
    assert pep695("type X = int\n", "x.py") == ["x.py:1: `type` statement"]
    assert (
        pep695("from typing import TypeVar\nT = TypeVar('T')\ndef f(x: T) -> T:\n    return x\n", "ok.py")
        == []
    )
