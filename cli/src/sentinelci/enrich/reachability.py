"""Reachability of a vulnerable package by static import analysis (SPEC section 6.1), for PyPI and npm.

Answers `enrichment.reachability` for SCA package findings from the scanned source tree, without running,
importing or installing anything from it. It answers only `imported`, or nothing:

- `imported`: first-party code imports the package (Python: `import`, `from ... import`, literal
  `import_module` / `__import__`; JavaScript/TypeScript: `import ... from`, `export ... from`, `import '...'`,
  literal `require(...)` and `import(...)`), or the lockfile graph shows that an imported package depends
  on it (its runtime `dependencies`, never optional or peer ones).
- nothing otherwise, which the risk engine counts as the worst case (R = 1.0, above `imported`).

`not_imported` is not claimed: a library can load a package itself (FastAPI templates load jinja2, PyJWT's
RS256 loads cryptography, `next/image` loads sharp), and a lockfile does not record the optional dependencies
that explain it. It needs per-library evidence first (#19 review). `reachable` (the vulnerable function is
called) needs call-graph analysis, a stretch goal (SPEC section 16).

Since `imported` lowers a score a little, a wrong `imported` is the error to avoid; a missed import is safe:
- imports are read from code only (comments removed), never guessed from names in strings or comments;
- a file that cannot be read or parsed is skipped, and the size limits are fixed (no clock), so the same tree
  always gives the same answer;
- CONTAINER findings are not classified (an image may hold another copy than the one the code imports), and
  neither are malicious packages (`MAL-` advisories) nor npm packages with install scripts: their code runs
  whether or not anything imports it;
- with several trees (PR mode: the base and the head), `imported` must hold in every one of them, so a change
  cannot lower the score of its own dependencies by adding an import.
"""

from __future__ import annotations

import ast
import json
import os
import re
import tomllib
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from sentinelci.enrich.import_names import IMPORT_NAMES
from sentinelci.enrich.models import EnrichmentError
from sentinelci.normalize.fingerprint import purl_base

ECOSYSTEMS = ("pypi", "npm")
MAX_FILES = 50_000
MAX_FILE_BYTES = 16 * 1024 * 1024  # large package-lock.json files reach a few MB
MAX_SOURCE_BYTES = 2 * 1024 * 1024  # a larger .py or .js file is generated or minified: skipped
MAX_JS_KEYWORDS = 20_000  # import/export/require/from per file; more is not hand-written code: skipped
MAX_MODULE_DEPTH = 8  # dotted levels of an import compared with module names (the longest listed has 3)
# Installed third-party code and caches: their imports say nothing about first-party code.
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "site-packages", "__pycache__",
                       ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache"})  # fmt: skip
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte"})
_REQUIREMENTS = re.compile(r"(?:[\w.-]*[-_.])?(?:requirements|constraints)(?:[-_.][\w.-]*)?\.(?:txt|in)")
_PEP508_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_PY_DYNAMIC_IMPORT = frozenset({"__import__", "import_module"})
# ast.parse needs memory quadratic in the length of a dotted name (150,000 parts exhaust a runner), and the
# process is killed, not an exception raised: a file with a chain of 64 or more dotted parts is not parsed.
_PY_LONG_DOTTED = re.compile(r"(?:[^\W\d]\w*+\s*+\.\s*+){63}[^\W\d]")

_JS_COMMENT_OR_STRING = re.compile(
    r"""//[^\n]*|/\*.*?\*/|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`""", re.S
)
# The span between the keyword and `from` is bounded, so text full of `import` words stays linear.
_JS_FROM = re.compile(r"""\b(?:import|export)\b[^'"`;]{0,2000}?\bfrom\s*(['"])([^'"\n]+)\1""")
_JS_BARE = re.compile(r"""\bimport\s*(['"])([^'"\n]+)\1""")
_JS_CALL = re.compile(r"""\b(?:require|import)\s*\(\s*(?:(['"])([^'"\n]+)\1|`([^`$\n]+)`)\s*[,)]""")
_JS_KEYWORD = re.compile(r"""\b(?:import|export|require|from)\b""")


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _modules(name: str) -> tuple[str, ...]:
    """Import names of a PyPI distribution: the reviewed table, else its name with _ or . for -."""
    return IMPORT_NAMES.get(name) or (name.replace("-", "_"), name.replace("-", "."))


@dataclass
class _Tree:
    """What one source tree shows; every field is filled by `_analyse`."""

    imports: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    # Packages a lockfile or requirements file lists, and the runtime dependencies of each.
    packages: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    edges: dict[str, dict[str, set[str]]] = field(default_factory=lambda: {e: {} for e in ECOSYSTEMS})
    install_scripts: set[str] = field(default_factory=set)
    _closure: dict[str, set[str]] = field(default_factory=dict)
    _prefixes: set[str] | None = None

    def _imports(self, ecosystem: str, name: str) -> bool:
        if ecosystem == "npm":
            return name in self.imports["npm"]
        if self._prefixes is None:  # `a.b.c` imports a, a.b and a.b.c (a few levels are enough)
            self._prefixes = set()
            for module in self.imports["pypi"]:
                parts = module.split(".", MAX_MODULE_DEPTH)[:MAX_MODULE_DEPTH]
                self._prefixes.update(".".join(parts[: i + 1]) for i in range(len(parts)))
        return any(m in self._prefixes for m in _modules(name))

    def imported(self, ecosystem: str, name: str) -> bool:
        """Imported by first-party code, or a runtime dependency (direct or not) of a package that is."""
        if ecosystem not in self._closure:
            seeds = {p for p in self.packages[ecosystem] if self._imports(ecosystem, p)}
            pending, closure = sorted(seeds), set(seeds)
            while pending:
                for dependency in self.edges[ecosystem].get(pending.pop(), ()):
                    if dependency not in closure:
                        closure.add(dependency)
                        pending.append(dependency)
            self._closure[ecosystem] = closure
        return name in self._closure[ecosystem] or self._imports(ecosystem, name)


class Reachability:
    """Reachability of package findings in one or more source trees (`imported` must hold in all)."""

    def __init__(self, trees: Sequence[_Tree]) -> None:
        self._trees = list(trees)

    @classmethod
    def of_trees(cls, roots: Iterable[Path]) -> Reachability:
        return cls([_analyse(Path(root)) for root in roots])

    def classify(self, finding: Mapping[str, Any]) -> str | None:
        """`imported`, or None: not imported as far as this analysis can tell, or not covered by it."""
        target = _target(finding)
        if target is None or not self._trees:
            return None
        ecosystem, name = target
        if ecosystem == "npm" and any(name in tree.install_scripts for tree in self._trees):
            return None
        return "imported" if all(tree.imported(ecosystem, name) for tree in self._trees) else None


def _target(finding: Mapping[str, Any]) -> tuple[str, str] | None:
    if finding.get("category") != "SCA":
        return None
    ids = [finding.get("rule_id"), *(finding.get("aliases") or [])]
    if any(isinstance(i, str) and i.upper().startswith("MAL-") for i in ids):
        return None  # malicious code runs on install, imported or not
    package = finding.get("package")
    purl = package.get("purl") if isinstance(package, Mapping) else None
    match = re.fullmatch(r"pkg:(pypi|npm)/(.+)", purl_base(purl)) if isinstance(purl, str) else None
    if match is None:
        return None
    ecosystem, name = match.group(1), unquote(match.group(2))
    return ecosystem, normalize_pypi(name) if ecosystem == "pypi" else name


# ---------------------------------------------------------------- walking the tree


def _analyse(root: Path) -> _Tree:
    if not root.is_dir() or root.is_symlink():
        raise EnrichmentError(f"reachability source is not a directory: {root}")
    tree = _Tree()
    requirement_files: dict[Path, _Requirements] = {}
    for path in _files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue  # unread: no import is claimed from it
        _read_file(path, data, root, tree, requirement_files)
    _apply_requirements(root, tree, requirement_files)
    return tree


def _files(root: Path) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(n for n in dirnames if n not in SKIP_DIRS)  # symlinked dirs: never walked
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink():
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield path


def _read_file(
    path: Path, data: bytes, root: Path, tree: _Tree, requirements: dict[Path, _Requirements]
) -> None:
    name, rel = path.name, path.relative_to(root).as_posix()
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            _npm_lock(json.loads(data), tree)
        elif name == "uv.lock":
            _python_lock(tomllib.loads(data.decode("utf-8")), tree, uv=True)
        elif name == "poetry.lock":
            _python_lock(tomllib.loads(data.decode("utf-8")), tree, uv=False)
        elif _REQUIREMENTS.fullmatch(name) or (
            path.parent.name == "requirements" and path.suffix in (".txt", ".in")
        ):
            requirements[path] = _parse_requirements(data.decode("utf-8", errors="replace"))
        elif len(data) > MAX_SOURCE_BYTES:
            return
        elif path.suffix == ".py":
            _python(data, rel, tree)
        elif path.suffix in JS_SUFFIXES:
            _javascript(data.decode("utf-8", errors="replace"), tree)
    except (ValueError, UnicodeDecodeError, AttributeError, TypeError, KeyError, RecursionError):
        return  # unreadable or nested too deep: skipped, so nothing is claimed from it


# ---------------------------------------------------------------- Python


def _callee(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _python(data: bytes, rel: str, tree: _Tree) -> None:
    if _PY_LONG_DOTTED.search(data.decode("utf-8", errors="replace")):
        return
    try:
        module = ast.parse(data, filename=rel)
    except (SyntaxError, ValueError, MemoryError):  # RecursionError: caught per file
        return
    imports = tree.imports["pypi"]
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.add(node.module)
            imports.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call) and _callee(node.func) in _PY_DYNAMIC_IMPORT:
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):  # `.x` never matches a module
                imports.add(arg.value)


# ---------------------------------------------------------------- JavaScript / TypeScript


def _npm_package(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#", "~", "node:", "http:", "https:", "data:", "file:")):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 and parts[1] else None
    return parts[0] or None


def _javascript(text: str, tree: _Tree) -> None:
    if len(_JS_KEYWORD.findall(text)) > MAX_JS_KEYWORDS:
        return
    # Comments removed, strings kept: an import named only in a comment is not an import.
    code = _JS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(0)[0] in "'\"`" else " ", text)
    specifiers = [m.group(2) for m in _JS_FROM.finditer(code)]
    specifiers += [m.group(2) for m in _JS_BARE.finditer(code)]
    specifiers += [m.group(2) or m.group(3) for m in _JS_CALL.finditer(code)]
    tree.imports["npm"].update(p for p in map(_npm_package, specifiers) if p)


# ---------------------------------------------------------------- lockfiles: the dependency graph


def _npm_lock(lock: Any, tree: _Tree) -> None:
    packages = lock.get("packages") if isinstance(lock, dict) else None
    for key, entry in (packages if isinstance(packages, dict) else {}).items():  # v2/v3; v1 has none
        if "node_modules/" not in key or not isinstance(entry, dict) or entry.get("link"):
            continue  # the project itself and its workspaces
        name = key.rsplit("node_modules/", 1)[1]
        tree.packages["npm"].add(name)
        tree.edges["npm"].setdefault(name, set()).update(map(str, entry.get("dependencies") or {}))
        if entry.get("hasInstallScript"):
            tree.install_scripts.add(name)


def _python_lock(lock: dict[str, Any], tree: _Tree, *, uv: bool) -> None:
    for package in lock.get("package", []) or []:
        source = package.get("source") or {}
        if uv and ("editable" in source or "virtual" in source):
            continue  # first-party: its imports are read from its source
        name = normalize_pypi(str(package["name"]))
        tree.packages["pypi"].add(name)
        dependencies = package.get("dependencies") or ([] if uv else {})
        names = [d["name"] for d in dependencies] if uv else list(dependencies)
        tree.edges["pypi"].setdefault(name, set()).update(normalize_pypi(str(d)) for d in names)


@dataclass
class _Requirements:
    names: set[str] = field(default_factory=set)
    via: dict[str, set[str]] = field(default_factory=dict)  # package -> the packages that require it
    includes: list[str] = field(default_factory=list)


_INCLUDE = re.compile(r"(?:-r|--requirement)(?:\s*=\s*|\s+|(?=[^\s=-]))(\S+)")


def _parse_requirements(text: str) -> _Requirements:
    """Names, `-r` includes, and pip-compile `# via` annotations (which package requires which)."""
    out = _Requirements()
    current: str | None = None
    in_via = False
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if current is None:
                continue
            if body == "via" or body.startswith("via "):
                in_via, entries = True, [body[3:].strip()] if body != "via" else []
            elif in_via:
                entries = [body]
            else:
                continue
            for entry in entries:
                if match := _PEP508_NAME.match(
                    entry
                ):  # never `-r file`: a name starts with a letter or digit
                    out.via.setdefault(current, set()).add(normalize_pypi(match.group(1)))
            continue
        in_via = False
        if include := _INCLUDE.fullmatch(line):
            out.includes.append(include.group(1))
            continue
        if line.startswith("-"):
            continue
        if match := _PEP508_NAME.match(line):
            current = normalize_pypi(match.group(1))
            out.names.add(current)
    return out


def _apply_requirements(root: Path, tree: _Tree, files: dict[Path, _Requirements]) -> None:
    """A pip-compile annotated requirements file is a lock: `# via X` is an edge from X to the package."""
    pending = [p for p in files if p.name == "requirements.txt"]
    seen: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        for include in files[path].includes if path in files else []:
            target = (path.parent / include).resolve()  # symlinks resolved: the target must be in the tree
            if not (target.is_relative_to(root.resolve()) and target.is_file()):
                continue
            if target not in files and target.stat().st_size <= MAX_FILE_BYTES:
                files[target] = _parse_requirements(target.read_text(encoding="utf-8", errors="replace"))
            pending.append(target)
    for parsed in files.values():
        tree.packages["pypi"].update(parsed.names)
        for package, requirers in parsed.via.items():
            for requirer in requirers:
                tree.edges["pypi"].setdefault(requirer, set()).add(package)
