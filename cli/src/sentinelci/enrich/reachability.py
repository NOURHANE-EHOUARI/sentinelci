"""Reachability of a vulnerable package by static import analysis (SPEC section 6.1), for PyPI and npm.

Answers `enrichment.reachability` for package findings from the scanned source tree, without running,
importing or installing anything from it:

- `imported`: first-party code imports the package (Python: `import`, `from ... import`, literal
  `import_module` / `__import__`; JavaScript/TypeScript: `import ... from`, `export ... from`, `import '...'`,
  literal `require(...)` and `import(...)`).
- `not_imported`: only with every proof below. A wrong `not_imported` halves a score, so it is never guessed:
  1. the package is a direct runtime dependency (`dependencies` of a package.json; `requirements.txt` or
     pyproject.toml dependencies);
  2. a lockfile proves that no other locked package depends on it (package-lock.json v2/v3, uv.lock,
     poetry.lock, or a pip-compile `# via` annotated requirements.txt);
  3. its import name is certain (npm: the package name; PyPI: a reviewed entry in enrich/import_names.py);
  4. it is not a package used without an import (servers, drivers loaded from a URL, optional accelerators);
  5. its name, import names and command names appear nowhere in the tree except in dependency declarations
     (not in a Dockerfile, a script, a config file, a string or a comment);
  6. the analysis of that language is complete: every source file parsed, no import of a computed name, no
     exec/eval, createRequire or entry-point plugins, no symlink, and no file or size limit reached.
- `unknown`: any other PyPI or npm package. Other ecosystems (Go, Maven, OS packages) are not analysed and
  stay absent, which the risk engine counts as the worst case.
- `reachable` (the vulnerable function is called) needs call-graph analysis, a stretch goal (SPEC section 16).

Several trees can be given (PR mode: the base and the head); the most reachable answer wins, so a change can
never lower the reachability of its own dependencies.
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

from sentinelci.enrich.import_names import IMPORT_NAMES, NPM_USED_WITHOUT_IMPORT, USED_WITHOUT_IMPORT
from sentinelci.enrich.models import EnrichmentError
from sentinelci.normalize.fingerprint import purl_base

ORDER = ("not_imported", "unknown", "imported", "reachable")  # least to most reachable
PACKAGE_CATEGORIES = frozenset({"SCA", "CONTAINER"})
ECOSYSTEMS = ("pypi", "npm")
MAX_FILES = 50_000
MAX_FILE_BYTES = 16 * 1024 * 1024  # large package-lock.json files reach a few MB
# Installed third-party code and caches: their imports are covered by the lockfile graph.
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "site-packages", "__pycache__",
                       ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache"})  # fmt: skip
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte"})
LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock",
                       "poetry.lock", "Pipfile.lock"})  # fmt: skip
_REQUIREMENTS = re.compile(r"(?:[\w.-]*[-_.])?(?:requirements|constraints)(?:[-_.][\w.-]*)?\.(?:txt|in)")
_PEP508_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_TOKEN = re.compile(r"@?[A-Za-z0-9_][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.\-]*)?")

_PY_DYNAMIC_IMPORT = frozenset({"__import__", "import_module", "run_module"})
_PY_PLUGINS = frozenset({"entry_points", "iter_entry_points", "load_entry_point"})
_PY_EXEC = frozenset({"exec", "eval"})

_JS_COMMENT_OR_STRING = re.compile(
    r"""//[^\n]*|/\*.*?\*/|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`""", re.S
)
_JS_FROM = re.compile(r"""\b(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"\n]+)\1""")
_JS_BARE = re.compile(r"""\bimport\s*(['"])([^'"\n]+)\1""")
_JS_CALL = re.compile(
    r"""\b(require(?:\s*\.\s*resolve)?|import)\s*\(\s*(?:(['"])([^'"\n]+)\2|`([^`$\n]+)`)\s*[,)]"""
)
_JS_ANY_CALL = re.compile(r"""\b(?:require|import)\s*\(""")
_JS_DYNAMIC = re.compile(r"""\bcreateRequire\b|\bmodule\s*\.\s*require\b|\beval\s*\(|\bnew\s+Function\s*\(""")

# Sections of manifests that only declare dependencies: a name there is not a use of the package.
_PACKAGE_JSON_DECLARATIONS = frozenset({"dependencies", "devDependencies", "peerDependencies",
                                        "optionalDependencies", "bundleDependencies", "bundledDependencies",
                                        "peerDependenciesMeta", "overrides", "resolutions"})  # fmt: skip
_TOML_DECLARATIONS = (
    ("project", "dependencies"),
    ("project", "optional-dependencies"),
    ("dependency-groups",),
    ("build-system", "requires"),
    ("tool", "poetry", "dependencies"),
    ("tool", "poetry", "dev-dependencies"),
    ("tool", "poetry", "group", "*", "dependencies"),
    ("tool", "uv", "dev-dependencies"),
    ("packages",),  # Pipfile
    ("dev-packages",),
)


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class _Tree:
    """What one source tree shows; every field is filled by `_analyse`."""

    imports: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    incomplete: dict[str, list[str]] = field(default_factory=lambda: {e: [] for e in ECOSYSTEMS})
    tokens: set[str] = field(default_factory=set)
    direct: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    locked: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    depended_on: dict[str, set[str]] = field(default_factory=lambda: {e: set() for e in ECOSYSTEMS})
    bins: dict[str, set[str]] = field(default_factory=dict)

    def give_up(self, reason: str, ecosystems: Iterable[str] = ECOSYSTEMS) -> None:
        for ecosystem in ecosystems:
            self.incomplete[ecosystem].append(reason)

    def classify(self, ecosystem: str, name: str) -> str:
        if ecosystem == "pypi":
            modules = IMPORT_NAMES.get(name, (name.replace("-", "_"),))
            imported = any(i == m or i.startswith(m + ".") for i in self.imports["pypi"] for m in modules)
        else:
            modules = (name,)
            imported = name in self.imports["npm"]
        if imported:
            return "imported"
        used_without_import = USED_WITHOUT_IMPORT if ecosystem == "pypi" else NPM_USED_WITHOUT_IMPORT
        names = {name, name.replace("-", "_"), name.replace("_", "-"), *modules, *self.bins.get(name, ())}
        proven = (
            not self.incomplete[ecosystem]
            and (ecosystem != "pypi" or name in IMPORT_NAMES)
            and name not in used_without_import
            and name in self.direct[ecosystem]
            and name in self.locked[ecosystem]
            and name not in self.depended_on[ecosystem]
            and not any(n.lower() in self.tokens for n in names)
        )
        return "not_imported" if proven else "unknown"


class Reachability:
    """Reachability of package findings in one or more source trees (the most reachable answer wins)."""

    def __init__(self, trees: Sequence[_Tree]) -> None:
        self._trees = list(trees)

    @classmethod
    def of_trees(cls, roots: Iterable[Path]) -> Reachability:
        return cls([_analyse(Path(root)) for root in roots])

    def classify(self, finding: Mapping[str, Any]) -> str | None:
        """`imported`, `not_imported` or `unknown`; None for a finding this analysis does not cover."""
        target = _target(finding)
        if target is None or not self._trees:
            return None
        return max((tree.classify(*target) for tree in self._trees), key=ORDER.index)


def _target(finding: Mapping[str, Any]) -> tuple[str, str] | None:
    if finding.get("category") not in PACKAGE_CATEGORIES:
        return None
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
    for path in _files(root, tree):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                tree.give_up(f"{path.relative_to(root)} is larger than {MAX_FILE_BYTES} bytes")
                continue
            data = path.read_bytes()
        except OSError as exc:
            tree.give_up(f"{path.relative_to(root)} cannot be read: {exc}")
            continue
        if b"\0" in data[:8192]:  # binary, or a source file in an encoding this analysis does not read
            if path.suffix == ".py" or path.suffix in JS_SUFFIXES:
                tree.give_up(
                    f"{path.relative_to(root)} is not UTF-8 text", ["pypi" if path.suffix == ".py" else "npm"]
                )
            continue
        _read_file(path, data, root, tree, requirement_files)
    _apply_requirements(root, tree, requirement_files)
    return tree


def _files(root: Path, tree: _Tree) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        kept = []
        for name in sorted(dirnames):
            if (here / name).is_symlink():
                tree.give_up(f"symlink {(here / name).relative_to(root)} is not followed")
            elif name not in SKIP_DIRS:
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink():
                tree.give_up(f"symlink {path.relative_to(root)} is not followed")
                continue
            count += 1
            if count > MAX_FILES:
                tree.give_up(f"more than {MAX_FILES} files")
                return
            yield path


def _read_file(
    path: Path, data: bytes, root: Path, tree: _Tree, requirements: dict[Path, _Requirements]
) -> None:
    name, rel = path.name, path.relative_to(root).as_posix()
    if name in LOCKFILES:
        _read_lockfile(name, data, rel, tree)
        return
    if _REQUIREMENTS.fullmatch(name) or (
        path.parent.name == "requirements" and path.suffix in (".txt", ".in")
    ):
        requirements[path] = _parse_requirements(data.decode("utf-8", errors="replace"))
        return
    text = data.decode("utf-8", errors="replace")
    if name == "package.json":
        text = _package_json(text, rel, tree)
    elif name in ("pyproject.toml", "Pipfile"):
        text = _toml_manifest(name, text, rel, tree)
    if path.suffix == ".py":
        _python(data, rel, tree)
    elif path.suffix in JS_SUFFIXES:
        _javascript(text, rel, tree)
    tree.tokens.update(_tokens(text))


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for token in _TOKEN.findall(text):
        token = token.lower()
        out.add(token)
        out.update(part for part in re.split(r"[/.]", token) if part)
        parts = token.split(".")
        out.update(".".join(parts[:i]) for i in range(1, len(parts)))
    return out


# ---------------------------------------------------------------- Python


def _callee(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _python(data: bytes, rel: str, tree: _Tree) -> None:
    try:
        module = ast.parse(data, filename=rel)
    except (SyntaxError, ValueError) as exc:
        tree.give_up(f"{rel} does not parse: {exc}", ["pypi"])
        return
    imports = tree.imports["pypi"]
    risky = _PY_DYNAMIC_IMPORT | _PY_PLUGINS
    called: set[int] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.add(node.module)
            for alias in node.names:
                imports.add(f"{node.module}.{alias.name}")
                if alias.name in risky and alias.asname not in (None, alias.name):
                    tree.give_up(f"{rel} renames {alias.name}", ["pypi"])
        elif isinstance(node, ast.Call):
            name = _callee(node.func)
            called.add(id(node.func))
            if name in _PY_DYNAMIC_IMPORT:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if not arg.value.startswith("."):
                        imports.add(arg.value)
                else:
                    tree.give_up(f"{rel}:{node.lineno} imports a computed name", ["pypi"])
            elif name in _PY_PLUGINS:
                tree.give_up(f"{rel}:{node.lineno} loads entry-point plugins", ["pypi"])
            elif name in _PY_EXEC and isinstance(node.func, ast.Name):
                tree.give_up(f"{rel}:{node.lineno} runs {name}()", ["pypi"])
    for node in ast.walk(module):  # the same functions passed around under another name
        if isinstance(node, ast.Name | ast.Attribute) and id(node) not in called:
            name = _callee(node)
            if name in risky or (name in _PY_EXEC and isinstance(node, ast.Name)):
                tree.give_up(f"{rel}:{node.lineno} refers to {name}", ["pypi"])
        elif isinstance(node, ast.Constant) and node.value in risky:
            tree.give_up(f"{rel}:{node.lineno} names {node.value}", ["pypi"])


# ---------------------------------------------------------------- JavaScript / TypeScript


def _npm_package(specifier: str) -> str | None:
    if specifier.startswith((".", "/", "#", "~", "node:", "http:", "https:", "data:", "file:")):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 and parts[1] else None
    return parts[0] or None


def _javascript(text: str, rel: str, tree: _Tree) -> None:
    # Comments removed (strings kept), so a quote in a comment cannot hide an import. Imports are read from
    # both versions, in case a regex literal confuses the comment stripper.
    code = _JS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(0)[0] in "'\"`" else " ", text)
    for version in (text, code):
        specifiers = [m.group(2) for m in _JS_FROM.finditer(version)]
        specifiers += [m.group(2) for m in _JS_BARE.finditer(version)]
        specifiers += [m.group(3) or m.group(4) for m in _JS_CALL.finditer(version)]
        tree.imports["npm"].update(p for p in map(_npm_package, specifiers) if p)
    literal = {m.start() for m in _JS_CALL.finditer(code) if "resolve" not in m.group(1)}
    if any(m.start() not in literal for m in _JS_ANY_CALL.finditer(code)):
        tree.give_up(f"{rel} imports a computed name", ["npm"])
    if _JS_DYNAMIC.search(code):
        tree.give_up(f"{rel} loads code dynamically (createRequire, eval, new Function)", ["npm"])


# ---------------------------------------------------------------- manifests and lockfiles


def _strings(value: Any, path: tuple[str, ...], skip: Sequence[tuple[str, ...]]) -> Iterator[str]:
    """Keys and string values of a TOML document, except under the declaration paths in `skip`."""
    if any(len(s) <= len(path) and all(a in ("*", b) for a, b in zip(s, path, strict=False)) for s in skip):
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item, (*path, str(key)), skip)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, path, skip)


def _package_json(text: str, rel: str, tree: _Tree) -> str:
    """Record the runtime dependencies; return the manifest text without its dependency declarations."""
    try:
        manifest = json.loads(text)
    except ValueError:
        tree.give_up(f"{rel} is not valid JSON", ["npm"])
        return text
    if not isinstance(manifest, dict):
        return text
    dependencies = manifest.get("dependencies")
    if isinstance(dependencies, dict):
        tree.direct["npm"].update(map(str, dependencies))
    rest = {k: v for k, v in manifest.items() if k not in _PACKAGE_JSON_DECLARATIONS}
    return json.dumps(rest)


def _toml_manifest(name: str, text: str, rel: str, tree: _Tree) -> str:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        tree.give_up(f"{rel} is not valid TOML", ["pypi"])
        return text
    direct = tree.direct["pypi"]
    if name == "pyproject.toml":
        for requirement in document.get("project", {}).get("dependencies", []) or []:
            if isinstance(requirement, str) and (match := _PEP508_NAME.match(requirement)):
                direct.add(normalize_pypi(match.group(1)))
        poetry = document.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
        direct.update(normalize_pypi(str(k)) for k in poetry if str(k).lower() != "python")
    else:  # Pipfile: no graph in Pipfile.lock, so these stay unproven
        direct.update(normalize_pypi(str(k)) for k in document.get("packages", {}) or {})
    return "\n".join(_strings(document, (), _TOML_DECLARATIONS))


def _read_lockfile(name: str, data: bytes, rel: str, tree: _Tree) -> None:
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            _npm_lock(json.loads(data), tree)
        elif name == "uv.lock":
            _python_lock(tomllib.loads(data.decode("utf-8")), tree, uv=True)
        elif name == "poetry.lock":
            _python_lock(tomllib.loads(data.decode("utf-8")), tree, uv=False)
        # yarn.lock, pnpm-lock.yaml, Pipfile.lock: no graph read, so nothing they hold is proven unused
    except (ValueError, UnicodeDecodeError, AttributeError, TypeError) as exc:
        tree.give_up(f"{rel} cannot be read: {exc}", ["npm" if name.endswith((".json", ".yaml")) else "pypi"])


def _npm_lock(lock: Any, tree: _Tree) -> None:
    packages = lock.get("packages") if isinstance(lock, dict) else None
    for key, entry in (packages if isinstance(packages, dict) else {}).items():  # v2/v3; v1 has none
        if "node_modules/" not in key or not isinstance(entry, dict) or entry.get("link"):
            continue  # the project itself and its workspaces
        name = key.rsplit("node_modules/", 1)[1]
        tree.locked["npm"].add(name)
        for kind in ("dependencies", "peerDependencies", "optionalDependencies"):
            tree.depended_on["npm"].update(map(str, entry.get(kind) or {}))
        bins = entry.get("bin")
        if isinstance(bins, dict):
            tree.bins.setdefault(name, set()).update(map(str, bins))


def _python_lock(lock: dict[str, Any], tree: _Tree, *, uv: bool) -> None:
    for package in lock.get("package", []) or []:
        source = package.get("source") or {}
        if uv and ("editable" in source or "virtual" in source):
            continue  # the project itself
        name = normalize_pypi(str(package["name"]))
        tree.locked["pypi"].add(name)
        depended = tree.depended_on["pypi"]
        if uv:
            depended.update(normalize_pypi(d["name"]) for d in package.get("dependencies", []) or [])
            for group in (package.get("optional-dependencies") or {}).values():
                depended.update(normalize_pypi(d["name"]) for d in group)
        else:
            depended.update(normalize_pypi(str(d)) for d in package.get("dependencies", {}) or {})
            for extra in (package.get("extras") or {}).values():
                depended.update(normalize_pypi(m.group(1)) for d in extra if (m := _PEP508_NAME.match(d)))


@dataclass
class _Requirements:
    names: set[str] = field(default_factory=set)
    direct: set[str] = field(default_factory=set)  # annotated "# via -r ..." or the project file
    depended_on: set[str] = field(default_factory=set)
    includes: list[str] = field(default_factory=list)
    annotated: bool = False


def _parse_requirements(text: str) -> _Requirements:
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
                out.annotated = True
                if entry.startswith(("-r", "-c")) or entry.split(" ")[-1].strip("()") in (
                    "pyproject.toml", "setup.py", "setup.cfg"
                ):  # fmt: skip
                    out.direct.add(current)
                elif match := _PEP508_NAME.match(entry):
                    out.depended_on.add(current)
            continue
        in_via = False
        if line.startswith(("-r ", "--requirement ", "-r\t")):
            out.includes.append(line.split(None, 1)[1].strip())
            continue
        if line.startswith("-"):
            continue
        if match := _PEP508_NAME.match(line):
            current = normalize_pypi(match.group(1))
            out.names.add(current)
    return out


def _apply_requirements(root: Path, tree: _Tree, files: dict[Path, _Requirements]) -> None:
    """requirements.txt and the files it includes are runtime; a pip-compile annotated file is a lock."""
    runtime: set[Path] = set()
    pending = [p for p in files if p.name == "requirements.txt"]
    while pending:
        path = pending.pop()
        if path in runtime:
            continue
        runtime.add(path)
        for include in files[path].includes if path in files else []:
            target = (path.parent / include).resolve()  # symlinks resolved: the target must be in the tree
            if not (target.is_relative_to(root.resolve()) and target.is_file()):
                continue
            if target not in files:
                if target.stat().st_size > MAX_FILE_BYTES:
                    tree.give_up(f"{target.name} is larger than {MAX_FILE_BYTES} bytes", ["pypi"])
                    continue
                files[target] = _parse_requirements(target.read_text(encoding="utf-8", errors="replace"))
            pending.append(target)
    for path, parsed in files.items():
        tree.depended_on["pypi"].update(parsed.depended_on)
        if path not in runtime:
            continue
        if parsed.annotated:
            tree.direct["pypi"].update(parsed.direct)
            tree.locked["pypi"].update(parsed.names)
        else:
            tree.direct["pypi"].update(parsed.names)  # direct, but unproven: no graph
