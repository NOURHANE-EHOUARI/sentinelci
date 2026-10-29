"""Reachability by static import analysis (task B2, SPEC 6.1): imported, not_imported or unknown.

`not_imported` lowers R from the model's `unknown` to its `not_imported` weight, so it is claimed only with
proof: a direct runtime dependency, locked with no other package depending on it, with a certain import name,
mentioned nowhere but in the dependency declarations, and a complete analysis. Every case below that lacks
one of those proofs must answer `unknown`.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from sentinelci import enrich
from sentinelci.cli import app
from sentinelci.enrich import enrich_finding, load_snapshot
from sentinelci.enrich import reachability as reach
from sentinelci.enrich.reachability import Reachability

ROOT = Path(__file__).resolve().parents[3]
FINDING_FIXTURES = ROOT / "schemas" / "fixtures" / "finding" / "valid"
SCA = {
    k: v
    for k, v in json.loads(
        (FINDING_FIXTURES / "sca-enriched-and-scored.json").read_text(encoding="utf-8")
    ).items()
    if k not in ("enrichment", "risk")
}
SECRET = json.loads((FINDING_FIXTURES / "secret-in-config.json").read_text(encoding="utf-8"))
EMPTY_SNAPSHOT = load_snapshot(enrich.EMPTY_SNAPSHOT)


def finding(purl: str, category: str = "SCA") -> dict[str, Any]:
    kind, _, rest = purl.partition(":")[2].partition("/")
    name = rest.rpartition("@")[0] or rest
    package = {"purl": purl, "name": name.replace("%40", "@"), "version": "1.0.0", "ecosystem": kind}
    return {**SCA, "category": category, "package": package}


def tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def classify(root: Path, purl: str) -> str | None:
    return Reachability.of_trees([root]).classify(finding(purl))


# ---------------------------------------------------------------- Python


def uv_lock(*packages: tuple[str, list[str]], project: list[str] | None = None) -> str:
    """A uv.lock: the editable project (depending on `project`) and registry packages with their deps."""
    blocks = []
    root_deps = project if project is not None else [name for name, _ in packages]
    for name, deps, source in [("app", root_deps, '{ editable = "." }')] + [
        (n, d, '{ registry = "https://pypi.org/simple" }') for n, d in packages
    ]:
        dep_lines = "".join(f'    {{ name = "{d}" }},\n' for d in deps)
        blocks.append(
            f'[[package]]\nname = "{name}"\nversion = "1.0.0"\nsource = {source}\n'
            + (f"dependencies = [\n{dep_lines}]\n" if deps else "")
        )
    return 'version = 1\nrequires-python = ">=3.12"\n\n' + "\n".join(blocks)


def pyproject(*deps: str, extra: str = "") -> str:
    listed = "".join(f'    "{d}>=1",\n' for d in deps)
    return f'[project]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n{listed}]\n{extra}'


PY_BASE = {
    "pyproject.toml": pyproject("requests", "pyyaml", "lxml"),
    "uv.lock": uv_lock(("requests", ["urllib3"]), ("urllib3", []), ("pyyaml", []), ("lxml", [])),
    "app/main.py": "import requests\n\n\ndef run() -> None:\n    requests.get('https://example.invalid')\n",
}


@pytest.fixture
def py_repo(tmp_path: Path) -> Path:
    return tree(tmp_path / "repo", PY_BASE)


def test_a_direct_locked_dependency_nobody_imports_is_not_imported(py_repo: Path) -> None:
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "not_imported"


@pytest.mark.parametrize(
    "code",
    [
        "import lxml\n",
        "import lxml.etree as et\n",
        "from lxml import etree\n",
        "from lxml.html import fromstring\n",
        "import importlib\nimportlib.import_module('lxml.etree')\n",
        "from importlib import import_module\nimport_module('lxml')\n",
        "__import__('lxml')\n",
        "def f():\n    import lxml  # a local import counts too\n",
        "try:\n    import lxml\nexcept ImportError:\n    lxml = None\n",
    ],
)
def test_every_static_python_import_form_is_seen(py_repo: Path, code: str) -> None:
    tree(py_repo, {"app/parse.py": code})
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "imported"


def test_a_distribution_is_matched_by_its_import_name(py_repo: Path) -> None:
    assert classify(py_repo, "pkg:pypi/pyyaml@6.0") == "not_imported"
    tree(py_repo, {"app/config.py": "import yaml\n"})
    assert classify(py_repo, "pkg:pypi/pyyaml@6.0") == "imported"
    assert classify(py_repo, "pkg:pypi/PyYAML@6.0") == "imported", "PyPI names are case-insensitive"


def test_relative_imports_are_first_party(py_repo: Path) -> None:
    # A first-party module named lxml is not the package; the name still appears, so no proof of non-use.
    tree(py_repo, {"app/x.py": "from . import lxml\nfrom .lxml import etree\n"})
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_an_imported_package_outside_the_table_is_still_imported(tmp_path: Path) -> None:
    repo = tree(tmp_path, {**PY_BASE, "app/x.py": "import some_rare_lib\n"})
    assert classify(repo, "pkg:pypi/some-rare-lib@1.0") == "imported"


@pytest.mark.parametrize(
    ("files", "why"),
    [
        ({"uv.lock": uv_lock(("requests", ["urllib3", "lxml"]), ("urllib3", []), ("lxml", []))},
         "another locked package depends on it"),
        ({"pyproject.toml": pyproject("requests", "pyyaml")}, "not a direct dependency"),
        ({"uv.lock": uv_lock(("requests", ["urllib3"]), ("urllib3", []), ("pyyaml", []))}, "not locked"),
        ({"Dockerfile": "FROM python:3.12\nRUN python -c 'import lxml'\n"}, "mentioned in a Dockerfile"),
        ({"app/settings.py": "PARSER = 'lxml'\n"}, "named in a string (bs4 parser, Django settings)"),
        ({"pyproject.toml": pyproject("requests", "pyyaml", "lxml", extra='[tool.x]\nplugin = "lxml"\n')},
         "named in a tool section of pyproject.toml"),
        ({"app/x.py": "import importlib\nname = 'x'\nimportlib.import_module(name)\n"}, "computed import"),
        ({"app/x.py": "__import__(f'{prefix}')\n"}, "computed __import__"),
        ({"app/x.py": "load = __import__\n"}, "aliased __import__"),
        ({"app/x.py": "from importlib import import_module as load\nload(name)\n"}, "renamed"),
        ({"app/x.py": "import importlib\ngetattr(importlib, 'import_module')(name)\n"}, "by name"),
        ({"app/x.py": "exec(source)\n"}, "exec"),
        ({"app/x.py": "eval(source)\n"}, "eval"),
        ({"app/x.py": "from importlib.metadata import entry_points\nentry_points(group='x')\n"},
         "plugins loaded by entry point"),
        ({"app/broken.py": "def f(:\n"}, "a file that does not parse"),
    ],
)  # fmt: skip
def test_without_every_proof_the_answer_is_unknown(py_repo: Path, files: dict[str, str], why: str) -> None:
    tree(py_repo, files)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "unknown", why


def test_a_transitive_dependency_is_unknown_even_when_pinned(py_repo: Path) -> None:
    assert classify(py_repo, "pkg:pypi/urllib3@1.26.0") == "unknown"


def test_a_distribution_without_a_reviewed_import_name_is_unknown(tmp_path: Path) -> None:
    repo = tree(
        tmp_path,
        {
            "pyproject.toml": pyproject("some-rare-lib"),
            "uv.lock": uv_lock(("some-rare-lib", [])),
            "app/main.py": "print('hello')\n",
        },
    )
    assert classify(repo, "pkg:pypi/some-rare-lib@1.0") == "unknown"


@pytest.mark.parametrize("package", ["gunicorn", "psycopg2-binary", "uvloop", "python-multipart", "tzdata"])
def test_packages_used_without_an_import_are_unknown(
    tmp_path: Path, package: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even with a reviewed import name, a package that runs without being imported is never not_imported.
    monkeypatch.setitem(reach.IMPORT_NAMES, package, (package.replace("-", "_"),))
    repo = tree(
        tmp_path,
        {
            "pyproject.toml": pyproject(package),
            "uv.lock": uv_lock((package, [])),
            "app/main.py": "print('hello')\n",
        },
    )
    assert classify(repo, f"pkg:pypi/{package}@1.0") == "unknown"


def test_pip_compile_annotations_give_the_graph(tmp_path: Path) -> None:
    requirements = (
        "lxml==4.9.0\n    # via -r requirements.in\n"
        "requests==2.32.0\n    # via -r requirements.in\n"
        "urllib3==2.0.0\n    # via requests\n"
    )
    repo = tree(tmp_path, {"requirements.txt": requirements, "app/main.py": "import requests\n"})
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "not_imported"
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") == "unknown"


def test_pip_compile_multi_line_via_lists_count(tmp_path: Path) -> None:
    requirements = (
        "lxml==4.9.0\n    # via\n    #   -r requirements.in\n    #   some-parser\n"
        "some-parser==1.0\n    # via -r requirements.in\n"
    )
    repo = tree(tmp_path, {"requirements.txt": requirements, "app/main.py": "import some_parser\n"})
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_a_plain_requirements_file_proves_nothing(tmp_path: Path) -> None:
    # `pip freeze` output lists transitive packages as if they were direct: no graph, no claim.
    repo = tree(tmp_path, {"requirements.txt": "lxml==4.9.0\nrequests==2.32.0\n", "app/main.py": "x = 1\n"})
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_poetry_lock_gives_the_graph(tmp_path: Path) -> None:
    poetry = (
        '[[package]]\nname = "lxml"\nversion = "4.9.0"\n\n'
        '[[package]]\nname = "requests"\nversion = "2.32.0"\n\n[package.dependencies]\nurllib3 = ">=1"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n'
    )
    pyproject_poetry = (
        '[tool.poetry]\nname = "app"\nversion = "0.1.0"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.12"\nlxml = "^4.9"\nrequests = "^2"\n'
    )
    repo = tree(
        tmp_path,
        {"pyproject.toml": pyproject_poetry, "poetry.lock": poetry, "app/main.py": "import requests\n"},
    )
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "not_imported"
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") == "unknown"


# ---------------------------------------------------------------- JavaScript / TypeScript


def package_lock(packages: dict[str, dict[str, Any]], root_deps: dict[str, str]) -> str:
    entries: dict[str, Any] = {"": {"name": "web", "dependencies": root_deps}}
    entries.update({f"node_modules/{name}": {"version": "1.0.0", **e} for name, e in packages.items()})
    return json.dumps({"name": "web", "lockfileVersion": 3, "packages": entries})


JS_BASE = {
    "package.json": json.dumps(
        {
            "name": "web",
            "scripts": {"start": "node src/server.js"},
            "dependencies": {"express": "^4", "lodash": "^4", "@scope/kit": "^1"},
            "devDependencies": {"jest": "^29"},
        }
    ),
    "package-lock.json": package_lock(
        {
            "express": {"dependencies": {"qs": "^6"}},
            "qs": {},
            "lodash": {},
            "@scope/kit": {},
            "jest": {"dev": True, "bin": {"jest": "bin/jest.js"}},
        },
        {"express": "^4", "lodash": "^4", "@scope/kit": "^1"},
    ),
    "src/server.js": "const express = require('express');\nexpress().listen(3000);\n",
}


@pytest.fixture
def js_repo(tmp_path: Path) -> Path:
    return tree(tmp_path / "web", JS_BASE)


def test_js_direct_locked_dependency_nobody_imports_is_not_imported(js_repo: Path) -> None:
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "not_imported"
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") == "not_imported"
    assert classify(js_repo, "pkg:npm/express@4.18.0") == "imported"


@pytest.mark.parametrize(
    "code",
    [
        "import _ from 'lodash';\n",
        'import { map } from "lodash/fp";\n',
        "import * as _ from 'lodash'\n",
        "import 'lodash';\n",
        "export { map } from 'lodash';\n",
        "const _ = require('lodash');\n",
        'const _ = require( "lodash" )\n',
        "const _ = require(`lodash`);\n",
        "const _ = await import('lodash');\n",
        "import {\n  map, // it's mapped here\n  filter,\n} from 'lodash';\n",
        "import type { Dict } from 'lodash';\n",
        "import _ = require('lodash');\n",
        "require.resolve('lodash');\n",
    ],
)
def test_every_js_import_form_is_seen(js_repo: Path, code: str) -> None:
    tree(js_repo, {"src/util.ts": code})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "imported"


def test_js_scoped_and_subpath_imports(js_repo: Path) -> None:
    tree(js_repo, {"src/a.mjs": "import { x } from '@scope/kit/deep/path.js';\n"})
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") == "imported"


@pytest.mark.parametrize(
    ("files", "why"),
    [
        ({"src/x.js": "const name = 'lo' + 'dash';\nrequire(name);\n"}, "computed require"),
        ({"src/x.js": "const m = await import(`./${name}`);\n"}, "computed dynamic import"),
        ({"src/x.js": "const r = createRequire(import.meta.url);\n"},
         "createRequire"),
        ({"src/x.js": "eval(code);\n"}, "eval"),
        ({"src/x.js": "const f = new Function('return 1');\n"}, "new Function"),
        ({"src/x.js": "// the lodash fallback\nmodule.exports = 1;\n"}, "mentioned in a comment"),
        ({"README.md": "We used lodash once.\n"}, "mentioned in the README"),
    ],
)  # fmt: skip
def test_js_without_every_proof_the_answer_is_unknown(js_repo: Path, files: dict[str, str], why: str) -> None:
    tree(js_repo, files)
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "unknown", why


def test_npm_packages_used_without_an_import_are_unknown(js_repo: Path) -> None:
    manifest = json.loads(JS_BASE["package.json"])
    manifest["dependencies"]["pg"] = "^8"
    lock = json.loads(JS_BASE["package-lock.json"])
    lock["packages"]["node_modules/pg"] = {"version": "8.0.0"}
    tree(js_repo, {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(lock)})
    assert classify(js_repo, "pkg:npm/pg@8.0.0") == "unknown", (
        "Sequelize and Knex load pg from a dialect name"
    )


def test_a_require_inside_a_comment_is_not_a_computed_import(js_repo: Path) -> None:
    tree(js_repo, {"src/x.js": "/* require(name) */\n// import(name)\nmodule.exports = 1;\n"})
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") == "not_imported"


def test_js_transitive_dev_and_unlocked_packages_are_unknown(js_repo: Path) -> None:
    assert classify(js_repo, "pkg:npm/qs@6.0.0") == "unknown", "a dependency of express"
    assert classify(js_repo, "pkg:npm/jest@29.0.0") == "unknown", "dev only"
    tree(js_repo, {"package-lock.json": package_lock({"express": {}}, {"express": "^4"})})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "unknown", "not in the lock"


def test_a_peer_dependency_of_a_locked_package_is_unknown(js_repo: Path) -> None:
    lock = json.loads(JS_BASE["package-lock.json"])
    lock["packages"]["node_modules/express"]["peerDependencies"] = {"lodash": "^4"}
    tree(js_repo, {"package-lock.json": json.dumps(lock)})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "unknown"


def test_a_bin_named_in_the_scripts_is_unknown(js_repo: Path) -> None:
    manifest = json.loads(JS_BASE["package.json"])
    manifest["scripts"]["lint"] = "kit-cli check src"
    lock = json.loads(JS_BASE["package-lock.json"])
    lock["packages"]["node_modules/@scope/kit"]["bin"] = {"kit-cli": "bin/cli.js"}
    tree(js_repo, {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(lock)})
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") == "unknown"


def test_without_package_lock_nothing_is_proven(js_repo: Path) -> None:
    (js_repo / "package-lock.json").unlink()
    tree(js_repo, {"yarn.lock": "lodash@^4:\n  version 4.17.20\n"})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "unknown"


def test_lockfile_v1_proves_nothing(js_repo: Path) -> None:
    tree(js_repo, {"package-lock.json": json.dumps({"lockfileVersion": 1, "dependencies": {"lodash": {}}})})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "unknown"


# ---------------------------------------------------------------- the tree itself


def test_installed_packages_are_not_first_party_code(js_repo: Path, py_repo: Path) -> None:
    tree(js_repo, {"node_modules/other/index.js": "require('lodash');\n"})
    tree(py_repo, {".venv/lib/site.py": "import lxml\n"})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "not_imported"
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "not_imported"


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_a_symlink_makes_the_analysis_incomplete(py_repo: Path, tmp_path: Path, kind: str) -> None:
    outside = tree(tmp_path / "outside", {"lib.py": "import lxml\n"})
    if kind == "directory":
        (py_repo / "shared").symlink_to(outside, target_is_directory=True)
    else:
        (py_repo / "app" / "lib.py").symlink_to(outside / "lib.py")
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_limits_make_the_analysis_incomplete(py_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 10)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "unknown"
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 5 * 1024 * 1024)
    monkeypatch.setattr(reach, "MAX_FILES", 2)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_binary_files_are_skipped(py_repo: Path) -> None:
    (py_repo / "logo.png").write_bytes(b"\x89PNG\x00\x00lxml\x00" * 10)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "not_imported"


@pytest.mark.parametrize(
    ("name", "purl"), [("app/x.py", "pkg:pypi/lxml@4.9.0"), ("src/x.js", "pkg:npm/lodash@1.0")]
)
def test_a_source_file_that_is_not_utf8_makes_the_analysis_incomplete(
    py_repo: Path, js_repo: Path, name: str, purl: str
) -> None:
    repo = py_repo if name.endswith(".py") else js_repo
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_bytes("import lxml\nrequire('lodash')\n".encode("utf-16"))
    assert classify(repo, purl) == "unknown"


def test_requirement_includes_are_runtime_but_only_inside_the_tree(tmp_path: Path) -> None:
    locked = "lxml==4.9.0\n    # via -r base.in\nrequests==2.32.0\n    # via -r base.in\n"
    repo = tree(
        tmp_path / "repo",
        {
            "requirements.txt": "-r requirements/base.txt\n",
            "requirements/base.txt": locked,
            "app/main.py": "import requests\n",
        },
    )
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "not_imported"
    # The same lock outside the scanned tree is never read: nothing proven.
    (tmp_path / "outside.txt").write_text(locked, encoding="utf-8")
    (repo / "requirements" / "base.txt").unlink()
    tree(repo, {"requirements.txt": "-r ../outside.txt\n"})
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "unknown"


def test_the_most_reachable_tree_wins(tmp_path: Path) -> None:
    # PR mode passes the base and the head: removing an import in the change cannot lower reachability.
    base = tree(tmp_path / "base", {**PY_BASE, "app/parse.py": "import lxml\n"})
    head = tree(tmp_path / "head", PY_BASE)
    assert classify(head, "pkg:pypi/lxml@4.9.0") == "not_imported"
    both = Reachability.of_trees([base, head])
    assert both.classify(finding("pkg:pypi/lxml@4.9.0")) == "imported"
    assert Reachability.of_trees([head, base]).classify(finding("pkg:pypi/lxml@4.9.0")) == "imported"


@pytest.mark.parametrize(
    ("purl", "category"),
    [
        ("pkg:golang/github.com/x/y@1.0.0", "SCA"),
        ("pkg:maven/org.example/lib@1.0.0", "SCA"),
        ("pkg:deb/debian/openssl@3.0.0", "CONTAINER"),
    ],
)
def test_other_ecosystems_are_not_analysed(py_repo: Path, purl: str, category: str) -> None:
    assert Reachability.of_trees([py_repo]).classify(finding(purl, category)) is None


def test_a_package_finding_in_an_image_is_analysed_like_sca(py_repo: Path) -> None:
    assert Reachability.of_trees([py_repo]).classify(finding("pkg:pypi/lxml@4.9.0", "CONTAINER")) == (
        "not_imported"
    )


def test_findings_without_a_package_are_not_analysed(py_repo: Path) -> None:
    assert Reachability.of_trees([py_repo]).classify(SECRET) is None


def test_the_analysis_never_runs_the_scanned_code(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    repo = tree(
        tmp_path / "repo",
        {
            **PY_BASE,
            "conftest.py": f"open({str(marker)!r}, 'w').close()\n",
            "app/__init__.py": f"open({str(marker)!r}, 'w').close()\n",
            "setup.py": f"open({str(marker)!r}, 'w').close()\n",
        },
    )
    Reachability.of_trees([repo]).classify(finding("pkg:pypi/lxml@4.9.0"))
    assert not marker.exists()


# ---------------------------------------------------------------- enrichment and CLI


def test_enrich_sets_reachability_and_is_idempotent(
    py_repo: Path, finding_validator: Draft202012Validator
) -> None:
    analysis = Reachability.of_trees([py_repo])
    once = enrich_finding(finding("pkg:pypi/lxml@4.9.0"), EMPTY_SNAPSHOT, None, analysis)
    assert once["enrichment"] == {"reachability": "not_imported"}
    assert enrich_finding(once, EMPTY_SNAPSHOT, None, analysis) == once
    finding_validator.validate(once)


def test_without_sources_reachability_is_absent(py_repo: Path) -> None:
    enriched = enrich_finding(
        {**finding("pkg:pypi/lxml@4.9.0"), "enrichment": {"reachability": "not_imported"}},
        EMPTY_SNAPSHOT,
        None,
    )
    assert "enrichment" not in enriched, "a stale value from an earlier run is never kept"


def test_cli_enrich_with_sources(py_repo: Path, tmp_path: Path) -> None:
    findings = tmp_path / "findings.ndjson"
    rows = [finding("pkg:pypi/lxml@4.9.0"), finding("pkg:pypi/requests@2.0.0"), SECRET]
    findings.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    out = tmp_path / "out.ndjson"
    result = CliRunner().invoke(
        app, ["enrich", "--findings", str(findings), "--out", str(out), "--source", str(py_repo)]
    )
    assert result.exit_code == 0, result.output
    got = [
        json.loads(line).get("enrichment", {}).get("reachability")
        for line in out.read_text("utf-8").split("\n")[:-1]
    ]
    assert sorted(map(str, got)) == ["None", "imported", "not_imported"]
    assert "reachability: 1 imported, 0 unknown, 1 not_imported" in result.output


def test_cli_enrich_fails_closed_on_a_missing_source(tmp_path: Path) -> None:
    findings = tmp_path / "findings.ndjson"
    findings.write_text(json.dumps(SECRET) + "\n", encoding="utf-8")
    out = tmp_path / "out.ndjson"
    out.write_text("stale", encoding="utf-8")
    result = CliRunner().invoke(
        app, ["enrich", "--findings", str(findings), "--out", str(out), "--source", str(tmp_path / "nope")]
    )
    assert result.exit_code == 3
    assert not out.exists()
