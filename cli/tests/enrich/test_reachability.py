"""Reachability by static import analysis (task B2, SPEC 6.1): `imported`, or nothing.

Absent counts as the worst case (R = 1.0) and `imported` lowers it a little (0.9), so a missed import is safe
and a wrong `imported` is the error to avoid. `not_imported` is never claimed (#19 review, option (c)): the
first block of tests is Nourhane's table of libraries that load a package themselves.
"""

import json
import time
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


def finding(purl: str, category: str = "SCA", **fields: Any) -> dict[str, Any]:
    kind, _, rest = purl.partition(":")[2].partition("/")
    name = rest.rpartition("@")[0] or rest
    package = {"purl": purl, "name": name.replace("%40", "@"), "version": "1.0.0", "ecosystem": kind}
    return {**SCA, "category": category, "package": package, **fields}


def tree(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def classify(root: Path, purl: str) -> str | None:
    return Reachability.of_trees([root]).classify(finding(purl))


def uv_lock(*packages: tuple[str, list[str]], project: list[str] | None = None, extra: str = "") -> str:
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
    return 'version = 1\nrequires-python = ">=3.12"\n\n' + "\n".join(blocks) + extra


def package_lock(packages: dict[str, dict[str, Any]], root_deps: dict[str, str]) -> str:
    entries: dict[str, Any] = {"": {"name": "web", "dependencies": root_deps}}
    entries.update({f"node_modules/{name}": {"version": "1.0.0", **e} for name, e in packages.items()})
    return json.dumps({"name": "web", "lockfileVersion": 3, "packages": entries})


PY_BASE = {
    "uv.lock": uv_lock(("requests", ["urllib3"]), ("urllib3", []), ("pyyaml", []), ("lxml", [])),
    "app/main.py": "import requests\n\n\ndef run() -> None:\n    requests.get('https://example.invalid')\n",
}
JS_BASE = {
    "package.json": json.dumps({"name": "web", "dependencies": {"express": "^4", "lodash": "^4"}}),
    "package-lock.json": package_lock(
        {"express": {"dependencies": {"qs": "^6"}}, "qs": {}, "lodash": {}, "@scope/kit": {}},
        {"express": "^4", "lodash": "^4", "@scope/kit": "^1"},
    ),
    "src/server.js": "const express = require('express');\nexpress().listen(3000);\n",
}


@pytest.fixture
def py_repo(tmp_path: Path) -> Path:
    return tree(tmp_path / "repo", PY_BASE)


@pytest.fixture
def js_repo(tmp_path: Path) -> Path:
    return tree(tmp_path / "web", JS_BASE)


# ---------------------------------------------------------------- B1: a library loads it, nothing imports it


@pytest.mark.parametrize(
    ("code", "locked", "package"),
    [
        (
            "from fastapi.templating import Jinja2Templates\n",
            [("fastapi", ["starlette"]), ("starlette", []), ("jinja2", [])],
            "jinja2",
        ),
        (
            "from starlette.middleware.sessions import SessionMiddleware\n",
            [("starlette", []), ("itsdangerous", [])],
            "itsdangerous",
        ),
        (
            "import jwt\njwt.encode({}, key, algorithm='RS256')\n",
            [("pyjwt", []), ("cryptography", [])],
            "cryptography",
        ),
        (
            "import pandas as pd\npd.read_html(url)\n",
            [("pandas", ["numpy"]), ("numpy", []), ("lxml", [])],
            "lxml",
        ),
        ("import pandas as pd\ndf.plot()\n", [("pandas", []), ("matplotlib", [])], "matplotlib"),
        ("import pandas as pd\npd.read_sql(q, url)\n", [("pandas", []), ("sqlalchemy", [])], "sqlalchemy"),
        (
            "import markdown\nmarkdown.markdown(t, extensions=['codehilite'])\n",
            [("markdown", []), ("pygments", [])],
            "pygments",
        ),
    ],
    ids=[
        "fastapi-jinja2",
        "starlette-itsdangerous",
        "pyjwt-cryptography",
        "pandas-lxml",
        "pandas-matplotlib",
        "pandas-sqlalchemy",
        "markdown-pygments",
    ],
)
def test_a_package_a_library_loads_itself_is_never_called_unused(
    tmp_path: Path, code: str, locked: list[tuple[str, list[str]]], package: str
) -> None:
    """#19 B1: a direct, locked dependency nobody imports gets no answer (worst case), never not_imported."""
    repo = tree(tmp_path, {"uv.lock": uv_lock(*locked), "app/main.py": code})
    assert classify(repo, f"pkg:pypi/{package}@1.0") is None


def test_next_image_and_sharp(js_repo: Path) -> None:
    manifest = {"name": "web", "dependencies": {"next": "^14", "sharp": "^0.33"}}
    lock = package_lock({"next": {"optionalDependencies": {"sharp": "^0.33"}}, "sharp": {}}, {"next": "^14"})
    tree(
        js_repo,
        {
            "package.json": json.dumps(manifest),
            "package-lock.json": lock,
            "src/page.jsx": "import Image from 'next/image';\n",
        },
    )
    assert classify(js_repo, "pkg:npm/sharp@0.33.0") is None
    assert classify(js_repo, "pkg:npm/next@14.0.0") == "imported"


@pytest.mark.parametrize("purl", ["pkg:pypi/lxml@4.9.0", "pkg:pypi/pyyaml@6.0", "pkg:npm/lodash@4.17.20"])
def test_no_package_is_ever_not_imported_or_unknown(py_repo: Path, js_repo: Path, purl: str) -> None:
    repo = py_repo if "pypi" in purl else js_repo
    assert classify(repo, purl) is None


# ---------------------------------------------------------------- Python imports


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


@pytest.mark.parametrize(
    "code",
    [
        "# import lxml\n",
        "x = 'import lxml'\n",
        "from . import lxml\nfrom .lxml import etree\n",
        "import importlib\nimportlib.import_module('.lxml', 'app')\n",
        "import importlib\nname = 'lxml'\nimportlib.import_module(name)\n",
        "import lxmlx\nimport lxml_tools\n",
    ],
    ids=["comment", "string", "relative", "relative-dynamic", "computed", "longer-names"],
)
def test_what_is_not_an_import_of_the_package_is_not_counted(py_repo: Path, code: str) -> None:
    tree(py_repo, {"app/parse.py": code})
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None


def test_a_distribution_is_matched_by_its_import_name(py_repo: Path) -> None:
    tree(py_repo, {"app/config.py": "import yaml\n"})
    assert classify(py_repo, "pkg:pypi/pyyaml@6.0") == "imported"
    assert classify(py_repo, "pkg:pypi/PyYAML@6.0") == "imported", "PyPI names are case-insensitive"
    tree(py_repo, {"app/config.py": "import pyyaml\n"})
    assert classify(py_repo, "pkg:pypi/pyyaml@6.0") is None, "a listed distribution is only its modules"


@pytest.mark.parametrize(
    ("code", "purl"),
    [
        ("import some_rare_lib\n", "pkg:pypi/some-rare-lib@1.0"),
        ("from google.cloud import storage\n", "pkg:pypi/google-cloud-storage@2.0"),
        ("import ruamel.yaml\n", "pkg:pypi/ruamel.yaml@0.18"),
    ],
    ids=["underscore", "namespace", "dotted-name"],
)
def test_an_unlisted_distribution_is_matched_by_its_name(tmp_path: Path, code: str, purl: str) -> None:
    """#19 nit: unlisted namespace distributions came out unknown instead of imported."""
    assert classify(tree(tmp_path, {"app/x.py": code}), purl) == "imported"


# ---------------------------------------------------------------- S1: through the lockfile graph


def test_a_runtime_dependency_of_an_imported_package_is_imported(py_repo: Path) -> None:
    """#19 S1: urllib3 under requests (the old test at line 159 asserted unknown)."""
    assert classify(py_repo, "pkg:pypi/urllib3@2.0.0") == "imported"
    tree(py_repo, {"app/main.py": "print('no import')\n"})
    assert classify(py_repo, "pkg:pypi/urllib3@2.0.0") is None


def test_the_graph_is_followed_to_the_end(tmp_path: Path) -> None:
    lock = uv_lock(("a-lib", ["b-lib"]), ("b-lib", ["c-lib"]), ("c-lib", []), project=["a-lib"])
    repo = tree(tmp_path, {"uv.lock": lock, "app/main.py": "import a_lib\n"})
    assert classify(repo, "pkg:pypi/c-lib@1.0") == "imported"


def test_optional_dependencies_are_not_edges(tmp_path: Path) -> None:
    extra = '\n[package.optional-dependencies]\njinja = [\n    { name = "jinja2" },\n]\n'
    lock = uv_lock(("starlette", []), ("jinja2", []), extra="")
    lock = lock.replace(
        'name = "starlette"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\n',
        'name = "starlette"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\n' + extra,
    )
    repo = tree(tmp_path, {"uv.lock": lock, "app/main.py": "import starlette\n"})
    assert "optional-dependencies" in (repo / "uv.lock").read_text(encoding="utf-8")
    assert classify(repo, "pkg:pypi/jinja2@3.0") is None


def test_poetry_lock_gives_the_graph(tmp_path: Path) -> None:
    poetry = (
        '[[package]]\nname = "requests"\nversion = "2.32.0"\n\n[package.dependencies]\nurllib3 = ">=1"\n\n'
        '[package.extras]\nsocks = ["PySocks (>=1.5.6)"]\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.0"\n\n'
        '[[package]]\nname = "pysocks"\nversion = "1.7.1"\n'
    )
    repo = tree(tmp_path, {"poetry.lock": poetry, "app/main.py": "import requests\n"})
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") == "imported"
    assert classify(repo, "pkg:pypi/pysocks@1.7.1") is None, "extras are not edges"


def test_pip_compile_annotations_give_the_graph(tmp_path: Path) -> None:
    requirements = (
        "requests==2.32.0\n    # via -r requirements.in\n"
        "urllib3==2.0.0\n    # via requests\n"
        "lxml==4.9.0\n    # via\n    #   -r requirements.in\n    #   some-parser\n"
        "some-parser==1.0\n    # via -r requirements.in\n"
    )
    repo = tree(tmp_path, {"requirements.txt": requirements, "app/main.py": "import requests\n"})
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") == "imported"
    assert classify(repo, "pkg:pypi/lxml@4.9.0") is None
    tree(repo, {"app/parse.py": "import some_parser\n"})
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "imported", "multi-line via lists count"


@pytest.mark.parametrize(
    "include", ["-r base.txt", "-rbase.txt", "--requirement=base.txt", "--requirement base.txt"]
)
def test_every_include_form_is_followed(tmp_path: Path, include: str) -> None:
    """#19 nit: `-rfile` and `--requirement=file` were not followed."""
    locked = "requests==2.32.0\n    # via -r base.in\nurllib3==2.0.0\n    # via requests\n"
    files = {
        "requirements.txt": f"{include}\n",
        "requirements/base.txt": locked,
        "app/main.py": "import requests\n",
    }
    repo = tree(tmp_path / "repo", {k.replace("requirements/", ""): v for k, v in files.items()})
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") == "imported"


def test_an_include_outside_the_tree_is_never_read(tmp_path: Path) -> None:
    (tmp_path / "outside.txt").write_text(
        "requests==2.32.0\nurllib3==2.0.0\n    # via requests\n", encoding="utf-8"
    )
    repo = tree(
        tmp_path / "repo", {"requirements.txt": "-r ../outside.txt\n", "app/main.py": "import requests\n"}
    )
    assert classify(repo, "pkg:pypi/urllib3@2.0.0") is None


def test_an_editable_package_counts_only_through_its_source(tmp_path: Path) -> None:
    """#19 B2: a uv editable `mylib` depending on jinja2: its source decides, not its lock entry."""
    lock = uv_lock(("jinja2", []), project=["mylib"]) + (
        '\n[[package]]\nname = "mylib"\nversion = "0.1.0"\nsource = { editable = "../mylib" }\n'
        'dependencies = [\n    { name = "jinja2" },\n]\n'
    )
    repo = tree(tmp_path / "repo", {"uv.lock": lock, "app/main.py": "import mylib\n"})
    assert classify(repo, "pkg:pypi/jinja2@3.0") is None
    tree(repo, {"mylib/render.py": "import jinja2\n"})
    assert classify(repo, "pkg:pypi/jinja2@3.0") == "imported"


# ---------------------------------------------------------------- JavaScript / TypeScript


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
    ],
)
def test_every_js_import_form_is_seen(js_repo: Path, code: str) -> None:
    tree(js_repo, {"src/util.ts": code})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "imported"


@pytest.mark.parametrize(
    "code",
    [
        "// import _ from 'lodash';\n",
        "// import 'lodash';\n",
        "/* require('lodash') */\n",
        "const name = 'lo' + 'dash';\nrequire(name);\n",
        "const s = 'see lodash';\n",
    ],
    ids=["line-comment", "bare-in-comment", "block-comment", "computed", "string"],
)
def test_what_is_not_a_js_import_of_the_package_is_not_counted(js_repo: Path, code: str) -> None:
    tree(js_repo, {"src/util.js": code})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") is None


def test_js_scoped_and_subpath_imports(js_repo: Path) -> None:
    tree(js_repo, {"src/a.mjs": "import { x } from '@scope/kit/deep/path.js';\n"})
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") == "imported"


def test_js_runtime_dependencies_count_peer_and_optional_ones_do_not(js_repo: Path) -> None:
    assert classify(js_repo, "pkg:npm/qs@6.0.0") == "imported", "a dependency of express"
    lock = json.loads(JS_BASE["package-lock.json"])
    lock["packages"]["node_modules/express"] = {
        "dependencies": {"qs": "^6"},
        "peerDependencies": {"lodash": "^4"},
        "optionalDependencies": {"@scope/kit": "^1"},
    }
    tree(js_repo, {"package-lock.json": json.dumps(lock)})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") is None
    assert classify(js_repo, "pkg:npm/%40scope/kit@1.0.0") is None


def test_without_a_graph_only_direct_imports_count(js_repo: Path) -> None:
    (js_repo / "package-lock.json").unlink()
    tree(js_repo, {"yarn.lock": "qs@^6:\n  version 6.0.0\n"})
    assert classify(js_repo, "pkg:npm/express@4.18.0") == "imported"
    assert classify(js_repo, "pkg:npm/qs@6.0.0") is None


def test_a_package_with_an_install_script_gets_no_answer(js_repo: Path) -> None:
    """#19 S6: its code runs on install, imported or not."""
    lock = json.loads(JS_BASE["package-lock.json"])
    lock["packages"]["node_modules/express"]["hasInstallScript"] = True
    tree(js_repo, {"package-lock.json": json.dumps(lock)})
    assert classify(js_repo, "pkg:npm/express@4.18.0") is None


# ---------------------------------------------------------------- which findings, which trees


@pytest.mark.parametrize(
    ("purl", "category"),
    [
        ("pkg:golang/github.com/x/y@1.0.0", "SCA"),
        ("pkg:maven/org.example/lib@1.0.0", "SCA"),
        ("pkg:deb/debian/openssl@3.0.0", "CONTAINER"),
        ("pkg:pypi/requests@2.0.0", "CONTAINER"),
    ],
)
def test_only_pypi_and_npm_sca_findings_are_classified(py_repo: Path, purl: str, category: str) -> None:
    """#19 S5: an image's copy of a package is not the one the code imports."""
    assert Reachability.of_trees([py_repo]).classify(finding(purl, category)) is None


@pytest.mark.parametrize("ids", [{"rule_id": "MAL-2026-1"}, {"aliases": ["mal-2026-1"]}])
def test_a_malicious_package_gets_no_answer(py_repo: Path, ids: dict[str, Any]) -> None:
    """#19 S6: malicious code runs on install, imported or not."""
    assert Reachability.of_trees([py_repo]).classify(finding("pkg:pypi/requests@2.0.0", **ids)) is None


def test_findings_without_a_package_are_not_classified(py_repo: Path) -> None:
    assert Reachability.of_trees([py_repo]).classify(SECRET) is None


def test_imported_must_hold_in_every_tree(tmp_path: Path) -> None:
    """PR mode passes the base and the head: adding an import in the change cannot lower its own score."""
    base = tree(tmp_path / "base", PY_BASE)
    head = tree(tmp_path / "head", {**PY_BASE, "app/parse.py": "import lxml\n"})
    lxml = finding("pkg:pypi/lxml@4.9.0")
    assert Reachability.of_trees([head]).classify(lxml) == "imported"
    assert Reachability.of_trees([base, head]).classify(lxml) is None
    assert Reachability.of_trees([head, base]).classify(lxml) is None
    assert Reachability.of_trees([base, head]).classify(finding("pkg:pypi/requests@2.0")) == "imported"


def test_installed_packages_are_not_first_party_code(js_repo: Path, py_repo: Path) -> None:
    tree(js_repo, {"node_modules/other/index.js": "require('lodash');\n"})
    tree(py_repo, {".venv/lib/site.py": "import lxml\n"})
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") is None
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_symlinks_are_not_followed(py_repo: Path, tmp_path: Path, kind: str) -> None:
    outside = tree(tmp_path / "outside", {"lib.py": "import lxml\n"})
    if kind == "directory":
        (py_repo / "shared").symlink_to(outside, target_is_directory=True)
    else:
        (py_repo / "app" / "lib.py").symlink_to(outside / "lib.py")
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None


def test_files_beyond_the_limits_are_skipped(py_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tree(py_repo, {"app/parse.py": "import lxml\n"})
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "imported"
    monkeypatch.setattr(reach, "MAX_SOURCE_BYTES", 12)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") == "imported", "12 bytes is within 12"
    monkeypatch.setattr(reach, "MAX_SOURCE_BYTES", 11)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None
    monkeypatch.setattr(reach, "MAX_SOURCE_BYTES", 1024)
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 10)
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None
    monkeypatch.setattr(reach, "MAX_FILE_BYTES", 1024 * 1024)
    monkeypatch.setattr(reach, "MAX_FILES", 2)  # sorted walk: uv.lock, then app/main.py; app/parse.py is cut
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None


def test_binary_and_non_utf8_files_are_skipped(py_repo: Path) -> None:
    (py_repo / "logo.png").write_bytes(b"\x89PNG\x00\x00import lxml\x00" * 10)
    (py_repo / "app" / "x.py").write_bytes("import lxml\n".encode("utf-16"))
    assert classify(py_repo, "pkg:pypi/lxml@4.9.0") is None


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


# ---------------------------------------------------------------- S2: hostile files cannot crash or stall it


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("package-lock.json", "[" * 100_000 + "]" * 100_000),
        ("package.json", "[" * 100_000 + "]" * 100_000),
        ("uv.lock", "x = " + "[" * 50_000 + "]" * 50_000 + "\n"),
        ("poetry.lock", "x = " + "[" * 50_000 + "]" * 50_000 + "\n"),
        ("app/sum.py", "x = " + "1+" * 200_000 + "1\n"),
        ("app/neg.py", "x = " + "-" * 200_000 + "1\n"),
        ("app/deep.py", "x = " + "(" * 50_000 + ")" * 50_000 + "\n"),
        ("app/calls.py", "x = f" + "()" * 50_000 + "\n"),
    ],
    ids=["lock-json", "package-json", "uv-lock", "poetry-lock", "sum", "unary", "parens", "calls"],
)
def test_deeply_nested_files_are_skipped_not_fatal(py_repo: Path, name: str, content: str) -> None:
    tree(py_repo, {name: content})
    assert classify(py_repo, "pkg:pypi/requests@2.0") == "imported", "the rest of the tree still counts"


@pytest.mark.parametrize(
    "text",
    [
        "import " * 19_000,
        "import x from " * 6_000 + "\n",
        "import {" + " a," * 300_000 + "\n",
        ("import " + "a" * 1_990 + " ") * 200,
    ],
    ids=["import-words", "from-without-string", "long-braces", "near-the-bound"],
)
def test_js_text_full_of_import_words_stays_fast(js_repo: Path, text: str) -> None:
    """#19 S2: _JS_FROM was quadratic (140 KB took 49.6 s)."""
    tree(js_repo, {"src/hostile.js": text})
    start = time.monotonic()
    assert classify(js_repo, "pkg:npm/express@4.18.0") == "imported"
    assert time.monotonic() - start < 5


def test_too_many_js_keywords_skip_the_file(js_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tree(js_repo, {"src/util.js": "import _ from 'lodash';\n"})
    monkeypatch.setattr(reach, "MAX_JS_KEYWORDS", 2)
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") == "imported", "import and from: 2 keywords"
    monkeypatch.setattr(reach, "MAX_JS_KEYWORDS", 1)
    assert classify(js_repo, "pkg:npm/lodash@4.17.20") is None


def test_a_long_dotted_import_stays_small(tmp_path: Path) -> None:
    """#19 S2: every prefix of a long dotted name used memory quadratic in its length."""
    repo = tree(tmp_path, {"app/x.py": "import a.b.c.d.e.f.g.h.i.j\n"})
    assert classify(repo, "pkg:pypi/a@1.0") == "imported"
    assert classify(repo, "pkg:pypi/a-b-c-d-e-f-g-h@1.0") == "imported", "8 levels"
    assert classify(repo, "pkg:pypi/a-b-c-d-e-f-g-h-i@1.0") is None, "beyond the depth that is compared"


@pytest.mark.parametrize("parts", [64, 200_000])
def test_a_file_with_a_huge_dotted_name_is_not_parsed(tmp_path: Path, parts: int) -> None:
    """ast.parse needs memory quadratic in a dotted name: 150,000 parts got the process killed (exit 137)."""
    dotted = ".".join(["a"] * parts)
    repo = tree(tmp_path, {"app/x.py": f"import requests\nimport {dotted}\n", "app/y.py": "import lxml\n"})
    start = time.monotonic()
    assert classify(repo, "pkg:pypi/requests@2.0") is None, "that file is skipped"
    assert classify(repo, "pkg:pypi/lxml@4.9.0") == "imported", "the others still count"
    assert time.monotonic() - start < 5


def test_63_dotted_parts_are_still_parsed(tmp_path: Path) -> None:
    dotted = ".".join(["a"] * 63)
    repo = tree(tmp_path, {"app/x.py": f"import requests\nx = {dotted}\n"})
    assert classify(repo, "pkg:pypi/requests@2.0") == "imported"


def test_an_unexpected_error_exits_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(root: Path) -> Any:
        raise KeyError("an unforeseen shape")

    monkeypatch.setattr(reach, "_analyse", broken)
    findings = tmp_path / "findings.ndjson"
    findings.write_text(json.dumps(SECRET) + "\n", encoding="utf-8")
    out = tmp_path / "out.ndjson"
    result = CliRunner().invoke(
        app, ["enrich", "--findings", str(findings), "--out", str(out), "--source", str(tmp_path)]
    )
    assert result.exit_code == 3
    assert "unexpected KeyError" in result.output
    assert not out.exists()


# ---------------------------------------------------------------- enrichment and CLI


def test_enrich_sets_reachability_and_is_idempotent(
    py_repo: Path, finding_validator: Draft202012Validator
) -> None:
    analysis = Reachability.of_trees([py_repo])
    once = enrich_finding(finding("pkg:pypi/requests@2.0.0"), EMPTY_SNAPSHOT, None, analysis)
    assert once["enrichment"] == {"reachability": "imported"}
    assert enrich_finding(once, EMPTY_SNAPSHOT, None, analysis) == once
    finding_validator.validate(once)


def test_a_stale_reachability_is_never_kept(py_repo: Path) -> None:
    stale = {**finding("pkg:pypi/lxml@4.9.0"), "enrichment": {"reachability": "not_imported"}}
    assert "enrichment" not in enrich_finding(stale, EMPTY_SNAPSHOT, None)
    assert "enrichment" not in enrich_finding(stale, EMPTY_SNAPSHOT, None, Reachability.of_trees([py_repo]))


def test_cli_enrich_with_sources(py_repo: Path, tmp_path: Path) -> None:
    findings = tmp_path / "findings.ndjson"
    rows = [finding("pkg:pypi/lxml@4.9.0"), finding("pkg:pypi/requests@2.0.0"), SECRET]
    findings.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    out = tmp_path / "out.ndjson"
    result = CliRunner().invoke(
        app, ["enrich", "--findings", str(findings), "--out", str(out), "--source", str(py_repo)]
    )
    assert result.exit_code == 0, result.output
    rows_out = [json.loads(line) for line in out.read_text("utf-8").split("\n")[:-1]]
    got = {
        (r.get("package") or {}).get("name", r["category"]): r.get("enrichment", {}).get("reachability")
        for r in rows_out
    }
    assert got == {"lxml": None, "requests": "imported", "SECRET": None}
    assert "reachability: 1 imported" in result.output


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


def test_a_conditional_dependency_is_not_an_edge(tmp_path: Path) -> None:
    """colorama is a dependency of pytest only on Windows: on Linux it is not even installed."""
    lock = uv_lock(
        ("pytest", ["iniconfig"]), ("iniconfig", []), ("colorama", []), project=["pytest"]
    ).replace(
        '    { name = "iniconfig" },\n',
        '    { name = "iniconfig" },\n    { name = "colorama", marker = "sys_platform == \'win32\'" },\n',
        1,
    )
    poetry = (
        '[[package]]\nname = "click"\nversion = "8.0"\n\n[package.dependencies]\n'
        'colorama = {version = "*", markers = "platform_system == \\"Windows\\""}\nsix = "*"\n\n'
        '[[package]]\nname = "colorama"\nversion = "0.4"\n\n[[package]]\nname = "six"\nversion = "1.16"\n'
    )
    assert 'colorama", marker' in lock.split('[[package]]\nname = "pytest"')[1], "the marker is on pytest's own edge"
    uv_repo = tree(tmp_path / "uv", {"uv.lock": lock, "app/main.py": "import pytest\n"})
    assert classify(uv_repo, "pkg:pypi/iniconfig@2.0") == "imported"
    assert classify(uv_repo, "pkg:pypi/colorama@0.4") is None
    poetry_repo = tree(tmp_path / "poetry", {"poetry.lock": poetry, "app/main.py": "import click\n"})
    assert classify(poetry_repo, "pkg:pypi/six@1.16") == "imported"
    assert classify(poetry_repo, "pkg:pypi/colorama@0.4") is None
