"""SentinelCI's SAST rules (configs/opengrep/*.yaml), pinned case by case with the real Opengrep (task A1).

Every rule has code it must flag and code it must leave alone. The samples are written at run time: no
deliberately vulnerable file is committed outside `demo-shop/`. Opt-in like the other real-tool tests: set
SENTINEL_TOOLS_DIR to a `sentinel tools install` directory. The structure tests always run.
"""

import os
import re
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml

from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.opengrep import RULES_DIR, RULES_PACKAGE, rule_ids, scan_sast_with_run

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")

# (rule, file name, must the rule flag it, code)
CASES: list[tuple[str, str, bool, str]] = [
    ('python-shell-command-from-data', 'sh1.py', True,
     'import subprocess\n'
     'def f(name):\n'
     '    subprocess.run("ls " + name, shell=True)\n'),
    ('python-shell-command-from-data', 'sh2.py', True,
     'import subprocess\n'
     'def f(cmd):\n'
     '    subprocess.Popen(cmd, shell=True, stdout=None)\n'),
    ('python-shell-command-from-data', 'sh3.py', True,
     'import os\n'
     'def f(path):\n'
     '    os.system(f"rm -rf {path}")\n'),
    ('python-shell-command-from-data', 'sh4.py', True,
     'import subprocess\n'
     'def f(x):\n'
     '    return subprocess.getoutput("cat " + x)\n'),
    ('python-shell-command-from-data', 'sh-ok1.py', False,
     'import subprocess\n'
     'def f(name):\n'
     '    subprocess.run(["ls", name])\n'),
    ('python-shell-command-from-data', 'sh-ok2.py', False,
     'import subprocess, os\n'
     'subprocess.run("ls -l", shell=True)\n'
     'os.system("true")\n'),
    ('python-code-evaluated-from-data', 'ev1.py', True,
     'def f(expr):\n'
     '    return eval(expr)\n'),
    ('python-code-evaluated-from-data', 'ev2.py', True,
     'def f(src):\n'
     '    exec(src, {})\n'),
    ('python-code-evaluated-from-data', 'ev-ok.py', False,
     'x = eval("1 + 1")\n'
     'import ast\n'
     'def f(s):\n'
     '    return ast.literal_eval(s)\n'),
    ('python-sql-built-from-strings', 'sql1.py', True,
     'def f(cur, uid):\n'
     '    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'),
    ('python-sql-built-from-strings', 'sql2.py', True,
     'def f(conn, name):\n'
     '    conn.execute("SELECT * FROM t WHERE n = \'%s\'" % name)\n'),
    ('python-sql-built-from-strings', 'sql3.py', True,
     'def f(db, n):\n'
     '    db.executemany("DELETE FROM t WHERE n = " + n, [])\n'),
    ('python-sql-built-from-strings', 'sql4.py', True,
     'import sqlalchemy\n'
     'def f(s, n):\n'
     '    s.execute(sqlalchemy.text("SELECT {}".format(n)))\n'),
    ('python-sql-built-from-strings', 'sql-ok.py', False,
     'def f(cur, uid):\n'
     '    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
     '    cur.execute("SELECT 1")\n'),
    ('python-unsafe-deserialization', 'de1.py', True,
     'import pickle\n'
     'def f(data):\n'
     '    return pickle.loads(data)\n'),
    ('python-unsafe-deserialization', 'de2.py', True,
     'import yaml\n'
     'def f(text):\n'
     '    return yaml.load(text)\n'),
    ('python-unsafe-deserialization', 'de3.py', True,
     'import yaml\n'
     'def f(text):\n'
     '    return yaml.load(text, Loader=yaml.Loader)\n'),
    ('python-unsafe-deserialization', 'de-ok.py', False,
     'import yaml, json\n'
     'def f(text):\n'
     '    yaml.safe_load(text)\n'
     '    yaml.load(text, Loader=yaml.SafeLoader)\n'
     '    return json.loads(text)\n'),
    ('python-tls-verification-disabled', 'tls1.py', True,
     'import requests\n'
     'def f(u):\n'
     '    return requests.get(u, verify=False)\n'),
    ('python-tls-verification-disabled', 'tls2.py', True,
     'import httpx\n'
     'def f(u):\n'
     '    return httpx.post(u, json={}, verify=False)\n'),
    ('python-tls-verification-disabled', 'tls-ok.py', False,
     'import requests\n'
     'def f(u):\n'
     '    return requests.get(u, timeout=5)\n'),
    ('python-debug-mode-enabled', 'dbg1.py', True,
     'from flask import Flask\n'
     'app = Flask(__name__)\n'
     'app.run(host="0.0.0.0", debug=True)\n'),
    ('python-debug-mode-enabled', 'dbg2.py', True,
     'import fastapi\n'
     'app = fastapi.FastAPI(debug=True)\n'),
    ('python-debug-mode-enabled', 'dbg-ok.py', False,
     'from flask import Flask\n'
     'app = Flask(__name__)\n'
     'app.run(debug=False)\n'),
    ('python-jwt-signature-not-verified', 'jwt1.py', True,
     'import jwt\n'
     'def f(t):\n'
     '    return jwt.decode(t, options={"verify_signature": False})\n'),
    ('python-jwt-signature-not-verified', 'jwt2.py', True,
     'import jwt\n'
     'def f(t, k):\n'
     '    return jwt.decode(t, k, algorithms=["HS256", "none"])\n'),
    ('python-jwt-signature-not-verified', 'jwt-ok.py', False,
     'import jwt\n'
     'def f(t, k):\n'
     '    return jwt.decode(t, k, algorithms=["HS256"])\n'),
    ('js-shell-command-from-data', 'cp1.js', True,
     'const cp = require("child_process");\n'
     'function f(name) {\n'
     '  cp.exec("ls " + name);\n'
     '}\n'),
    ('js-shell-command-from-data', 'cp2.ts', True,
     'import { execSync } from "child_process";\n'
     'export function f(dir: string) {\n'
     '  execSync(`rm -rf ${dir}`);\n'
     '}\n'),
    ('js-shell-command-from-data', 'cp-ok.js', False,
     'const cp = require("child_process");\n'
     'cp.exec("ls -l");\n'
     'const db = { exec: (q) => q };\n'
     'function g(q) { return db.exec(q); }\n'),
    ('js-code-evaluated-from-data', 'jev1.js', True,
     'function f(src) {\n'
     '  return eval(src);\n'
     '}\n'),
    ('js-code-evaluated-from-data', 'jev2.js', True,
     'function f(body) {\n'
     '  return new Function("a", body);\n'
     '}\n'),
    ('js-code-evaluated-from-data', 'jev-ok.js', False,
     'const x = eval("1 + 1");\n'
     'const g = JSON.parse("{}");\n'),
    ('js-html-from-data', 'xss1.js', True,
     'function f(el, name) {\n'
     '  el.innerHTML = "<b>" + name + "</b>";\n'
     '}\n'),
    ('js-html-from-data', 'xss2.ts', True,
     'export function f(html: string) {\n'
     '  document.write(html);\n'
     '}\n'),
    ('js-html-from-data', 'xss-ok.js', False,
     'function f(el, name) {\n'
     '  el.textContent = name;\n'
     '  el.innerHTML = "<b>static</b>";\n'
     '}\n'),
    ('js-tls-verification-disabled', 'jtls1.js', True,
     'const https = require("https");\n'
     'const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });\n'),
    ('js-tls-verification-disabled', 'jtls2.js', True,
     'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'),
    ('js-tls-verification-disabled', 'jtls-ok.js', False,
     'const https = require("https");\n'
     'const agent = new https.Agent({ rejectUnauthorized: true });\n'),
]  # fmt: skip


def _rules() -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for entry in files(RULES_PACKAGE).joinpath(RULES_DIR).iterdir():
        if entry.name.endswith(".yaml"):
            rules += yaml.safe_load(entry.read_text(encoding="utf-8"))["rules"]
    return rules


def test_every_rule_has_code_it_flags_and_code_it_leaves_alone() -> None:
    flagged = {rule for rule, _, expected, _ in CASES if expected}
    spared = {rule for rule, _, expected, _ in CASES if not expected}
    assert flagged == spared == set(rule_ids()), "a rule without both kinds of cases is not pinned"
    assert len({name for _, name, _, _ in CASES}) == len(CASES), "one file per case"


@pytest.mark.parametrize("rule", _rules(), ids=lambda rule: str(rule["id"]))
def test_every_rule_carries_what_a_finding_needs(rule: dict[str, Any]) -> None:
    assert re.fullmatch(r"(python|js)-[a-z0-9-]+", rule["id"])
    assert rule["severity"] in {"ERROR", "WARNING"}
    metadata = rule["metadata"]
    assert metadata["title"] and metadata["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert metadata["cwe"] and all(re.fullmatch(r"CWE-[0-9]+", cwe) for cwe in metadata["cwe"])
    assert "$" not in rule["message"], "a message never interpolates code: no code reaches a finding"


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
@pytest.mark.integration
def test_the_rules_flag_exactly_the_vulnerable_cases(tmp_path: Path) -> None:
    target = tmp_path / "samples"
    target.mkdir()
    for _, name, _, code in CASES:
        (target / name).write_text(code)
    scan = scan_sast_with_run(target, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    found = {(result["check_id"], Path(result["path"]).name) for result in scan.results}
    expected = {(rule, name) for rule, name, flag, _ in CASES if flag}
    assert found == expected, {"missed": sorted(expected - found), "unexpected": sorted(found - expected)}
    assert scan.warnings == []
