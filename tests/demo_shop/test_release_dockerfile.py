"""shop-api's release Dockerfile (ADR-0011, decision 6; task A9): what makes it the hardened image, checked on
the file, and against the pinned Trivy (opt-in with SENTINEL_TOOLS_DIR, like the other real-tool tests).

The image itself is built by `make release` once B9's application and requirements files exist; nothing here
builds it.
"""

import os
import re
import shutil
from pathlib import Path

import pytest

from sentinelci.remediation.dockerfile import NON_ROOT_USER
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.trivy import scan_iac_with_run

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "demo-shop" / "services" / "shop-api"
DOCKERFILE = SERVICE / "Dockerfile.release"
IGNORE = SERVICE / "Dockerfile.release.dockerignore"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
BASE = re.compile(r"^python:3\.12\.[0-9]+-slim-[a-z]+@sha256:[a-f0-9]{64}$")


def instructions() -> list[tuple[str, str]]:
    """(keyword, its arguments with continuations joined), in order; comments and blank lines skipped."""
    found: list[tuple[str, str]] = []
    pending = ""
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending = f"{pending} {stripped.removesuffix(chr(92)).strip()}".strip()
        if not stripped.endswith(chr(92)):
            keyword, _, arguments = pending.partition(" ")
            found.append((keyword.upper(), arguments.strip()))
            pending = ""
    assert not pending, "the last instruction continues past the end of the file"
    return found


def final_stage() -> list[tuple[str, str]]:
    found = instructions()
    last_from = max(i for i, (keyword, _) in enumerate(found) if keyword == "FROM")
    return found[last_from:]


def test_the_base_is_python_312_slim_pinned_by_digest_and_every_stage_uses_it() -> None:
    found = instructions()
    (pinned,) = [text for keyword, text in found if keyword == "ARG" and text.startswith("PYTHON=")]
    assert BASE.fullmatch(pinned.removeprefix("PYTHON=")), pinned
    froms = [text.split()[0] for keyword, text in found if keyword == "FROM"]
    assert froms and set(froms) == {"${PYTHON}"}, "no stage from another, unpinned image"


def test_the_builder_frontend_is_never_pulled() -> None:
    first = DOCKERFILE.read_text(encoding="utf-8").splitlines()[0]
    assert not re.match(r"#\s*syntax\s*=", first, re.IGNORECASE), (
        "a `# syntax=` frontend is pulled at build time"
    )


def test_dependencies_are_hash_pinned_and_nothing_unlisted_is_installed() -> None:
    found = instructions()
    runs = [text for keyword, text in found if keyword == "RUN"]
    assert len(runs) == 1 and "--require-hashes" in runs[0] and "--no-deps" in runs[0]
    assert "ARG REQUIREMENTS=requirements.release.txt" in DOCKERFILE.read_text(encoding="utf-8")
    # Wheels only by default (Hiba's review of #69): no setup.py runs, and an sdist's build dependencies,
    # whose hashes pip does not check, never enter the release image. Only the BLOCK build turns it off.
    assert '--only-binary="${ONLY_BINARY}"' in runs[0]
    assert ("ARG", "ONLY_BINARY=:all:") in found
    assert not any(tool in run for run in runs for tool in ("curl", "wget", "apt-get", "| sh"))
    assert not [keyword for keyword, _ in found if keyword in ("ADD", "HEALTHCHECK")]


def test_the_final_stage_runs_nothing_as_root_and_listens_on_8080() -> None:
    stage = final_stage()
    keywords = [keyword for keyword, _ in stage]
    assert "RUN" not in keywords, "the final stage runs no shell step"
    assert ("USER", NON_ROOT_USER) in stage, "UID and GID 10001, the fixers' non-root user"
    assert keywords.index("USER") < keywords.index("CMD")
    assert ("EXPOSE", "8080") in stage
    assert stage[-1] == ("CMD", '["python", "-m", "app"]')
    copies = [text for keyword, text in stage if keyword == "COPY"]
    assert copies == ["--from=dependencies /opt/venv /opt/venv", "app/ ./app/"]


def test_the_build_context_is_an_allow_list_of_what_the_dockerfile_copies() -> None:
    rules = [
        line for line in IGNORE.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")
    ]
    assert rules == ["*", "!app/", "!requirements.release.txt", "!requirements.block.txt"]
    sources = {"requirements.release.txt", "requirements.block.txt", "app/"}
    copied = {
        text.split()[0] for keyword, text in instructions() if keyword == "COPY" and "--from" not in text
    }
    assert copied <= sources | {"${REQUIREMENTS}"}, "a COPY source outside the allow-list"


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
def test_the_pinned_trivy_reports_only_the_missing_healthcheck(tmp_path: Path) -> None:
    """DS-0026 (LOW) is by design: the cluster's probes check health. Anything else is a regression."""
    target = tmp_path / "shop-api"
    target.mkdir()
    shutil.copy(DOCKERFILE, target / DOCKERFILE.name)
    results, _ = scan_iac_with_run(
        target, lock=load_lock(ROOT / "tools.lock.toml"), tools_dir=Path(str(TOOLS_DIR)), repo_root=tmp_path
    )
    rules = sorted(
        misconfiguration["ID"]
        for result in results
        for misconfiguration in result.get("Misconfigurations") or []
        if misconfiguration.get("Status") == "FAIL"
    )
    assert rules == ["DS-0026"], rules
