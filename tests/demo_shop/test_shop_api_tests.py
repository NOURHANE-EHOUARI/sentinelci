"""shop-api's own tests and their image (B9, ADR-0014), checked from SentinelCI's side.

shop-api's code never runs here (CLAUDE.md: demo-shop's code runs only in a container). These tests read
files; the last ones run shop-api's tests in the test image, in the sandbox A6's `llm:code` check uses, when
SENTINEL_SHOP_TEST_IMAGE names that image (`docker build -f demo-shop/services/shop-api/Dockerfile.test -q
demo-shop/services/shop-api`). They show both halves of what makes the tests worth something:
- on the seeded code, the behaviour tests pass and every security test fails (each seed is real);
- with the reference fix (fixtures/shop_api_reference_fix.py), everything passes (each seed can be fixed,
  and a fix keeps the behaviour).
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from sentinelci.remediation.code import service_of
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.trivy import scan_iac_with_run

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "demo-shop" / "services" / "shop-api"
SECURITY = SERVICE / "security_tests"
BEHAVIOUR = SERVICE / "tests"
DOCKERFILE = SERVICE / "Dockerfile.test"
REFERENCE_FIX = Path(__file__).parent / "fixtures" / "shop_api_reference_fix.py"
TEST_IMAGE = os.environ.get("SENTINEL_SHOP_TEST_IMAGE")
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
# The sandbox of A6's `llm:code` check (cli/src/sentinelci/remediation/code.py, ADR-0014 decision 3).
SANDBOX = (
    "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--user", "65534:65534", "--pids-limit", "256", "--memory", "1g", "--cpus", "2",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 (a tmpfs inside the container, not a host path)
    "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
)  # fmt: skip
REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")


def sast_seeds() -> list[dict[str, object]]:
    truth = yaml.safe_load(
        (ROOT / "demo-shop" / "ground-truth" / "findings.yaml").read_text(encoding="utf-8")
    )
    return [seed for seed in truth["seeds"] if seed["category"] == "SAST"]


def python_sast_seeds() -> list[dict[str, object]]:
    """The SAST seeds a security test proves: those in a Python file. The verified fix rate's scope rule
    (decided 17 November, before the 27 November run): the code fixer's check (A6, ADR-0014 decision 3)
    verifies Python only, with pytest in this service's test image, so a SAST seed in another language (the
    web service's JavaScript, GT-SAST-007 to 010) has no security test and is listed as not attempted."""
    return [seed for seed in sast_seeds() if str(seed["location"]["path"]).endswith(".py")]  # type: ignore[index]


def security_test_of(rule: str) -> Path:
    return SECURITY / f"test_{rule.replace('-', '_')}.py"


def pins(path: Path) -> dict[str, list[str]]:
    """Every requirement of a hash-pinned file: name -> its hashes."""
    found: dict[str, list[str]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT.match(line)
        if match:
            current = match.group(1).lower()
            found[current] = []
        elif line.strip().startswith("--hash=sha256:") and current is not None:
            found[current].append(line.strip().removesuffix("\\").strip())
        elif line.strip() and not line.startswith("#"):
            raise AssertionError(f"{path.name}: not a pinned requirement or a hash: {line!r}")
    return found


# ---------------------------------------------------------------- the files


@pytest.mark.parametrize("seed", python_sast_seeds(), ids=lambda seed: str(seed["id"]))
def test_every_python_sast_seed_has_its_own_security_test(seed: dict[str, object]) -> None:
    (detection,) = seed["expected"]["detections"]  # type: ignore[index]
    test_file = security_test_of(detection["rule"])
    assert test_file.is_file(), f"{seed['id']}: {test_file.relative_to(ROOT)} is missing"
    assert str(seed["id"]) in test_file.read_text(encoding="utf-8"), "the test names the seed it proves"


def test_every_security_test_is_a_seeds() -> None:
    rules = {d["rule"] for seed in python_sast_seeds() for d in seed["expected"]["detections"]}  # type: ignore[attr-defined]
    expected = {security_test_of(rule).name for rule in rules}
    assert {path.name for path in SECURITY.glob("test_*.py")} == expected


def test_a_sast_seed_in_another_language_is_never_attempted() -> None:
    """The scope rule (python_sast_seeds): A6's check finds no service with behaviour tests above a seed
    that is not Python, so `make remediate-code` lists its finding as not verifiable and never sends it to
    the model; and no security test is named after its rule."""
    others = [seed for seed in sast_seeds() if seed not in python_sast_seeds()]
    assert others, "the web service's JavaScript seeds"
    for seed in others:
        path = f"demo-shop/{seed['location']['path']}"  # type: ignore[index]
        assert service_of(ROOT, path) is None, f"{seed['id']}: {path} has tests above it"
        (detection,) = seed["expected"]["detections"]  # type: ignore[index]
        assert not security_test_of(detection["rule"]).exists(), seed["id"]


def test_the_behaviour_tests_are_where_the_check_looks_for_them() -> None:
    """A6's check runs the nearest `tests/` with a `test_*.py` file above the edited file."""
    assert list(BEHAVIOUR.glob("test_*.py")), "shop-api has behaviour tests"
    assert not (SERVICE / "app" / "tests").exists(), "no closer tests/ would shadow them"


def test_the_test_image_is_the_release_base_with_hash_pinned_wheels() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    release = (SERVICE / "Dockerfile.release").read_text(encoding="utf-8")
    (base,) = re.findall(r"^ARG PYTHON=(\S+)$", text, re.MULTILINE)
    assert base == re.findall(r"^ARG PYTHON=(\S+)$", release, re.MULTILINE)[0], "the release's own base"
    assert re.fullmatch(r"python:3\.12\.[0-9]+-slim-[a-z]+@sha256:[a-f0-9]{64}", base)
    install = " ".join(text.split("\\\n"))
    for flag in ("--require-hashes", "--no-deps", "--only-binary :all:"):
        assert flag in install
    for name in ("requirements.release.txt", "requirements.test.txt"):
        assert f"--requirement /tmp/{name}" in install
    assert re.findall(r"^FROM (\S+)", text, re.MULTILINE) == ["${PYTHON}"]
    assert re.search(r"^USER 65534:65534$", text, re.MULTILINE), "nobody, as the check runs it"
    assert "COPY app" not in text, "no application in the image: the check mounts the code it tests"


def test_the_test_image_build_context_is_the_two_requirements_files() -> None:
    lines = (SERVICE / "Dockerfile.test.dockerignore").read_text(encoding="utf-8").splitlines()
    entries = [line for line in lines if line and not line.startswith("#")]
    assert entries == ["*", "!requirements.release.txt", "!requirements.test.txt"]


def test_the_test_requirements_are_hash_pinned_and_repeat_no_release_pin() -> None:
    test = pins(SERVICE / "requirements.test.txt")
    release = pins(SERVICE / "requirements.release.txt")
    assert {"pytest", "httpx2"} <= set(test)
    assert all(hashes for hashes in test.values()), "every test requirement has its hashes"
    assert not set(test) & set(release), "pip refuses a package listed twice with --require-hashes"


@pytest.mark.skipif(not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory")
def test_the_pinned_trivy_reports_only_the_missing_healthcheck(tmp_path: Path) -> None:
    """DS-0026 (LOW) is by design, as for the release image: a test image runs no service to check. Anything
    else is a regression."""
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


# ---------------------------------------------------------------- in the test image (opt-in)

in_the_image = pytest.mark.skipif(
    not TEST_IMAGE or shutil.which("docker") is None,
    reason="set SENTINEL_SHOP_TEST_IMAGE to the image Dockerfile.test builds (and have Docker)",
)


def run_in_image(service: Path, *targets: str) -> subprocess.CompletedProcess[str]:
    """pytest in the test image, in the check's sandbox, with `service` mounted read-only at /srv."""
    command = [
        "docker", "run", "--rm", *SANDBOX,
        "--mount", f"type=bind,source={service},target=/srv,readonly", "--workdir", "/srv",
        str(TEST_IMAGE), "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header", *targets,
    ]  # fmt: skip
    return subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)


def copy_of_the_service(tmp_path: Path) -> Path:
    copy = tmp_path / "shop-api"
    for part in ("app", "tests", "security_tests"):
        shutil.copytree(SERVICE / part, copy / part)
    return copy


@in_the_image
def test_on_the_seeded_code_the_behaviour_tests_pass(tmp_path: Path) -> None:
    ran = run_in_image(copy_of_the_service(tmp_path), "tests")
    assert ran.returncode == 0, ran.stdout[-2000:]


@in_the_image
@pytest.mark.parametrize("seed", python_sast_seeds(), ids=lambda seed: str(seed["id"]))
def test_on_the_seeded_code_each_security_test_fails(tmp_path: Path, seed: dict[str, object]) -> None:
    """Each seed is real: its test fails with assertions (pytest exit 1), not with an error (exit 2 to 4)."""
    (detection,) = seed["expected"]["detections"]  # type: ignore[index]
    test_file = security_test_of(detection["rule"]).relative_to(SERVICE)
    ran = run_in_image(copy_of_the_service(tmp_path), str(test_file))
    assert ran.returncode == 1, ran.stdout[-2000:]
    assert " passed" not in ran.stdout.splitlines()[-1], "every case of the seed's test fails"


@in_the_image
def test_with_the_reference_fix_every_test_passes(tmp_path: Path) -> None:
    service = copy_of_the_service(tmp_path)
    shutil.copyfile(REFERENCE_FIX, service / "app" / "main.py")
    ran = run_in_image(service, "tests", "security_tests")
    assert ran.returncode == 0, ran.stdout[-2000:]
