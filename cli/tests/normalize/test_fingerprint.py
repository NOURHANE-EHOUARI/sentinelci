"""Fingerprint rules of SPEC section 13.1, checked against an independent hashlib computation."""

import hashlib

import pytest

from sentinelci.normalize.fingerprint import (
    config_fingerprint,
    package_fingerprint,
    purl_base,
    sast_fingerprint,
    secret_fingerprint,
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_secret_fingerprint_follows_spec_formula() -> None:
    expected = _sha("generic-api-key|" + _sha("s3cr3t"))
    assert secret_fingerprint("generic-api-key", "s3cr3t") == expected


def test_secret_fingerprint_ignores_location() -> None:
    # Same credential leaked twice is one risk: the formula has no path or line.
    assert secret_fingerprint("r", "v") == secret_fingerprint("r", "v")
    assert secret_fingerprint("r", "v") != secret_fingerprint("r", "w")


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:pypi/example-lib@1.2.0", "pkg:pypi/example-lib"),
        ("pkg:npm/%40types/node@20.1.0", "pkg:npm/%40types/node"),
        # Qualifiers describe the environment, not the package: they are dropped (decision on PR #1).
        ("pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12", "pkg:deb/debian/openssl"),
        ("pkg:golang/github.com/x/net@v0.20.0#http2", "pkg:golang/github.com/x/net#http2"),
        ("pkg:pypi/no-version", "pkg:pypi/no-version"),
        # Non-canonical purls with an unencoded "@" in the namespace (some tools emit them).
        ("pkg:npm/@scope/left-pad@1.0.0", "pkg:npm/@scope/left-pad"),
        ("pkg:npm/@scope/left-pad", "pkg:npm/@scope/left-pad"),
    ],
)
def test_purl_base(purl: str, expected: str) -> None:
    assert purl_base(purl) == expected


def test_package_fingerprint_ignores_environment_qualifiers() -> None:
    # A base-image point release or another architecture must not make a finding look new in PR mode,
    # and Grype/Trivy (which emit different qualifiers) must dedupe to the same fingerprint.
    a = package_fingerprint(
        "CONTAINER", "CVE-2099-0002", "pkg:deb/debian/openssl@3.0.11-1?arch=amd64&distro=debian-12"
    )
    b = package_fingerprint(
        "CONTAINER", "CVE-2099-0002", "pkg:deb/debian/openssl@3.0.11-1?arch=arm64&distro=debian-12.7"
    )
    c = package_fingerprint("CONTAINER", "CVE-2099-0002", "pkg:deb/debian/openssl@3.0.11-1")
    assert a == b == c


def test_package_fingerprint_survives_version_change_of_the_same_vulnerability() -> None:
    before = package_fingerprint("SCA", "CVE-2099-0001", "pkg:pypi/example-lib@1.2.0")
    after = package_fingerprint("SCA", "CVE-2099-0001", "pkg:pypi/example-lib@1.2.3")
    assert before == after
    assert before == _sha("SCA|CVE-2099-0001|pkg:pypi/example-lib")


def test_sast_fingerprint_survives_whitespace_and_line_shifts() -> None:
    a = sast_fingerprint("rule.sqli", "app/db.py", "cur.execute(f'...{name}')")
    b = sast_fingerprint("rule.sqli", "app/db.py", "    cur.execute(f'...{name}')   \n")
    assert a == b
    assert a != sast_fingerprint("rule.sqli", "app/other.py", "cur.execute(f'...{name}')")


def test_config_fingerprint_formula() -> None:
    assert config_fingerprint("CKV_K8S_16", "infra/k8s/app.yaml", "Deployment.default.shop") == _sha(
        "CKV_K8S_16|infra/k8s/app.yaml|Deployment.default.shop"
    )
