"""The Trivy rule ids of misconfigurations that expose a service by themselves, pinned against the real Trivy.

SC-011 (Track B, `policies/`) blocks these when a change introduces them, whatever their score: a privileged
pod or a public bucket creates the exposure itself, so the risk model's exposure factor does not apply. The
gate matches them by `rule_id`, so a Trivy upgrade that renames or drops one of these checks would silently
turn SC-011 off for it. These tests run the pinned Trivy on one minimal configuration per id (each must report
its id) and on ordinary configurations that must report none of them (public HTTPS, EKS defaults, a private
bucket), so the list stays both alive and quiet.

The configurations are written at run time: no deliberately insecure file is committed outside `demo-shop/`.
Opt-in like the other real-tool tests: set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory.
"""

import os
from collections import defaultdict
from pathlib import Path, PurePosixPath

import pytest

from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.trivy import normalize_trivy_config
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.trivy import scan_iac_with_run

REPO_LOCK = Path(__file__).resolve().parents[3] / "tools.lock.toml"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
TOOLS_DIR = os.environ.get("SENTINEL_TOOLS_DIR")
real = pytest.mark.skipif(
    not TOOLS_DIR, reason="set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory"
)

DIGEST = "sha256:" + "0" * 64
IMAGE = f"registry.local/app@{DIGEST}"


def _pod(name: str, spec: str, container: str = "") -> str:
    return (
        f"apiVersion: v1\nkind: Pod\nmetadata: {{name: {name}}}\nspec:\n{spec}"
        f"  containers:\n    - name: c\n      image: {IMAGE}\n{container}"
    )


def _hostpath(path: str) -> str:
    return _pod(
        "p",
        f"  volumes:\n    - name: v\n      hostPath: {{path: {path}}}\n",
        "      volumeMounts: [{name: v, mountPath: /mnt/host}]\n",
    )


def _aws_ingress(port: int) -> str:
    return f"""resource "aws_security_group" "g" {{
  name        = "g"
  description = "probe"
  ingress {{
    description = "probe"
    from_port   = {port}
    to_port     = {port}
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
"""


def _gcp_ingress(port: int) -> str:
    return f"""resource "google_compute_firewall" "f" {{
  name    = "f"
  network = "default"
  allow {{
    protocol = "tcp"
    ports    = ["{port}"]
  }}
  source_ranges = ["0.0.0.0/0"]
}}
"""


def _azure_ingress(port: int) -> str:
    return f"""resource "azurerm_network_security_rule" "r" {{
  name                        = "r"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "{port}"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "probe"
  network_security_group_name = "probe"
}}
"""


def _rds(*, public: bool) -> str:
    return f"""resource "aws_db_instance" "d" {{
  identifier          = "probe"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = {str(public).lower()}
  storage_encrypted   = true
}}
"""


# The proposed SC-011 list: rule id -> (file name, minimal configuration that must report it).
EXPOSING: dict[str, tuple[str, str]] = {
    # A container that can take over its node.
    "KSV-0017": ("pod.yaml", _pod("p", "", "      securityContext: {privileged: true}\n")),
    "KSV-0009": ("pod.yaml", _pod("p", "  hostNetwork: true\n")),
    "KSV-0010": ("pod.yaml", _pod("p", "  hostPID: true\n")),
    "KSV-0008": ("pod.yaml", _pod("p", "  hostIPC: true\n")),
    "KSV-0005": (
        "pod.yaml",
        _pod("p", "", "      securityContext:\n        capabilities: {add: [SYS_ADMIN]}\n"),
    ),
    "KSV-0006": ("pod.yaml", _hostpath("/var/run/docker.sock")),
    "KSV-0121": ("pod.yaml", _hostpath("/")),
    # Data stores open to the internet.
    "AWS-0092": (
        "main.tf",
        'resource "aws_s3_bucket" "b" { bucket = "probe" }\n'
        'resource "aws_s3_bucket_acl" "b" {\n  bucket = aws_s3_bucket.b.id\n  acl    = "public-read"\n}\n',
    ),
    "AWS-0180": ("main.tf", _rds(public=True)),
    "GCP-0001": (  # Trivy evaluates the binding of a bucket the configuration declares
        "main.tf",
        'resource "google_storage_bucket" "b" {\n  name     = "probe"\n  location = "EU"\n}\n'
        'resource "google_storage_bucket_iam_binding" "b" {\n  bucket  = google_storage_bucket.b.name\n'
        '  role    = "roles/storage.objectViewer"\n  members = ["allUsers"]\n}\n',
    ),
    "GCP-0017": (
        "main.tf",
        'resource "google_sql_database_instance" "d" {\n  name             = "probe"\n'
        '  database_version = "POSTGRES_15"\n  settings {\n    tier = "db-f1-micro"\n'
        "    ip_configuration {\n      ipv4_enabled = true\n"
        '      authorized_networks {\n        name  = "world"\n        value = "0.0.0.0/0"\n      }\n'
        "    }\n  }\n}\n",
    ),
    "AZU-0007": (
        "main.tf",
        'resource "azurerm_storage_container" "c" {\n  name                  = "probe"\n'
        '  storage_account_name  = "probe"\n  container_access_type = "blob"\n}\n',
    ),
    # Remote administration open to the internet (SSH, RDP). Rules on "any port from anywhere" are left out:
    # they also fire on a public HTTPS endpoint (see QUIET).
    "AWS-0107": ("main.tf", _aws_ingress(22)),
    "GCP-0071": ("main.tf", _gcp_ingress(22)),
    "GCP-0070": ("main.tf", _gcp_ingress(3389)),
    "AZU-0050": ("main.tf", _azure_ingress(22)),
    "AZU-0048": ("main.tf", _azure_ingress(3389)),
}

# Ordinary configurations that must report none of the ids above: each one is a false positive SC-011 would
# turn into a BLOCK. Name -> (file name, configuration).
QUIET: dict[str, tuple[str, str]] = {
    "aws-public-https": ("main.tf", _aws_ingress(443)),
    "aws-rdp-from-a-private-range": ("main.tf", _aws_ingress(3389).replace("0.0.0.0/0", "10.0.0.0/8")),
    "gcp-public-https": ("main.tf", _gcp_ingress(443)),
    "azure-public-https": ("main.tf", _azure_ingress(443)),
    "eks-defaults": (
        "main.tf",
        'resource "aws_eks_cluster" "c" {\n  name     = "probe"\n'
        '  role_arn = "arn:aws:iam::000000000000:role/probe"\n'
        '  vpc_config {\n    subnet_ids = ["subnet-00000000"]\n  }\n}\n',
    ),
    "private-bucket-without-access-block": ("main.tf", 'resource "aws_s3_bucket" "b" { bucket = "probe" }\n'),
    "private-database": ("main.tf", _rds(public=False)),
    "log-directory-hostpath": ("pod.yaml", _hostpath("/var/log/app")),
    "net-bind-service": (
        "pod.yaml",
        _pod("p", "", "      securityContext:\n        capabilities: {add: [NET_BIND_SERVICE]}\n"),
    ),
    "plain-pod": ("pod.yaml", _pod("p", "")),
}


def _write(root: Path, cases: dict[str, tuple[str, str]]) -> None:
    for name, (file_name, text) in cases.items():
        case = root / name
        case.mkdir(parents=True)
        (case / file_name).write_text(text, encoding="utf-8")


def _rules_by_case(root: Path) -> dict[str, set[str]]:
    """One real Trivy run over every case directory: the rule ids reported in each."""
    results, run = scan_iac_with_run(root, lock=load_lock(REPO_LOCK), tools_dir=Path(str(TOOLS_DIR)))
    findings = normalize_trivy_config(
        results,
        run=Run(repo="NOURHANE-EHOUARI/sentinelci", commit=COMMIT, context="pr"),
        tool=Tool(name="trivy", version=run.version),
    )
    found: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        assert finding.location is not None and finding.category == "IAC"
        found[PurePosixPath(finding.location.path).parts[0]].add(finding.rule_id)
    return found


def test_every_id_has_one_configuration_and_the_ids_are_distinct_from_the_quiet_cases() -> None:
    assert len(EXPOSING) == len(set(EXPOSING))
    assert not set(EXPOSING) & set(QUIET)
    for rule_id in EXPOSING:
        prefix, number = rule_id.split("-")
        assert prefix in {"KSV", "AWS", "GCP", "AZU"} and len(number) == 4 and number.isdigit(), rule_id


@real
@pytest.mark.integration
def test_the_pinned_trivy_reports_every_exposing_id(tmp_path: Path) -> None:
    _write(tmp_path, EXPOSING)
    found = _rules_by_case(tmp_path)
    missing = {rule_id for rule_id in EXPOSING if rule_id not in found[rule_id]}
    assert not missing, f"the pinned Trivy no longer reports {sorted(missing)}: update the SC-011 list"


@real
@pytest.mark.integration
def test_ordinary_configurations_report_no_exposing_id(tmp_path: Path) -> None:
    _write(tmp_path, QUIET)
    found = _rules_by_case(tmp_path)
    noisy = {name: sorted(rules & set(EXPOSING)) for name, rules in found.items() if rules & set(EXPOSING)}
    assert not noisy, f"SC-011 would block ordinary configurations: {noisy}"
    assert found["plain-pod"], "control: Trivy did scan the quiet cases"
