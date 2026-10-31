"""The Trivy rule ids of misconfigurations that expose a service by themselves, pinned against the real Trivy.

SC-011 (policies/exposing.rego) blocks these when a change introduces them, whatever their score: a privileged
pod or a public bucket creates the exposure itself, so the risk model's exposure factor does not apply. The
gate matches them by `rule_id`, so a Trivy upgrade that renamed or dropped one of these checks would silently
turn SC-011 off for it. These tests run the pinned Trivy on one minimal configuration per listed id (each must
report its id) and on ordinary configurations that must report none of them (public HTTPS, EKS defaults, a
private bucket, Cloud SQL defaults), so the list stays both alive and quiet. The ids come from the file the
gate reads (`exposing_rule_ids`), not from a copy: a listed id without a probe, or a probe for an unlisted id,
fails without Trivy.

A Trivy bump must re-run these tests: `VERIFIED_WITH` records the version they last passed with, and a test
that needs no Trivy fails as soon as `tools.lock.toml` names another one.

Trivy 0.76.1 blind spots, which no listed id can catch (SC-011 is narrower than its name):
- a rule whose parent resource is not declared in the same configuration (a literal id or a variable, such
  as a group passed into a module) is not evaluated: SSH from 0.0.0.0/0 in an
  `aws_vpc_security_group_ingress_rule` (AWS provider v5), an Azure SQL firewall rule open to every address
  (AZU-0029) and a bucket IAM binding to `allUsers` (GCP-0001) then report nothing;
  `aws_security_group_rule` reports AWS-0107 either way;
- KSV-0121 covers hostPath `/`, `/etc` and `/proc`, not `/var/run`, the containerd socket or
  `/var/lib/kubelet`;
- `capabilities.add: [ALL]` reports KSV-0022 only, not KSV-0005 or KSV-0120;
- an S3 bucket policy with `Principal = "*"` does not report AWS-0092.

The configurations are written at run time: no deliberately insecure file is committed outside `demo-shop/`.
Opt-in like the other real-tool tests: set SENTINEL_TOOLS_DIR to a `sentinel tools install` directory.
"""

import os
from collections import defaultdict
from pathlib import Path, PurePosixPath

import pytest

from sentinelci.contracts.finding import Run, Tool
from sentinelci.normalize.trivy import normalize_trivy_config
from sentinelci.policy.exposing import exposing_rule_ids
from sentinelci.scanners.lock import load_lock
from sentinelci.scanners.trivy import scan_iac_with_run

REPO = Path(__file__).resolve().parents[3]
REPO_LOCK = REPO / "tools.lock.toml"
LISTED = exposing_rule_ids(REPO / "policies")  # the list the SC-011 gate reads
# The Trivy version these tests last passed with. Bump it only after running them with the new version.
VERIFIED_WITH = "0.76.1"
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


def _capabilities(*names: str) -> str:
    return _pod("p", "", f"      securityContext:\n        capabilities: {{add: [{', '.join(names)}]}}\n")


def _hostpath(path: str) -> str:
    return _pod(
        "p",
        f"  volumes:\n    - name: v\n      hostPath: {{path: {path}}}\n",
        "      volumeMounts: [{name: v, mountPath: /mnt/host}]\n",
    )


def _aws_ingress(port: int, source: str = "0.0.0.0/0") -> str:
    # With the egress rule real security groups declare (`aws_security_group` drops AWS's default one): it
    # reports AWS-0104, which must never be listed.
    return f"""resource "aws_security_group" "g" {{
  name        = "g"
  description = "probe"
  ingress {{
    description = "probe"
    from_port   = {port}
    to_port     = {port}
    protocol    = "tcp"
    cidr_blocks = ["{source}"]
  }}
  egress {{
    description = "any"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
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


def _azure_ingress(port: int, source: str = "*", name: str = "r") -> str:
    return f"""resource "azurerm_network_security_rule" "{name}" {{
  name                        = "{name}"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "{port}"
  source_address_prefix       = "{source}"
  destination_address_prefix  = "*"
  resource_group_name         = "probe"
  network_security_group_name = "probe"
}}
"""


def _azure_sql_firewall(end: str) -> str:
    # Trivy evaluates the rule only with its server in the same configuration.
    return f"""resource "azurerm_mssql_server" "s" {{
  name                = "probe"
  resource_group_name = "probe"
  location            = "westeurope"
  version             = "12.0"
}}
resource "azurerm_mssql_firewall_rule" "r" {{
  name             = "r"
  server_id        = azurerm_mssql_server.s.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "{end}"
}}
"""


def _bigquery(special_group: str) -> str:
    return f"""resource "google_bigquery_dataset" "d" {{
  dataset_id = "probe"
  access {{
    role          = "READER"
    special_group = "{special_group}"
  }}
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


# A resource Trivy always reports with unlisted ids, added to quiet cases that report nothing by themselves:
# the control below then proves their file was parsed.
GCP_WITNESS = 'resource "google_storage_bucket" "witness" {\n  name     = "witness"\n  location = "EU"\n}\n'
AZURE_WITNESS = _azure_ingress(443, name="witness")  # AZU-0047, excluded from the list

# One probe per id of policies/exposing.rego: rule id -> (file name, minimal configuration reporting it).
EXPOSING: dict[str, tuple[str, str]] = {
    # A container that can take over its node.
    "KSV-0017": ("pod.yaml", _pod("p", "", "      securityContext: {privileged: true}\n")),
    "KSV-0009": ("pod.yaml", _pod("p", "  hostNetwork: true\n")),
    "KSV-0010": ("pod.yaml", _pod("p", "  hostPID: true\n")),
    "KSV-0008": ("pod.yaml", _pod("p", "  hostIPC: true\n")),
    "KSV-0005": ("pod.yaml", _capabilities("SYS_ADMIN")),
    "KSV-0120": ("pod.yaml", _capabilities("SYS_MODULE")),  # kernel modules
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
    "GCP-0046": ("main.tf", _bigquery("allAuthenticatedUsers")),
    "AZU-0007": (
        "main.tf",
        'resource "azurerm_storage_container" "c" {\n  name                  = "probe"\n'
        '  storage_account_name  = "probe"\n  container_access_type = "blob"\n}\n',
    ),
    "AZU-0029": ("main.tf", _azure_sql_firewall("255.255.255.255")),
    # Remote administration and database ports open to the internet. Rules on "any port from anywhere" are
    # left out: they also fire on a public HTTPS endpoint (see QUIET).
    "AWS-0107": ("main.tf", _aws_ingress(22)),
    "GCP-0071": ("main.tf", _gcp_ingress(22)),
    "GCP-0070": ("main.tf", _gcp_ingress(3389)),
    "AZU-0050": ("main.tf", _azure_ingress(22)),
    "AZU-0048": ("main.tf", _azure_ingress(3389)),
    "AZU-0074": ("main.tf", _azure_ingress(3306)),
}

# Ordinary configurations that must report none of the listed ids: each one would be a false positive SC-011
# turns into a BLOCK. Name -> (file name, configuration). Every case must report at least one (unlisted) id.
QUIET: dict[str, tuple[str, str]] = {
    "aws-public-https": ("main.tf", _aws_ingress(443)),
    "aws-rdp-from-a-private-range": ("main.tf", _aws_ingress(3389, "10.0.0.0/8")),
    "gcp-public-https": ("main.tf", _gcp_ingress(443)),
    "azure-public-https": ("main.tf", _azure_ingress(443)),
    "azure-postgres-from-the-vnet": ("main.tf", _azure_ingress(5432, "VirtualNetwork") + AZURE_WITNESS),
    # 0.0.0.0-0.0.0.0 is Azure's "allow Azure services" rule (a firewall range here, not a bind address).
    "azure-sql-allows-azure-services": ("main.tf", _azure_sql_firewall("0.0.0.0")),  # noqa: S104
    "eks-defaults": (
        "main.tf",
        'resource "aws_eks_cluster" "c" {\n  name     = "probe"\n'
        '  role_arn = "arn:aws:iam::000000000000:role/probe"\n'
        '  vpc_config {\n    subnet_ids = ["subnet-00000000"]\n  }\n}\n',
    ),
    # The provider default gives Cloud SQL a public IP: GCP-0017 fires on it (and on an office-only range), so
    # GCP-0017 is not listed.
    "cloud-sql-defaults": (
        "main.tf",
        'resource "google_sql_database_instance" "d" {\n  name             = "probe"\n'
        '  database_version = "POSTGRES_15"\n  settings {\n    tier = "db-f1-micro"\n  }\n}\n',
    ),
    "bigquery-project-readers": ("main.tf", _bigquery("projectReaders") + GCP_WITNESS),
    "private-bucket-without-access-block": ("main.tf", 'resource "aws_s3_bucket" "b" { bucket = "probe" }\n'),
    "private-database": ("main.tf", _rds(public=False)),
    "log-directory-hostpath": ("pod.yaml", _hostpath("/var/log/app")),
    "net-bind-service": ("pod.yaml", _capabilities("NET_BIND_SERVICE")),
    "ptrace-and-raw-sockets": ("pod.yaml", _capabilities("SYS_PTRACE", "NET_RAW")),
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
    assert run.version == VERIFIED_WITH
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


def test_every_listed_id_has_one_probe_and_the_quiet_cases_are_distinct() -> None:
    assert set(EXPOSING) == LISTED, f"probes and exposing.rego differ: {sorted(set(EXPOSING) ^ LISTED)}"
    assert not set(EXPOSING) & set(QUIET)


def test_a_trivy_bump_reruns_these_tests() -> None:
    """Runs without Trivy: a lock that names another Trivy fails here until the real tests pass with it."""
    locked = load_lock(REPO_LOCK).tools["trivy"].version
    assert locked == VERIFIED_WITH, (
        f"tools.lock.toml pins Trivy {locked}, but the SC-011 rule ids were verified with {VERIFIED_WITH}: "
        "run this file with SENTINEL_TOOLS_DIR set, fix the list or the probes, then update VERIFIED_WITH"
    )


@real
@pytest.mark.integration
def test_the_pinned_trivy_reports_every_listed_id(tmp_path: Path) -> None:
    _write(tmp_path, EXPOSING)
    found = _rules_by_case(tmp_path)
    missing = {rule_id for rule_id in EXPOSING if rule_id not in found[rule_id]}
    assert not missing, f"the pinned Trivy no longer reports {sorted(missing)}: update the SC-011 list"


@real
@pytest.mark.integration
def test_ordinary_configurations_report_no_listed_id(tmp_path: Path) -> None:
    _write(tmp_path, QUIET)
    found = _rules_by_case(tmp_path)
    assert set(found) == set(QUIET), f"control: Trivy reported nothing for {sorted(set(QUIET) - set(found))}"
    noisy = {name: sorted(rules & LISTED) for name, rules in found.items() if rules & LISTED}
    assert not noisy, f"SC-011 would block ordinary configurations: {noisy}"
