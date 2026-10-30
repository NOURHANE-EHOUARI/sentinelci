# Misconfigurations that expose the service by themselves (rule SC-011, SPEC section 6.3). Owned by Track B.
#
# A privileged pod, a data store open to the internet or SSH/RDP open to the world creates the exposure itself,
# so the risk model's exposure factor (X, from sentinel.yaml) does not apply: SC-011 blocks these whatever
# their score, while every other misconfiguration keeps its risk-model priority (IaC weight 0.5).
#
# The ids are Trivy rule ids, as findings carry them in `rule_id`. Each one is pinned against the pinned Trivy
# by cli/tests/scanners/test_trivy_exposing.py (#28): a minimal configuration must report it, and ordinary
# ones (public HTTPS, EKS defaults, a private bucket) must not, so a Trivy upgrade that renames or drops a
# check fails that test instead of silently turning SC-011 off. Excluded after checking with the pinned Trivy:
# GCP-0027 and AZU-0047 (also fire on public HTTPS), AWS-0040/0041 (EKS defaults), AWS-0086/0087/0091/0093
# (a private bucket without a public access block), GCP-0017 (any Cloud SQL instance with a public IP, provider
# defaults and an office-only range included). The gate matches these ids on Trivy findings only.
# Trivy 0.76.1 blind spots, which no id here can catch: see cli/tests/scanners/test_trivy_exposing.py.
# Keep one id per line: sentinelci.policy.exposing reads them.
package sentinel.exposing

import rego.v1

rule_ids := {
	# node takeover from a pod
	"KSV-0017", # privileged container
	"KSV-0009", # hostNetwork
	"KSV-0010", # hostPID
	"KSV-0008", # hostIPC
	"KSV-0005", # SYS_ADMIN capability
	"KSV-0006", # Docker socket mounted
	"KSV-0121", # host root filesystem mounted
	"KSV-0120", # SYS_MODULE capability (kernel modules)
	# data stores open to the internet
	"AWS-0092", # S3 bucket public through its ACL
	"AWS-0180", # RDS instance publicly accessible
	"GCP-0001", # storage bucket readable by allUsers
	"AZU-0007", # storage container public
	"AZU-0029", # SQL server firewall open to every address
	"GCP-0046", # BigQuery dataset readable by allAuthenticatedUsers
	# SSH, RDP and other sensitive ports open to the internet
	"AWS-0107", # security group: SSH from 0.0.0.0/0
	"GCP-0071", # firewall: SSH from the internet
	"GCP-0070", # firewall: RDP from the internet
	"AZU-0050", # network security rule: SSH from the internet
	"AZU-0048", # network security rule: RDP from the internet
	"AZU-0074", # network security rule: database, FTP or telnet port from any source
}
