# METADATA
# title: IAM policy grants every action on every resource
# description: >-
#   An IAM policy statement that allows every action ("*" or "*:*") on every resource ("*") gives full
#   administrator access to whoever holds the policy, whatever the conditions. Trivy's own checks do not report
#   it (ADR-0012): this check belongs to SentinelCI and is loaded from SentinelCI's configuration, never from
#   the scanned repository.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege
# custom:
#   id: SENTINEL-AWS-0001
#   avd_id: SENTINEL-AWS-0001
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: no-full-admin-policy
#   recommended_action: Allow only the actions the holder needs, on the resources it needs them on.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package sentinelci.aws.iam.sentinel_aws_0001

import rego.v1

# Every policy document Trivy adapted from the configuration (Terraform, or CloudFormation YAML): the policies
# it declares, and the inline policies of the roles, users and groups it declares. Not seen, because Trivy does
# not adapt them: a policy attached by ARN (such as the AWS-managed AdministratorAccess), whose document is not
# in the configuration; a policy attached to a role, user or group the configuration does not declare; a
# Terraform policy read with file() or templatefile(); a CloudFormation AWS::IAM::ManagedPolicy; and any policy
# of a CloudFormation JSON template (Trivy adapts no IAM policy from JSON). Not this check: an Allow with
# NotAction on every resource (broad, but not every action).
policies contains policy if {
	some policy in input.aws.iam.policies
}

policies contains policy if {
	some kind in ["roles", "users", "groups"]
	some holder in input.aws.iam[kind]
	some policy in holder.policies
}

# An action pattern made only of IAM wildcards matches every action: "*" and "*:*", but also "**" or "*:?*".
every_action(action) if regex.match(`^[*?]*\*[*?]*(:[*?]*\*[*?]*)?$`, action)

# "*" among the resources, or NotResource (every resource but the ones it names) with no Resource.
every_resource(statement) if "*" in statement.Resource

every_resource(statement) if {
	is_array(statement.NotResource)
	count(statement.NotResource) > 0
	not "*" in statement.NotResource
	not is_array(statement.Resource)
}

full_admin(statement) if {
	statement.Effect == "Allow"
	some action in statement.Action
	every_action(action)
	every_resource(statement)
}

deny contains res if {
	some policy in policies
	document := json.unmarshal(policy.document.value)
	some statement in document.Statement
	full_admin(statement)
	res := result.new(
		sprintf("IAM policy %q allows every action on every resource", [policy.name.value]),
		policy.document,
	)
}
