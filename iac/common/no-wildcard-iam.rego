# iac/common/no-wildcard-iam.rego
package common.iam.no_wildcard

import future.keywords.if
import future.keywords.in

# Title:   IAM policies must not use wildcard (*) actions or resources
# Control: SOC2-CC6.2, CIS-ALL
# Applies: OpenTofu plan JSON — cloud-agnostic (Azure role definitions,
#          AWS IAM policies)
#
# Wildcard IAM grants violate the principle of least privilege and allow
# privilege escalation. A single over-privileged role can compromise an
# entire cloud tenant (SOC2 CC6.2).

# Azure role definitions — check for wildcard actions in custom role definitions
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_definition"
    perm := resource.change.after.permissions[_]
    action := perm.actions[_]
    action == "*"
    msg := sprintf(
        "DENY [SOC2-CC6.2] Role definition '%s': wildcard action '*' in permissions.actions. Use explicit action strings (e.g. 'Microsoft.Storage/storageAccounts/read'). Wildcard grants violate least-privilege (SOC2 CC6.2).",
        [resource.name],
    )
}

# AWS IAM policies — check for wildcard in Action field
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    doc := json.unmarshal(resource.change.after.policy)
    stmt := doc.Statement[_]
    is_wildcard_action(stmt.Action)
    msg := sprintf(
        "DENY [SOC2-CC6.2] IAM policy '%s': wildcard Action '%v' found in Statement. Use explicit Action strings. Wildcard grants violate least-privilege (SOC2 CC6.2).",
        [resource.name, stmt.Action],
    )
}

# AWS IAM policies — check for wildcard in Resource field on Allow statements
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    doc := json.unmarshal(resource.change.after.policy)
    stmt := doc.Statement[_]
    stmt.Effect == "Allow"
    is_wildcard_resource(stmt.Resource)
    msg := sprintf(
        "DENY [SOC2-CC6.2] IAM policy '%s': wildcard Resource '*' in an Allow statement. Scope resources to specific ARNs. Wildcard resource grants violate least-privilege (SOC2 CC6.2).",
        [resource.name],
    )
}

is_wildcard_action(action) if action == "*"

is_wildcard_action(action) if {
    is_array(action)
    action[_] == "*"
}

is_wildcard_resource(resource) if resource == "*"

is_wildcard_resource(resource) if {
    is_array(resource)
    resource[_] == "*"
}
