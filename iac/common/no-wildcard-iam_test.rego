package common.iam.no_wildcard_test

import future.keywords.if
import future.keywords.in
import data.common.iam.no_wildcard

# --- Azure: wildcard action in role definition ---
test_deny_azure_wildcard_action if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "role-team-alpha-custom",
            "type": "azurerm_role_definition",
            "change": {
                "after": {
                    "permissions": [{
                        "actions": ["*"],
                        "not_actions": []
                    }]
                }
            }
        }]
    }
    count(result) == 1
    result[_] contains "wildcard action"
}

# --- Azure: specific action is allowed ---
test_pass_azure_specific_action if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "role-team-alpha-reader",
            "type": "azurerm_role_definition",
            "change": {
                "after": {
                    "permissions": [{
                        "actions": [
                            "Microsoft.Storage/storageAccounts/read",
                            "Microsoft.Storage/storageAccounts/listKeys/action"
                        ],
                        "not_actions": []
                    }]
                }
            }
        }]
    }
    count(result) == 0
}

# --- AWS: wildcard Action string ---
test_deny_aws_wildcard_action_string if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "policy-team-beta-admin",
            "type": "aws_iam_policy",
            "change": {
                "after": {
                    "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}"
                }
            }
        }]
    }
    count(result) >= 1
    result[_] contains "wildcard Action"
}

# --- AWS: wildcard Resource in Allow statement ---
test_deny_aws_wildcard_resource if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "policy-team-beta-s3",
            "type": "aws_iam_policy",
            "change": {
                "after": {
                    "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
                }
            }
        }]
    }
    count(result) >= 1
    result[_] contains "wildcard Resource"
}

# --- AWS: scoped policy passes ---
test_pass_aws_scoped_policy if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "policy-team-gamma-s3-reader",
            "type": "aws_iam_policy",
            "change": {
                "after": {
                    "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}"
                }
            }
        }]
    }
    count(result) == 0
}

# --- Pass: unrelated resource type is ignored ---
test_pass_unrelated_resource if {
    result := no_wildcard.deny with input as {
        "resource_changes": [{
            "name": "rg-team-alpha",
            "type": "azurerm_resource_group",
            "change": {"after": {"location": "eastus"}}
        }]
    }
    count(result) == 0
}
