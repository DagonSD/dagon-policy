package azure.storage.no_public_access_test

import future.keywords.if
import future.keywords.in
import data.azure.storage.no_public_access

# --- Deny: public access explicitly true ---
test_deny_public_access_true if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "st-team-alpha-prod",
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "allow_blob_public_access": true,
                    "name": "stteamalphaprod"
                }
            }
        }]
    }
    count(result) == 1
    result[_] contains "allow_blob_public_access must be false"
}

# --- Deny: allow_blob_public_access key absent (unsafe default) ---
test_deny_missing_key if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "st-team-beta-prod",
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "name": "stteambetaprod"
                }
            }
        }]
    }
    count(result) == 1
    result[_] contains "allow_blob_public_access is not set"
}

# --- Pass: public access explicitly false ---
test_pass_public_access_false if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "st-team-gamma-prod",
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "allow_blob_public_access": false,
                    "name": "stteamgammaprod"
                }
            }
        }]
    }
    count(result) == 0
}

# --- Pass: unrelated resource type is ignored ---
test_pass_unrelated_resource if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "rg-team-alpha",
            "type": "azurerm_resource_group",
            "change": {
                "after": {
                    "location": "eastus"
                }
            }
        }]
    }
    count(result) == 0
}
