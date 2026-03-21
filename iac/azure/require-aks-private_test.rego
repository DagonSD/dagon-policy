package azure.aks.require_private_cluster_test

import future.keywords.if
import future.keywords.in
import data.azure.aks.require_private_cluster

# --- Deny: cluster is not private ---
test_deny_public_cluster if {
    result := require_private_cluster.deny with input as {
        "resource_changes": [{
            "name": "aks-team-alpha-prod",
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "private_cluster_enabled": false,
                    "name": "aks-team-alpha-prod"
                }
            }
        }]
    }
    count(result) == 1
    result[_] contains "private_cluster_enabled must be true"
}

# --- Deny: private_cluster_enabled key absent (defaults to false) ---
test_deny_missing_private_flag if {
    result := require_private_cluster.deny with input as {
        "resource_changes": [{
            "name": "aks-team-beta-prod",
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "name": "aks-team-beta-prod"
                }
            }
        }]
    }
    count(result) == 1
}

# --- Pass: private cluster with no IP ranges ---
test_pass_private_cluster if {
    result := require_private_cluster.deny with input as {
        "resource_changes": [{
            "name": "aks-team-gamma-prod",
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "private_cluster_enabled": true,
                    "api_server_authorized_ip_ranges": null,
                    "name": "aks-team-gamma-prod"
                }
            }
        }]
    }
    count(result) == 0
}

# --- Pass: unrelated resource type is ignored ---
test_pass_unrelated_resource if {
    result := require_private_cluster.deny with input as {
        "resource_changes": [{
            "name": "rg-team-alpha",
            "type": "azurerm_resource_group",
            "change": {"after": {"location": "eastus"}}
        }]
    }
    count(result) == 0
}
