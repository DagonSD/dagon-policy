# iac/azure/require-aks-private.rego
package azure.aks.require_private_cluster

import future.keywords.if
import future.keywords.in

# Title:   Azure Kubernetes Service cluster must be private
# Control: HIPAA-164.312, SOC2-CC6.2
# Applies: OpenTofu plan JSON for azurerm_kubernetes_cluster resources
#
# A public AKS API server is reachable from the internet, which means
# any credential leak or misconfigured RBAC grants external access to
# the Kubernetes control plane. Private clusters ensure the API server
# is reachable only from within the VNet (HIPAA §164.312).

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
    not resource.change.after.private_cluster_enabled == true
    msg := sprintf(
        "DENY [HIPAA-164.312] AKS cluster '%s': private_cluster_enabled must be true. A public API server is reachable from the internet. Set private_cluster_enabled = true in your azurerm_kubernetes_cluster resource.",
        [resource.name],
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
    resource.change.after.private_cluster_enabled == true
    resource.change.after.api_server_authorized_ip_ranges != null
    count(resource.change.after.api_server_authorized_ip_ranges) > 0
    msg := sprintf(
        "DENY [HIPAA-164.312] AKS cluster '%s': api_server_authorized_ip_ranges must be empty when private_cluster_enabled = true. Remove the IP allowlist — it is redundant and may create a false sense of security for private clusters.",
        [resource.name],
    )
}
