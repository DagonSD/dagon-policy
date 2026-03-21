# iac/azure/require-encryption-at-rest.rego
package azure.storage.require_encryption_at_rest

import future.keywords.if
import future.keywords.in

# Title:   Azure Storage Account must use infrastructure encryption and modern TLS
# Control: SOC2-CC6.6, CIS-AZ-3.1
# Applies: OpenTofu plan JSON for azurerm_storage_account resources
#
# Azure Storage is encrypted at rest by default with Microsoft-managed keys.
# For regulated workloads, infrastructure_encryption_enabled adds a second
# layer of encryption at the infrastructure level (double encryption).
# min_tls_version must be TLS1_2 to prevent use of deprecated protocol versions.

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.after.infrastructure_encryption_enabled == false
    msg := sprintf(
        "DENY [SOC2-CC6.6] Storage account '%s': infrastructure_encryption_enabled must be true for regulated workloads. Double encryption (platform key + infrastructure key) is required. Set infrastructure_encryption_enabled = true.",
        [resource.name],
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.after.min_tls_version != "TLS1_2"
    msg := sprintf(
        "DENY [SOC2-CC6.6] Storage account '%s': min_tls_version must be 'TLS1_2'. TLS 1.0 and 1.1 have known vulnerabilities. Set min_tls_version = \"TLS1_2\".",
        [resource.name],
    )
}
