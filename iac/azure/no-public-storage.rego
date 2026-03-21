# iac/azure/no-public-storage.rego
package azure.storage.no_public_access

import future.keywords.if
import future.keywords.in

# Title:   Azure Storage Account must disable public blob access
# Control: SOC2-CC6.1, CIS-AZ-3.7
# Applies: OpenTofu plan JSON for azurerm_storage_account resources
#
# Public blob access allows unauthenticated reads of any blob in any
# container within the storage account that does not have its own ACL.
# This is a primary vector for data exfiltration (SOC2 CC6.1).

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.after.allow_blob_public_access == true
    msg := sprintf(
        "DENY [SOC2-CC6.1] Storage account '%s': allow_blob_public_access must be false. Public blob access enables unauthenticated data reads. Set allow_blob_public_access = false in your azurerm_storage_account resource.",
        [resource.name],
    )
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not has_key(resource.change.after, "allow_blob_public_access")
    msg := sprintf(
        "DENY [SOC2-CC6.1] Storage account '%s': allow_blob_public_access is not set. Explicitly set allow_blob_public_access = false to prevent accidental public access enablement by ARM defaults.",
        [resource.name],
    )
}

has_key(obj, key) if {
    _ = obj[key]
}
