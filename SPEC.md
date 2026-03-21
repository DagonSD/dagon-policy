# dagon-policy — Specification

## Purpose

Policy-as-code enforcement layer. Provides Kubernetes admission policies (Kyverno) and IaC validation rules (OPA/Conftest). Policies are cloud-agnostic by design — Kubernetes and compliance controls do not change based on the underlying cloud provider.

---

## Design Principle: Compliance-First, Cloud-Agnostic

Kyverno policies operate at the Kubernetes API level and are identical whether the cluster is AKS, EKS, or GKE. OPA/Rego rules validate OpenTofu plan JSON regardless of which cloud provider is targeted. New clouds require no changes to existing policies.

---

## Repository Structure

```
kyverno/
  baseline/                    # Foundational security (applied everywhere)
    block-latest-image-tag/
      policy.yaml
      kyverno-test.yaml
    require-resource-limits/
      policy.yaml
      kyverno-test.yaml
    require-non-root/
      policy.yaml
      kyverno-test.yaml
    require-readonly-rootfs/
      policy.yaml
      kyverno-test.yaml
    block-privileged-containers/
      policy.yaml
      kyverno-test.yaml
    require-network-policy/
      policy.yaml
      kyverno-test.yaml
  regulated/                   # Applied to namespaces with compliance tier labels
    require-encryption-labels/
      policy.yaml
      kyverno-test.yaml
    block-external-registries/
      policy.yaml
      kyverno-test.yaml
    require-pod-disruption-budget/
      policy.yaml
      kyverno-test.yaml
  tenant-isolation/            # Enforce tenant boundary policies
    restrict-cross-namespace/
      policy.yaml
      kyverno-test.yaml
    enforce-tenant-label/
      policy.yaml
      kyverno-test.yaml

iac/
  azure/                       # Azure-specific IaC rules (MVP)
    no-public-storage.rego
    no-public-storage_test.rego
    require-aks-private.rego
    require-aks-private_test.rego
    require-encryption-at-rest.rego
    require-encryption-at-rest_test.rego
  aws/                         # Future
    no-public-s3.rego
    require-eks-private.rego
  gcp/                         # Future
    no-public-gcs.rego
    require-gke-private.rego
  common/                      # Cloud-agnostic IaC rules
    no-wildcard-iam.rego       # No * in IAM actions (applies to all clouds)
    no-wildcard-iam_test.rego

docs/
  compliance-mapping.md        # Control ID → policy file mapping
```

---

## Kyverno Policy Standards

### Required Metadata Annotations

Every `ClusterPolicy` must include:

```yaml
metadata:
  name: block-latest-image-tag
  annotations:
    policies.kyverno.io/title: "Block 'latest' Image Tag"
    policies.kyverno.io/category: "Image Security"
    policies.kyverno.io/severity: "high"
    policies.kyverno.io/controls: "SOC2-CC6.1, NIST-CM-7"
    policies.kyverno.io/description: >-
      Container images must reference a pinned semantic version or immutable
      digest. The 'latest' tag is mutable and creates non-deterministic
      deployments. Fix: replace 'myimage:latest' with 'myimage:v1.2.3' or
      'myimage@sha256:<digest>'.
```

### Required Policy Structure

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: <policy-name>
  annotations: { ... }  # Required — see above
spec:
  validationFailureAction: Enforce   # Default; use Audit only during rollout
  background: true                   # Scan existing resources
  rules:
    - name: <rule-name>
      match:
        any:
          - resources:
              kinds: [Pod]            # Always specific kinds, never *
              namespaceSelector:
                matchExpressions:
                  - key: dagon.io/managed
                    operator: In
                    values: ["true"]  # Only apply to Dagon-managed namespaces
      exclude:
        any:
          - resources:
              namespaces:             # Always exclude system namespaces
                - kube-system
                - kyverno
                - argo-system
                - cert-manager
                - external-secrets
      validate:
        message: >-
          <clear failure message with fix instructions>
        pattern:
          spec:
            containers:
              - <pattern>
```

### Test File Requirements

Every `policy.yaml` requires a sibling `kyverno-test.yaml`:

```yaml
apiVersion: cli.kyverno.io/v1alpha1
kind: Test
metadata:
  name: block-latest-image-tag-test
policies:
  - policy.yaml
resources:
  - resources.yaml
results:
  - policy: block-latest-image-tag
    rule: check-image-tag
    resource: pod-with-latest-tag
    result: fail           # Must have at least one fail case
  - policy: block-latest-image-tag
    rule: check-image-tag
    resource: pod-with-pinned-tag
    result: pass           # Must have at least one pass case
```

---

## OPA/Rego IaC Rules

### Azure Rule Pattern (`iac/azure/`)

```rego
# iac/azure/no-public-storage.rego
package azure.storage.no_public_access

import future.keywords.if
import future.keywords.in

# Title: Azure Storage Account must disable public blob access
# Control: SOC2-CC6.1, CIS-AZ-3.7
# Applies to: tofu plan output for azurerm_storage_account resources

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    resource.change.after.allow_blob_public_access == true

    msg := sprintf(
        "Storage account '%s' has public blob access enabled. Set allow_blob_public_access = false.",
        [resource.name]
    )
}
```

### Running IaC Policy Checks

```bash
# Generate plan JSON
tofu plan -out=tfplan && tofu show -json tfplan > plan.json

# Run all Azure rules
conftest test plan.json --policy iac/azure/ --policy iac/common/

# Run specific control
conftest test plan.json --policy iac/azure/no-public-storage.rego
```

---

## Compliance Control Mapping

| Control ID | Framework | Kyverno Policy | OPA Rule | Status |
|---|---|---|---|---|
| CC6.1 | SOC2 | `block-latest-image-tag` | `no-public-storage` | MVP |
| CC6.2 | SOC2 | `require-network-policy` | `no-wildcard-iam` | MVP |
| CC6.6 | SOC2 | `require-non-root` | `require-encryption-at-rest` | MVP |
| CC7.1 | SOC2 | `require-resource-limits` | — | MVP |
| §164.312 | HIPAA | `block-privileged-containers` | `require-aks-private` | Future |
| Art. 25 | GDPR | `require-encryption-labels` | — | Future |

Full mapping: `docs/compliance-mapping.md`

---

## Namespace Labeling Convention

Dagon-managed namespaces must carry labels that drive policy targeting:

```yaml
metadata:
  labels:
    dagon.io/managed: "true"
    dagon.io/tenant-id: "<tenant-uuid>"
    dagon.io/compliance-tier: "soc2"   # "baseline" | "soc2" | "hipaa" | "gdpr"
    dagon.io/environment: "dev"
```

Policies use `namespaceSelector` to match on `dagon.io/managed: "true"` so they never interfere with system namespaces.

---

## Non-Goals

- No cloud-specific admission policies (cloud identity enforcement is handled by `dagon-api`)
- No runtime security (Falco, Tetragon) — that is a `dagon-gitops` concern
- No policies that mutate resources silently without an audit trail
