# arxen-policy — Claude Code Guide

## Purpose

Cluster-level security guardrails: Kyverno admission policies and OPA/Rego rules for IaC. Enforces SOC2, HIPAA, and GDPR controls across all Arxen-managed Kubernetes clusters.

## Architecture

```
kyverno/
  <tier>/
    <policy-name>/
      policy.yaml           # The ClusterPolicy definition
      kyverno-test.yaml     # Required unit test (pass + fail cases)
iac/
  azure/
    <rule-name>.rego        # OPA/Rego rule for Azure IaC validation
    <rule-name>_test.rego   # Required tests
  common/
    <rule-name>.rego        # Cloud-agnostic OPA/Rego rules
    <rule-name>_test.rego   # Required tests
```

## Kyverno Policy Standards

**Every policy MUST have:**
- `kind: ClusterPolicy` (not namespace-scoped `Policy`) unless explicitly required
- `validationFailureAction: Enforce` (default) or `Audit` — always explicit
- `background: true` to scan existing resources
- Descriptive `message` explaining the failure, why it failed, and how to fix it
- `exclude` block for system namespaces: `kube-system`, `kyverno`, `argo-system`, `cert-manager`, `external-secrets`
- Compliance mapping in annotations (e.g., `policies.kyverno.io/controls: "SOC2 CC6.1"`)

**Policy metadata annotation pattern:**
```yaml
annotations:
  policies.kyverno.io/title: "Block Latest Image Tag"
  policies.kyverno.io/category: "Image Security"
  policies.kyverno.io/controls: "SOC2 CC6.1"
  policies.kyverno.io/description: >-
    Container images must use pinned semantic versions, not 'latest'.
```

## Testing

Every `policy.yaml` requires a sibling `kyverno-test.yaml` with both `pass` and `fail` test cases.

Run tests locally:
```bash
kyverno test kyverno/<policy-name>/
```

## Constraints

- Never match `*` (all resource kinds) — scope `match.any[].resources.kinds` to specific kinds
- Never omit the test file — policies without tests will not be merged
- Never write `mutate` rules that could silently change user-submitted resources without an audit trail
