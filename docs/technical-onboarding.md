# arxen-policy — Technical Onboarding Guide

Welcome to the team. This document is your map for understanding, contributing to, and extending this repository. It assumes you can read YAML and at least one general-purpose language, but does not assume prior experience with Kyverno, OPA, or policy-as-code patterns. Each section builds on the previous one.

---

## What This Repository Is

`arxen-policy` is the **policy enforcement layer** for the Arxen platform. It has two distinct jobs:

1. **Kubernetes admission control** — Kyverno `ClusterPolicy` resources that intercept API server requests and block non-compliant workload configurations before they are persisted to etcd.
2. **Infrastructure-as-Code validation** — OPA/Rego rules that validate OpenTofu plan JSON before `tofu apply` runs, catching misconfigurations before cloud resources are created.

Both jobs share the same goal: shift security checks as far left as possible. A rejected API server request costs nothing. A compliance violation discovered during a SOC 2 audit costs a lot.

---

## Repository Layout

```
arxen-policy/
├── kyverno/
│   ├── baseline/               # Applied to all arxen.io/managed namespaces
│   │   ├── block-latest-image-tag/
│   │   ├── block-privileged-containers/
│   │   ├── require-network-policy/
│   │   ├── require-non-root/
│   │   ├── require-readonly-rootfs/
│   │   └── require-resource-limits/
│   ├── regulated/              # Applied when arxen.io/compliance-tier ∈ {soc2, hipaa, gdpr}
│   │   ├── block-external-registries/
│   │   ├── require-encryption-labels/
│   │   └── require-pod-disruption-budget/
│   └── tenant-isolation/       # Applied to all arxen.io/managed namespaces
│       ├── enforce-tenant-label/
│       └── restrict-cross-namespace/
├── iac/
│   ├── azure/                  # azurerm resource type rules
│   │   ├── no-public-storage.rego
│   │   ├── no-public-storage_test.rego
│   │   ├── require-aks-private.rego
│   │   ├── require-aks-private_test.rego
│   │   ├── require-encryption-at-rest.rego
│   │   └── require-encryption-at-rest_test.rego
│   └── common/                 # Cloud-agnostic rules (AWS + Azure today)
│       ├── no-wildcard-iam.rego
│       └── no-wildcard-iam_test.rego
├── docs/
│   ├── compliance-mapping.md   # Control ID → policy cross-reference
│   ├── guide-for-non-technical-readers.md
│   └── technical-onboarding.md (this file)
├── .github/workflows/
│   └── policy-ci.yaml          # CI: kyverno test + opa test + yamllint
├── Makefile
├── SPEC.md                     # Canonical design spec
└── README.md
```

Each policy directory contains exactly:
- `policy.yaml` — the `ClusterPolicy` definition
- `kyverno-test.yaml` — the test manifest (required, enforced by CI)
- `resources.yaml` — synthetic test resources referenced by the test
- `values.yaml` — optional context variables for the test runner

---

## Tool Stack and Version Requirements

| Tool | Version | Purpose |
|---|---|---|
| Kyverno CLI | v1.12+ | Policy authoring, local testing, CLI admission simulation |
| OPA CLI | v0.68+ | Rego evaluation, unit tests (`opa test`) |
| Conftest | v0.50+ | Feed structured plan JSON through Rego rules |
| yamllint | 1.35.1 | Lint Kyverno YAML (pinned in CI) |

Kyverno is **not** installed locally as a cluster controller to run tests. The CLI alone is sufficient — it simulates admission evaluation against the resource definitions in `resources.yaml`.

---

## Part 1 — Kyverno Policies

### How Kyverno Works in the Cluster

Kyverno runs as a validating admission webhook. When a resource is submitted to the API server, the API server calls Kyverno synchronously before writing anything to etcd. Kyverno evaluates every matching `ClusterPolicy` rule and either:
- Returns `allowed: true` → the API server proceeds
- Returns `allowed: false` with a denial message → the API server rejects the request with HTTP 422

`background: true` in the policy spec enables a separate reconciliation loop that scans existing resources and writes `PolicyReport` / `ClusterPolicyReport` objects. These reports are the compliance evidence collected by `arxen-controls-evidence`.

### ClusterPolicy Anatomy

Every policy follows this structure exactly. Deviations require a documented reason in the PR:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy             # Always ClusterPolicy, never namespace-scoped Policy
metadata:
  name: <kebab-case-name>
  annotations:
    policies.kyverno.io/title: "Human-readable title"
    policies.kyverno.io/category: "Category"
    policies.kyverno.io/severity: "low | medium | high | critical"
    policies.kyverno.io/subject: "Pod"         # Primary resource kind targeted
    policies.kyverno.io/controls: "SOC2-CC6.1" # Comma-separated control IDs
    policies.kyverno.io/description: >-
      What the policy enforces, why it matters (include the control ID inline),
      and exactly how to fix a violation.
spec:
  validationFailureAction: Enforce   # Enforce = hard block; Audit = report only
  background: true                   # Required — enables PolicyReport generation
  rules:
    - name: <rule-name>
      match:
        any:
          - resources:
              kinds: [Pod]           # Always specific kinds. Never * (wildcard kinds are banned)
              namespaceSelector:
                matchExpressions:
                  - key: arxen.io/managed
                    operator: In
                    values: ["true"]
      exclude:
        any:
          - resources:
              namespaces:            # Always exclude these system namespaces
                - kube-system
                - kyverno
                - argo-system
                - cert-manager
                - external-secrets
      validate:
        message: >-
          Violation message. Must name the resource, the offending field,
          the control ID, and the fix. Use JMESPath expressions like
          '{{ request.object.metadata.name }}' for dynamic context.
        # Rule body: pattern, foreach, or deny (see below)
```

### Three Rule Body Styles

**`pattern`** — structural matching. The resource must match the shape described. Anchors control matching behavior:
- `=()` — conditional anchor: only apply this check if the field exists
- `^()` — global anchor: if any element in the list fails this, deny the whole request
- `!` prefix on a value — negation

```yaml
validate:
  pattern:
    spec:
      securityContext:
        runAsNonRoot: true
```

**`foreach`** — iterate over a list within the resource. Used for containers and initContainers, where you need to check every element:

```yaml
validate:
  foreach:
    - list: "request.object.spec.containers"
      pattern:
        image: "!*:latest & !*:*latest* & ?*:?*"
    - list: "request.object.spec.initContainers"
      pattern:
        image: "!*:latest & !*:*latest* & ?*:?*"
```

**`deny`** — explicit JMESPath condition evaluation. Used when the denial condition is a computed expression rather than a structural pattern. The `restrict-cross-namespace` policy uses this:

```yaml
validate:
  deny:
    conditions:
      any:
        - key: "{{ request.object.spec.volumes[].projected.sources[].serviceAccountToken.audience | length(@) }}"
          operator: GreaterThan
          value: 0
```

### Targeting: How Policies Know What to Check

Policies target resources by combining two selectors:

**`match.any[].resources.namespaceSelector`** — namespace labels control which namespaces the policy is active in. The `arxen.io/managed: "true"` label is the gate for all policies. Regulated policies additionally require `arxen.io/compliance-tier ∈ {soc2, hipaa, gdpr}`.

**`exclude`** — system namespaces are always hardcoded out. This prevents policies from interfering with Kyverno's own pods, Argo CD, cert-manager, and external-secrets — all of which have legitimate reasons to break the rules that tenant workloads must follow.

Namespace labels are set by `arxen-gitops` at namespace provisioning time:

```yaml
metadata:
  labels:
    arxen.io/managed: "true"
    arxen.io/tenant-id: "<uuid>"
    arxen.io/compliance-tier: "soc2"   # baseline | soc2 | hipaa | gdpr
    arxen.io/environment: "prod"       # dev | staging | prod
```

### Kyverno Test Structure

The test runner (`kyverno test <dir>`) reads `kyverno-test.yaml` and evaluates each result assertion. The test file declares:
- Which policies to load
- Which resources to simulate (from `resources.yaml`)
- The expected outcome (`pass` or `fail`) for each resource/rule combination

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
    resource: pod-with-latest-tag   # name matches metadata.name in resources.yaml
    namespace: team-alpha
    kind: Pod
    result: fail                    # policy must block this resource
  - policy: block-latest-image-tag
    rule: check-image-tag
    resource: pod-with-pinned-tag
    namespace: team-alpha
    kind: Pod
    result: pass                    # policy must allow this resource
```

The `namespace` field is required when the policy uses a `namespaceSelector`. The test runner will not match the resource to the policy without it, and the test will silently produce a wrong result. Always include it.

Every test file must have at minimum one `fail` case and one `pass` case. CI enforces this by running `--detailed-results` and failing on any assertion mismatch.

### Running Tests Locally

```bash
# Test a single policy directory
kyverno test kyverno/baseline/block-latest-image-tag/ --detailed-results

# Test an entire tier
kyverno test kyverno/baseline/ --detailed-results
kyverno test kyverno/regulated/ --detailed-results
kyverno test kyverno/tenant-isolation/ --detailed-results
```

---

## Part 2 — OPA / Rego IaC Rules

### How IaC Validation Fits the Workflow

The IaC validation path is:

```
.tf files (OpenTofu)
    → tofu plan -out=tfplan
    → tofu show -json tfplan > plan.json
    → conftest test plan.json --policy iac/azure/ --policy iac/common/
```

Conftest loads the Rego rules, feeds `plan.json` as `input`, and collects all `deny` messages. Non-empty `deny` output causes a non-zero exit code, which fails the CI step. This runs in `arxen-gitops` CI before any `tofu apply` is allowed.

The rules in this repo only define the policy logic. The actual CI invocation lives in `arxen-gitops`.

### Rego Package Conventions

Each rule file defines a single focused package. Package naming follows the path:

```
iac/azure/no-public-storage.rego   → package azure.storage.no_public_access
iac/common/no-wildcard-iam.rego    → package common.iam.no_wildcard
```

All rules use `future.keywords.if` and `future.keywords.in` for readable syntax (required for Rego v1 compatibility without the legacy syntax).

### Rule Pattern

All rules evaluate against `input.resource_changes` — the OpenTofu plan JSON structure. Every rule is a `deny` set rule. OPA collects all `deny` messages across all loaded packages; if the set is non-empty, Conftest fails.

```rego
package azure.storage.no_public_access

import future.keywords.if
import future.keywords.in

deny contains msg if {
    resource := input.resource_changes[_]          # iterate over all planned changes
    resource.type == "azurerm_storage_account"     # filter to the relevant resource type
    resource.change.after.allow_blob_public_access == true   # identify the violation
    msg := sprintf(
        "DENY [SOC2-CC6.1] Storage account '%s': allow_blob_public_access must be false. ...",
        [resource.name],
    )
}
```

Every deny message must include the control ID in brackets (`[SOC2-CC6.1]`) so that CI output is scannable and ties back to `docs/compliance-mapping.md`.

**Missing field handling** — never assume a field exists. Write a separate rule for the missing-key case:

```rego
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not has_key(resource.change.after, "allow_blob_public_access")  # field absent = unsafe default
    msg := sprintf("DENY [SOC2-CC6.1] Storage account '%s': allow_blob_public_access is not set. ...", [resource.name])
}

has_key(obj, key) if { _ = obj[key] }
```

This matters because provider defaults often enable insecure options when a field is omitted.

### Common Rules (Cloud-Agnostic)

`iac/common/` contains rules that apply regardless of cloud provider. `no-wildcard-iam.rego` handles both `azurerm_role_definition` (Azure) and `aws_iam_policy` (AWS) in the same file because the violation pattern is the same concept:

```rego
# Azure path
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_definition"
    perm := resource.change.after.permissions[_]
    action := perm.actions[_]
    action == "*"
    msg := sprintf("DENY [SOC2-CC6.2] Role definition '%s': wildcard action '*' ...", [resource.name])
}

# AWS path — note json.unmarshal since AWS stores the policy doc as a JSON string
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    doc := json.unmarshal(resource.change.after.policy)
    stmt := doc.Statement[_]
    is_wildcard_action(stmt.Action)
    msg := sprintf("DENY [SOC2-CC6.2] IAM policy '%s': wildcard Action '%v' ...", [resource.name, stmt.Action])
}
```

When adding AWS or GCP rules, check `iac/common/` first. If the security concern is cloud-agnostic (IAM, tagging, encryption), it likely belongs there rather than in a cloud-specific subdirectory.

### Rego Unit Tests

OPA's built-in test framework (`opa test`) discovers test files by the `_test` suffix. Each test is a rule starting with `test_` that evaluates the rule under test by injecting a synthetic `input` via `with input as { ... }`:

```rego
package azure.storage.no_public_access_test

import data.azure.storage.no_public_access

test_deny_public_access_true if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "st-team-alpha-prod",
            "type": "azurerm_storage_account",
            "change": { "after": { "allow_blob_public_access": true } }
        }]
    }
    count(result) == 1                               # exactly one denial
    result[_] contains "allow_blob_public_access must be false"  # assert message content
}

test_pass_public_access_false if {
    result := no_public_access.deny with input as {
        "resource_changes": [{
            "name": "st-team-gamma-prod",
            "type": "azurerm_storage_account",
            "change": { "after": { "allow_blob_public_access": false } }
        }]
    }
    count(result) == 0    # no denials on compliant input
}
```

Test each rule at least four ways:
1. Explicit violation → `count(result) == 1`
2. Missing field (if applicable) → `count(result) == 1`
3. Compliant value → `count(result) == 0`
4. Unrelated resource type → `count(result) == 0`

Run locally:

```bash
opa test iac/azure/ --verbose
opa test iac/common/ --verbose
```

---

## Part 3 — CI Pipeline

Three jobs run on every PR and push to `main`. All three must pass for merge.

```
┌─────────────────────────────┐
│  kyverno-test               │  kyverno test kyverno/baseline/ --detailed-results
│  (ubuntu-22.04)             │  kyverno test kyverno/regulated/ --detailed-results
│                             │  kyverno test kyverno/tenant-isolation/ --detailed-results
├─────────────────────────────┤
│  opa-rego-test              │  opa test iac/azure/ --verbose
│  (ubuntu-22.04)             │  opa test iac/common/ --verbose
├─────────────────────────────┤
│  lint                       │  yamllint -c .yamllint.yaml kyverno/
│  (ubuntu-22.04)             │
└─────────────────────────────┘
```

Tool versions are pinned in the workflow file (`KYVERNO_VERSION`, `OPA_VERSION`). If you need to upgrade a tool, update the workflow and the README in the same PR — keep them in sync.

---

## Part 4 — Compliance Mapping

Every policy annotation carries `policies.kyverno.io/controls` with comma-separated control IDs. Every Rego `deny` message opens with `DENY [<control-id>]`. These IDs tie back to `docs/compliance-mapping.md`, which is the evidence index used during audits.

| Framework | Control | Concern |
|---|---|---|
| SOC 2 | CC6.1 | Logical access — image integrity, registry control |
| SOC 2 | CC6.2 | Network access — namespace isolation, IAM least-privilege |
| SOC 2 | CC6.6 | System hardening — non-root, read-only rootfs, no privileged mode |
| SOC 2 | CC7.1 | Availability — resource limits, disruption budgets |
| HIPAA | §164.312 | Technical safeguards — ePHI protection, private cluster endpoints |
| GDPR | Art. 25 | Privacy by design — encryption labels, data-at-rest confirmation |

When you add a new policy, update `docs/compliance-mapping.md` in the same PR. The mapping must stay current — it is pulled directly into audit evidence packages.

---

## Part 5 — Adding a New Policy

Follow these steps for any new Kyverno policy:

### 1. Identify the tier and create the directory

```
kyverno/baseline/<policy-name>/       # applies to all managed namespaces
kyverno/regulated/<policy-name>/      # applies only to soc2/hipaa/gdpr namespaces
kyverno/tenant-isolation/<policy-name>/
```

### 2. Write `policy.yaml`

Start from the annotated template in SPEC.md. Mandatory checklist:
- [ ] `kind: ClusterPolicy`
- [ ] `validationFailureAction: Enforce`
- [ ] `background: true`
- [ ] All five annotations filled in, including `controls`
- [ ] `match` scoped to specific `kinds` (no `*`)
- [ ] `namespaceSelector` on `arxen.io/managed: "true"` (add `compliance-tier` for regulated)
- [ ] `exclude` block contains all five system namespaces
- [ ] `message` names the resource, the offending field, the control ID, and the fix

### 3. Write `resources.yaml`

Define one Kubernetes resource per test case. Give each a unique `metadata.name`. Keep them minimal — only the fields the policy rule touches need to be present. Label the namespace correctly:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-latest-tag
  namespace: team-alpha
spec:
  containers:
    - name: app
      image: nginx:latest
```

### 4. Write `kyverno-test.yaml`

One result assertion per resource. Include both `pass` and `fail` cases. Always include `namespace` when the policy uses a `namespaceSelector`.

### 5. Test locally

```bash
kyverno test kyverno/<tier>/<policy-name>/ --detailed-results
```

Fix any assertion mismatches before pushing.

### 6. Update compliance mapping

Add a row to `docs/compliance-mapping.md` under the relevant control section and update the summary table at the top.

### Adding a New Rego Rule

1. Create `iac/<cloud>/<rule-name>.rego` and `iac/<cloud>/<rule-name>_test.rego`
2. Follow the package naming convention: `package <cloud>.<resource-category>.<rule_name>`
3. Write at minimum four test cases: explicit violation, missing field, compliant value, unrelated resource
4. Run `opa test iac/<cloud>/ --verbose`
5. Add to `docs/compliance-mapping.md`

---

## Part 6 — Design Decisions and Non-Goals

**Why `ClusterPolicy`, not `Policy`?**
`ClusterPolicy` is cluster-scoped and evaluated for all namespaces that match the selector. Namespace-scoped `Policy` objects would have to be replicated per namespace, which creates drift risk and makes audit evidence collection more complex.

**Why `Enforce`, not `Audit` by default?**
`Audit` mode lets violations through and only reports them. For a multi-tenant platform with compliance obligations, silent pass-through is not acceptable for new policies. Use `Audit` only during rollout of a policy that targets existing resources that may not yet be compliant, and only for a defined transition window.

**Why `background: true`?**
Background scanning catches resources that existed before the policy was installed, or resources that were created while the webhook was unavailable. Without it, `PolicyReport` objects are incomplete and cannot be used as audit evidence.

**Why are `mutate` rules banned?**
Silent mutation of user-submitted resources creates an audit gap: the resource in the cluster does not match what the user submitted. This makes it impossible to determine whether a configuration was intentionally set or silently overridden. Any defaulting behavior that is required must go through the provisioning pipeline in `arxen-api` or `arxen-gitops`, where it is logged explicitly.

**Why no runtime security here?**
Admission control happens at request time. Runtime security (detecting anomalous behavior in running containers) is a different concern handled by Falco/Tetragon, configured in `arxen-gitops`. This repo has no opinion on runtime.

**Why no cloud-identity enforcement in Kyverno?**
Cloud IAM, workload identity bindings, and service account annotations are managed by `arxen-api` at tenant provisioning time. Kyverno policies operate on the Kubernetes API surface — they cannot reason about Azure RBAC or AWS IAM state.

**Why is `*` banned as a `kinds` value?**
Matching all resource kinds causes Kyverno to call the webhook for every create/update in the cluster, including high-frequency resources like `Event`, `EndpointSlice`, and `Lease`. This significantly increases API server latency and can saturate the webhook under load. Always scope to the specific kinds the rule actually checks.

---

## Quick Reference

```bash
# Run all Kyverno tests
kyverno test kyverno/baseline/ --detailed-results
kyverno test kyverno/regulated/ --detailed-results
kyverno test kyverno/tenant-isolation/ --detailed-results

# Run all OPA tests
opa test iac/azure/ --verbose
opa test iac/common/ --verbose

# Validate a real plan file
tofu plan -out=tfplan && tofu show -json tfplan > plan.json
conftest test plan.json --policy iac/azure/ --policy iac/common/

# Lint YAML
yamllint -c .yamllint.yaml kyverno/

# Evaluate a single Rego rule interactively
opa eval -i plan.json -d iac/azure/no-public-storage.rego 'data.azure.storage.no_public_access.deny'
```
