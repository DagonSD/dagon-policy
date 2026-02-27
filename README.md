# dagon-policy

Policy-as-code for Dagon: security, compliance, and platform guardrails.

## Scope
- Kubernetes admission policies (e.g., Kyverno / Gatekeeper)
- IaC policy checks (e.g., OPA/Conftest rules for Terraform/OpenTofu)
- Baseline controls for regulated workloads (secure defaults)

## Goals
- Prevent insecure configurations from reaching production
- Provide clear, explainable policy failures
- Keep policy definitions versioned and reviewable

## Structure
- `k8s/` Kubernetes admission policies
- `iac/` Infrastructure policy checks
- `docs/` Policy rationale and examples

## License
Open-source (recommended: Apache-2.0).
