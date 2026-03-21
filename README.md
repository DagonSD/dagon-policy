# dagon-policy

Policy-as-code enforcement layer for Dagon: Kubernetes admission policies
(Kyverno) and IaC validation rules (OPA/Conftest).

## Scope

- Kubernetes admission policies via Kyverno ClusterPolicies
- IaC policy checks via OPA/Rego rules validated with Conftest
- Baseline controls applied to all Dagon-managed namespaces
- Regulated controls for SOC2, HIPAA, and GDPR workloads
- Tenant isolation boundaries enforced at the Kubernetes API level

## Goals

- Prevent insecure configurations from reaching production
- Provide clear, explainable policy failures with fix instructions
- Keep policy definitions versioned, tested, and reviewable
- Map every rule to a specific compliance control ID

## Structure

```
kyverno/
  baseline/          # Applied to all dagon.io/managed namespaces
  regulated/         # Applied to soc2/hipaa/gdpr compliance-tier namespaces
  tenant-isolation/  # Tenant boundary enforcement
iac/
  azure/             # Azure-specific OpenTofu plan validation (MVP)
  common/            # Cloud-agnostic IaC rules
docs/
  compliance-mapping.md  # Control ID → policy file index
```

## Requirements

- [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/) v1.12+
- [OPA](https://www.openpolicyagent.org/docs/latest/) v0.68+
- [Conftest](https://www.conftest.dev/) v0.50+

Install all tools:

```bash
make install-tools
```

## Running Tests

```bash
# All tests
make test

# Kyverno policy tests only
make test-kyverno

# OPA/Rego unit tests only
make test-rego

# Validate a real Terraform/OpenTofu plan against Azure rules
make conftest-azure PLAN=path/to/plan.json
```

## Compliance Mapping

See [docs/compliance-mapping.md](docs/compliance-mapping.md) for the
full index of policies to SOC2, HIPAA, and GDPR control IDs.

## Contributing

Every policy file must have a sibling test file with at least one `pass`
and one `fail` case. PRs without tests will not be merged. See
[CLAUDE.md](CLAUDE.md) for full authoring standards.

## License

Apache-2.0
