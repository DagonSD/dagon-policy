# Dagon Policy — Compliance Control Mapping

This document maps each Dagon policy file to its corresponding compliance
framework control(s). Use this as evidence during SOC2, HIPAA, or GDPR
audits to demonstrate control coverage.

Last updated: 2026-03-21

---

## Summary Table

| Control ID       | Framework | Kyverno Policy                   | OPA/Rego Rule                    | Tier      | Status |
|------------------|-----------|----------------------------------|----------------------------------|-----------|--------|
| CC6.1            | SOC2      | `block-latest-image-tag`         | `no-public-storage`              | baseline  | Active |
| CC6.1            | SOC2      | `block-external-registries`      | —                                | regulated | Active |
| CC6.2            | SOC2      | `require-network-policy`         | `no-wildcard-iam`                | baseline  | Active |
| CC6.2            | SOC2      | `restrict-cross-namespace`       | —                                | tenant    | Active |
| CC6.6            | SOC2      | `require-non-root`               | `require-encryption-at-rest`     | baseline  | Active |
| CC6.6            | SOC2      | `require-readonly-rootfs`        | —                                | baseline  | Active |
| CC6.6            | SOC2      | `block-privileged-containers`    | —                                | baseline  | Active |
| CC7.1            | SOC2      | `require-resource-limits`        | —                                | baseline  | Active |
| CC7.1            | SOC2      | `require-pod-disruption-budget`  | —                                | regulated | Active |
| §164.312         | HIPAA     | `block-privileged-containers`    | `require-aks-private`            | baseline  | Active |
| §164.312         | HIPAA     | `require-pod-disruption-budget`  | —                                | regulated | Active |
| Art. 25          | GDPR      | `require-encryption-labels`      | —                                | regulated | Active |
| CC6.1 / Art. 25  | SOC2/GDPR | `enforce-tenant-label`           | —                                | tenant    | Active |

---

## Detailed Mappings

### SOC2 CC6.1 — Logical and Physical Access Controls

**Intent**: Restrict access to information assets to authorised users only.

- `kyverno/baseline/block-latest-image-tag/` — Mutable image tags allow
  uncontrolled code deployment. Pinned tags ensure only audited images run.
- `kyverno/regulated/block-external-registries/` — External registries bypass
  the organisation's vulnerability scanning pipeline.
- `iac/azure/no-public-storage.rego` — Public blob access enables
  unauthenticated reads of storage assets.

---

### SOC2 CC6.2 — Access Management and Network Controls

**Intent**: Restrict access based on authorisation and prevent unauthorised
network access.

- `kyverno/baseline/require-network-policy/` — Namespaces without a
  default-deny NetworkPolicy allow unrestricted pod-to-pod communication.
- `kyverno/tenant-isolation/restrict-cross-namespace/` — Cross-namespace
  ServiceAccount tokens can be used to escalate privileges across tenant
  boundaries.
- `iac/common/no-wildcard-iam.rego` — Wildcard IAM grants violate
  least-privilege and allow lateral movement within a cloud account.

---

### SOC2 CC6.6 — Logical Access — Security of System Components

**Intent**: Prevent unauthorised access via hardened system configuration.

- `kyverno/baseline/require-non-root/` — Root containers can modify container
  runtime files and exploit kernel vulnerabilities.
- `kyverno/baseline/require-readonly-rootfs/` — A writable root filesystem
  allows attackers to install malicious binaries at runtime.
- `kyverno/baseline/block-privileged-containers/` — Privileged containers
  have full host kernel access, enabling container escape.
- `iac/azure/require-encryption-at-rest.rego` — Data must be encrypted at
  rest to protect confidentiality if storage media is compromised.

---

### SOC2 CC7.1 — System Operations — Capacity and Availability

**Intent**: Ensure system resources are managed to support availability
commitments.

- `kyverno/baseline/require-resource-limits/` — Containers without limits
  can consume unbounded CPU and memory, causing noisy-neighbour denial of
  service for other tenants.
- `kyverno/regulated/require-pod-disruption-budget/` — Deployments without
  a PDB can be completely evicted during cluster maintenance, violating
  availability SLAs.

---

### HIPAA §164.312 — Technical Safeguards

**Intent**: Implement technical security measures to guard against
unauthorised access to ePHI transmitted over electronic communications
networks.

- `kyverno/baseline/block-privileged-containers/` — Privileged containers
  can access host filesystems where ePHI may be cached.
- `kyverno/regulated/require-pod-disruption-budget/` — HIPAA workloads
  require guaranteed availability during maintenance windows.
- `iac/azure/require-aks-private.rego` — A public AKS API server exposes
  the Kubernetes control plane to internet-based attacks, which could
  compromise ePHI stored in the cluster.

---

### GDPR Article 25 — Data Protection by Design and by Default

**Intent**: Implement appropriate technical measures to ensure that data
protection principles are implemented by default.

- `kyverno/regulated/require-encryption-labels/` — Namespaces handling
  personal data must confirm that underlying storage uses encryption at
  rest. The `dagon.io/encryption: "at-rest"` annotation is the audit
  evidence that this has been verified by the provisioning pipeline.

---

## Namespace Compliance Tier Targeting

Policies are scoped by compliance tier via `namespaceSelector`:

| Tier       | Policies Applied                                              |
|------------|---------------------------------------------------------------|
| `baseline` | All 6 baseline policies                                       |
| `soc2`     | All baseline + 3 regulated policies                           |
| `hipaa`    | All baseline + all regulated + `require-encryption-labels`    |
| `gdpr`     | All baseline + all regulated + `require-encryption-labels`    |

All tiers also receive tenant-isolation policies.

---

## Namespace Label Convention

```yaml
metadata:
  labels:
    dagon.io/managed: "true"
    dagon.io/tenant-id: "<tenant-uuid>"
    dagon.io/compliance-tier: "soc2"   # baseline | soc2 | hipaa | gdpr
    dagon.io/environment: "dev"        # dev | staging | prod
```

---

## Evidence Collection

Kyverno generates `PolicyReport` and `ClusterPolicyReport` objects in the
cluster. The `dagon-controls-evidence` repository collects these reports
automatically and archives them as compliance evidence. Each report entry
references the policy name, control ID (from annotations), resource
affected, and pass/fail result.
