# Understanding Arxen Security Policies — A Plain-Language Guide

This document explains what this repository does, why it exists, and how each of its parts works — without assuming any technical background. If you are a business stakeholder, compliance officer, auditor, or anyone curious about how Arxen enforces security rules in software, this guide is for you.

---

## The Big Picture: What Problem Does This Solve?

When a company runs software in the cloud, dozens or hundreds of small configuration decisions are made every day: Which version of an application is deployed? Can different parts of the system talk to each other? Is sensitive data stored securely?

Each of those decisions is a potential risk. A single misconfiguration — like accidentally making a storage bucket publicly readable, or running software as a system administrator when it doesn't need to be — can expose customer data, violate regulations, or bring a service down.

Traditionally, these rules lived in documents, wikis, or people's heads. Someone would have to remember to check a checklist before each deployment. That approach is slow, inconsistent, and very easy to forget.

**This repository is the automated version of that checklist.**

Instead of asking a human to review every deployment, the rules are written in code. The system checks every deployment automatically, in real time, and blocks anything that violates a rule before it can cause harm. If a rule is broken, the developer gets a clear explanation of what went wrong and how to fix it.

---

## Key Concepts Explained Simply

### Kubernetes — The Platform Where Applications Run

Think of Kubernetes as a very sophisticated operating system for running many applications at once across multiple computers. It manages where each application runs, how much memory and computing power it gets, and how applications communicate with each other.

Arxen uses Kubernetes to run customer workloads. The policies in this repository are the security guards that stand at the door of Kubernetes and decide what is and is not allowed in.

### Containers and Container Images — The Packages Applications Live In

A container is like a standardized shipping box for software. It packages an application and everything it needs to run into a single, portable unit. A container image is the blueprint for that box — a snapshot of the application at a specific point in time.

When developers deploy software, they specify which image (blueprint) to use. This is important for security: you want to know exactly what version of the software is running, so you can verify it has been checked for vulnerabilities.

### Policies — The Written Rules

A policy in this context is a rule written in code that says "any deployment must satisfy this condition." For example:
- "Every container must specify a precise version, not just the word 'latest'"
- "No application may run with administrator-level permissions on the server"
- "Every application must have a limit on how much memory it can use"

Policies are stored in this repository as files. They are version-controlled, meaning every change is tracked with a history of who changed what and why — just like a legal contract going through revisions.

### Compliance Frameworks — The External Standards We Follow

Arxen's customers operate in regulated industries. Three major compliance frameworks are relevant:

**SOC 2 (Service and Organization Controls 2)**
A US standard that proves a company handles customer data securely and with integrity. Think of it as a seal of approval from an independent auditor that says "this company has proper controls in place." SOC 2 has numbered controls (like CC6.1, CC6.2) that each address a specific security concern.

**HIPAA (Health Insurance Portability and Accountability Act)**
A US law that protects the privacy and security of medical information (called ePHI — electronic Protected Health Information). Any company that handles health data must comply. Violations can result in significant fines.

**GDPR (General Data Protection Regulation)**
A European Union regulation that protects the personal data of EU residents. It requires that systems are built with privacy in mind from the start — a principle called "privacy by design." Article 25 of GDPR specifically requires that data protection is the default setting, not an afterthought.

---

## The Three Layers of Protection

This repository enforces rules at two distinct points in the software delivery process, organized into three categories by severity.

### Layer 1 — Kubernetes Admission Policies (Kyverno)

These rules run **at the moment a developer tries to deploy something**. Before Kubernetes accepts a new deployment, Kyverno (the policy engine) checks it against every applicable rule. If the deployment fails a check, it is rejected immediately with a clear error message. The bad configuration never reaches the running system.

This is like a security guard at a building entrance checking ID before anyone enters — not after.

#### Baseline Policies — Applied Everywhere

These rules apply to every Arxen-managed application, regardless of what the application does or which customer it belongs to. They represent the minimum acceptable security bar.

| Policy | What It Prevents | Why It Matters |
|---|---|---|
| **Block "latest" image tag** | Deploying a container without specifying an exact version | "Latest" is ambiguous — today's "latest" and tomorrow's "latest" may be completely different software. This makes deployments unpredictable and impossible to audit. |
| **Block privileged containers** | Applications running with full administrator access to the server | An application with admin access can do anything on the machine — including reading other customers' data or disabling security controls. |
| **Require non-root user** | Applications running as the "root" (administrator) user inside their container | Even inside a container, root access makes it easier for an attacker to escape the container and reach the underlying server. |
| **Require read-only filesystem** | Applications that can write files to their own core system area | If an attacker compromises an application, they could install malicious software. A read-only filesystem prevents this. |
| **Require resource limits** | Applications that don't declare a maximum on CPU and memory usage | Without limits, a single misbehaving application can consume all available resources on a server, causing every other application on that server to fail. |
| **Require network policy** | Namespaces (isolated areas) with no network traffic rules | Without network rules, any application can freely communicate with any other application. Network policies ensure applications only talk to who they are supposed to talk to. |

#### Regulated Policies — Applied to Sensitive Workloads

These rules apply only to namespaces (isolated application groups) that have been labeled as handling sensitive or regulated data. They add an extra layer on top of the baseline.

| Policy | What It Prevents | Why It Matters |
|---|---|---|
| **Block external registries** | Pulling container images from sources outside Arxen's approved registry | External registries skip Arxen's vulnerability scanning. An image from an unknown source could contain malware. |
| **Require encryption labels** | Namespaces handling personal data without confirming encryption is enabled | Confirms that the team responsible for the namespace has explicitly verified that data is encrypted at rest — a GDPR and HIPAA requirement. |
| **Require pod disruption budget** | Deploying services with no plan for what happens during planned maintenance | Without this, a scheduled server update could shut down every instance of a service simultaneously, causing an outage. This is a SOC 2 availability control. |

#### Tenant Isolation Policies — Applied to All Managed Namespaces

Arxen runs workloads for multiple customers (tenants) on shared infrastructure. These rules prevent one customer's applications from being able to reach or affect another customer's applications.

| Policy | What It Prevents | Why It Matters |
|---|---|---|
| **Enforce tenant label** | Deploying resources without a clearly identified owner | Every resource must be tagged with the customer it belongs to, enabling auditing and access control. |
| **Restrict cross-namespace access** | Applications using identity tokens that grant access across customer boundaries | A misconfigured service account could accidentally grant one customer's application access to another customer's resources. |

---

### Layer 2 — Infrastructure-as-Code Validation (OPA / Rego / Conftest)

These rules run **before infrastructure is even created** — during the planning phase of cloud resource provisioning.

When an engineer wants to create or change a cloud resource (like a database, a storage bucket, or a server), they write a configuration file describing what they want. This is called Infrastructure as Code (IaC). The tool OpenTofu reads those files and produces a "plan" — a preview of what it is about to create or change.

Before that plan is applied, Conftest runs it through the OPA/Rego rules to check whether the proposed infrastructure meets security requirements. Again, problems are caught before they exist in the real world.

**OPA** stands for Open Policy Agent — an open-source tool for writing and enforcing policies across many different systems.

**Rego** is the language used to write those policies. It reads like a series of conditions: "If this resource is of this type AND this setting is turned on, then deny it and explain why."

**Conftest** is the command-line tool that feeds a plan file into OPA and reports which rules passed and which failed.

#### Current IaC Rules (Azure)

| Rule | What It Checks | Compliance |
|---|---|---|
| **No public storage** | Azure storage accounts must not allow public, unauthenticated access to files | SOC 2 CC6.1 |
| **Require AKS private cluster** | The Kubernetes control plane must not be exposed to the public internet | HIPAA §164.312 |
| **Require encryption at rest** | Storage resources must have encryption enabled | SOC 2 CC6.6 |
| **No wildcard IAM** | Permission grants must not use `*` (which means "everything") — every permission must be specific | SOC 2 CC6.2 |

---

## How Testing Works

A rule that has never been tested might not actually work. This repository treats policies the same way software engineers treat application code: every rule must have automated tests.

### Kyverno Tests

Each Kyverno policy has a companion test file. The test file describes two categories of fictional deployments:

- **Pass cases** — deployments that follow the rule correctly (the policy should allow them)
- **Fail cases** — deployments that violate the rule (the policy should block them)

When the tests run, the test framework simulates what would happen if each fictional deployment were submitted to Kubernetes. It then checks whether the policy made the right decision in every case. If a policy blocks something it should have allowed, or allows something it should have blocked, the test fails and no one can merge that policy change.

**Example — the "Block latest image tag" policy test:**

| Fictional Deployment | What It Does | Expected Result |
|---|---|---|
| `pod-with-latest-tag` | Uses image `nginx:latest` | **Fail** — policy should block it |
| `pod-with-no-tag` | Uses image `nginx` with no version at all | **Fail** — policy should block it |
| `pod-with-pinned-tag` | Uses image `nginx:1.25.3` | **Pass** — policy should allow it |
| `pod-with-digest` | Uses image `nginx@sha256:abc123...` | **Pass** — policy should allow it |

### OPA / Rego Tests

IaC rules have the same pattern. Each rule file has a companion test file that defines example infrastructure plans — some compliant, some not — and verifies that the rule produces the right output for each.

Tests run automatically in the CI/CD pipeline (the automated system that processes every code change). A policy without tests cannot be merged into the main branch.

---

## How Compliance Evidence Is Produced

When Kyverno enforces a policy on a running Kubernetes cluster, it writes a report called a **PolicyReport**. These reports record:

- Which resource was checked
- Which policy rule was evaluated
- Whether it passed or failed
- Which compliance control ID (e.g., SOC 2 CC6.1) was being enforced

These reports are collected automatically by a separate Arxen system and archived as evidence for audits. When an auditor asks "How do you know your Kubernetes deployments comply with SOC 2 CC6.1?", the answer is these reports — timestamped, machine-generated, and tied directly to the policy code that produced them.

---

## How Policies Target the Right Workloads

Not every rule applies to every application. Arxen uses labels — small metadata tags — on namespaces (isolated sections of Kubernetes) to indicate what kind of workload they contain. Policies use these labels to decide whether they apply.

| Label | What It Means |
|---|---|
| `arxen.io/managed: "true"` | This namespace is managed by Arxen and subject to all baseline policies |
| `arxen.io/compliance-tier: "soc2"` | This namespace runs SOC 2 workloads — baseline + regulated policies apply |
| `arxen.io/compliance-tier: "hipaa"` | This namespace handles health data — all policies apply, with HIPAA-specific checks |
| `arxen.io/compliance-tier: "gdpr"` | This namespace handles EU personal data — all policies apply, with GDPR-specific checks |
| `arxen.io/tenant-id: "<id>"` | Identifies which customer this namespace belongs to |

System namespaces (internal Kubernetes infrastructure like `kube-system`) are always excluded from policies so that core platform components are never accidentally blocked.

---

## What Happens When a Policy Is Violated

When a deployment or infrastructure change violates a rule, the system does not silently discard it. It returns a clear, human-readable error message that explains:

1. **What failed** — the name of the resource and which rule it violated
2. **Why it failed** — the specific configuration that triggered the rule
3. **How to fix it** — concrete instructions for making the deployment compliant

For example, if a developer tries to deploy a container using `nginx:latest`, they would see a message like:

> *"Pod 'my-app' has a container using the 'latest' tag or an untagged image. Mutable tags create non-deterministic deployments that cannot be audited (SOC2 CC6.1). Use a semantic version tag (e.g. myimage:v1.2.3) or an immutable digest (e.g. myimage@sha256:...) on every container."*

The developer can fix the issue, resubmit, and proceed — no security review meeting required.

---

## Summary

This repository is Arxen's automated security guardrail system. It:

- **Prevents** insecure configurations from ever reaching production
- **Enforces** SOC 2, HIPAA, and GDPR requirements automatically and consistently
- **Provides** clear, actionable feedback to developers when something is wrong
- **Generates** auditable evidence of compliance as a byproduct of normal operations
- **Tests itself** — every rule is verified to work correctly before it can be used

The result is a system where security and compliance are not a separate gate that slows teams down, but a continuous, invisible check built into the development process itself.
