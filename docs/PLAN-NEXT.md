# PKI Platform - Future Roadmap

## Philosophy

V1 is intentionally conservative:

- Offline-first
- Single-admin
- Git-native
- OpenSSL-backed
- No online issuance
- No web UI

Every future feature must preserve:

- Private keys remain local whenever possible
- Git remains the source of truth
- Filesystem remains canonical
- Auditability is never reduced

---

# V2 - Operational Maturity

Goal:

Improve administrator experience and deployment reliability.

## Native Go Certificate Engine

Reduce OpenSSL dependency.

Current:

CLI
→ OpenSSL

Target:

CLI
→ PKI Engine
→ Native Go x509

OpenSSL may remain as a compatibility backend.

Benefits:

- Fewer subprocess calls
- Easier testing
- Better portability
- Easier Windows support

---

## YubiKey Support

Implement:

- PIV slot support
- Root CA signing
- Intermediate signing

Signer implementations:

- FileSigner
- YubiKeySigner

Use cases:

- Root CA stored on YubiKey
- Intermediate stored on YubiKey

---

## PKCS#11 Support

Implement:

- SoftHSM
- Thales
- Nitrokey HSM
- Future vendor support

New signer:

- PKCS11Signer

---

## Improved Publication System

Current:

Git Push
→ Server Pull
→ Rebuild

Future:

Git Push
→ Validation
→ Publish

Validation checks:

- Broken chains
- Invalid CRLs
- Missing files
- Policy violations

---

## Certificate Renewal Workflows

Add:

pki renew

Capabilities:

- Discover expiring certs
- Reissue using previous values
- Preserve metadata

---

## CSR Workflows

Support:

pki csr sign

Use cases:

- External keypairs
- Existing systems
- Hardware appliances

---

## Enhanced Analysis

New commands:

pki analyze trust

pki analyze duplicates

pki analyze usage

pki analyze exposure

Examples:

- Duplicate SANs
- Weak algorithms
- Long-lived certs
- Broken chains

---

## Enhanced Policy Engine

Add:

- Named policies
- Inheritance
- Overrides

Example:

global.yaml

tls-policy.yaml

smime-policy.yaml

---

## Git Commit Signing Enforcement

Require:

- Signed commits
- Trusted commit keys

Audit trail becomes cryptographically verifiable.

---

# V3 - Enterprise Features

Goal:

Support larger organizations without abandoning offline-first principles.

---

## Multi-Admin Support

Add:

- User identities
- Roles
- Authorization

Roles:

- PKI Admin
- Auditor
- Issuer
- Policy Manager

---

## Approval Workflows

Example:

Request
→ Review
→ Approval
→ Issue

Optional feature.

Disabled by default.

---

## Web UI

Read-only first.

Functions:

- Browse certificates
- View revocations
- Audit exploration
- Trust hierarchy

No issuance initially.

---

## Online Enrollment

Controlled enrollment process.

Clients submit:

- CSR
- Metadata

Admins approve from CLI.

Server never directly issues.

---

## ACME Support

Support:

- RFC 8555 ACME

Use cases:

- Internal TLS
- mTLS workloads

Implementation:

ACME API
→ Generates request
→ Uses existing issuance engine

Must still respect policy validation.

---

## Certificate Templates Marketplace

Repository of profiles.

Examples:

- Kubernetes
- Postfix
- Dovecot
- Traefik
- Envoy
- Code Signing
- S/MIME

---

## Organization-Wide Search

Cross-PKI search:

pki search --all-tenants

---

# V4 - High Assurance PKI

Goal:

Support security-sensitive deployments.

---

## Mandatory HSM Mode

Enforce:

- Root key cannot exist on disk
- Intermediate key cannot exist on disk

Required:

- YubiKey
- PKCS#11

---

## Threshold Signing

Support:

M of N approvals.

Examples:

2-of-3 administrators

3-of-5 administrators

---

## Air-Gapped Root Workflow

Dedicated commands:

pki export-sign-request

pki import-sign-response

Use case:

Offline root laptop.

---

## Transparency Log

Certificate transparency style system.

Every issuance recorded.

Properties:

- Append only
- Verifiable
- Auditable

---

## Tamper-Evident Audit Logs

Hash chain:

Audit N
→ hashes Audit N-1

Detects modification attempts.

---

# V5 - Ecosystem

Goal:

Become a PKI platform rather than a PKI tool.

---

## Plugin System

Examples:

- Custom certificate profiles
- Custom issuers
- Custom publication targets

---

## API SDK

Official SDKs:

- Go
- Python
- Rust

---

## Terraform Provider

Resources:

- CA
- Intermediate
- Certificate

---

## Kubernetes Operator

Manage PKI from CRDs.

---

## External Artifact Distribution

Support:

- S3
- Azure Blob
- GCS
- GitHub Pages
- Static hosting

---

# Features Explicitly Deferred

Not planned unless demand exists.

- Public CA operation
- Commercial trust programs
- Browser root inclusion
- ADCS replacement
- LDAP directory services
- Email server software
- Hardware appliance management

---

# Long-Term Vision

The project should ultimately become:

"A Git-native PKI platform that combines the simplicity of OpenSSL, the operational model of Git, and the security practices of modern certificate infrastructure."

Core values remain unchanged:

- Offline-first
- Git-native
- Auditable
- Immutable
- Open standards
- HSM-ready
