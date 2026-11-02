# PKI Platform - Architecture & V1 Plan

## Vision

A Git-native, offline-first PKI platform written in Go.

The platform provides:

- Local certificate issuance
- Root and Intermediate CA management
- RFC 6960 compliant OCSP responder
- Automatic CRL generation and publishing
- S/MIME support
- TLS server/client certificates
- mTLS certificates
- Generic code-signing certificates
- Custom OID support
- Audit logging
- Multi-PKI support
- Future HSM/YubiKey support

OpenSSL is an implementation backend, not the primary architecture.

---

# Core Principles

## Offline-First Security Model

Private keys never leave the administrator workstation.

CLI responsibilities:

- Root CA management
- Intermediate management
- Certificate issuance
- Certificate revocation
- CRL generation
- Artifact publishing
- Git commits

Server responsibilities:

- OCSP responder
- CRL distribution
- AIA distribution
- Read-only PKI APIs
- Audit viewing
- Published artifact hosting

Server must never:

- Issue certificates
- Store CA private keys
- Hold root keys
- Hold intermediate keys

---

## Canonical Storage Model

Filesystem is canonical.

SQLite is an index/cache.

Filesystem contains:

- Certificates
- Metadata
- Revocations
- Policies
- Audit records
- Published artifacts

SQLite contains:

- Search indexes
- Filtering data
- Reporting data
- Analysis data

A fresh clone of the Git repository should be sufficient to rebuild SQLite.

---

## Git as Source of Truth

PKI state lives in Git.

Every operation creates traceable history.

Benefits:

- Backups
- Replication
- Auditability
- Disaster recovery
- Signed commits
- Change review

Publishing Flow:

CLI
→ Commit
→ Push
→ Server Watcher detects change
→ Pull latest repo
→ Rebuild artifacts
→ Reload OCSP data
→ Publish updates

---

# Supported Certificate Types

V1:

- TLS Server
- TLS Client
- mTLS Service
- S/MIME
- Generic Code Signing
- OCSP Signing

Removed from V1:

- SSH certificates

---

# CA Hierarchy

Recommended structure:

Root CA

- TLS Intermediate
- S/MIME Intermediate
- Code Signing Intermediate
- OCSP Intermediate

Separation of trust domains is mandatory.

Compromise of one intermediate must not require rebuilding the entire PKI.

---

# Cryptographic Algorithms

Supported:

- RSA 3072+
- ECDSA P-256
- Ed25519

Recommended Defaults:

TLS: ECDSA P-256
S/MIME: RSA 3072
Code Signing: RSA 3072
OCSP: ECDSA P-256

Ed25519 supported where ecosystem compatibility allows.

---

# Multi-Tenant Architecture

Designed from day one.

Example:

```text
repos/
  corp-a/
  corp-b/
  corp-c/
```

Each tenant maintains its own:

- Policies
- Authorities
- Certificates
- Revocations
- CRLs
- Audit data

---

# Repository Structure

```text
tenant/
├── tenant.yaml
├── policy/
│   └── policy.yaml
├── profiles/
├── authorities/
│   ├── root/
│   ├── tls/
│   ├── smime/
│   ├── codesign/
│   └── ocsp/
├── certificates/
│   ├── active/
│   ├── revoked/
│   └── expired/
├── revocations/
├── crls/
├── audit/
├── publish/
└── cache/
    └── sqlite.db
```

---

# Certificate Profiles

Everything issues from profiles.

Examples:

- tls-server.yaml
- tls-client.yaml
- mtls.yaml
- smime.yaml
- codesign.yaml
- ocsp.yaml

Profiles define:

- EKUs
- Key usage
- SAN requirements
- Validity periods
- Algorithms
- Policy constraints

---

# PKI Policy Layer

Every certificate request passes through policy validation.

Example:

```yaml
max_validity_days: 397

allowed_algorithms:
  - rsa3072
  - ecdsa-p256
  - ed25519

allow_custom_oid: true
allow_wildcards: false
```

Policy validates:

- Allowed algorithms
- Allowed profiles
- Validity periods
- OIDs
- Naming conventions

---

# Custom OID Support

Required.

Example:

```yaml
custom_extensions:
  - oid: 1.2.3.4.5
    critical: false
    value: custom-data
```

---

# Revocation Model

Certificates are immutable.

Allowed:

- Issue
- Revoke
- Replace

Not allowed:

- Modify issued certificate

Supported revocation reasons:

- unspecified
- keyCompromise
- caCompromise
- affiliationChanged
- superseded
- cessationOfOperation
- certificateHold
- privilegeWithdrawn
- aaCompromise

---

# Automatic CRL Generation

Revocation event:

1. Update metadata
2. Create audit record
3. Regenerate CRL
4. Publish CRL
5. Update SQL index
6. Commit changes

Manual CRL generation should not be required.

---

# OCSP Architecture

RFC 6960 compliant implementation.

Do not use OpenSSL responder at runtime.

Runtime Flow:

Client
→ OCSP Request
→ Parse ASN.1
→ Lookup Certificate
→ Build BasicOCSPResponse
→ Sign Response
→ Return DER

Statuses:

- good
- revoked
- unknown

OCSP signing uses dedicated OCSP signing certificates.

---

# Server Responsibilities

Components:

- Git watcher
- Repo synchronizer
- Artifact builder
- RFC6960 OCSP responder
- CRL publisher
- AIA publisher
- Read-only API
- Health endpoints

Internet-facing deployment.

---

# Read-Only API

```http
GET /api/v1/certificate/{serial}
GET /api/v1/intermediates
GET /api/v1/root
GET /api/v1/revocations
GET /api/v1/crls
GET /api/v1/audit
GET /api/v1/health
```

Additional endpoints:

```http
GET /root.pem
GET /tls-intermediate.pem
GET /smime-intermediate.pem
GET /codesign-intermediate.pem
POST /ocsp
```

---

# Audit Logging

Immutable audit records.

Tracked events:

- Root creation
- Intermediate creation
- Certificate issuance
- Certificate revocation
- Policy modification
- CRL publication
- Publishing events

Audit records should be queryable from CLI and API.

---

# Signer Abstraction

Future HSM support must be designed from the start.

Go interface:

```go
type Signer interface {
    Public() crypto.PublicKey
    Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}
```

Implementations:

- FileSigner
- YubiKeySigner
- PKCS11Signer
- SoftHSMSigner

---

# CLI Philosophy

Interactive-first.

Inspired by modern setup CLIs.

Avoid forcing administrators to type serial numbers.

Use searchable selectors backed by SQLite indexes.

---

# Major CLI Commands

```text
pki init
pki issue
pki revoke
pki inspect
pki search
pki tree
pki analyze
pki audit
pki doctor
pki diff
pki publish
```

---

# Interactive Certificate Selection

Instead of:

```bash
pki revoke --serial 1234
```

Use:

```bash
pki revoke
```

Interactive search:

- Common name
- Email
- SAN
- Status
- Profile

Then choose from results.

---

# Inspect Command

```bash
pki inspect
```

Displays:

- Subject
- Issuer
- Serial
- Status
- Validity
- SANs
- EKUs
- Key usage
- OIDs
- AIA
- OCSP URL
- CRL URL

---

# Search Command

Examples:

```bash
pki search --status active
pki search --profile smime
pki search --expires 30d
pki search --issuer tls
```

---

# Tree Command

Displays trust hierarchy.

```text
Root
├── TLS Intermediate
├── S/MIME Intermediate
└── Code Signing Intermediate
```

---

# Analyze Command

Subcommands:

- expirations
- revocations
- intermediates
- algorithms
- policy

Provides operational visibility into PKI health.

---

# Doctor Command

Health diagnostics.

Checks:

- Root validity
- Intermediate validity
- CRL status
- OCSP status
- Git status
- Policy correctness
- Published artifact completeness

---

# Diff Command

Shows changes since previous publish.

Examples:

- New certificates
- Revocations
- CRL updates
- Policy changes

---

# OpenSSL Usage

OpenSSL is a backend implementation.

Initial uses:

- Root creation
- Intermediate creation
- CSR handling
- Certificate issuance
- CRL generation

OpenSSL should not define the public architecture.

---

# Explicitly Out of Scope for V1

- ACME
- Web UI
- LDAP
- Active Directory integration
- CMP
- EST
- Enrollment workflows
- Approval workflows
- Multi-admin RBAC
- Online certificate issuance

---

# V1 Success Criteria

A single administrator can:

- Create PKIs
- Create roots and intermediates
- Issue TLS certificates
- Issue S/MIME certificates
- Issue code-signing certificates
- Revoke certificates
- Automatically publish CRLs
- Serve RFC-compliant OCSP responses
- Track all actions in audit logs
- Manage everything through Git
- Recover the entire PKI from repository state
