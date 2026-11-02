# ARCHITECTURE.md

# PKI Platform Architecture

## Overview

The platform is an offline-first, Git-native PKI management system.

Principles:
- Filesystem is canonical source of truth
- SQLite is an index/cache layer
- Private keys never leave the admin workstation
- Server is read-only and never issues certificates
- Git is the replication and publication mechanism
- Audit data is immutable
- Certificates are immutable
- Multiple PKIs (tenants) supported

---

# High-Level Architecture

```text
+-------------------+
| Admin Workstation |
+-------------------+
| Interactive CLI   |
| Policy Engine     |
| PKI Engine        |
| OpenSSL Provider  |
| SQLite Index      |
+---------+---------+
          |
          | Git Push
          v
+-------------------+
| Git Repository    |
+---------+---------+
          |
          | Pull/Watch
          v
+-------------------+
| PKI Server        |
+-------------------+
| Repo Watcher      |
| Artifact Builder  |
| OCSP Responder    |
| CRL Publisher     |
| AIA Publisher     |
| Read-only API     |
+-------------------+
```

---

# Repository Layout

```text
tenants/

  example-corp/

    tenant.yaml

    policy/
      policy.yaml

    profiles/
      tls-server.yaml
      tls-client.yaml
      smime.yaml
      codesign.yaml
      ocsp.yaml
      mtls.yaml

    authorities/
      root/
      tls/
      smime/
      codesign/
      ocsp/

    certificates/
      active/
      revoked/
      expired/

    revocations/

    crls/

    audit/

    publish/

    cache/
      index.db
```

---

# Trust Hierarchy

```text
Root CA
 |
 +-- TLS Intermediate
 |
 +-- S/MIME Intermediate
 |
 +-- Code Signing Intermediate
 |
 +-- OCSP Intermediate
 |
 +-- Future Intermediates
```

Separate intermediates isolate compromise domains.

---

# Component Architecture

## CLI Layer

Responsibilities:

- Interactive workflows
- Search and selection
- Certificate issuance
- Certificate revocation
- Certificate inspection
- Analysis tools
- Git operations
- Publication workflow

Primary Commands:

```text
pki init
pki issue
pki revoke
pki inspect
pki search
pki tree
pki analyze
pki audit
pki diff
pki doctor
pki publish
```

---

## PKI Engine

Responsibilities:

- Issuance orchestration
- Revocation orchestration
- Policy validation
- Certificate lifecycle tracking
- Audit generation

Flow:

```text
Request
 -> Policy Validation
 -> Profile Validation
 -> OpenSSL Provider
 -> Filesystem Write
 -> SQLite Index Update
 -> Audit Entry
 -> Git Commit
```

---

## OpenSSL Provider

Purpose:

Abstract OpenSSL implementation details.

Future providers:

```text
OpenSSLProvider
GoX509Provider
```

Interface:

```go
type CertificateProvider interface {
    CreateCA(...)
    CreateIntermediate(...)
    Issue(...)
    Revoke(...)
    GenerateCRL(...)
}
```

---

# Policy Engine

All issuance must pass policy validation.

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

Validation Areas:

- Validity
- Algorithms
- Profile restrictions
- Key sizes
- Extension constraints
- Custom OIDs

---

# Profile System

Profiles define certificate behavior.

Example:

```yaml
name: tls-server

eku:
  - serverAuth

key_usage:
  - digitalSignature

san:
  required: true
```

Supported Profiles:

```text
tls-server
tls-client
smime
codesign
ocsp
mtls
```

---

# Storage Model

## Filesystem (Canonical)

Stores:

- Certificates
- Private keys
- CRLs
- Policies
- Profiles
- Audit records

## SQLite (Index)

Stores:

- Search data
- Metadata
- Reporting indexes
- Statistics
- Query acceleration

Filesystem must always be recoverable without SQLite.

---

# Database Schema

## certificates

```sql
id
serial
subject
issuer
profile
algorithm
status
issued_at
expires_at
path
```

## revocations

```sql
id
certificate_id
reason
comment
revoked_at
```

## audit_logs

```sql
id
timestamp
action
object_type
object_id
summary
```

## intermediates

```sql
id
name
purpose
algorithm
created_at
```

---

# Audit Architecture

Audit records are append-only.

Allowed:

```text
Create
Issue
Revoke
Publish
Generate CRL
Generate OCSP
```

Not Allowed:

```text
Edit audit entry
Delete audit entry
Modify audit entry
```

---

# Search System

Search should drive user workflows.

Never require users to memorize serials.

Example:

```text
pki revoke

Search:
> mail

Results:
 mail.example.com
 smtp.example.com
```

The selected certificate becomes the operation target.

---

# Inspect System

```text
pki inspect
```

Shows:

- Subject
- Issuer
- Serial
- Profile
- Status
- SANs
- EKUs
- Key algorithm
- Expiration
- AIA URLs
- CRL URLs
- OCSP URLs

---

# Analysis System

Supported analyzers:

```text
pki analyze expirations
pki analyze revocations
pki analyze algorithms
pki analyze intermediates
pki analyze policy
```

Future:

```text
pki analyze trust
pki analyze risk
```

---

# Health System

```text
pki doctor
```

Checks:

- Root validity
- Intermediate validity
- CRL availability
- OCSP signer validity
- Git status
- Policy consistency
- Publish status

---

# Git Architecture

Git is the source of truth.

Workflow:

```text
Issue Certificate
 -> Files Updated
 -> Audit Written
 -> Git Commit
 -> Git Push
```

Server Flow:

```text
Watch Repository
 -> Pull Changes
 -> Rebuild Artifacts
 -> Reload Data
```

---

# Publication Architecture

Published Artifacts:

```text
root.pem
intermediate.pem
crl.pem
chains/
ocsp/
```

Private keys are never published.

---

# Server Architecture

## Repo Watcher

Detects Git changes.

## Artifact Builder

Builds publish directory.

## CRL Publisher

Serves current CRLs.

## AIA Publisher

Serves CA certificates and chains.

## Certificate API

Read-only access.

## Audit API

Read-only audit view.

---

# OCSP Architecture

RFC 6960 compliant.

Flow:

```text
OCSP Request
 -> Parse Request
 -> Lookup Serial
 -> Determine Status
 -> Generate Response
 -> Sign Response
 -> Return DER
```

Statuses:

```text
good
revoked
unknown
```

Runtime OCSP must not shell out to OpenSSL.

---

# Revocation Architecture

Flow:

```text
Revoke
 -> Store Revocation
 -> Update Index
 -> Generate CRL
 -> Refresh OCSP Data
 -> Audit Entry
 -> Commit
```

Reasons:

```text
unspecified
keyCompromise
caCompromise
affiliationChanged
superseded
cessationOfOperation
certificateHold
privilegeWithdrawn
aaCompromise
```

---

# Cryptography Strategy

Recommended Defaults:

```text
TLS         ECDSA P-256
OCSP        ECDSA P-256
S/MIME      RSA-3072
CodeSign    RSA-3072
```

Supported:

```text
RSA-3072
ECDSA P-256
Ed25519
```

---

# Signing Abstraction

Required from day one.

```go
type Signer interface {
    Public() crypto.PublicKey

    Sign(
        rand io.Reader,
        digest []byte,
        opts crypto.SignerOpts,
    ) ([]byte, error)
}
```

Implementations:

```text
FileSigner
YubiKeySigner
PKCS11Signer
SoftHSMSigner
```

---

# Non-Goals For V1

```text
ACME
Web UI
LDAP
AD Integration
EST
CMP
Online Issuance
Multi-Admin Approval
```
