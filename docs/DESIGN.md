# DESIGN.md

# PKI Platform Detailed Design

**Version:** 1.0
**Status:** Approved for Implementation

---

# Purpose

This document defines the implementation details of the PKI Platform.

The platform is designed as:

- Offline-first
- Git-native
- Filesystem-canonical
- Single-admin
- Private-key-local
- RFC-compliant
- Future HSM-ready

The system is intended for small organizations that require:

- Internal PKI
- TLS certificates
- Client certificates
- mTLS certificates
- S/MIME certificates
- Generic code-signing certificates
- OCSP infrastructure
- CRL infrastructure

---

# Design Principles

## Offline First

Private keys never leave the administrator workstation.
Only public artifacts are published.

### Allowed on Server
- Root certificates
- Intermediate certificates
- Certificate metadata
- CRLs
- OCSP data
- Audit records
- Read-only indexes

### Forbidden on Server
- Root private keys
- Intermediate private keys
- OCSP private keys
- Certificate issuance
- Certificate revocation

## Git Native
Git is the operational source of truth.
All changes should be committed into Git.

## Immutable Operations
Allowed: Issue, Inspect, Revoke, Replace.
Forbidden: Modify certificate metadata or certificates.

## Filesystem Canonical
Filesystem is authoritative.
SQLite is a cache/index and can be rebuilt.

---

# System Architecture

    CLI
      ↓
    PKI Engine
      ↓
    Policy / OpenSSL Provider / SQLite Index
      ↓
    Git Repository
      ↓
    PKI Server
      ├─ OCSP
      ├─ CRL
      ├─ AIA
      ├─ Audit API
      └─ Search API

---

# Repository Layout

    tenant/
    ├── tenant.yaml
    ├── policy/
    ├── profiles/
    ├── authorities/
    ├── certificates/
    ├── revocations/
    ├── crls/
    ├── audit/
    ├── publish/
    └── cache/index.sqlite

---

# Multi-Tenant Model

Each PKI tenant is self-contained in its own Git repository.

---

# Certificate Authorities

## Root CA
- Offline
- Long validity
- Signs intermediates only

## Intermediates
- TLS
- S/MIME
- Code Signing
- OCSP

Compromise of one intermediate should not affect others.

---

# Profiles

Examples:
- tls-server
- tls-client
- smime
- codesign
- mtls
- ocsp

Profiles define validity, EKUs, key usage, SAN requirements, and defaults.

---

# Policy Layer

Controls:
- Max validity
- Allowed algorithms
- Wildcards
- Custom OIDs
- Allowed profiles

Supported algorithms:
- RSA 3072
- ECDSA P-256
- Ed25519

---

# Custom OID Support

Custom certificate extensions must be supported and validated by policy.

---

# Audit System

Immutable audit events:
- ROOT_CREATED
- INTERMEDIATE_CREATED
- CERT_ISSUED
- CERT_REVOKED
- CRL_GENERATED
- PUBLISH_COMPLETED

---

# Signer Interface

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

# Git Workflow

Issue → Validate → Generate → Write Files → Update Index → Audit → Git Commit

Revocation → Revocation Record → CRL Generation → Audit → Git Commit

Publication:

Git Push → Server Pull → Validate → Rebuild Publish Directory → Reload OCSP

---

# SQLite Index

Tables:
- certificates
- revocations
- audit_events
- intermediates
- profiles

Used only for search and reporting.

---

# OCSP Responder

RFC 6960 compliant.

Flow:
1. Parse request
2. Extract serial
3. Lookup status
4. Build response
5. Sign response
6. Return DER

Runtime OCSP handling must not shell out to OpenSSL.

---

# CRL Generation

Automatically triggered on every revocation.

---

# Server API

Read-only:

- GET /api/v1/certificates
- GET /api/v1/certificates/{serial}
- GET /api/v1/root
- GET /api/v1/intermediates
- GET /api/v1/audit
- GET /api/v1/health

---

# CLI Commands

Core:
- pki init
- pki publish
- pki doctor

Authorities:
- pki root create
- pki intermediate create
- pki intermediate inspect

Certificates:
- pki issue
- pki revoke
- pki inspect
- pki search

Analysis:
- pki analyze expirations
- pki analyze revocations
- pki analyze algorithms
- pki analyze policy
- pki tree

Audit:
- pki audit

---

# Interactive Selection

Users should select certificates interactively instead of typing serial numbers.

---

# Doctor Checks

- Root exists
- Intermediate validity
- CRL validity
- OCSP signer validity
- Git repository state
- Policy validity
- Publish integrity

---

# Testing Strategy

Unit Tests:
- policies
- profiles
- indexing
- revocation
- audit

Integration Tests:
- OpenSSL provider
- issuance
- revocation
- publish
- git synchronization

Compliance Tests:
- RFC 5280
- RFC 6960
- CRL validation

---

# V1 Non-Goals

- ACME
- LDAP
- EST
- CMP
- Web UI
- RBAC
- Online issuance
- Multi-admin approval

---

# Success Criteria

1. Multiple PKIs supported.
2. Private keys remain local.
3. TLS, client, mTLS, S/MIME, code-signing, and OCSP certs supported.
4. RFC-compliant OCSP.
5. Automatic CRLs.
6. Git-native publication.
7. Interactive certificate management.
8. Future HSM support without redesign.
