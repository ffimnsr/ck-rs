# ISSUES.md - Chainkeeper V1 Implementation Backlog

## Backlog Contract

### Goals

Turn `docs/PLAN.md`, `docs/ARCHITECTURE.md`, and `docs/DESIGN.md` into a concrete, test-driven implementation backlog that an LLM agent or engineer can execute without making architectural decisions.

### Overview

This backlog is organized into independently workable phases. Phase 1 is the only mandatory shared gate. Phases 2 through 10 own disjoint crates and can be implemented in parallel against the frozen contracts created in Phase 1. Phase 11 is the integration and release gate.

The project is Chainkeeper. The reference documents describe Go, but this repository is `cs-rs`, `AGENTS.md` mandates Rust, and the requested structure is a multi-crate Cargo workspace. The implementation decision is therefore Rust with a multi-crate workspace. All Go interface sketches in the reference documents are translated to Rust traits with equivalent behavior.

### Rules

- Treat `docs/PLAN.md`, `docs/ARCHITECTURE.md`, and `docs/DESIGN.md` as immutable reference input. Do not edit them.
- Implement Rust 2024 edition with MSRV `1.99`.
- Use `ck` as the CLI binary, `ck-server` as the server binary, and `chainkeeper-*` as the workspace crate prefix.
- Do not create a web UI, ACME, EST, CMP, LDAP, RBAC, approval workflow, online issuance, YubiKey, or PKCS#11 implementation in V1. Define the `Signer` trait only.
- Every mutating operation must end with a Git commit. No mutating operation may leave uncommitted PKI state on success.
- Never commit or publish private keys. Private keys live only on the administrator workstation or in a server-provided OCSP signer secret path.
- The filesystem is canonical. SQLite must always be recoverable by `ck index rebuild`.
- Do not add work items that require manual human review, manual deployment, or manual verification. Every checklist item must be verifiable by a command, test, or CI job.
- Non-actionable constraints are plain bullets, not checkboxes.

---

## Global Decisions

### Goals

Freeze cross-phase decisions so phase implementations do not diverge.

### Overview

These decisions override ambiguities and contradictions in the reference documents. They are non-negotiable for V1.

### Rules

- The repository represents exactly one tenant. Multi-PKI means multiple repositories, not a `tenants/` directory inside one repository.
- `tenant.yaml` lives at repository root.
- The SQLite cache lives at `cache/index.sqlite` and is gitignored.
- `publish/` is committed by `ck publish` for static hosting. The server rebuilds to an external `--publish-dir` and never commits.
- Private key files are gitignored and never included in `publish/`.
- Generated content is written atomically: write to a temp file in the target directory, `fsync`, then rename over the destination.
- All timestamps are RFC 3339 UTC with second precision.
- All serial numbers are 16 random bytes encoded as 32 uppercase hex characters.
- All audit event IDs are ULIDs.
- All YAML configs include `version: 1` and reject unknown fields.
- All JSON API responses are stable and documented by tests.
- All binaries write user-facing output with `println!`/`eprintln!`; `tracing` is reserved for diagnostics.

### Decision Matrix

| Area | Decision |
|---|---|
| Project name | Chainkeeper |
| Crate prefix | `chainkeeper-` |
| CLI binary | `ck` |
| Server binary | `ck-server` |
| Language | Rust 2024, MSRV 1.99 |
| Workspace | Multi-crate Cargo workspace, resolver 2, shared workspace lints |
| CLI | `ck`, `clap` derive, `inquire` for TTY selection, `comfy-table` for tables |
| Server | `ck-server`, `axum`, `tokio`, `tower-http` |
| SQLite | `rusqlite` with `bundled`, `rusqlite_migration` |
| X.509 / keys / CRL | `openssl` crate, in-process, no subprocess execution |
| OCSP codec | `rasn-ocsp` and `rasn-cms`; `openssl` for signature operations through `Signer` |
| Certificate parsing | `x509-parser` |
| Git | `git2` |
| File watching | `notify` plus OID polling fallback |
| YAML | `serde_yaml_ng` |
| JSON | `serde_json` |
| Time | `time` |
| Errors | `thiserror` in libraries, `anyhow` in binaries |
| Logging | `tracing` and `tracing-subscriber` JSON |
| Atomic state swap | `arc-swap` |
| Testing | `tempfile`, `assert_cmd`, `predicates`, `tokio::test` |
| Algorithms | `rsa3072`, `ecdsa-p256`, `ed25519` |
| Default TLS algorithm | `ecdsa-p256` |
| Default S/MIME algorithm | `rsa3072` |
| Default code-signing algorithm | `rsa3072` |
| Default OCSP algorithm | `ecdsa-p256` |
| Root validity | 7300 days |
| Intermediate validity | 3650 days |
| OCSP signer validity | 90 days |
| Leaf certificate max validity | 397 days |
| CRL next update | 7 days after generation |
| OCSP next update | 1 hour after generation |
| OCSP transport | `POST /ocsp` only |
| API style | Plural resources under `/api/v1` |
| Audit storage | One immutable JSON file per event at `audit/events/<ULID>.json` |
| Key encryption | Unencrypted PKCS#8 with mode `0600` by default; AES-256-CBC encryption when `CHAINKEEPER_KEY_PASSPHRASE` is set |
| Root key storage | `authorities/root/key.pem`, gitignored |
| Intermediate key storage | `authorities/<name>/key.pem`, gitignored |
| Leaf key storage | `certificates/<status>/<SERIAL>.key.pem`, gitignored |
| OCSP signer key location | `authorities/ocsp-signer/key.pem` on the workstation; server reads it from `CHAINKEEPER_OCSP_KEY_PATH` |
| Server CA key access | Forbidden for root and intermediate keys |
| Server OCSP key access | Allowed only for the dedicated OCSP responder key, never for CA keys |
| Server TLS | Terminated by a reverse proxy in V1; `ck-server` serves HTTP |
| Authentication | No authentication in V1; API and artifacts are public read-only |

### Repository Layout Decision

```text
tenant.yaml
policy/policy.yaml
profiles/{tls-server,tls-client,mtls,smime,codesign,ocsp}.yaml
authorities/root/{cert.pem,key.pem,chain.pem,authority.yaml}
authorities/{tls,smime,codesign,ocsp}/{cert.pem,key.pem,chain.pem,authority.yaml}
authorities/ocsp-signer/{cert.pem,key.pem,chain.pem,authority.yaml}
certificates/active/<SERIAL>.{pem,yaml,key.pem}
certificates/revoked/<SERIAL>.{pem,yaml,key.pem}
certificates/expired/<SERIAL>.{pem,yaml,key.pem}
revocations/<SERIAL>.yaml
crls/<authority>.{crl.der,crl.pem,yaml,number}
audit/events/<ULID>.json
publish/
cache/index.sqlite
.gitignore
```

### Gitignore Decision

```gitignore
/target/
/cache/
/.chainkeeper/
authorities/**/key.pem
certificates/**/*.key.pem
*.key
```

### Phase Dependency Map

| Phase | Owns | Depends on | Parallel-safe after |
|---|---|---|---|
| 1 | Workspace, `chainkeeper-core`, `chainkeeper-testkit`, crate stubs | none | n/a, this is the gate |
| 2 | `chainkeeper-store` | Phase 1 contracts | Phase 1 |
| 3 | `chainkeeper-crypto` | Phase 1 contracts | Phase 1 |
| 4 | `chainkeeper-policy` | Phase 1 contracts | Phase 1 |
| 5 | `chainkeeper-audit`, `chainkeeper-git` | Phase 1 contracts | Phase 1 |
| 6 | `chainkeeper-engine` | Phase 1 contracts, test doubles | Phase 1 |
| 7 | `chainkeeper-publish` | Phase 1 contracts | Phase 1 |
| 8 | `chainkeeper-ocsp` | Phase 1 contracts | Phase 1 |
| 9 | `chainkeeper-cli` | Phase 1 contracts, test doubles | Phase 1 |
| 10 | `chainkeeper-server` | Phase 1 contracts, test doubles | Phase 1 |
| 11 | Integration tests, CI, packaging | all phases | all phases |

### Traceability Matrix

| Reference section | Covered by |
|---|---|
| Core Principles, Offline-First | Phases 1, 5, 6, 11 |
| Canonical Storage, Git Source of Truth | Phases 1, 2, 5, 6 |
| Supported Certificate Types | Phases 3, 4, 6 |
| CA Hierarchy | Phases 3, 6 |
| Cryptographic Algorithms | Phases 3, 4 |
| Multi-Tenant Architecture | Phases 1, 6, 11 |
| Repository Structure | Phases 1, 2 |
| Certificate Profiles | Phase 4 |
| PKI Policy Layer | Phase 4 |
| Custom OID Support | Phases 3, 4, 6 |
| Revocation Model | Phases 6, 7 |
| Automatic CRL Generation | Phases 6, 7 |
| OCSP Architecture | Phases 8, 10 |
| Server Responsibilities | Phase 10 |
| Read-Only API | Phase 10 |
| Audit Logging | Phases 5, 6, 10 |
| Signer Abstraction | Phase 3 |
| CLI Philosophy, Commands, Selection | Phase 9 |
| Inspect, Search, Tree, Analyze, Doctor, Diff | Phases 6, 9 |
| OpenSSL Usage | Phase 3 |
| Out of Scope | Global Decisions, phase rules |

### Out of Scope for V1

- ACME
- Web UI
- LDAP or Active Directory integration
- CMP or EST
- Enrollment or approval workflows
- Multi-admin RBAC
- Online certificate issuance
- YubiKey, PKCS#11, or SoftHSM signer implementations
- `ck renew`
- `ck csr sign`
- Cross-tenant search
- Signed Git commit enforcement
- Tamper-evident audit hash chains
- External artifact distribution targets

---

## Phase 1 - Foundation and Frozen Contracts

### Goals

Create the Rust workspace, freeze all cross-crate types and traits, provide deterministic test doubles, and establish formatting, linting, and CI so every later phase can work independently.

### Overview

This phase does not implement PKI behavior. It defines the contracts that Phases 2 through 10 consume. All crates are created up front so every later phase can compile and test its own crate without waiting for another phase. The only shared source of truth after this phase is `chainkeeper-core`.

### Rules

- Only Phase 1 may change public types and traits in `chainkeeper-core` without a new backlog item.
- Later phases must not modify another phase's crate.
- Later phases may add private helpers inside their own crate.
- Later phases may add dependencies to their own `Cargo.toml` only from the predeclared `[workspace.dependencies]`.
- Test doubles in `chainkeeper-testkit` must be deterministic and must not use real clocks, fixed filesystem paths, fixed ports, or process-global mutable state.
- Every public library crate must start with `#![forbid(unsafe_code)]`.
- All public traits must be object-safe because the CLI and server consume them as `Arc<dyn Trait>`.
- Use `#[non_exhaustive]` on public enums and structs that may grow.

### Work Items

- [x] **1.1 Create the Cargo workspace**
  - [x] 1.1.1 Create root `Cargo.toml`.
    - Set `[workspace] resolver = "2"`.
    - Set `[workspace.package] edition = "2024"`, `rust-version = "1.99"`.
    - Add members: `crates/chainkeeper-core`, `crates/chainkeeper-store`, `crates/chainkeeper-crypto`, `crates/chainkeeper-policy`, `crates/chainkeeper-audit`, `crates/chainkeeper-git`, `crates/chainkeeper-engine`, `crates/chainkeeper-publish`, `crates/chainkeeper-ocsp`, `crates/chainkeeper-cli`, `crates/chainkeeper-server`, `crates/chainkeeper-testkit`.
    - Add `[workspace.lints.rust] unsafe_code = "forbid"`, `unused_must_use = "deny"`.
    - Add `[workspace.lints.clippy] all = "warn"`, `pedantic = "warn"`, `nursery = "warn"`.
    - Predeclare every third-party dependency listed in the Global Decision Matrix in `[workspace.dependencies]`.
  - [x] 1.1.2 Create `rustfmt.toml`.
    - Set `edition = "2024"`, `max_width = 100`, `use_field_init_shorthand = true`, `imports_granularity = "Crate"`.
  - [x] 1.1.3 Create `clippy.toml`.
    - Set `msrv = "1.99"`.
  - [x] 1.1.4 Create root `.gitignore` exactly as specified in the Global Decisions.
  - [x] 1.1.5 Create `deny.toml`.
    - Deny unknown registries, unknown git sources, yanked crates, and incompatible licenses.
    - Allow `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`.
  - [x] 1.1.6 Create `.github/workflows/ci.yml`.
    - Add jobs for `fmt`, `clippy`, `test`, `doc`, `deny`, and `msrv`.
    - Use `cargo fmt --all --check`.
    - Use `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
    - Use `cargo test --quiet --workspace --all-features`.
    - Use `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
    - Use `cargo deny check`.
    - Run the MSRV job with Rust `1.99.0`.

- [x] **1.2 Create crate skeletons**
  - [x] 1.2.1 Create library crates.
    - Create `chainkeeper-core`, `chainkeeper-store`, `chainkeeper-crypto`, `chainkeeper-policy`, `chainkeeper-audit`, `chainkeeper-git`, `chainkeeper-engine`, `chainkeeper-publish`, `chainkeeper-ocsp`, and `chainkeeper-testkit`.
    - Each library crate contains `src/lib.rs` with `#![forbid(unsafe_code)]` and `#![warn(missing_debug_implementations)]`.
    - Each library crate sets `[lints] workspace = true`.
  - [x] 1.2.2 Create binary crates.
    - Create `chainkeeper-cli` with `[[bin]] name = "ck"` and `src/main.rs`.
    - Create `chainkeeper-server` with `[[bin]] name = "ck-server"` and `src/main.rs`.
    - Binaries depend on `chainkeeper-core` and expose no public library API unless required for tests.
  - [x] 1.2.3 Add compile-time dependency direction guards.
    - `chainkeeper-store` depends on `chainkeeper-core` only.
    - `chainkeeper-crypto` depends on `chainkeeper-core` only.
    - `chainkeeper-policy` depends on `chainkeeper-core` only.
    - `chainkeeper-audit` and `chainkeeper-git` depend on `chainkeeper-core` only.
    - `chainkeeper-engine` depends on `chainkeeper-core` only at compile time.
    - `chainkeeper-publish` depends on `chainkeeper-core` only at compile time.
    - `chainkeeper-ocsp` depends on `chainkeeper-core` only at compile time.
    - `chainkeeper-cli` and `chainkeeper-server` depend on `chainkeeper-core` and `chainkeeper-engine` factory signatures.
    - Add a test in `crates/chainkeeper-core/tests/dependency_direction.rs` that reads each crate's `Cargo.toml` and asserts the allowed dependency set.

- [x] **1.3 Define domain identifiers and primitives**
  - [x] 1.3.1 Implement `Serial`.
    - Newtype around `String`.
    - Constructor accepts only `^[0-9A-F]{1,64}$`.
    - Reject empty, lowercase, odd-length, and path separators.
    - Implement `Display`, `FromStr`, `Serialize`, `Deserialize`.
  - [x] 1.3.2 Implement `AuthorityName`.
    - Newtype around `String`.
    - Constructor accepts only `^[a-z][a-z0-9-]{1,31}$`.
    - Reject `.`, `..`, `/`, `\`, and empty names.
  - [x] 1.3.3 Implement `ProfileName`, `TenantId`, and `EventId`.
    - `ProfileName` follows the `AuthorityName` regex.
    - `TenantId` accepts `^[a-z][a-z0-9-]{1,63}$`.
    - `EventId` wraps a ULID string.
  - [x] 1.3.4 Implement `KeyAlgorithm`.
    - Variants: `Rsa3072`, `EcdsaP256`, `Ed25519`.
    - Serde strings: `rsa3072`, `ecdsa-p256`, `ed25519`.
    - Include `default_for_profile(profile: &str) -> KeyAlgorithm`.
  - [x] 1.3.5 Implement `SignatureScheme`.
    - Variants: `RsaPkcs1Sha256`, `EcdsaSha256`, `Ed25519`.
    - Map from `KeyAlgorithm` with a single total function.
  - [x] 1.3.6 Implement `RevocationReason`.
    - Variants matching the reference document: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`, `aaCompromise`.
    - Map to the RFC 5280 reason code used by OpenSSL.
    - Reject `removeFromCrl` because V1 does not support unrevocation.

- [x] **1.4 Define configuration and record types**
  - [x] 1.4.1 Implement `TenantConfig`.
    - Fields: `version`, `tenant_id`, `display_name`, `created_at`, `default_profile`.
    - Add `ocsp_url`, `ca_issuers_url_template`, `crl_url_template`.
    - Validate URL templates contain `{authority}` where applicable.
  - [x] 1.4.2 Implement `Policy`.
    - Fields: `version`, `max_validity_days`, `allowed_algorithms`, `allowed_profiles`, `allow_custom_oid`, `allow_wildcards`, `max_sans`, `allowed_san_suffixes`, `cn_must_match_san`.
    - Defaults: `max_validity_days = 397`, all three algorithms, all six profiles, `allow_custom_oid = true`, `allow_wildcards = false`, `max_sans = 100`, empty suffix list, `cn_must_match_san = true`.
  - [x] 1.4.3 Implement `Profile`.
    - Fields: `name`, `version`, `authority`, `algorithm`, `validity_days`, `key_usage`, `eku`, `san_required`, `san_types`, `allow_custom_oid`.
    - Define `KeyUsage` and `ExtendedKeyUsage` enums with serde names exactly matching the reference documents.
  - [x] 1.4.4 Implement `AuthorityConfig`.
    - Fields: `name`, `kind`, `parent`, `algorithm`, `validity_days`, `path_len`, `key_usage`, `created_at`.
    - `AuthorityKind` variants: `Root`, `Intermediate`, `OcspSigner`.
  - [x] 1.4.5 Implement `CertificateRecord`.
    - Fields: `serial`, `subject`, `issuer`, `profile`, `authority`, `algorithm`, `sans`, `ekus`, `key_usages`, `issued_at`, `expires_at`, `path`, `revoked_at`, `revocation_reason`, `replaces`.
  - [x] 1.4.6 Implement `CertificateStatus`.
    - Variants: `Active`, `Revoked`, `Expired`.
    - Provide `derive(now, record) -> CertificateStatus` with precedence revoked, expired, active.
  - [x] 1.4.7 Implement `RevocationRecord`.
    - Fields: `version`, `serial`, `authority`, `reason`, `comment`, `revoked_at`, `crl_number`.
  - [x] 1.4.8 Implement `AuditEvent` and `NewAuditEvent`.
    - Fields: `id`, `seq`, `timestamp`, `action`, `object_type`, `object_id`, `summary`, `actor`, `details`.
    - `AuditAction` variants: `REPO_INITIALIZED`, `ROOT_CREATED`, `INTERMEDIATE_CREATED`, `OCSP_SIGNER_CREATED`, `CERT_ISSUED`, `CERT_REVOKED`, `CERT_REPLACED`, `CRL_GENERATED`, `PUBLISH_COMPLETED`, `POLICY_UPDATED`, `PROFILE_UPDATED`, `INDEX_REBUILT`.
  - [x] 1.4.9 Implement request/result types.
    - `InitRequest`, `CreateAuthorityRequest`, `CreateOcspSignerRequest`, `IssueRequest`, `RevokeRequest`, `SearchQuery`, `AuditQuery`, `PublishOptions`, `DiffRequest`.
    - `IssueRequest` fields include `profile`, `subject`, `sans`, `custom_extensions`, `algorithm`, `validity_days`, `csr_pem`, `key_out`, `replaces`.
    - `SubjectName` fields: `cn`, `organization`, `organizational_unit`, `country`, `state`, `locality`, `email`.
    - `San` enum variants: `Dns`, `Ip`, `Email`, `Uri`.
    - `CustomExtension` fields: `oid`, `critical`, `value_utf8`, `value_hex`; exactly one value field must be set.
  - [x] 1.4.10 Implement report types.
    - `InitReport`, `IssueReport`, `RevokeReport`, `InspectReport`, `TreeReport`, `AnalyzeReport`, `DoctorReport`, `DoctorFinding`, `Severity`, `DiffReport`, `IndexReport`.
    - `AnalyzeKind` variants: `Expirations`, `Revocations`, `Intermediates`, `Algorithms`, `Policy`.
    - `DoctorFinding` fields: `code`, `severity`, `message`, `object_id`.
  - [x] 1.4.11 Implement `PublishManifest` and `PublishArtifact`.
    - Fields include `version`, `generated_at`, `source_commit`, `tenant_id`, `artifacts`.
    - `PublishArtifact` fields: `path`, `sha256`, `bytes`.
  - [x] 1.4.12 Implement `ServerSnapshot` and `ServerHealth`.
    - `ServerSnapshot` includes `repo_commit`, `manifest`, `certificates`, `revocations`, `authorities`, `crls`, `audit_events`.
    - `ServerHealth` includes `status`, `repo_commit`, `publish_commit`, `ocsp_ready`, `errors`.

- [x] **1.5 Define the frozen trait contracts**
  - [x] 1.5.1 Define `Clock`.
    - `fn now(&self) -> OffsetDateTime`.
    - `SystemClock` returns real UTC time.
    - `FixedClock` lives in `chainkeeper-testkit` only.
  - [x] 1.5.2 Define `IdGenerator`.
    - `fn ulid(&self) -> String`.
    - `fn serial(&self) -> Serial`.
    - Production implementation uses `rand` and `ulid`.
  - [x] 1.5.3 Define `Signer`.
    - `fn algorithm(&self) -> KeyAlgorithm`.
    - `fn public_key_der(&self) -> Result<Vec<u8>>`.
    - `fn sign(&self, message: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>>`.
    - Document that HSM implementations will implement this trait without changing callers.
  - [x] 1.5.4 Define `CertificateProvider`.
    - `fn generate_key(&self, alg: KeyAlgorithm) -> Result<KeyMaterial>`.
    - `fn create_root(&self, req: &CreateAuthorityRequest) -> Result<AuthorityBundle>`; the provider generates and returns the root key.
    - `fn create_intermediate(&self, req: &CreateAuthorityRequest, parent: &AuthorityMaterial, parent_signer: &dyn Signer) -> Result<AuthorityBundle>`.
    - `fn create_ocsp_signer(&self, req: &CreateOcspSignerRequest, parent: &AuthorityMaterial, parent_signer: &dyn Signer) -> Result<SignerBundle>`.
    - `fn issue(&self, req: &IssueRequest, signer: &dyn Signer) -> Result<IssuedCertificate>`.
    - `fn generate_crl(&self, req: &CrlRequest, signer: &dyn Signer) -> Result<CrlBundle>`.
  - [x] 1.5.5 Define `CertificateStore`.
    - `fn load_tenant(&self) -> Result<TenantConfig>`.
    - `fn load_policy(&self) -> Result<Policy>`.
    - `fn load_profiles(&self) -> Result<Vec<Profile>>`.
    - `fn write_certificate(&self, cert: &IssuedCertificate) -> Result<PathBuf>`.
    - `fn get_certificate(&self, serial: &Serial) -> Result<Option<CertificateRecord>>`.
    - `fn list_certificates(&self) -> Result<Vec<CertificateRecord>>`.
    - `fn move_certificate(&self, serial: &Serial, to: CertificateStatus) -> Result<()>`.
    - `fn write_revocation(&self, record: &RevocationRecord) -> Result<PathBuf>`.
    - `fn list_revocations(&self) -> Result<Vec<RevocationRecord>>`.
    - `fn write_authority(&self, bundle: &AuthorityBundle) -> Result<()>`.
    - `fn load_authority(&self, name: &AuthorityName) -> Result<Option<AuthorityMaterial>>`.
    - `fn list_authorities(&self) -> Result<Vec<AuthorityRecord>>`.
  - [x] 1.5.6 Define `IndexStore`.
    - `fn open(path: &Path) -> Result<Self>` is not object-safe; instead define `fn rebuild(&self, records: &IndexRecords) -> Result<IndexReport>` and `fn query(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>>`.
    - Add methods `upsert_certificate`, `upsert_revocation`, `upsert_authority`, `upsert_audit_event`, `list_audit`, `stats`, `schema_version`.
  - [x] 1.5.7 Define `ProfileRegistry`.
    - `fn get(&self, name: &ProfileName) -> Result<Profile>`.
    - `fn list(&self) -> Vec<Profile>`.
    - `fn validate(&self, profile: &Profile) -> Result<()>`.
  - [x] 1.5.8 Define `PolicyEngine`.
    - `fn validate_issue(&self, policy: &Policy, profile: &Profile, request: &IssueRequest) -> Result<()>`.
    - `fn validate_custom_extension(&self, policy: &Policy, ext: &CustomExtension) -> Result<()>`.
    - `fn validate_profile(&self, policy: &Policy, profile: &Profile) -> Result<()>`.
  - [x] 1.5.9 Define `AuditLog`.
    - `fn append(&self, event: NewAuditEvent) -> Result<AuditEvent>`.
    - `fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>>`.
    - `fn next_seq(&self) -> Result<u64>`.
  - [x] 1.5.10 Define `GitRepository`.
    - `fn init(&self, path: &Path) -> Result<()>`.
    - `fn head_commit(&self) -> Result<String>`.
    - `fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String>`.
    - `fn diff(&self, from: &str, to: &str) -> Result<Vec<GitChange>>`.
    - `fn status(&self) -> Result<GitStatus>`.
    - `fn is_clean(&self) -> Result<bool>`.
  - [x] 1.5.11 Define `RepositoryLock`.
    - `fn acquire_exclusive(&self, timeout: Duration) -> Result<LockGuard>`.
    - `LockGuard` releases on drop.
  - [x] 1.5.12 Define `CrlManager`.
    - `fn update_for_authority(&self, authority: &AuthorityName) -> Result<CrlBundle>`.
    - `fn list_crls(&self) -> Result<Vec<CrlRecord>>`.
  - [x] 1.5.13 Define `PublishBuilder`.
    - `fn build(&self, options: &PublishOptions) -> Result<PublishManifest>`.
    - `fn validate_publish_dir(&self, path: &Path) -> Result<()>`.
  - [x] 1.5.14 Define `OcspResponder`.
    - `fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>>`.
    - `fn reload(&self) -> Result<()>`.
    - `fn ready(&self) -> bool`.
  - [x] 1.5.15 Define `ChainkeeperService`.
    - Methods: `init`, `create_root`, `create_intermediate`, `create_ocsp_signer`, `issue`, `revoke`, `inspect`, `search`, `tree`, `analyze`, `audit`, `doctor`, `diff`, `publish`, `rebuild_index`.
    - Each method takes `&self` and returns the matching report type.
  - [x] 1.5.16 Define `ServerStateProvider`.
    - `fn snapshot(&self) -> Arc<ServerSnapshot>`.
    - `fn reload(&self) -> Result<Arc<ServerSnapshot>>`.
    - `fn health(&self) -> ServerHealth`.
  - [x] 1.5.17 Add a contract test that constructs every trait as `Arc<dyn Trait>`.
    - The test lives in `crates/chainkeeper-core/tests/object_safety.rs`.
    - It uses `chainkeeper-testkit` fakes for each trait.

- [x] **1.6 Define errors**
  - [x] 1.6.1 Create `ChainkeeperError` in `chainkeeper-core`.
    - Variants: `Config`, `Validation`, `Policy`, `Profile`, `Crypto`, `Storage`, `Index`, `Audit`, `Git`, `Lock`, `Publish`, `Ocsp`, `NotFound`, `AlreadyExists`, `Conflict`, `NotImplemented`, `Io`.
    - Include `message`, optional `source`, and optional `object_id`.
  - [x] 1.6.2 Implement `exit_code()`.
    - `0` success outside the error type.
    - `1` for operation, validation, policy, crypto, storage, index, audit, git, publish, OCSP, not-found, conflict, I/O.
    - `2` is reserved for CLI usage errors produced by `clap`.
    - `3` for doctor findings reporting errors.
  - [x] 1.6.3 Add `Context` helpers.
    - `ChainkeeperError::with_context(self, message: impl Into<String>) -> Self`.
    - `ChainkeeperError::not_found(object: &str, id: &str)`.
  - [x] 1.6.4 Add a test asserting stable display strings for every variant.
    - Use `insta` only if the project already adopted it; otherwise assert exact `format!` output.

- [x] **1.7 Define filesystem layout helpers**
  - [x] 1.7.1 Create `RepositoryPaths`.
    - Fields for every path in the Repository Layout Decision.
    - Constructor validates root is a directory.
    - Methods return `PathBuf`; no method accepts raw user segments.
  - [x] 1.7.2 Implement safe segment builders.
    - `certificate_path(serial, ext)`, `revocation_path(serial)`, `authority_path(name, file)`, `audit_event_path(ulid)`, `crl_path(authority, ext)`.
    - Each builder validates its newtype before joining.
  - [x] 1.7.3 Implement `atomic_write`.
    - Accept destination, bytes, and mode.
    - Create a `tempfile::NamedTempFile` in the destination parent.
    - Write, `sync_all`, persist over destination.
    - On Unix set mode `0600` for keys and `0644` for public artifacts.
  - [x] 1.7.4 Add traversal tests.
    - Assert `Serial::from_str("../etc/passwd")`, `AuthorityName::from_str("..")`, and `ProfileName::from_str("a/b")` fail.
    - Assert every path builder stays under repository root for valid inputs.

- [x] **1.8 Create `chainkeeper-testkit`**
  - [x] 1.8.1 Implement `FakeClock`.
    - Stores an `OffsetDateTime` behind `RwLock`; exposes `set`, `advance`.
    - Implements `Clock`.
  - [x] 1.8.2 Implement `FakeIdGenerator`.
    - Produces deterministic serials `00000000000000000000000000000001`, `...02`, and ULIDs `01J00000000000000000000001`.
    - Uses a per-instance `AtomicU64`; no global state.
  - [x] 1.8.3 Implement `InMemoryCertificateStore`.
    - Stores tenants, policies, profiles, authorities, certificates, and revocations in `RwLock` maps.
    - Enforces serial uniqueness and path validation.
  - [x] 1.8.4 Implement `FakeCertificateProvider`.
    - Produces deterministic PEM fixtures from checked-in test fixtures.
    - Supports success and configurable failure injection per method.
  - [x] 1.8.5 Implement `FakeSigner`.
    - Returns deterministic signatures derived from `sha2::Sha256(message)`.
  - [x] 1.8.6 Implement `InMemoryAuditLog`.
    - Appends to a vector and rejects duplicate event IDs.
  - [x] 1.8.7 Implement `InMemoryGitRepository`.
    - Stores commits in memory, returns deterministic OIDs, and tracks changed paths.
  - [x] 1.8.8 Implement `FakeOcspResponder` and `FakePublishBuilder`.
  - [x] 1.8.9 Implement `TempTenant`.
    - Creates a `tempfile::TempDir`, writes the default layout, returns `RepositoryPaths`.
    - Includes unique pid plus monotonic counter in the temp directory prefix.
  - [x] 1.8.10 Implement fixture builders.
    - Build valid root, intermediate, OCSP signer, and leaf certificate fixtures with `openssl` crate at test time.
    - Do not depend on pre-existing files outside the test temp directory.
  - [x] 1.8.11 Add a test that runs two `TempTenant` instances in parallel and asserts no shared paths or state.

- [x] **1.9 Add contract tests**
  - [x] 1.9.1 Add serialization round-trip tests for every config and record type.
  - [x] 1.9.2 Add YAML unknown-field rejection tests.
  - [x] 1.9.3 Add default-value tests for `Policy`, `Profile`, and all six built-in profile defaults.
  - [x] 1.9.4 Add trait object-safety tests.
  - [x] 1.9.5 Add error display and exit-code tests.

- [x] **1.10 Add build metadata and diagnostics**
  - [x] 1.10.1 Add `vergen-gix` build metadata to `ck` and `ck-server`.
    - Expose `--version` with version, commit SHA, and target triple.
  - [x] 1.10.2 Add `tracing-subscriber` initialization helper in `chainkeeper-core`.
    - JSON output when `CHAINKEEPER_LOG_FORMAT=json`.
    - Human output otherwise.
    - Default filter `info`.
  - [x] 1.10.3 Add `--no-color` support at the CLI layer only.
    - Do not add color logic to library crates.

### Acceptance Criteria

- [x] `cargo metadata --no-deps --format-version 1` lists all twelve workspace crates.
- [x] `cargo test --quiet -p chainkeeper-core` passes.
- [x] `cargo test --quiet -p chainkeeper-testkit` passes.
- [x] `cargo test --quiet --workspace` passes with all stub crates.
- [x] `cargo fmt --all --check` passes.
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` passes.
- [x] `cargo deny check` passes.
- [x] A test asserts every public trait is usable as `Arc<dyn Trait>`.
- [x] A test asserts all path builders reject traversal inputs.
- [x] A test asserts all fixtures are isolated per `TempTenant` and pass under parallel test execution.

---

## Phase 2 - Canonical Store, SQLite Index, and Search

### Goals

Implement the filesystem-canonical repository store, atomic writes, locking, SQLite schema, index rebuild, and all read queries used by search, inspect, analyze, and the server.

### Overview

This phase owns `chainkeeper-store`. It has no dependency on cryptographic issuance. Tests use fixtures and hand-written records. The index is disposable: deleting `cache/index.sqlite` and rebuilding must produce identical query results.

### Rules

- The filesystem is authoritative; SQLite may never be the only copy of a record.
- Never write a record that fails schema validation.
- Every public artifact write uses `atomic_write`.
- Private key writes use mode `0600`; directories use `0700`; public artifacts use `0644`.
- Do not parse certificate PEM in this phase except to extract serial and issuer fields for fixture validation. Use `x509-parser`.
- Do not read from network, environment, or current working directory. All paths come from `RepositoryPaths`.
- Tests must use `TempTenant` and must not use fixed paths.
- Concurrent writers must serialize through `RepositoryLock`.

### Work Items

- [x] **2.1 Implement repository layout operations**
  - [x] 2.1.1 Implement `init_layout`.
    - Create every directory from the Repository Layout Decision.
    - Create empty `revocations/`, `crls/`, `audit/events/`, `publish/`, `cache/`.
    - Do not create private keys.
  - [x] 2.1.2 Implement `write_tenant`, `write_policy`, `write_profile`, and `load_*`.
    - Serialize YAML with `version: 1`.
    - Validate on write and on load.
  - [x] 2.1.3 Implement authority material writes.
    - Write `cert.pem`, `chain.pem`, `authority.yaml`.
    - Write `key.pem` only when supplied and mode `0600`.
    - Reject writes when a different authority with the same name already exists and the certificate differs.
  - [x] 2.1.4 Implement certificate writes.
    - Write `<SERIAL>.pem`, `<SERIAL>.yaml`, and optional `<SERIAL>.key.pem`.
    - Validate the PEM serial matches the metadata serial.
    - Reject duplicate serials.
  - [x] 2.1.5 Implement certificate moves.
    - Move `active` to `revoked` or `expired` with `std::fs::rename` inside the repository.
    - Move the `.pem`, `.yaml`, and optional `.key.pem` together.
    - Abort the operation if any source is missing.
  - [x] 2.1.6 Implement revocation writes.
    - Write `revocations/<SERIAL>.yaml` with `create_new`.
    - Reject duplicate revocation records.
  - [x] 2.1.7 Implement CRL writes.
    - Write `crls/<authority>.crl.der`, `.crl.pem`, `.yaml`, and `.number`.
    - Increment `.number` atomically using `atomic_write`.
  - [x] 2.1.8 Implement audit event path writes.
    - Write `audit/events/<ULID>.json` with `create_new`.
    - Reject duplicate IDs.
  - [x] 2.1.9 Implement `list_certificates`, `list_revocations`, `list_authorities`, and `list_audit_events`.
    - Scan directories in deterministic lexical order.
    - Skip temp files and hidden files.

- [x] **2.2 Implement file locking**
  - [x] 2.2.1 Implement `FileRepositoryLock` using `fs2`.
    - Lock file at `.chainkeeper/lock`.
    - Create `.chainkeeper/` with mode `0700`.
    - Support timeout using bounded retry with 25 ms sleep.
  - [x] 2.2.2 Implement `LockGuard` with RAII release.
  - [x] 2.2.3 Add tests.
    - Two processes or threads contend for the lock; second times out.
    - Lock releases on drop and after panic.
    - Test uses a unique temp path.

- [x] **2.3 Implement SQLite schema and migrations**
  - [x] 2.3.1 Create migration `0001_initial.sql`.
    - Enable `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`.
    - Table `meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`.
    - Table `certificates`.
    - Table `revocations`.
    - Table `intermediates`.
    - Table `profiles`.
    - Table `audit_events`.
    - Table `crls`.
    - FTS5 table `certificates_fts`.
  - [x] 2.3.2 Define `certificates` columns.
    - `id INTEGER PRIMARY KEY`, `serial TEXT NOT NULL UNIQUE`, `subject TEXT NOT NULL`, `issuer TEXT NOT NULL`, `profile TEXT NOT NULL`, `authority TEXT NOT NULL`, `algorithm TEXT NOT NULL`, `status TEXT NOT NULL`, `issued_at TEXT NOT NULL`, `expires_at TEXT NOT NULL`, `path TEXT NOT NULL`, `sans_json TEXT NOT NULL`, `email TEXT`, `eku_json TEXT NOT NULL`, `key_usage_json TEXT NOT NULL`, `revoked_at TEXT`, `revocation_reason TEXT`, `replaces TEXT`.
    - Create indexes on `status`, `profile`, `authority`, `expires_at`, `subject`, and `email`.
  - [x] 2.3.3 Define `revocations` columns.
    - `id INTEGER PRIMARY KEY`, `certificate_id INTEGER NOT NULL REFERENCES certificates(id)`, `serial TEXT NOT NULL UNIQUE`, `authority TEXT NOT NULL`, `reason TEXT NOT NULL`, `comment TEXT NOT NULL DEFAULT ''`, `revoked_at TEXT NOT NULL`, `crl_number INTEGER`.
  - [x] 2.3.4 Define `intermediates` columns.
    - `id INTEGER PRIMARY KEY`, `name TEXT NOT NULL UNIQUE`, `kind TEXT NOT NULL`, `parent TEXT`, `algorithm TEXT NOT NULL`, `not_before TEXT NOT NULL`, `not_after TEXT NOT NULL`, `path TEXT NOT NULL`.
  - [x] 2.3.5 Define `profiles` columns.
    - `name TEXT PRIMARY KEY`, `authority TEXT NOT NULL`, `algorithm TEXT NOT NULL`, `validity_days INTEGER NOT NULL`, `yaml_sha256 TEXT NOT NULL`.
  - [x] 2.3.6 Define `audit_events` columns.
    - `id TEXT PRIMARY KEY`, `seq INTEGER NOT NULL UNIQUE`, `timestamp TEXT NOT NULL`, `action TEXT NOT NULL`, `object_type TEXT NOT NULL`, `object_id TEXT NOT NULL`, `summary TEXT NOT NULL`, `path TEXT NOT NULL`.
  - [x] 2.3.7 Define `crls` columns.
    - `authority TEXT PRIMARY KEY`, `crl_number INTEGER NOT NULL`, `this_update TEXT NOT NULL`, `next_update TEXT NOT NULL`, `revoked_count INTEGER NOT NULL`, `path TEXT NOT NULL`, `sha256 TEXT NOT NULL`.
  - [x] 2.3.8 Create FTS5 index.
    - `certificates_fts(serial, subject, sans, email, profile)`.
    - Use a standalone FTS table maintained by the indexer, not external-content triggers.
    - Rebuild FTS rows inside the same transaction as certificate upserts.
  - [x] 2.3.9 Implement schema version checks.
    - Store schema version in `meta('schema_version')`.
    - On mismatch, run migrations up to the current version.
    - On unsupported newer version, return `ChainkeeperError::Index`.
  - [x] 2.3.10 Add migration tests.
    - Open an empty database and assert all tables exist.
    - Open an old-version database fixture and assert migration succeeds.
    - Assert reopening is idempotent.

- [x] **2.4 Implement index writes and rebuild**
  - [x] 2.4.1 Implement `upsert_certificate`.
    - Use `INSERT ... ON CONFLICT(serial) DO UPDATE`.
    - Update FTS row by deleting and reinserting serial.
    - Store derived status from `CertificateStatus::derive`.
  - [x] 2.4.2 Implement `upsert_revocation`.
    - Resolve `certificate_id` by serial.
    - Reject unknown serial with `NotFound`.
  - [x] 2.4.3 Implement `upsert_authority`.
  - [x] 2.4.4 Implement `upsert_audit_event`.
  - [x] 2.4.5 Implement `rebuild`.
    - Clear all mutable tables in one transaction.
    - Scan filesystem records.
    - Insert certificates, revocations, authorities, profiles, and audit events.
    - Update `meta('rebuilt_at')`.
    - Return counts in `IndexReport`.
  - [x] 2.4.6 Implement `repair`.
    - Rebuild index.
    - Move expired active certificates to `certificates/expired/`.
    - Never modify certificate or metadata content.
    - Report moved serials in `IndexReport`.
  - [x] 2.4.7 Implement `stats`.
    - Return totals per status, profile, authority, algorithm.
  - [x] 2.4.8 Add tests.
    - Create a store with fixtures, rebuild, delete DB, rebuild, assert identical query results.
    - Insert a revocation, rebuild, assert status is revoked.
    - Advance `FakeClock` past expiry, run `repair`, assert file location changes and status is expired.
    - Corrupt a metadata file, assert rebuild reports the exact path and line.

- [x] **2.5 Implement search and filtering**
  - [x] 2.5.1 Implement `SearchQuery` execution.
    - Fields: `text`, `status`, `profile`, `authority`, `expires_within_days`, `include_expired`, `limit`, `offset`.
    - `text` matches serial, subject, CN, email, and SAN using FTS5 with prefix matching.
    - Sort by `expires_at ASC`, then `serial ASC`.
  - [x] 2.5.2 Implement `expires_within_days`.
    - Compute cutoff from injected `Clock`.
    - Exclude expired unless `include_expired` is true.
  - [x] 2.5.3 Implement bounded pagination.
    - Default `limit = 50`, maximum `1000`.
    - Reject `offset > 1_000_000`.
  - [x] 2.5.4 Implement `count`.
  - [x] 2.5.5 Add tests.
    - Search by CN substring.
    - Search by email.
    - Search by SAN.
    - Search by status.
    - Search by profile.
    - Search by expires window 30 days.
    - Search with 1,000 fixtures completes under 2 seconds on CI.

- [x] **2.6 Implement read-side record parsing**
  - [x] 2.6.1 Implement PEM parsing with `x509-parser`.
    - Extract serial, subject string, issuer string, not_before, not_after, SANs, EKUs, key usages, and public key algorithm.
    - Return `ChainkeeperError::Storage` with file path on parse failure.
  - [x] 2.6.2 Implement metadata YAML parsing.
    - Validate metadata serial equals PEM serial.
    - Validate `issued_at < expires_at`.
  - [x] 2.6.3 Implement canonical JSON/YAML serialization helpers.
    - Sort map keys for deterministic fixture output.
    - Use `serde_json::to_vec_pretty` with a trailing newline.

- [x] **2.7 Implement index drift detection**
  - [x] 2.7.1 Compare filesystem records with index rows.
  - [x] 2.7.2 Return `DoctorFinding` entries with codes `IDX_MISSING`, `IDX_EXTRA`, `IDX_HASH_MISMATCH`.
  - [x] 2.7.3 Add tests with intentionally stale index rows and missing rows.

- [x] **2.8 Add store integration tests**
  - [x] 2.8.1 Test atomic write failure.
    - Make destination directory read-only on Unix.
    - Assert old file remains unchanged.
  - [x] 2.8.2 Test key permissions.
    - On Unix assert `0600` for keys and `0700` for `.chainkeeper/`.
  - [x] 2.8.3 Test duplicate serial rejection.
  - [x] 2.8.4 Test parallel writes.
    - Spawn 16 threads writing distinct serials through the lock.
    - Assert all 16 exist and index count is 16.
  - [x] 2.8.5 Test deterministic listing order.
    - Insert records in random order, assert list output is lexical.

### Acceptance Criteria

- [x] `cargo test --quiet -p chainkeeper-store` passes.
- [x] A test deletes `cache/index.sqlite`, rebuilds, and asserts identical certificate, revocation, authority, audit, and search results.
- [x] A test asserts `chainkeeper-store` never writes outside `RepositoryPaths`.
- [x] A test asserts all private key writes use mode `0600` on Unix.
- [x] A test asserts 16 concurrent writers produce 16 unique serials with no index loss.
- [x] A test asserts `repair` moves expired certificates without modifying file contents.
- [x] A test asserts search by CN, email, SAN, status, profile, authority, and expiry window.
- [x] `cargo clippy -p chainkeeper-store --all-targets -- -D warnings` passes.

---

## Phase 3 - Crypto Provider, Signers, and Authority Material

### Goals

Implement in-process X.509 key generation, root and intermediate creation, OCSP signer creation, leaf certificate issuance, and CRL signing using the `openssl` crate behind the frozen `CertificateProvider` and `Signer` traits.

### Overview

This phase owns `chainkeeper-crypto`. It produces and verifies cryptographic artifacts but does not orchestrate repository writes or policy validation. All operations are deterministic with respect to injected serial, clock, and subject inputs.

### Rules

- Never shell out to the `openssl` binary from product code. Use the `openssl` crate only.
- Never log private key material, passphrases, or unredacted PEM blocks.
- Keys use PKCS#8 PEM.
- RSA keys are 3072 bits. Ed25519 uses raw Ed25519. ECDSA uses P-256 with SHA-256.
- Root CA certificates are self-signed and have `basicConstraints` critical with `CA:TRUE`.
- Intermediate CA certificates have `basicConstraints` critical with `CA:TRUE` and `pathLenConstraint = 0`.
- Leaf certificates have `basicConstraints` critical with `CA:FALSE`.
- OCSP signer certificates have EKU `OCSPSigning` and key usage `digitalSignature`.
- Authority key identifier and subject key identifier are present on every certificate except where OpenSSL omits SKI for Ed25519; if omitted, tests must assert AKI still exists.
- CRL signing uses the issuing intermediate, not the root.
- Tests must verify generated chains using `openssl::x509::X509StoreContext`, not only string comparison.

### Work Items

- [x] **3.1 Implement key generation**
  - [x] 3.1.1 Implement `generate_key` for `Rsa3072`.
    - Generate RSA 3072.
    - Encode PKCS#8 PEM.
    - Return `KeyMaterial` with PEM bytes and public key DER.
  - [x] 3.1.2 Implement `generate_key` for `EcdsaP256`.
    - Generate P-256 key.
    - Encode PKCS#8 PEM.
  - [x] 3.1.3 Implement `generate_key` for `Ed25519`.
    - Generate Ed25519 key.
    - Encode PKCS#8 PEM.
  - [x] 3.1.4 Implement passphrase encryption.
    - Read passphrase from `CHAINKEEPER_KEY_PASSPHRASE` only at the binary boundary and pass it as `Option<SecretString>`.
    - Encrypt with AES-256-CBC and PBKDF2 when present.
    - Decrypt transparently in `FileSigner`.
    - Add tests for correct, wrong, and missing passphrase.
  - [x] 3.1.5 Add key generation tests.
    - Assert parseable PKCS#8.
    - Assert public key size: RSA 3072, ECDSA 256-bit, Ed25519 32-byte public key.
    - Assert RSA key generation is not used for `ecdsa-p256`.

- [x] **3.2 Implement `FileSigner`**
  - [x] 3.2.1 Load a PEM private key from a path.
  - [x] 3.2.2 Implement `public_key_der`.
  - [x] 3.2.3 Implement `sign`.
    - `RsaPkcs1Sha256` uses PKCS#1 v1.5 with SHA-256.
    - `EcdsaSha256` uses ECDSA with SHA-256.
    - `Ed25519` signs the message directly.
  - [x] 3.2.4 Reject scheme/algorithm mismatches with `ChainkeeperError::Crypto`.
  - [x] 3.2.5 Add tests.
    - Sign a fixed message and verify with the public key.
    - Reject signing with a mismatched scheme.
    - Assert `FileSigner` implements `Signer` as `Arc<dyn Signer>`.

- [x] **3.3 Implement root authority creation**
  - [x] 3.3.1 Build the X.509 name from `SubjectName`.
    - Emit CN, O, OU, C, ST, L, and emailAddress in that order.
  - [x] 3.3.2 Set serial from `IdGenerator`.
  - [x] 3.3.3 Set validity from `Clock` and request validity days.
  - [x] 3.3.4 Add root extensions.
    - `basicConstraints` critical, CA true, path length 1.
    - `keyUsage` critical: `keyCertSign`, `cRLSign`.
    - Subject key identifier.
    - Authority key identifier equal to SKI.
  - [x] 3.3.5 Self-sign with the generated root key.
  - [x] 3.3.6 Return `AuthorityBundle` with certificate PEM, chain PEM equal to certificate, key PEM, and `AuthorityConfig`.
  - [x] 3.3.7 Add tests.
    - Parse certificate and assert self-signed.
    - Assert CA true and path length 1.
    - Assert key usage exactly keyCertSign and cRLSign.
    - Verify with a trust store containing only the root.
    - Assert validity equals request and clock.

- [x] **3.4 Implement intermediate authority creation**
  - [x] 3.4.1 Build intermediate request with parent root material.
  - [x] 3.4.2 Set `basicConstraints` critical, CA true, path length 0.
  - [x] 3.4.3 Set key usage `keyCertSign`, `cRLSign`.
  - [x] 3.4.4 Set AKI to parent SKI.
  - [x] 3.4.5 Sign with parent signer.
  - [x] 3.4.6 Return chain PEM containing intermediate then root.
  - [x] 3.4.7 Add tests.
    - Verify chain to root.
    - Assert intermediate is not self-signed.
    - Assert path length 0.
    - Assert intermediate validity does not exceed parent expiry.

- [x] **3.5 Implement OCSP signer creation**
  - [x] 3.5.1 Build end-entity certificate under the OCSP intermediate.
  - [x] 3.5.2 Set `basicConstraints` critical CA false.
  - [x] 3.5.3 Set key usage `digitalSignature`.
  - [x] 3.5.4 Set EKU `OCSPSigning`.
  - [x] 3.5.5 Set validity 90 days and clamp to parent expiry.
  - [x] 3.5.6 Return `SignerBundle` with cert, key, and chain containing signer, OCSP intermediate, and root.
  - [x] 3.5.7 Add tests.
    - Verify chain.
    - Assert EKU exactly OCSPSigning.
    - Assert CA false.
    - Assert key usage exactly digitalSignature.

- [x] **3.6 Implement leaf certificate issuance**
  - [x] 3.6.1 Handle generated-key issuance.
    - Generate key for requested algorithm.
    - Build CSR-like public key request internally.
  - [x] 3.6.2 Handle supplied CSR.
    - Parse PEM CSR with `openssl::x509::X509Req`.
    - Verify CSR signature.
    - Reject a CSR whose public key is not in the issuer chain.
    - Use CSR subject and SANs unless overridden by request; reject conflicting overrides.
  - [x] 3.6.3 Set serial, validity, and issuer.
  - [x] 3.6.4 Add leaf extensions.
    - `basicConstraints` critical CA false.
    - `keyUsage` critical from profile.
    - `extendedKeyUsage` from profile.
    - SAN from profile and request.
    - SKI and AKI.
    - AIA `caIssuers` URL from tenant config.
    - CRL distribution point from tenant config.
    - Custom extensions after validation.
  - [x] 3.6.5 Encode certificate PEM and private key PEM when generated.
  - [x] 3.6.6 Return `IssuedCertificate` with serial, PEM, key PEM, subject, issuer, SANs, EKUs, key usages, and timestamps.
  - [x] 3.6.7 Add tests.
    - Verify leaf chain to root.
    - Assert issuer equals intermediate subject.
    - Assert SANs exactly match request.
    - Assert AIA and CRL URLs contain the authority placeholder replacement.
    - Assert custom extension OID and critical flag survive round-trip.
    - Assert supplied CSR path does not generate a private key.
    - Assert invalid CSR signature is rejected.

- [x] **3.7 Implement CRL generation**
  - [x] 3.7.1 Build a CRL from revocation records.
    - Include only certificates issued by the target authority.
    - Include revocation reason codes.
    - Include invalidity date if present.
  - [x] 3.7.2 Set CRL fields.
    - `thisUpdate` from `Clock`.
    - `nextUpdate` = `thisUpdate + 7 days`, clamped to authority expiry.
    - CRL number from `CrlRequest`.
  - [x] 3.7.3 Add CRL extensions.
    - AKI.
    - CRL number.
  - [x] 3.7.4 Sign with the issuing authority signer.
  - [x] 3.7.5 Return DER and PEM.
  - [x] 3.7.6 Add tests.
    - Verify CRL signature with issuer public key.
    - Assert CRL number increments.
    - Assert only target-authority revocations appear.
    - Assert `nextUpdate > thisUpdate`.
    - Assert reason code round-trip for all nine reasons.

- [x] **3.8 Add provider-level security tests**
  - [x] 3.8.1 Assert no `std::process::Command` or `tokio::process::Command` in `crates/chainkeeper-crypto/src`.
    - Implement as a test that recursively scans source files.
  - [x] 3.8.2 Assert private key PEM is never included in certificate PEM.
  - [x] 3.8.3 Assert passphrase is not present in returned errors.
  - [x] 3.8.4 Assert wrong key is rejected for signing.
  - [x] 3.8.5 Assert self-signed root cannot be used as an intermediate child.

### Acceptance Criteria

- [x] `cargo test --quiet -p chainkeeper-crypto` passes.
- [x] Tests verify root, intermediate, OCSP signer, and leaf chains with `X509StoreContext`.
- [x] Tests cover RSA 3072, ECDSA P-256, and Ed25519 key generation and signing.
- [x] Tests assert CA, path length, key usage, EKU, SAN, AIA, CRL DP, SKI, and AKI extensions.
- [x] Tests cover passphrase-protected and unprotected keys.
- [x] Tests assert supplied CSR issuance does not generate a private key.
- [x] Tests assert CRL signatures verify and all nine revocation reasons round-trip.
- [x] A test asserts no subprocess execution exists in `chainkeeper-crypto`.
- [x] `cargo clippy -p chainkeeper-crypto --all-targets -- -D warnings` passes.

---

## Phase 4 - Policy and Profile Engine

### Goals

Implement the policy engine, the six built-in certificate profiles, custom OID validation, SAN and wildcard rules, and all pure validation used before issuance.

### Overview

This phase owns `chainkeeper-policy`. It is a deterministic, side-effect-free crate. It does not generate keys, write files, or call Git. Tests are table-driven and require no OpenSSL provider.

### Rules

- All issuance must pass `PolicyEngine::validate_issue`; there is no bypass flag in V1.
- Policy validation happens before profile validation, and both happen before any key generation.
- Profile YAML is the only source of EKU, key usage, SAN requirements, and default algorithm.
- Custom OID values are exactly one of `value_utf8` or `value_hex`.
- Reserved extension OIDs cannot be overridden through custom extensions.
- Wildcards are allowed only as the leftmost DNS label and only when policy enables them.
- `cn_must_match_san = true` means the CN must exactly match one DNS SAN or one email SAN.
- All errors include the field name and the rejected value, except secrets; custom extension values are not secrets.

### Work Items

- [x] **4.1 Implement built-in profiles**
  - [x] 4.1.1 Add `tls-server.yaml`.
    - Authority `tls`, algorithm `ecdsa-p256`, validity 397 days.
    - Key usage `digitalSignature`, `keyEncipherment`.
    - EKU `serverAuth`.
    - SAN required, types `dns`, `ip`.
  - [x] 4.1.2 Add `tls-client.yaml`.
    - Authority `tls`, algorithm `ecdsa-p256`, validity 397 days.
    - Key usage `digitalSignature`.
    - EKU `clientAuth`.
    - SAN required, types `dns`, `email`, `ip`.
  - [x] 4.1.3 Add `mtls.yaml`.
    - Authority `tls`, algorithm `ecdsa-p256`, validity 397 days.
    - Key usage `digitalSignature`, `keyEncipherment`.
    - EKU `clientAuth`, `serverAuth`.
    - SAN required, types `dns`, `ip`.
  - [x] 4.1.4 Add `smime.yaml`.
    - Authority `smime`, algorithm `rsa3072`, validity 397 days.
    - Key usage `digitalSignature`, `keyEncipherment`, `contentCommitment`.
    - EKU `emailProtection`.
    - SAN required, types `email`.
  - [x] 4.1.5 Add `codesign.yaml`.
    - Authority `codesign`, algorithm `rsa3072`, validity 397 days.
    - Key usage `digitalSignature`.
    - EKU `codeSigning`.
    - SAN not required.
  - [x] 4.1.6 Add `ocsp.yaml`.
    - Authority `ocsp`, algorithm `ecdsa-p256`, validity 90 days.
    - Key usage `digitalSignature`.
    - EKU `OCSPSigning`.
    - SAN not required.
  - [x] 4.1.7 Embed all six YAML files with `include_str!`.
  - [x] 4.1.8 Implement `ProfileRegistry::defaults`.
  - [x] 4.1.9 Add tests asserting exact profile fields.
  - [x] 4.1.10 Add tests that every default profile authority exists in the default authority set.

- [x] **4.2 Implement profile validation**
  - [x] 4.2.1 Validate profile name matches its authority mapping.
  - [x] 4.2.2 Validate profile validity is positive and at most 397 days for leaf profiles.
  - [x] 4.2.3 Validate profile algorithm is one of the three supported algorithms.
  - [x] 4.2.4 Validate EKU and key usage are non-empty.
  - [x] 4.2.5 Validate SAN types are known.
  - [x] 4.2.6 Reject profile authority names not in `{tls, smime, codesign, ocsp}`.
  - [x] 4.2.7 Add table-driven tests for each rejection.

- [x] **4.3 Implement policy parsing and defaults**
  - [x] 4.3.1 Add default `policy.yaml`.
    - `max_validity_days: 397`
    - `allowed_algorithms: [rsa3072, ecdsa-p256, ed25519]`
    - `allowed_profiles` contains all six profiles.
    - `allow_custom_oid: true`
    - `allow_wildcards: false`
    - `max_sans: 100`
    - `allowed_san_suffixes: []`
    - `cn_must_match_san: true`
  - [x] 4.3.2 Reject `max_validity_days == 0` and values above 397.
  - [x] 4.3.3 Reject empty `allowed_algorithms` and empty `allowed_profiles`.
  - [x] 4.3.4 Reject `max_sans == 0` and values above 1000.
  - [x] 4.3.5 Normalize SAN suffixes to lowercase and reject leading dots except `example.com`.
  - [x] 4.3.6 Add tests for all invalid policy values.

- [x] **4.4 Implement issuance validation**
  - [x] 4.4.1 Validate profile is in `allowed_profiles`.
  - [x] 4.4.2 Validate request algorithm is allowed.
  - [x] 4.4.3 Apply profile algorithm when request algorithm is absent.
  - [x] 4.4.4 Validate effective validity.
    - Use request validity when present.
    - Otherwise use profile validity.
    - Reject effective validity above `max_validity_days`.
    - Reject validity above authority remaining lifetime.
  - [x] 4.4.5 Validate subject.
    - CN required and non-empty for all profiles.
    - C must be exactly two uppercase ASCII letters when present.
    - Email must contain exactly one `@` and a non-empty local part and domain.
  - [x] 4.4.6 Validate SAN count is at most `max_sans`.
  - [x] 4.4.7 Validate SAN types match profile `san_types`.
  - [x] 4.4.8 Validate SAN required flag.
  - [x] 4.4.9 Validate DNS SAN syntax.
    - Lowercase ASCII letters, digits, hyphen, and dot only.
    - No empty labels.
    - No label longer than 63 characters.
    - Total name at most 253 characters.
  - [x] 4.4.10 Validate wildcard DNS SANs.
    - Only `*.` prefix allowed.
    - Reject `*` elsewhere.
    - Reject wildcard when policy disallows it.
    - Reject wildcard for S/MIME and code-signing profiles.
  - [x] 4.4.11 Validate IP SANs with `std::net::IpAddr`.
  - [x] 4.4.12 Validate email SANs.
  - [x] 4.4.13 Validate URI SANs.
    - Require scheme `https`, `spiffe`, or `urn`.
    - Reject spaces and control characters.
  - [x] 4.4.14 Validate `allowed_san_suffixes`.
    - Non-empty list means every DNS SAN must equal or end with `.<suffix>`.
    - Wildcards are checked after stripping the `*.` prefix.
  - [x] 4.4.15 Validate CN-to-SAN matching when enabled.
  - [x] 4.4.16 Add table-driven tests for every rule, including boundary values.

- [x] **4.5 Implement custom OID validation**
  - [x] 4.5.1 Validate OID syntax.
    - At least two arcs.
    - Digits only.
    - No leading zero in arcs except `0`.
    - First arc in `0..=2`.
    - Second arc in `0..=39` when first arc is `0` or `1`.
  - [x] 4.5.2 Reject reserved OIDs.
    - `2.5.29.17` SAN
    - `2.5.29.19` basicConstraints
    - `2.5.29.15` keyUsage
    - `2.5.29.37` extKeyUsage
    - `2.5.29.14` subjectKeyIdentifier
    - `2.5.29.35` authorityKeyIdentifier
    - `2.5.29.31` cRLDistributionPoints
    - `1.3.6.1.5.5.7.1.1` authorityInfoAccess
  - [x] 4.5.3 Reject duplicate OIDs in one request.
  - [x] 4.5.4 Reject when `allow_custom_oid` is false.
  - [x] 4.5.5 Reject both `value_utf8` and `value_hex` set.
  - [x] 4.5.6 Reject neither value set.
  - [x] 4.5.7 Reject `value_hex` with non-hex characters or odd length.
  - [x] 4.5.8 Reject `value_utf8` larger than 1024 bytes and `value_hex` larger than 4096 bytes.
  - [x] 4.5.9 Reject critical custom extensions when policy disallows critical custom OIDs; add policy field `allow_critical_custom_oid` default `false`.
  - [x] 4.5.10 Add tests for valid and invalid OIDs and values.

- [x] **4.6 Implement profile/policy cross-validation**
  - [x] 4.6.1 Validate every profile authority has a matching authority config when a repository is present.
  - [x] 4.6.2 Validate profile algorithm is allowed by policy.
  - [x] 4.6.3 Validate profile validity is at most policy max.
  - [x] 4.6.4 Return `DoctorFinding` codes `POLICY_PROFILE_MISSING`, `POLICY_ALGORITHM_DENIED`, `POLICY_VALIDITY_EXCEEDED`.
  - [x] 4.6.5 Add tests using synthetic authority sets.

- [x] **4.7 Add property tests**
  - [x] 4.7.1 Add property tests for DNS SAN validation.
    - Generated valid names always parse.
    - Generated invalid names with spaces or empty labels always fail.
  - [x] 4.7.2 Add property tests for OID validation.
    - Serialized valid OIDs round-trip.
    - OIDs with leading zeros fail.
  - [x] 4.7.3 Add property tests for CN matching.
    - If CN equals a DNS SAN, validation passes.
    - If CN differs from all SANs and matching is enabled, validation fails.

### Acceptance Criteria

- [x] `cargo test --quiet -p chainkeeper-policy` passes.
- [x] Tests assert exact defaults for all six built-in profiles.
- [x] Tests assert every policy validation rule with boundary values.
- [x] Tests assert wildcard acceptance only for leftmost `*.` when enabled.
- [x] Tests assert custom OID syntax, reserved OID, duplicate OID, value encoding, size, and criticality rules.
- [x] Tests assert CN-to-SAN matching behavior.
- [x] Property tests run under `cargo test --quiet -p chainkeeper-policy`.
- [x] `cargo clippy -p chainkeeper-policy --all-targets -- -D warnings` passes.

---

## Phase 5 - Audit Log, Git Transactions, and Repository Locking

### Goals

Implement immutable audit event storage, Git repository operations, commit generation, diff support, and the transaction boundary used by every mutating command.

### Overview

This phase owns `chainkeeper-audit` and `chainkeeper-git`. It has no dependency on cryptographic issuance. Tests use `TempTenant` and a temporary Git repository.

### Rules

- Audit records are append-only. There is no update or delete API.
- Use `OpenOptions::new().write(true).create_new(true)` for audit event files.
- Audit sequence numbers are monotonic and unique within one repository.
- Git commits are created by the application, not by shelling out to `git`.
- Do not commit unrelated working-tree changes. Stage only the paths supplied by the caller.
- Refuse to commit when a required path does not exist.
- Commit messages use the `feat(ck):` or `chore(ck):` prefixes defined below.
- Git identity must come from repository config, then global config, then environment. If absent, return `ChainkeeperError::Git` with an actionable message.
- Tests must set Git identity explicitly and must not depend on the host global Git config.

### Work Items

- [x] **5.1 Implement audit event serialization**
  - [x] 5.1.1 Serialize `AuditEvent` to canonical JSON.
    - Sort object keys.
    - Add trailing newline.
    - Reject non-UTC timestamps.
  - [x] 5.1.2 Deserialize with `deny_unknown_fields`.
  - [x] 5.1.3 Add schema tests for every `AuditAction`.
  - [x] 5.1.4 Add a test asserting all `details` values are JSON objects, not raw strings.

- [x] **5.2 Implement `FileAuditLog`**
  - [x] 5.2.1 Implement `next_seq`.
    - Scan `audit/events/*.json`.
    - Return max `seq + 1`.
    - Fail on duplicate sequence numbers.
  - [x] 5.2.2 Implement `append`.
    - Allocate `seq` under repository lock.
    - Create event ID if absent.
    - Write `audit/events/<ULID>.json` with `create_new`.
    - Return the stored event.
  - [x] 5.2.3 Implement `list`.
    - Filter by action, object type, object ID, since, until, and limit.
    - Sort by `seq` ascending.
  - [x] 5.2.4 Implement `verify`.
    - Assert sequence numbers are contiguous from 1.
    - Assert every file parses.
    - Assert no duplicate IDs or sequence numbers.
    - Return `DoctorFinding` codes `AUDIT_SEQ_GAP`, `AUDIT_DUPLICATE`, `AUDIT_INVALID`.
  - [x] 5.2.5 Add tests.
    - Duplicate event ID is rejected.
    - Concurrent appends under the lock produce contiguous sequence numbers.
    - Editing an event file is detected by `verify`.
    - Deleting an event file is detected by `verify`.
    - Listing filters work.

- [x] **5.3 Implement Git repository wrapper**
  - [x] 5.3.1 Implement `init`.
    - Create repository at path.
    - Set initial branch `main`.
    - Write `.gitignore`.
    - Add all files.
    - Create initial commit with message `feat(ck): initialize tenant <tenant_id>`.
  - [x] 5.3.2 Implement `head_commit`.
    - Return full 40-character SHA.
    - Return `ChainkeeperError::Git` when no commits exist.
  - [x] 5.3.3 Implement `status`.
    - Return staged, unstaged, and untracked paths.
  - [x] 5.3.4 Implement `is_clean`.
  - [x] 5.3.5 Implement `commit`.
    - Stage exactly the supplied paths.
    - Reject paths outside repository root.
    - Reject missing paths.
    - Create one commit.
    - Return full SHA.
    - Leave unrelated unstaged changes untouched.
  - [x] 5.3.6 Implement `diff`.
    - Return `GitChange { path, kind }` for added, modified, deleted, and renamed files.
    - Support commit-to-commit and commit-to-working-tree diffs.
  - [x] 5.3.7 Implement `log` for the last `n` commits.
  - [x] 5.3.8 Add tests.
    - Init creates one commit and clean status.
    - Commit stages only supplied paths.
    - Commit does not include an unrelated modified file.
    - Commit with missing path fails and leaves index unchanged.
    - Diff reports added, modified, and deleted files.
    - Path traversal in commit paths is rejected.

- [x] **5.4 Implement repository transaction helper**
  - [x] 5.4.1 Implement `RepositoryTransaction`.
    - Acquire exclusive lock.
    - Record a list of paths to stage.
    - Provide `stage_path(path)`.
    - Provide `commit(message)`.
    - On drop without commit, release lock and leave files for inspection; do not auto-delete.
  - [x] 5.4.2 Implement rollback for created files.
    - Track files created by the transaction.
    - Provide `rollback_created()`.
    - Do not delete pre-existing files.
  - [x] 5.4.3 Add tests.
    - Successful transaction commits.
    - Failed transaction rolls back created files and leaves pre-existing files.
    - Lock is released after rollback.
    - Two concurrent transactions cannot commit overlapping paths.

- [x] **5.5 Implement commit message builders**
  - [x] 5.5.1 Add `CommitMessage` constructors.
    - Init: `feat(ck): initialize tenant <id>`
    - Root: `feat(ck): create root authority <name>`
    - Intermediate: `feat(ck): create intermediate authority <name>`
    - OCSP signer: `feat(ck): create ocsp signer <name>`
    - Issue: `feat(ck): issue certificate <serial> profile <profile>`
    - Revoke: `feat(ck): revoke certificate <serial> reason <reason>`
    - Replace: `feat(ck): replace certificate <old> with <new>`
    - CRL: `feat(ck): regenerate crl <authority> number <n>`
    - Publish: `chore(ck): publish artifacts from <source_commit>`
    - Index: `chore(ck): rebuild index`
  - [x] 5.5.2 Add tests asserting exact messages and no trailing whitespace.

- [x] **5.6 Implement Gitignore and secret checks**
  - [x] 5.6.1 Add `ensure_gitignore`.
    - Write the exact Global Decisions `.gitignore` when absent.
    - Append missing rules when present.
    - Never remove unrelated rules.
  - [x] 5.6.2 Add `assert_no_staged_private_keys`.
    - Inspect staged paths for `key.pem` or `*.key`.
    - Return `ChainkeeperError::Git` if any are staged.
  - [x] 5.6.3 Add tests.
    - `ck init` produces a clean repository with no tracked keys.
    - A deliberate `git add authorities/root/key.pem` is rejected by the guard.
    - Existing custom gitignore rules survive.

- [x] **5.7 Implement commit signing compatibility**
  - [x] 5.7.1 Respect Git config `commit.gpgsign`.
    - If enabled, use `git2` commit signing with the configured key.
    - If signing fails, return `ChainkeeperError::Git` and do not create an unsigned commit.
  - [x] 5.7.2 Add a test with a temporary GPG key only if `gpg` is available and `CHAINKEEPER_TEST_GPG=1`.
    - Otherwise assert the config is read and the code path is selected without creating a commit.
  - [x] 5.7.3 Never disable hooks or verification in product code.

### Acceptance Criteria

- [x] `cargo test --quiet -p chainkeeper-audit` passes.
- [x] `cargo test --quiet -p chainkeeper-git` passes.
- [x] A test asserts audit files are created with `create_new` and duplicate IDs fail.
- [x] A test asserts concurrent audit appends produce contiguous sequence numbers.
- [x] A test asserts `verify` detects edited and deleted audit files.
- [x] A test asserts commits stage only supplied paths and leave unrelated changes untouched.
- [x] A test asserts private keys cannot be staged.
- [x] A test asserts commit message formats exactly.
- [x] `cargo clippy -p chainkeeper-audit -p chainkeeper-git --all-targets -- -D warnings` passes.

---

## Phase 6 - Certificate Lifecycle Engine

### Goals

Implement the orchestration layer that composes policy validation, key generation, filesystem writes, indexing, audit, CRL refresh, publishing, and Git commits into each CLI operation.

### Overview

This phase owns `chainkeeper-engine`. It consumes only the frozen traits from `chainkeeper-core` and test doubles from `chainkeeper-testkit`. It must be fully testable without OpenSSL or a real Git repository. Phase 11 wires the concrete implementations.

### Rules

- The engine never calls OpenSSL, SQLite, or Git directly; it calls injected traits.
- Mutating operations acquire the repository lock before reading state and hold it through commit.
- Order of operations for issuance: load policy and profile, validate, load authority, generate or parse key, create certificate, write certificate files, update index, append audit, update CRL if needed, commit.
- Order of operations for revocation: load certificate, validate reason, write revocation record, move certificate to revoked, update index, regenerate CRL, refresh publish, append audit, commit.
- On any error before commit, roll back files created by this operation. Do not delete pre-existing files.
- Never issue a certificate if policy validation fails.
- Never issue a certificate if the selected authority is expired or revoked.
- Never revoke an already revoked certificate; return `Conflict`.
- `replaces` must point to an existing certificate. Replace performs revoke with reason `superseded`, then issue with `replaces` set.
- `ck init` is idempotent only when the target directory is empty or contains only an empty `.git`; otherwise fail with `AlreadyExists`.

### Work Items

- [x] **6.1 Implement engine construction**
  - [x] 6.1.1 Add `EngineDependencies` struct.
    - Fields: clock, ids, provider, store, index, profiles, policy, audit, git, lock, crl, publish, paths.
    - All fields are `Arc<dyn Trait>`.
  - [x] 6.1.2 Add `Engine::new(deps) -> Result<Self>` with non-null validation.
  - [x] 6.1.3 Implement `ChainkeeperService` for `Engine`.
  - [x] 6.1.4 Add a test constructing the engine entirely from `chainkeeper-testkit` fakes.

- [x] **6.2 Implement `init`**
  - [x] 6.2.1 Validate target directory.
    - Accept empty directory.
    - Accept directory containing only an empty `.git`.
    - Reject non-empty directory and return `AlreadyExists`.
  - [x] 6.2.2 Create repository layout.
  - [x] 6.2.3 Write `tenant.yaml` from `InitRequest`.
  - [x] 6.2.4 Write default `policy.yaml`.
  - [x] 6.2.5 Write all six default profiles.
  - [x] 6.2.6 Write default `authorities/` directories without keys.
  - [x] 6.2.7 Write `.gitignore`.
  - [x] 6.2.8 Initialize Git and create first commit.
  - [x] 6.2.9 Open and initialize index.
  - [x] 6.2.10 Append `REPO_INITIALIZED` audit event.
  - [x] 6.2.11 Commit audit event and index metadata.
  - [x] 6.2.12 Add tests.
    - Init creates exact layout.
    - Init rejects non-empty directory.
    - Init is reproducible with a fixed clock and IDs.
    - Init leaves no private keys.
    - Init produces one commit.

- [x] **6.3 Implement root and intermediate creation**
  - [x] 6.3.1 Implement `create_root`.
    - Validate no existing root.
    - Validate algorithm is allowed by policy.
    - Validate root validity is 7300 days unless request overrides within policy.
    - Generate key and create authority.
    - Write authority files.
    - Update index.
    - Append `ROOT_CREATED`.
    - Commit.
  - [x] 6.3.2 Implement `create_intermediate`.
    - Validate parent exists and is root.
    - Validate name in `{tls, smime, codesign, ocsp}`.
    - Validate no existing intermediate with the same name.
    - Create intermediate.
    - Write files.
    - Update index.
    - Append `INTERMEDIATE_CREATED`.
    - Commit.
  - [x] 6.3.3 Implement `create_ocsp_signer`.
    - Validate OCSP intermediate exists.
    - Validate no existing signer.
    - Create signer.
    - Write files.
    - Update index.
    - Append `OCSP_SIGNER_CREATED`.
    - Commit.
  - [x] 6.3.4 Add tests.
    - Root creation twice fails with `AlreadyExists`.
    - Intermediate creation under missing parent fails.
    - Intermediate name outside allowed set fails.
    - OCSP signer creation before OCSP intermediate fails.
    - Every success appends exactly one audit event and one commit.

- [x] **6.4 Implement issuance**
  - [x] 6.4.1 Load repository config and state.
  - [x] 6.4.2 Validate policy and profile with `PolicyEngine`.
  - [x] 6.4.3 Select issuing authority from profile.
  - [x] 6.4.4 Validate authority is active and not expired.
  - [x] 6.4.5 Validate `replaces` when present.
    - Target exists.
    - Target is active.
    - Target profile equals new profile.
  - [x] 6.4.6 Generate key when `csr_pem` is absent.
  - [x] 6.4.7 Generate certificate through provider.
  - [x] 6.4.8 Write certificate PEM, metadata, and optional key.
  - [x] 6.4.9 Update index.
  - [x] 6.4.10 Append `CERT_ISSUED` or `CERT_REPLACED`.
  - [x] 6.4.11 When `replaces` is present, perform revocation first and then issue.
  - [x] 6.4.12 Commit all created and moved paths.
  - [x] 6.4.13 Add tests.
    - Issue TLS, client, mTLS, S/MIME, code-signing, and OCSP certificates.
    - Policy failure creates no files and no commit.
    - Provider failure rolls back created files.
    - Duplicate serial failure retries with a new serial up to 3 times, then fails.
    - Replace revokes old as superseded and links new to old.
    - Issuance writes no private key when CSR is supplied.
    - Issuance with `key_out` writes key only at the requested path.

- [x] **6.5 Implement revocation**
  - [x] 6.5.1 Load certificate by serial.
  - [x] 6.5.2 Reject missing certificate with `NotFound`.
  - [x] 6.5.3 Reject already revoked certificate with `Conflict`.
  - [x] 6.5.4 Validate reason.
  - [x] 6.5.5 Write revocation record.
  - [x] 6.5.6 Move certificate files to `revoked`.
  - [x] 6.5.7 Update index.
  - [x] 6.5.8 Regenerate CRL for issuing authority through `CrlManager`.
  - [x] 6.5.9 Refresh publish directory through `PublishBuilder` when `publish/` already exists.
  - [x] 6.5.10 Append `CERT_REVOKED`.
  - [x] 6.5.11 Commit all changed paths.
  - [x] 6.5.12 Add tests.
    - Revoke active certificate succeeds.
    - Revoke missing certificate fails.
    - Revoke twice fails.
    - All nine reasons accepted.
    - CRL manager called exactly once.
    - Publish refresh called only when publish exists.
    - Failure in CRL generation aborts before commit and rolls back revocation files.

- [x] **6.6 Implement inspect**
  - [x] 6.6.1 Load certificate by serial or path.
  - [x] 6.6.2 Build `InspectReport` with subject, issuer, serial, profile, status, validity, SANs, EKUs, key usages, algorithm, AIA URLs, OCSP URL, CRL URLs, fingerprint SHA-256.
  - [x] 6.6.3 Add tests for each field and for missing certificate.

- [x] **6.7 Implement search and tree**
  - [x] 6.7.1 Implement `search` delegating to `IndexStore` after validating query bounds.
  - [x] 6.7.2 Implement `tree`.
    - Load authorities.
    - Require exactly one root.
    - Build parent-child tree.
    - Reject cycles and orphan intermediates.
    - Return `TreeReport`.
  - [x] 6.7.3 Add tests with the default hierarchy and with a broken hierarchy.

- [x] **6.8 Implement analyze**
  - [x] 6.8.1 Implement `analyze expirations`.
    - Buckets: expired, 0-30, 31-60, 61-90, 91+ days.
    - Group by profile and authority.
  - [x] 6.8.2 Implement `analyze revocations`.
    - Counts by reason and month.
  - [x] 6.8.3 Implement `analyze intermediates`.
    - Remaining validity, algorithm, path length, parent.
    - Emit findings for intermediates expiring within 90 days.
  - [x] 6.8.4 Implement `analyze algorithms`.
    - Counts by algorithm and profile.
    - Emit findings for algorithms not in policy.
  - [x] 6.8.5 Implement `analyze policy`.
    - Emit findings for certificates exceeding current max validity, disallowed algorithms, disallowed wildcards, and disallowed custom OIDs.
  - [x] 6.8.6 Add tests with deterministic clocks and fixtures.

- [x] **6.9 Implement audit query**
  - [x] 6.9.1 Delegate to `AuditLog::list`.
  - [x] 6.9.2 Validate limit default 100 and maximum 10,000.
  - [x] 6.9.3 Add tests for filters and ordering.

- [x] **6.10 Implement doctor**
  - [x] 6.10.1 Implement checks.
    - `ROOT_MISSING`: error.
    - `ROOT_EXPIRED`: error.
    - `ROOT_EXPIRING_SOON`: warning when less than 365 days remain.
    - `INTERMEDIATE_MISSING`: error for each required authority.
    - `INTERMEDIATE_EXPIRED`: error.
    - `INTERMEDIATE_EXPIRING_SOON`: warning when less than 90 days remain.
    - `INTERMEDIATE_CHAIN_INVALID`: error.
    - `CRL_MISSING`: error.
    - `CRL_EXPIRED`: error.
    - `CRL_NEXT_UPDATE_SOON`: warning when less than 24 hours remain.
    - `OCSP_SIGNER_MISSING`: warning on workstation, error on server.
    - `OCSP_SIGNER_EXPIRED`: error.
    - `OCSP_SIGNER_EKU_INVALID`: error.
    - `GIT_NOT_INITIALIZED`: error.
    - `GIT_DIRTY`: warning.
    - `GIT_REMOTE_MISSING`: warning.
    - `POLICY_INVALID`: error.
    - `PROFILE_INVALID`: error.
    - `PUBLISH_MISSING`: warning.
    - `PUBLISH_HASH_MISMATCH`: error.
    - `PUBLISH_PRIVATE_KEY_FOUND`: error.
    - `INDEX_DRIFT`: warning.
    - `AUDIT_INVALID`: error.
    - `UNENCRYPTED_CA_KEY`: warning.
  - [x] 6.10.2 Implement exit semantics.
    - Any error finding returns `DoctorReport::has_errors = true`.
    - Warnings alone do not set errors.
  - [x] 6.10.3 Add tests for every finding using targeted broken fixtures.
  - [x] 6.10.4 Add a clean-repository test asserting zero findings.

- [x] **6.11 Implement diff**
  - [x] 6.11.1 Read last publish manifest `source_commit`.
  - [x] 6.11.2 Call `GitRepository::diff(source_commit, HEAD)`.
  - [x] 6.11.3 Categorize changes.
    - Certificates: `certificates/`.
    - Revocations: `revocations/`.
    - CRLs: `crls/`.
    - Policy: `policy/` and `profiles/`.
    - Audits: `audit/`.
    - Publish: `publish/`.
  - [x] 6.11.4 Support `--since <rev>`.
  - [x] 6.11.5 Return `NotFound` when no manifest exists and no `--since` is supplied.
  - [x] 6.11.6 Add tests for each category and for no changes.

- [x] **6.12 Implement publish and index delegation**
  - [x] 6.12.1 Implement `publish` delegating to `PublishBuilder`.
  - [x] 6.12.2 Append `PUBLISH_COMPLETED`.
  - [x] 6.12.3 Commit `publish/` and audit event.
  - [x] 6.12.4 Implement `rebuild_index` delegating to `IndexStore::rebuild`.
  - [x] 6.12.5 Append `INDEX_REBUILT`.
  - [x] 6.12.6 Commit index metadata and moved files.
  - [x] 6.12.7 Add tests with fake publish builder.

- [x] **6.13 Add engine failure-injection tests**
  - [x] 6.13.1 Fail provider after key generation and assert key is deleted.
  - [x] 6.13.2 Fail index write after certificate write and assert certificate files are deleted.
  - [x] 6.13.3 Fail audit append after index write and assert certificate, metadata, and index rows are rolled back.
  - [x] 6.13.4 Fail Git commit after audit and assert operation returns error with uncommitted files reported.
  - [x] 6.13.5 Fail CRL generation after revocation write and assert revocation files are rolled back.

### Acceptance Criteria

- [x] `cargo test --quiet -p chainkeeper-engine` passes.
- [x] Engine tests run with fakes only and do not require OpenSSL, SQLite, or Git.
- [x] A test covers init, root, intermediate, OCSP signer, issue, revoke, replace, inspect, search, tree, analyze, audit, doctor, diff, publish, and rebuild.
- [x] A test asserts policy failure creates no files and no commit.
- [x] A test asserts every mutating success creates exactly one Git commit.
- [x] A test asserts failure injection rolls back created files and index rows.
- [x] A test asserts doctor emits every documented finding code.
- [x] A test asserts diff categorizes all change types.
- [x] `cargo clippy -p chainkeeper-engine --all-targets -- -D warnings` passes.

---

## Phase 7 - CRL Management and Publish Artifact Builder

### Goals

Implement automatic CRL regeneration and the deterministic publish directory builder, including manifest generation, hash validation, chain files, and private-key exclusion.

### Overview

This phase owns `chainkeeper-publish`. It implements `CrlManager` and `PublishBuilder` using `CertificateProvider`, `CertificateStore`, `GitRepository`, and `AuditLog` traits. Tests use `chainkeeper-testkit` fakes and temporary directories.

### Rules

- CRL generation is automatic on revocation; there is no required manual CRL command.
- CRL number is monotonic per authority and never reused.
- Publish output is deterministic for identical inputs and fixed clock.
- Publish output contains public artifacts only.
- Publish manifest is written last.
- Stale files not present in the new manifest are removed after new files are written.
- Publish validation fails if any file in the publish tree contains a PEM `PRIVATE KEY` block.
- Publish must not follow symlinks.
- Server publish output goes to `--publish-dir`; CLI publish output goes to repository `publish/`.

### Work Items

- [ ] **7.1 Implement CRL number allocation**
  - [ ] 7.1.1 Read `crls/<authority>.number`.
  - [ ] 7.1.2 If absent, start at 1.
  - [ ] 7.1.3 Write the next number atomically after successful CRL generation.
  - [ ] 7.1.4 Reject number `0` and non-integer contents.
  - [ ] 7.1.5 Add tests for first generation, increment, and corrupted number file.

- [ ] **7.2 Implement CRL manager**
  - [ ] 7.2.1 Load authority and signer.
  - [ ] 7.2.2 Load all revocation records for authority.
  - [ ] 7.2.3 Call `CertificateProvider::generate_crl`.
  - [ ] 7.2.4 Write DER, PEM, metadata, and number.
  - [ ] 7.2.5 Append `CRL_GENERATED` audit event.
  - [ ] 7.2.6 Update index CRL row.
  - [ ] 7.2.7 Return `CrlBundle`.
  - [ ] 7.2.8 Add tests.
    - Empty revocation list produces a valid empty CRL.
    - One revocation appears in the CRL.
    - Revocations from another authority are excluded.
    - CRL number increments on second generation.
    - Corrupt authority key fails without writing number.

- [ ] **7.3 Implement publish layout**
  - [ ] 7.3.1 Define canonical artifact paths.
    - `root.pem`
    - `intermediates/<authority>.pem`
    - `chains/<profile>/<SERIAL>.pem`
    - `crl/<authority>.crl`
    - `crl/<authority>.crl.pem`
    - `aia/<authority>.pem`
    - `manifest.json`
  - [ ] 7.3.2 Build chain files.
    - Leaf certificate first.
    - Issuing intermediate second.
    - Root last.
    - Include only authorities present in the repository.
  - [ ] 7.3.3 Build `aia` files for root and every intermediate.
  - [ ] 7.3.4 Copy current CRL DER and PEM for every authority with revocations or an existing CRL.
  - [ ] 7.3.5 Write `root.pem` from the root certificate.
  - [ ] 7.3.6 Add tests asserting exact relative paths and PEM order.

- [ ] **7.4 Implement manifest generation**
  - [ ] 7.4.1 Sort artifacts by path.
  - [ ] 7.4.2 Compute SHA-256 and byte length for each artifact.
  - [ ] 7.4.3 Record `source_commit` from `GitRepository::head_commit`.
  - [ ] 7.4.4 Record `generated_at` from `Clock`.
  - [ ] 7.4.5 Record `tenant_id`.
  - [ ] 7.4.6 Exclude `manifest.json` from the artifact list.
  - [ ] 7.4.7 Write manifest last with a trailing newline.
  - [ ] 7.4.8 Add tests.
    - Manifest is deterministic with fixed clock and commit.
    - Artifact hashes match file contents.
    - Manifest excludes itself.
    - Manifest includes no `key.pem` or `*.key` paths.

- [ ] **7.5 Implement atomic publish**
  - [ ] 7.5.1 Build into a sibling temp directory.
  - [ ] 7.5.2 Write artifacts and manifest to temp directory.
  - [ ] 7.5.3 Validate temp directory.
  - [ ] 7.5.4 Remove stale files in destination not present in manifest.
  - [ ] 7.5.5 Move new files into destination atomically.
  - [ ] 7.5.6 Remove temp directory on success and failure.
  - [ ] 7.5.7 Reject destination outside allowed root.
  - [ ] 7.5.8 Add tests.
    - Interrupted build leaves previous destination intact.
    - Stale file is removed.
    - New file replaces old file.
    - Destination symlink is rejected.

- [ ] **7.6 Implement publish validation**
  - [ ] 7.6.1 Walk publish tree without following symlinks.
  - [ ] 7.6.2 Reject any path containing `key` with a PEM private key block.
  - [ ] 7.6.3 Reject any file whose name is `key.pem`.
  - [ ] 7.6.4 Reject any file that is not listed in manifest.
  - [ ] 7.6.5 Reject manifest artifact whose SHA-256 does not match.
  - [ ] 7.6.6 Reject manifest artifact path traversal.
  - [ ] 7.6.7 Add tests for each rejection.

- [ ] **7.7 Implement publish diff support**
  - [ ] 7.7.1 Add `PublishBuilder::changed_paths(previous_manifest, next_manifest)`.
  - [ ] 7.7.2 Return added, removed, and modified artifact paths.
  - [ ] 7.7.3 Add tests.

- [ ] **7.8 Add integration with revocation**
  - [ ] 7.8.1 Add `refresh_after_revocation` helper.
    - Regenerate CRL for issuing authority.
    - If repository `publish/` exists, rebuild `publish/`.
    - Return the list of changed paths.
  - [ ] 7.8.2 Add tests.
    - No publish directory means only CRL files change.
    - Existing publish directory means CRL and chain artifacts update.
    - Publish refresh failure leaves CRLs updated and returns error.

### Acceptance Criteria

- [ ] `cargo test --quiet -p chainkeeper-publish` passes.
- [ ] Tests assert CRL generation for empty and non-empty revocation sets.
- [ ] Tests assert CRL number monotonicity and per-authority isolation.
- [ ] Tests assert exact publish paths and chain ordering.
- [ ] Tests assert deterministic manifest for fixed clock and commit.
- [ ] Tests assert stale files are removed and prior publish survives a failed build.
- [ ] Tests assert private keys and symlinks are rejected.
- [ ] Tests assert manifest hash, path traversal, and unlisted-file validation.
- [ ] `cargo clippy -p chainkeeper-publish --all-targets -- -D warnings` passes.

---

## Phase 8 - OCSP Responder Core

### Goals

Implement an RFC 6960 OCSP request parser, response builder, signer, status lookup, nonce handling, reload, and error handling that never shells out to OpenSSL.

### Overview

This phase owns `chainkeeper-ocsp`. It implements `OcspResponder` using `rasn-ocsp` for ASN.1 and the frozen `Signer` trait for signatures. Tests use generated fixtures and the `openssl ocsp` client for independent verification.

### Rules

- Runtime OCSP must not execute a subprocess.
- Support SHA-1 and SHA-256 certificate ID hashes in requests.
- Reject unsupported hash algorithms with `malformedRequest`.
- Return `unauthorized` when the issuer cannot be matched.
- Return `unknown` for a recognized issuer with an unknown serial.
- Return `good` only when the certificate is active and not revoked.
- Return `revoked` with revocation time and reason when revoked.
- Echo the request nonce byte-for-byte when present.
- Reject nonces longer than 32 bytes with `malformedRequest`.
- Include the OCSP signer certificate and its chain in the response.
- Do not log request bodies at `info`; log only byte length and result code.

### Work Items

- [ ] **8.1 Implement OCSP request parsing**
  - [ ] 8.1.1 Parse `OCSPRequest` with `rasn-ocsp`.
  - [ ] 8.1.2 Reject trailing bytes.
  - [ ] 8.1.3 Reject unsupported request version.
  - [ ] 8.1.4 Extract request list.
  - [ ] 8.1.5 Reject empty request list.
  - [ ] 8.1.6 Extract hash algorithm, issuer name hash, issuer key hash, and serial.
  - [ ] 8.1.7 Extract optional nonce extension.
  - [ ] 8.1.8 Return `OcspRequestMeta` with raw issuer name DER and issuer key hash.
  - [ ] 8.1.9 Add tests for valid SHA-1 and SHA-256 requests.
  - [ ] 8.1.10 Add tests for empty list, trailing bytes, unsupported hash, malformed DER, and oversized nonce.

- [ ] **8.2 Implement issuer matching**
  - [ ] 8.2.1 Build issuer index from authority certificates.
  - [ ] 8.2.2 Compute issuer name hash using request hash algorithm over the raw issuer `Name` DER.
  - [ ] 8.2.3 Compute issuer key hash using request hash algorithm over the raw SPKI DER.
  - [ ] 8.2.4 Match both hashes and serial issuer.
  - [ ] 8.2.5 Return `unauthorized` when no authority matches.
  - [ ] 8.2.6 Add tests for correct match, wrong name hash, wrong key hash, and unknown issuer.

- [ ] **8.3 Implement status lookup**
  - [ ] 8.3.1 Build serial-to-status map from store records.
  - [ ] 8.3.2 Return `good` for active.
  - [ ] 8.3.3 Return `revoked` for revoked with `revocation_time` and `reason`.
  - [ ] 8.3.4 Return `unknown` for expired certificates that are not revoked.
  - [ ] 8.3.5 Return `unknown` for serials issued by another authority.
  - [ ] 8.3.6 Add tests for all statuses.

- [ ] **8.4 Implement response building**
  - [ ] 8.4.1 Build `OCSPResponse` with status `successful`.
  - [ ] 8.4.2 Build `BasicOCSPResponse`.
    - Version v1.
    - Responder ID byName using signer certificate subject and serial.
    - `producedAt` from `Clock`.
    - Single response for each request.
    - `thisUpdate` from `Clock`.
    - `nextUpdate` = `thisUpdate + 1 hour`.
  - [ ] 8.4.3 Include `certStatus` good, revoked, or unknown.
  - [ ] 8.4.4 Include nonce extension when requested.
  - [ ] 8.4.5 Sign `tbsResponseData` with the OCSP signer.
  - [ ] 8.4.6 Set signature algorithm from signer algorithm.
  - [ ] 8.4.7 Include signer certificate and chain in `certs`.
  - [ ] 8.4.8 Encode DER.
  - [ ] 8.4.9 Add tests.
    - `openssl ocsp -respin` parses the response.
    - Response signature verifies with the signer public key.
    - Nonce round-trips exactly.
    - `thisUpdate` and `nextUpdate` match fixed clock.

- [ ] **8.5 Implement error responses**
  - [ ] 8.5.1 Return `malformedRequest` for parse errors.
  - [ ] 8.5.2 Return `unauthorized` for unknown issuer.
  - [ ] 8.5.3 Return `internalError` for signing or storage errors.
  - [ ] 8.5.4 Return `tryLater` when state is not loaded.
  - [ ] 8.5.5 Never include internal error strings in the DER response.
  - [ ] 8.5.6 Add tests for every response status.

- [ ] **8.6 Implement responder state and reload**
  - [ ] 8.6.1 Implement `OcspState`.
    - Authority index.
    - Certificate status map.
    - Signer certificate, key path, and chain.
  - [ ] 8.6.2 Implement `load_state` from store and paths.
  - [ ] 8.6.3 Validate signer certificate.
    - EKU exactly contains OCSPSigning.
    - Not expired.
    - Chain verifies to OCSP intermediate and root.
    - Public key matches signer.
  - [ ] 8.6.4 Implement atomic `reload` with `arc-swap`.
  - [ ] 8.6.5 On reload failure, keep previous state and return error.
  - [ ] 8.6.6 Implement `ready`.
  - [ ] 8.6.7 Add tests.
    - Valid state loads.
    - Missing signer key fails.
    - Wrong EKU fails.
    - Expired signer fails.
    - Reload swaps state atomically under concurrent requests.
    - Failed reload keeps old state.

- [ ] **8.7 Implement multi-request behavior**
  - [ ] 8.7.1 Support up to 10 certificate IDs per request.
  - [ ] 8.7.2 Reject more than 10 with `malformedRequest`.
  - [ ] 8.7.3 Build one single response per certificate ID in request order.
  - [ ] 8.7.4 Add tests for 1, 10, and 11 certificate IDs.

- [ ] **8.8 Add security tests**
  - [ ] 8.8.1 Assert no `std::process::Command` or `tokio::process::Command` in `crates/chainkeeper-ocsp/src`.
  - [ ] 8.8.2 Assert response contains no private key material.
  - [ ] 8.8.3 Assert oversized request is rejected before ASN.1 allocation.
  - [ ] 8.8.4 Assert malformed DER fuzz corpus does not panic.
  - [ ] 8.8.5 Add a fuzz target using `cargo-fuzz` metadata, runnable with `cargo fuzz run ocsp_request`.
  - [ ] 8.8.6 Add a bounded random byte test that runs 10,000 iterations and asserts no panic.

### Acceptance Criteria

- [ ] `cargo test --quiet -p chainkeeper-ocsp` passes.
- [ ] Tests cover SHA-1 and SHA-256 request parsing.
- [ ] Tests assert `good`, `revoked`, and `unknown` statuses.
- [ ] Tests assert `malformedRequest`, `unauthorized`, `internalError`, and `tryLater`.
- [ ] `openssl ocsp -respin` parses generated responses.
- [ ] Tests assert nonce round-trip and 32-byte nonce limit.
- [ ] Tests assert multi-request ordering and 10-request limit.
- [ ] Tests assert failed reload preserves previous state.
- [ ] A test asserts no subprocess execution exists in `chainkeeper-ocsp`.
- [ ] `cargo clippy -p chainkeeper-ocsp --all-targets -- -D warnings` passes.

---

## Phase 9 - CLI and Interactive UX

### Goals

Implement the `ck` binary, all V1 commands, JSON output, human tables, interactive selection, confirmations, exit codes, and non-TTY behavior.

### Overview

This phase owns `chainkeeper-cli`. Command handlers consume `&dyn ChainkeeperService` and a `Ui` abstraction so they can be tested with `chainkeeper-testkit` fakes. Interactive prompts are isolated and are never used when stdout is not a TTY.

### Rules

- Use `clap` derive for every command and flag.
- Use `inquire` only when `std::io::IsTerminal::is_terminal(&stdout)` is true.
- When not a TTY, missing required values must return exit code `2` with a precise message.
- `--json` must produce a single JSON document on stdout and nothing else.
- Human output goes to stdout; errors go to stderr.
- `--yes` suppresses confirmation prompts but never suppresses validation.
- Do not print private key contents.
- Do not print passphrases.
- Command handlers must be synchronous; do not introduce a Tokio runtime for CLI commands.
- Exit codes: `0` success, `1` operation error, `2` usage error, `3` doctor errors.

### Work Items

- [ ] **9.1 Implement global CLI structure**
  - [ ] 9.1.1 Add global flags.
    - `--repo <PATH>` default current directory.
    - `--json`.
    - `--no-color`.
    - `--yes`.
    - `--verbose`.
    - `--quiet`.
  - [ ] 9.1.2 Add `--version` with version, commit, and target triple.
  - [ ] 9.1.3 Add `--help` for every command and subcommand.
  - [ ] 9.1.4 Add exit-code mapping from `ChainkeeperError::exit_code`.
  - [ ] 9.1.5 Add a test asserting `--help` exits 0 for every command.
  - [ ] 9.1.6 Add a test asserting an unknown command exits 2.
  - [ ] 9.1.7 Add a test asserting `--json` writes only valid JSON to stdout on success.
  - [ ] 9.1.8 Add a test asserting errors go to stderr and stdout is empty on failure.

- [ ] **9.2 Implement `ck init`**
  - [ ] 9.2.1 Flags: `--tenant-id`, `--display-name`, `--default-profile`, `--force`.
  - [ ] 9.2.2 Call `ChainkeeperService::init`.
  - [ ] 9.2.3 Human output lists created paths and commit SHA.
  - [ ] 9.2.4 JSON output returns `InitReport`.
  - [ ] 9.2.5 Add tests for success, non-empty directory, and `--force` rejection.
  - [ ] 9.2.6 Add a non-TTY test asserting missing `--tenant-id` exits 2.

- [ ] **9.3 Implement authority commands**
  - [ ] 9.3.1 Implement `ck root create`.
    - Flags: `--cn`, `--algorithm`, `--validity-days`, `--org`, `--country`.
    - Defaults from decisions.
  - [ ] 9.3.2 Implement `ck intermediate create`.
    - Flags: `--name`, `--parent` default `root`, `--algorithm`, `--validity-days`, `--cn`.
    - Validate name against `{tls, smime, codesign, ocsp}`.
  - [ ] 9.3.3 Implement `ck intermediate inspect`.
    - Flags: optional `--name`; interactive selection when omitted.
  - [ ] 9.3.4 Implement `ck ocsp-signer create`.
    - Flags: `--cn`, `--validity-days` default 90.
  - [ ] 9.3.5 Add tests using fake service and assert exact JSON fields.

- [ ] **9.4 Implement issue command**
  - [ ] 9.4.1 Flags.
    - `--profile`, `--cn`, `--dns`, `--ip`, `--email`, `--uri`.
    - `--org`, `--ou`, `--country`, `--state`, `--locality`.
    - `--algorithm`, `--validity-days`.
    - `--custom-oid <OID>:<true|false>:<UTF8_VALUE>` repeatable.
    - `--custom-oid-hex <OID>:<true|false>:<HEX>` repeatable.
    - `--csr <PATH>`.
    - `--key-out <PATH>`.
    - `--replaces <SERIAL>`.
  - [ ] 9.4.2 Interactive flow.
    - Prompt for profile when missing.
    - Prompt for CN when missing.
    - Prompt for SANs when profile requires them.
    - Confirm before writing key material.
  - [ ] 9.4.3 Human output shows serial, subject, profile, expiry, certificate path, key path, fingerprint.
  - [ ] 9.4.4 JSON output returns `IssueReport`.
  - [ ] 9.4.5 Add tests.
    - All flags parse.
    - Custom OID strings parse into `CustomExtension`.
    - Missing CN in non-TTY exits 2.
    - `--yes` proceeds without confirmation in TTY test harness.
    - Replace flag forwards serial.
    - JSON output has no human text.

- [ ] **9.5 Implement revoke command**
  - [ ] 9.5.1 Flags: `--serial`, `--reason`, `--comment`, `--yes`.
  - [ ] 9.5.2 Interactive flow.
    - Prompt with searchable list of active certificates.
    - Display serial, CN, profile, expiry.
    - Require explicit confirmation.
  - [ ] 9.5.3 Human output shows serial, reason, CRL number, commit SHA.
  - [ ] 9.5.4 JSON output returns `RevokeReport`.
  - [ ] 9.5.5 Add tests.
    - All nine reasons accepted.
    - Unknown reason exits 2.
    - Missing serial in non-TTY exits 2.
    - `--yes` skips confirmation.
    - Revoke error maps to exit 1.

- [ ] **9.6 Implement inspect command**
  - [ ] 9.6.1 Flags: `--serial`, `--file`, `--json`.
  - [ ] 9.6.2 Interactive selector when neither serial nor file is supplied.
  - [ ] 9.6.3 Human table includes all fields from the reference document.
  - [ ] 9.6.4 JSON output returns `InspectReport`.
  - [ ] 9.6.5 Add tests for serial and file input.

- [ ] **9.7 Implement search command**
  - [ ] 9.7.1 Flags.
    - `--query`, `--status`, `--profile`, `--issuer`, `--expires <30d>`, `--all`, `--limit`, `--offset`.
  - [ ] 9.7.2 Parse duration syntax `Nd` and `Nh`.
  - [ ] 9.7.3 Human table columns: serial, CN, profile, status, expires, authority.
  - [ ] 9.7.4 JSON output returns `{ items, total, limit, offset }`.
  - [ ] 9.7.5 Add tests for every filter and invalid duration.

- [ ] **9.8 Implement tree command**
  - [ ] 9.8.1 Render ASCII tree.
  - [ ] 9.8.2 `--json` returns `TreeReport`.
  - [ ] 9.8.3 Add tests for default hierarchy and broken hierarchy.

- [ ] **9.9 Implement analyze command**
  - [ ] 9.9.1 Add subcommands: `expirations`, `revocations`, `intermediates`, `algorithms`, `policy`.
  - [ ] 9.9.2 Human output uses tables and grouped sections.
  - [ ] 9.9.3 `--json` returns `AnalyzeReport`.
  - [ ] 9.9.4 Add tests for each subcommand.

- [ ] **9.10 Implement audit command**
  - [ ] 9.10.1 Flags: `--action`, `--object-type`, `--object-id`, `--since`, `--until`, `--limit`.
  - [ ] 9.10.2 Human table columns: seq, timestamp, action, object, summary.
  - [ ] 9.10.3 `--json` returns event array.
  - [ ] 9.10.4 Add tests for filters and ordering.

- [ ] **9.11 Implement doctor command**
  - [ ] 9.11.1 Human output groups errors, warnings, and OK checks.
  - [ ] 9.11.2 `--json` returns `DoctorReport`.
  - [ ] 9.11.3 Exit 3 when errors exist.
  - [ ] 9.11.4 Exit 0 when only warnings exist.
  - [ ] 9.11.5 Add tests for both exit paths.

- [ ] **9.12 Implement diff command**
  - [ ] 9.12.1 Flags: `--since <REV>`.
  - [ ] 9.12.2 Human output groups by category.
  - [ ] 9.12.3 `--json` returns `DiffReport`.
  - [ ] 9.12.4 Add tests for no manifest and all categories.

- [ ] **9.13 Implement publish command**
  - [ ] 9.13.1 Flags: `--dry-run`, `--no-commit`.
  - [ ] 9.13.2 `--dry-run` builds to a temp directory and prints manifest summary.
  - [ ] 9.13.3 `--no-commit` writes artifacts but skips Git commit and audit.
  - [ ] 9.13.4 Human output lists artifact count, changed paths, and commit SHA.
  - [ ] 9.13.5 `--json` returns `PublishManifest`.
  - [ ] 9.13.6 Add tests for all modes.

- [ ] **9.14 Implement index command**
  - [ ] 9.14.1 Add `ck index rebuild [--repair]`.
  - [ ] 9.14.2 Human output shows counts.
  - [ ] 9.14.3 `--json` returns `IndexReport`.
  - [ ] 9.14.4 Add tests for rebuild and repair.

- [ ] **9.15 Implement interactive selector module**
  - [ ] 9.15.1 Define `Selector<T>` with `filter(text, items)`.
  - [ ] 9.15.2 Implement substring matching across CN, email, SANs, serial, and profile.
  - [ ] 9.15.3 Implement stable ordering by serial.
  - [ ] 9.15.4 Implement non-TTY fallback that returns an error, never blocks.
  - [ ] 9.15.5 Add unit tests for filtering, ordering, and non-TTY fallback.

- [ ] **9.16 Implement output formatting**
  - [ ] 9.16.1 Implement `Ui` trait with `info`, `warn`, `error`, `table`, `json`.
  - [ ] 9.16.2 Implement `HumanUi` and `JsonUi`.
  - [ ] 9.16.3 Respect `--no-color` and `NO_COLOR`.
  - [ ] 9.16.4 Disable color when stdout is not a TTY.
  - [ ] 9.16.5 Add tests for color decisions.

### Acceptance Criteria

- [ ] `cargo test --quiet -p chainkeeper-cli` passes.
- [ ] Every command and subcommand has a passing `--help` test.
- [ ] Every command has a JSON output test with exact fields.
- [ ] Tests assert exit codes 0, 1, 2, and 3.
- [ ] Tests assert non-TTY missing-value paths exit 2 without blocking.
- [ ] Tests assert interactive selector filters and ordering.
- [ ] Tests assert human output never contains private key blocks.
- [ ] `cargo clippy -p chainkeeper-cli --all-targets -- -D warnings` passes.

---

## Phase 10 - Read-Only Server, API, and Git Watcher

### Goals

Implement `ck-server` with read-only certificate, authority, CRL, audit, health, AIA, chain, and OCSP endpoints, plus Git change detection, atomic state reload, and artifact publishing.

### Overview

This phase owns `chainkeeper-server`. Server handlers consume `ServerStateProvider` and `OcspResponder` traits so route tests run with fakes. The real store, publish builder, and OCSP implementation are wired in Phase 11.

### Rules

- The server never issues, revokes, replaces, or modifies repository state.
- The server never holds root or intermediate private keys.
- The server reads the dedicated OCSP signer key only from `CHAINKEEPER_OCSP_KEY_PATH`.
- The server serves HTTP; TLS termination is external.
- Every endpoint except `POST /ocsp` is read-only.
- Reject non-GET methods on read routes with 405 and an `Allow` header.
- Reject request bodies larger than 64 KiB.
- Apply a 10-second request timeout.
- Reject path traversal in serial, authority, and file parameters.
- Set `X-Content-Type-Options: nosniff`.
- Set `Cache-Control` on artifacts and OCSP responses.
- On startup failure, exit non-zero and do not bind.
- On reload failure, keep serving the previous snapshot and mark health degraded.

### Work Items

- [ ] **10.1 Implement server configuration**
  - [ ] 10.1.1 Add config struct.
    - `bind` default `0.0.0.0:8080`.
    - `repo` default current directory.
    - `publish_dir` default `.chainkeeper/publish`.
    - `poll_interval` default 15 seconds.
    - `remote` optional.
    - `branch` default `main`.
    - `sync_remote` default false.
    - `ocsp_key_path` default `CHAINKEEPER_OCSP_KEY_PATH`.
  - [ ] 10.1.2 Load from `server.yaml` and environment overrides.
  - [ ] 10.1.3 Validate `repo` exists and is a Git repository.
  - [ ] 10.1.4 Validate `publish_dir` is outside the repository or under `.chainkeeper/`.
  - [ ] 10.1.5 Add tests for defaults, overrides, and invalid paths.

- [ ] **10.2 Implement application state**
  - [ ] 10.2.1 Implement `AppState`.
    - `Arc<dyn ServerStateProvider>`.
    - `Arc<dyn OcspResponder>`.
    - `publish_dir`.
  - [ ] 10.2.2 Implement `ServerSnapshot` loading from store and publish manifest.
  - [ ] 10.2.3 Build lookup maps by serial, profile, authority, and status.
  - [ ] 10.2.4 Add tests for snapshot construction.

- [ ] **10.3 Implement API routes**
  - [ ] 10.3.1 `GET /api/v1/certificates`.
    - Query: `status`, `profile`, `authority`, `expires_within`, `limit`, `cursor`.
    - Response: `{ items, next_cursor }`.
  - [ ] 10.3.2 `GET /api/v1/certificates/{serial}`.
    - Validate serial path segment.
    - Return 404 JSON on missing.
  - [ ] 10.3.3 `GET /api/v1/root`.
    - Return root certificate PEM with `application/x-pem-file`.
  - [ ] 10.3.4 `GET /api/v1/intermediates`.
    - Return JSON list with name, kind, parent, algorithm, not_before, not_after, pem_url.
  - [ ] 10.3.5 `GET /api/v1/revocations`.
    - Return JSON list.
  - [ ] 10.3.6 `GET /api/v1/crls`.
    - Return JSON list with authority, number, this_update, next_update, revoked_count, url.
  - [ ] 10.3.7 `GET /api/v1/audit`.
    - Query: `action`, `object_type`, `object_id`, `since`, `until`, `limit`, `cursor`.
  - [ ] 10.3.8 `GET /api/v1/health`.
    - Return `ServerHealth`.
  - [ ] 10.3.9 Add tests for each endpoint.
    - Assert status code, content type, body shape, and 404/400 paths.
    - Assert no endpoint accepts POST.

- [ ] **10.4 Implement artifact routes**
  - [ ] 10.4.1 `GET /root.pem`.
  - [ ] 10.4.2 `GET /intermediates/{name}.pem`.
  - [ ] 10.4.3 Aliases: `/tls-intermediate.pem`, `/smime-intermediate.pem`, `/codesign-intermediate.pem`, `/ocsp-intermediate.pem`.
  - [ ] 10.4.4 `GET /crl/{authority}.crl`.
  - [ ] 10.4.5 `GET /crl/{authority}.crl.pem`.
  - [ ] 10.4.6 `GET /aia/{authority}.pem`.
  - [ ] 10.4.7 `GET /chains/{profile}/{serial}.pem`.
  - [ ] 10.4.8 Set `Content-Type` and `Cache-Control: public, max-age=300`.
  - [ ] 10.4.9 Add `ETag` from manifest SHA-256 and support `If-None-Match`.
  - [ ] 10.4.10 Add `Last-Modified` and support `If-Modified-Since`.
  - [ ] 10.4.11 Reject path traversal and missing manifest entries with 404.
  - [ ] 10.4.12 Add tests for content type, caching, conditional requests, and traversal.

- [ ] **10.5 Implement OCSP route**
  - [ ] 10.5.1 `POST /ocsp`.
  - [ ] 10.5.2 Require `Content-Type: application/ocsp-request`.
  - [ ] 10.5.3 Enforce 64 KiB body limit.
  - [ ] 10.5.4 Call `OcspResponder::respond`.
  - [ ] 10.5.5 Return `application/ocsp-response`.
  - [ ] 10.5.6 Set `Cache-Control: public, max-age=3600`.
  - [ ] 10.5.7 Return 405 with `Allow: POST` for GET.
  - [ ] 10.5.8 Return 503 when responder not ready.
  - [ ] 10.5.9 Add tests for valid request, malformed request, oversized body, wrong content type, GET, and not-ready.

- [ ] **10.6 Implement health endpoints**
  - [ ] 10.6.1 `GET /healthz` returns 200 when the process is alive.
  - [ ] 10.6.2 `GET /readyz` returns 200 only when snapshot and OCSP are ready.
  - [ ] 10.6.3 `/readyz` returns 503 with JSON errors when not ready.
  - [ ] 10.6.4 Add tests for both states.

- [ ] **10.7 Implement error handling**
  - [ ] 10.7.1 Define JSON error shape `{ "error": { "code": "...", "message": "..." } }`.
  - [ ] 10.7.2 Map `NotFound` to 404.
  - [ ] 10.7.3 Map validation to 400.
  - [ ] 10.7.4 Map conflict to 409.
  - [ ] 10.7.5 Map internal errors to 500 without leaking paths or secrets.
  - [ ] 10.7.6 Add tests for each mapping.

- [ ] **10.8 Implement Git watcher**
  - [ ] 10.8.1 Watch `.git/HEAD` and `.git/refs` with `notify`.
  - [ ] 10.8.2 Add OID polling every `poll_interval`.
  - [ ] 10.8.3 Debounce bursts of events by 250 ms.
  - [ ] 10.8.4 On change, read `HEAD`.
  - [ ] 10.8.5 If OID unchanged, do nothing.
  - [ ] 10.8.6 If `sync_remote` is true, fetch and fast-forward.
    - Refuse when working tree is dirty.
    - Refuse non-fast-forward.
  - [ ] 10.8.7 Rebuild publish artifacts to `publish_dir`.
  - [ ] 10.8.8 Reload snapshot and OCSP state.
  - [ ] 10.8.9 Expose reload result in health.
  - [ ] 10.8.10 Add tests with a temporary Git repository.
    - Commit triggers reload.
    - Unchanged commit does not reload.
    - Dirty tree prevents remote sync.
    - Non-fast-forward prevents reset.
    - Reload failure preserves old snapshot.

- [ ] **10.9 Implement lifecycle and observability**
  - [ ] 10.9.1 Initialize tracing with request IDs.
  - [ ] 10.9.2 Add request logging at `debug`, errors at `warn`.
  - [ ] 10.9.3 Add graceful shutdown on SIGTERM and Ctrl-C.
  - [ ] 10.9.4 Add 10-second request timeout.
  - [ ] 10.9.5 Add 64 KiB body limit.
  - [ ] 10.9.6 Add `tower-http` compression for JSON and text.
  - [ ] 10.9.7 Add tests for graceful shutdown and timeout.
  - [ ] 10.9.8 Add a test asserting logs do not contain private key markers.

- [ ] **10.10 Add security tests**
  - [ ] 10.10.1 Assert no route other than `/ocsp` accepts POST, PUT, PATCH, or DELETE.
  - [ ] 10.10.2 Assert server never reads `authorities/**/key.pem` except `ocsp-signer`.
  - [ ] 10.10.3 Assert publish directory contains no private keys before serving.
  - [ ] 10.10.4 Assert path traversal attempts return 400 or 404 and never read outside publish dir.
  - [ ] 10.10.5 Assert malformed serial returns 400.
  - [ ] 10.10.6 Assert unknown authority returns 404.

### Acceptance Criteria

- [ ] `cargo test --quiet -p chainkeeper-server` passes.
- [ ] Tests cover every API and artifact route.
- [ ] Tests assert read-only behavior for all routes except `POST /ocsp`.
- [ ] Tests assert path traversal is rejected.
- [ ] Tests assert conditional GET with ETag and Last-Modified.
- [ ] Tests assert OCSP content type, body limit, and 405 for GET.
- [ ] Tests assert health and readiness transitions.
- [ ] Tests assert watcher reload on new commit and no reload on unchanged commit.
- [ ] Tests assert failed reload preserves previous snapshot.
- [ ] Tests assert server never reads root or intermediate private keys.
- [ ] `cargo clippy -p chainkeeper-server --all-targets -- -D warnings` passes.

---

## Phase 11 - Integration, Compliance, and Release Gate

### Goals

Wire concrete implementations into the CLI and server, prove the full offline-first workflow end to end, verify RFC compliance, enforce security invariants, and produce release-ready artifacts.

### Overview

This phase owns workspace-level integration tests, the real service factory, the real server state provider, CI release jobs, and packaging. It is the only phase that may depend on all other phases.

### Rules

- Integration tests must use unique temporary directories and must not use fixed ports or paths.
- Integration tests that start a server must bind `127.0.0.1:0` and read the assigned port.
- Every spawned server task must be cancelled and awaited before the test exits.
- Git identity must be set explicitly in each test repository.
- Use `openssl` CLI only for independent compliance verification, never for product behavior.
- Do not weaken tests to accommodate flaky scheduling. Fix root causes.
- Do not run aggregate verification scripts during agent work; run each phase target individually unless this phase explicitly requires the full suite.

### Work Items

- [ ] **11.1 Wire the real CLI service**
  - [ ] 11.1.1 Implement `chainkeeper_engine::open_service(repo: &Path) -> Result<Arc<dyn ChainkeeperService>>`.
    - Construct `RepositoryPaths`.
    - Open SQLite index.
    - Construct `FileCertificateStore`.
    - Construct `OpenSslProvider`.
    - Construct `FileAuditLog`.
    - Construct `GitRepository`.
    - Construct `FileRepositoryLock`.
    - Construct `CrlManager`.
    - Construct `PublishBuilder`.
    - Construct `Engine`.
  - [ ] 11.1.2 Replace the Phase 1 stub factory with the real factory.
  - [ ] 11.1.3 Ensure every CLI command uses the real factory outside tests.
  - [ ] 11.1.4 Add a test that constructs the service in a temp repository and runs `doctor`.

- [ ] **11.2 Wire the real server runtime**
  - [ ] 11.2.1 Implement `chainkeeper_server::runtime::build_state`.
    - Open store and index.
    - Build snapshot.
    - Build publish directory.
    - Load OCSP state.
  - [ ] 11.2.2 Implement watcher task wiring.
  - [ ] 11.2.3 Implement `main`.
    - Parse config.
    - Initialize tracing.
    - Build state.
    - Bind listener.
    - Serve with graceful shutdown.
  - [ ] 11.2.4 Add a test that starts the real server against a temp repository.
  - [ ] 11.2.5 Add a test that kills and awaits the server task.

- [ ] **11.3 Add end-to-end lifecycle tests**
  - [ ] 11.3.1 Init two tenants in two temp repositories.
    - Assert independent configs and indexes.
  - [ ] 11.3.2 Create root in each tenant.
  - [ ] 11.3.3 Create TLS, S/MIME, code-signing, and OCSP intermediates.
  - [ ] 11.3.4 Create OCSP signer.
  - [ ] 11.3.5 Issue TLS server certificate.
  - [ ] 11.3.6 Issue TLS client certificate.
  - [ ] 11.3.7 Issue mTLS certificate.
  - [ ] 11.3.8 Issue S/MIME certificate.
  - [ ] 11.3.9 Issue code-signing certificate.
  - [ ] 11.3.10 Issue OCSP signing certificate.
  - [ ] 11.3.11 Revoke a TLS certificate.
  - [ ] 11.3.12 Replace a certificate.
  - [ ] 11.3.13 Publish artifacts.
  - [ ] 11.3.14 Assert each mutating step created a Git commit.
  - [ ] 11.3.15 Delete `cache/index.sqlite`, rebuild, and assert search and inspect results are identical.
  - [ ] 11.3.16 Clone the repository without private keys, run doctor, and assert only expected key warnings remain.

- [ ] **11.4 Add RFC compliance tests**
  - [ ] 11.4.1 RFC 5280 certificate checks.
    - `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem` passes for each leaf.
    - Assert version 3, serial positivity, issuer/subject encoding, validity, basic constraints, key usage, EKU, SAN, SKI, AKI, AIA, and CRL DP.
    - Assert no duplicate extensions.
  - [ ] 11.4.2 RFC 5280 path length checks.
    - Leaf cannot sign another certificate.
    - Intermediate path length 0.
  - [ ] 11.4.3 CRL checks.
    - `openssl crl -in crl.pem -noout -verify -CAfile intermediate.pem` passes.
    - Revoked serial present with reason.
    - Non-revoked serial absent.
    - CRL number increases.
  - [ ] 11.4.4 OCSP checks.
    - `openssl ocsp -issuer intermediate.pem -cert leaf.pem -url http://127.0.0.1:<port>/ocsp -respout response.der` returns good.
    - Revoked certificate returns revoked with reason.
    - Unknown serial returns unknown.
    - `openssl ocsp -respin response.der -text` parses.
  - [ ] 11.4.5 Assert OCSP response uses the OCSP signer certificate, not a CA certificate.
  - [ ] 11.4.6 Assert nonce round-trip with `openssl ocsp` when supported.

- [ ] **11.5 Add security invariant tests**
  - [ ] 11.5.1 Scan the Git tree for `PRIVATE KEY` blocks and assert zero tracked keys.
  - [ ] 11.5.2 Scan `publish/` and server publish directory for `PRIVATE KEY` blocks and assert zero.
  - [ ] 11.5.3 Assert server rejects a publish directory containing a private key.
  - [ ] 11.5.4 Assert CLI logs do not contain `PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, or passphrase values.
  - [ ] 11.5.5 Assert all artifact writes are atomic by injecting a write failure.
  - [ ] 11.5.6 Assert audit files are append-only by attempting duplicate creation.
  - [ ] 11.5.7 Assert no product crate invokes `Command::new("openssl")`.
  - [ ] 11.5.8 Assert the server never opens root or intermediate key files.
  - [ ] 11.5.9 Assert file modes for keys and directories on Unix.
  - [ ] 11.5.10 Assert path traversal across CLI, store, publish, and server.

- [ ] **11.6 Add concurrency and failure tests**
  - [ ] 11.6.1 Run 20 parallel `ck issue` operations in one repository.
    - Assert unique serials, 20 certificates, 20 audit events, and 20 commits.
    - Assert no index rows lost.
  - [ ] 11.6.2 Run parallel `ck revoke` on the same certificate.
    - Assert exactly one succeeds and one returns conflict.
  - [ ] 11.6.3 Kill the process during publish and assert the previous publish remains valid.
  - [ ] 11.6.4 Occupy the lock and assert CLI times out with exit 1 and no files created.
  - [ ] 11.6.5 Corrupt index and assert rebuild recovers.
  - [ ] 11.6.6 Corrupt one certificate PEM and assert doctor reports the exact path and issue.
  - [ ] 11.6.7 Make publish directory read-only and assert publish fails without partial state.

- [ ] **11.7 Add release and packaging automation**
  - [ ] 11.7.1 Add `Dockerfile` for `ck` and `ck-server`.
    - Multi-stage Rust build.
    - Non-root runtime user.
    - `ck-server` exposed on 8080.
    - Healthcheck uses `/healthz`.
  - [ ] 11.7.2 Add `docker-bake.hcl` for building both images.
  - [ ] 11.7.3 Add CI job to build Docker images and run `docker run --rm <image> ck --version`.
  - [ ] 11.7.4 Add CI job to run `ck-server --help`.
  - [ ] 11.7.5 Add `cargo-audit` CI job.
  - [ ] 11.7.6 Add `cargo-deny` license and advisory job.
  - [ ] 11.7.7 Add release workflow that builds `ck` and `ck-server` for Linux x86_64 and aarch64.
  - [ ] 11.7.8 Add checksum generation for release binaries.
  - [ ] 11.7.9 Add a test asserting CI workflow YAML is valid with `actionlint`.
  - [ ] 11.7.10 Add a test asserting Dockerfile uses a non-root user.

- [ ] **11.8 Add documentation-as-code checks**
  - [ ] 11.8.1 Add rustdoc examples to `chainkeeper-core` for `Signer`, `PolicyEngine`, and `ChainkeeperService`.
  - [ ] 11.8.2 Run doctests with `cargo test --quiet --doc`.
  - [ ] 11.8.3 Add a compile-fail doctest proving `Signer` cannot be implemented with an unsafe block.
  - [ ] 11.8.4 Add a test that every public error variant has a documented exit code.
  - [ ] 11.8.5 Add `README.md` code fences that are extracted and compiled by `cargo test --doc` where applicable.

- [ ] **11.9 Add final verification targets**
  - [ ] 11.9.1 Add a `Makefile` target `verify` that runs fmt, clippy, tests, doc, and deny.
  - [ ] 11.9.2 Add a `Makefile` target `verify-phase` that accepts a crate name and runs only that crate's checks.
  - [ ] 11.9.3 Add a test asserting no phase-specific code is gated behind `#[cfg(test)]` in production paths.
  - [ ] 11.9.4 Add a test asserting all public traits remain object-safe.
  - [ ] 11.9.5 Add a test asserting the workspace contains exactly the twelve planned crates and no extra publishable crates.

### Acceptance Criteria

- [ ] `cargo test --quiet -p chainkeeper-engine -p chainkeeper-cli -p chainkeeper-server` passes with real implementations.
- [ ] End-to-end tests cover two independent tenants.
- [ ] End-to-end tests cover all six certificate profiles.
- [ ] End-to-end tests cover issue, revoke, replace, publish, OCSP, CRL, audit, search, inspect, tree, analyze, doctor, diff, and index rebuild.
- [ ] `openssl verify` passes for every generated leaf chain.
- [ ] `openssl crl -verify` passes for every generated CRL.
- [ ] `openssl ocsp` returns `good`, `revoked`, and `unknown` for the expected cases.
- [ ] A test asserts no tracked or published private keys exist.
- [ ] A test asserts no product crate shells out to `openssl`.
- [ ] A test asserts the server never opens root or intermediate key files.
- [ ] Concurrency tests pass with 20 parallel issuances and conflicting revocations.
- [ ] Failure tests assert no partial state after interrupted publish, index corruption, or lock timeout.
- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --quiet --workspace --all-features` passes.
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` passes.
- [ ] `cargo deny check` and `cargo audit` pass.
- [ ] `actionlint` validates all CI workflows.
- [ ] Docker images build and report `ck --version` and `ck-server --help`.
