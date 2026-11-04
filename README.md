# Chainkeeper

Offline-first PKI operations for a single tenant and repository. `ck` owns the
canonical repository, and `ck-server` publishes read-only artifacts and OCSP
responses from it.

## Quickstart

```sh
cargo install --path crates/chainkeeper-cli
ck init --tenant-id acme
ck root create --cn "Acme Root"
ck intermediate create --name tls
ck issue --profile tls-server --cn api.example.test --dns api.example.test
ck publish
ck doctor
```

Serve the published artifacts:

```sh
cargo run -p chainkeeper-server -- --repo . --bind 127.0.0.1:8080
```

## Contracts

Every workflow is expressed through the frozen traits in `chainkeeper-core`, so
the CLI, the server, and tests share one surface.

```rust
use chainkeeper_core::{KeyAlgorithm, Policy, ProfileName, SubjectName};

let subject = SubjectName::new("api.example.test");
assert_eq!(subject.cn, "api.example.test");
assert_eq!(ProfileName::new("tls-server").expect("profile").as_str(), "tls-server");
assert_eq!(KeyAlgorithm::EcdsaP256.as_str(), "ecdsa-p256");
assert!(!Policy::default().allowed_algorithms.is_empty());
```

## Operational notes

- `ck-server` is read-only: it never opens root or intermediate key material.
- OCSP responses are signed by the dedicated `ocsp-signer` authority. Strict
  RFC 6960 clients accept that delegation for certificates issued by the OCSP
  intermediate; other issuers must be configured as trusted responders.
- Set `CHAINKEEPER_OCSP_KEY_PATH` when the signer key lives outside the
  repository layout, and `CHAINKEEPER_KEY_PASSPHRASE` for encrypted keys.
- The SQLite index is disposable. A corrupt database is moved to
  `cache/index.sqlite.corrupt` and rebuilt from canonical records.

## Verification

```sh
make verify
make verify-phase CRATE=chainkeeper-engine
```

Repository internals live in `docs/ARCHITECTURE.md` and `docs/DESIGN.md`.
