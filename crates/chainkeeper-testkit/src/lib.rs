#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Deterministic test doubles for every Chainkeeper contract.
//!
//! Doubles never read the real clock, never use fixed filesystem paths or
//! fixed ports, and never mutate process-global state. Each instance owns its
//! own state so tests can run in parallel.

pub mod audit;
pub mod clock;
pub mod fixtures;
pub mod git;
pub mod ids;
pub mod ocsp;
pub mod provider;
pub mod publish;
pub mod registry;
pub mod signer;
pub mod store;
pub mod tenant;

pub use audit::InMemoryAuditLog;
pub use clock::FakeClock;
pub use fixtures::CertificateFixtures;
pub use git::InMemoryGitRepository;
pub use ids::FakeIdGenerator;
pub use ocsp::FakeOcspResponder;
pub use provider::{FakeCertificateProvider, FakeOperation};
pub use publish::FakePublishBuilder;
pub use registry::{
    FakeChainkeeperService, FakeCrlManager, FakeRepositoryLock, FakeServerStateProvider,
    InMemoryIndexStore, InMemoryProfileRegistry, NoopPolicyEngine,
};
pub use signer::FakeSigner;
pub use store::InMemoryCertificateStore;
pub use tenant::TempTenant;
