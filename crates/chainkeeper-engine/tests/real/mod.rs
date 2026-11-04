//! Real-service fixtures for the end-to-end lifecycle tests.
//!
//! Each fixture owns a temporary repository, pins the Git identity, and
//! disables commit signing so tests never inherit the host configuration.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chainkeeper_core::{
    AuthorityKind, AuthorityName, CertificateRecord, ChainkeeperError, ChainkeeperService,
    CreateAuthorityRequest, CreateOcspSignerRequest, InitRequest, IssueReport, IssueRequest,
    KeyAlgorithm, ProfileName, San, SearchQuery, SubjectName, TenantId,
};
use chainkeeper_engine::{
    Engine, OpenMode, ServiceOptions, finalize_init, open_service, open_with,
};
use chainkeeper_git::GitIdentity;
use tempfile::TempDir;

/// Pinned Git author name.
pub const GIT_NAME: &str = "Chainkeeper Test";
/// Pinned Git author email.
pub const GIT_EMAIL: &str = "test@example.test";

/// Options that never inherit the host Git configuration.
fn options(mode: OpenMode) -> ServiceOptions {
    ServiceOptions {
        mode,
        git_identity: Some(GitIdentity::new(GIT_NAME, GIT_EMAIL).expect("valid fixture identity")),
        commit_signing: Some(false),
    }
}

/// Repository initialised by `ck init`.
pub struct Tenant {
    /// Temporary repository root.
    pub directory: TempDir,
    /// Open engine.
    pub engine: Arc<Engine>,
}

impl Tenant {
    /// Repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Service surface.
    #[must_use]
    pub fn service(&self) -> &dyn ChainkeeperService {
        self.engine.as_ref()
    }
}

/// Initialises a fresh tenant repository.
///
/// # Panics
///
/// Panics when the fixture repository cannot be created.
#[must_use]
pub fn init_tenant(tenant_id: &str) -> Tenant {
    let directory = tempfile::tempdir().expect("temporary repository");
    let initial = open_with(directory.path(), &options(OpenMode::Init)).expect("open init service");
    let mut request = InitRequest::new(
        TenantId::new(tenant_id).expect("valid tenant id"),
        format!("Tenant {tenant_id}"),
        ProfileName::new("tls-server").expect("valid profile"),
    );
    request.ocsp_url = Some("http://ocsp.example.test".to_owned());
    request.ca_issuers_url_template = Some("http://ca.example.test/{authority}.pem".to_owned());
    request.crl_url_template = Some("http://crl.example.test/{authority}.crl".to_owned());
    initial.init(&request).expect("init repository");
    finalize_init(&initial).expect("persist index");
    drop(initial);

    let engine = open_with(directory.path(), &options(OpenMode::Normal)).expect("reopen service");
    Tenant { directory, engine }
}

/// Reopens a tenant from an existing repository root.
///
/// # Panics
///
/// Panics when the repository cannot be opened.
#[must_use]
pub fn reopen(root: &Path) -> Arc<Engine> {
    open_with(root, &options(OpenMode::Normal)).expect("reopen repository")
}

/// Opens the documented `open_service` entry point.
///
/// # Errors
///
/// Returns an error when the repository cannot be served.
pub fn service_for(root: &Path) -> Result<Arc<dyn ChainkeeperService>, ChainkeeperError> {
    open_service(root)
}

/// Root creation request.
#[must_use]
pub fn root_request() -> CreateAuthorityRequest {
    CreateAuthorityRequest {
        name: AuthorityName::new("root").expect("root name"),
        kind: AuthorityKind::Root,
        parent: None,
        subject: SubjectName::new("Chainkeeper Test Root"),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 7300,
        path_len: 1,
    }
}

/// Intermediate creation request.
#[must_use]
pub fn intermediate_request(name: &str) -> CreateAuthorityRequest {
    CreateAuthorityRequest {
        name: AuthorityName::new(name).expect("intermediate name"),
        kind: AuthorityKind::Intermediate,
        parent: Some(AuthorityName::new("root").expect("root name")),
        subject: SubjectName::new(format!("Chainkeeper Test {name}")),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 3650,
        path_len: 0,
    }
}

/// OCSP signer creation request.
#[must_use]
pub fn ocsp_signer_request() -> CreateOcspSignerRequest {
    CreateOcspSignerRequest {
        name: AuthorityName::new("ocsp-signer").expect("signer name"),
        parent: AuthorityName::new("ocsp").expect("ocsp authority"),
        subject: None,
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 90,
    }
}

/// Issues a certificate for `profile` with the subject and SANs each built-in
/// profile expects.
///
/// # Panics
///
/// Panics when issuance fails.
#[must_use]
pub fn issue(engine: &Engine, profile: &str, cn: &str) -> IssueReport {
    let sans = match profile {
        "tls-server" | "tls-client" | "mtls" | "codesign" | "ocsp" => {
            vec![San::Dns(cn.to_owned())]
        }
        "smime" => vec![San::Email(cn.to_owned())],
        _ => Vec::new(),
    };
    let request = IssueRequest {
        sans,
        ..IssueRequest::new(
            ProfileName::new(profile).expect("valid profile"),
            SubjectName::new(cn),
        )
    };
    engine.issue(&request).expect("issue certificate")
}

/// Issues every built-in profile and returns the reports.
///
/// # Panics
///
/// Panics when issuance fails.
#[must_use]
pub fn issue_every_profile(engine: &Engine) -> Vec<IssueReport> {
    vec![
        issue(engine, "tls-server", "server.example.test"),
        issue(engine, "tls-client", "client"),
        issue(engine, "mtls", "mtls.example.test"),
        issue(engine, "smime", "smime@example.test"),
        issue(engine, "codesign", "codesign.example.test"),
        issue(engine, "ocsp", "ocsp.example.test"),
    ]
}

/// Generates a CRL for every intermediate authority.
///
/// # Panics
///
/// Panics when a CRL cannot be generated or committed.
pub fn generate_crls(engine: &Engine, commit: bool) {
    for name in ["tls", "smime", "codesign", "ocsp"] {
        let authority = AuthorityName::new(name).expect("authority name");
        engine
            .crl
            .update_for_authority(&authority)
            .expect("generate CRL");
    }
    if commit {
        engine
            .commit(
                "test: generate CRLs",
                &[
                    engine.paths.crls_dir(),
                    engine.paths.audit_dir(),
                    engine.paths.cache_dir(),
                ],
            )
            .expect("commit CRLs");
    }
}

/// Number of commits reachable from `HEAD`.
///
/// # Panics
///
/// Panics when the repository cannot be read.
#[must_use]
pub fn commit_count(root: &Path) -> usize {
    let repository = git2::Repository::open(root).expect("open git repository");
    let mut walk = repository.revwalk().expect("revwalk");
    walk.push_head().expect("head");
    walk.count()
}

/// Search every certificate.
///
/// # Panics
///
/// Panics when the search fails.
#[must_use]
pub fn all_certificates(engine: &Engine) -> Vec<CertificateRecord> {
    engine
        .search(&SearchQuery::default())
        .expect("search certificates")
}

/// Recursively collects files whose name is `key.pem` below `root`.
#[must_use]
pub fn key_files(root: &Path) -> Vec<PathBuf> {
    fn walk(directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.file_name().is_some_and(|name| name == "key.pem") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found
}

/// Returns true when `bytes` contains a PEM private key marker.
#[must_use]
pub fn contains_private_key(bytes: &[u8]) -> bool {
    bytes
        .windows(b"PRIVATE KEY".len())
        .any(|window| window == b"PRIVATE KEY")
}

/// Contents of every blob in the `HEAD` tree.
///
/// # Panics
///
/// Panics when the repository or tree cannot be read.
#[must_use]
pub fn committed_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(
        repository: &git2::Repository,
        tree: &git2::Tree<'_>,
        prefix: &Path,
        found: &mut Vec<(PathBuf, Vec<u8>)>,
    ) {
        for entry in tree {
            let path = prefix.join(String::from_utf8_lossy(entry.name_bytes()).into_owned());
            match entry.kind() {
                Some(git2::ObjectType::Blob) => {
                    let blob = repository.find_blob(entry.id()).expect("blob");
                    found.push((path, blob.content().to_vec()));
                }
                Some(git2::ObjectType::Tree) => {
                    let nested = repository.find_tree(entry.id()).expect("tree");
                    walk(repository, &nested, &path, found);
                }
                _ => {}
            }
        }
    }
    let repository = git2::Repository::open(root).expect("open git repository");
    let head = repository.head().expect("head");
    let tree = head.peel_to_tree().expect("head tree");
    let mut found = Vec::new();
    walk(&repository, &tree, Path::new(""), &mut found);
    found.sort();
    found
}

/// Files tracked by the Git index.
///
/// # Panics
///
/// Panics when the repository cannot be read.
#[must_use]
pub fn tracked_files(root: &Path) -> Vec<PathBuf> {
    let repository = git2::Repository::open(root).expect("open git repository");
    let index = repository.index().expect("git index");
    index
        .iter()
        .map(|entry| root.join(String::from_utf8_lossy(&entry.path).into_owned()))
        .collect()
}

/// Recursively collects every file below `root`.
#[must_use]
pub fn files(root: &Path) -> Vec<PathBuf> {
    fn walk(directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found.sort();
    found
}
