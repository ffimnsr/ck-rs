#![allow(dead_code)]

//! Shared CLI command test doubles.

use std::path::PathBuf;
use std::sync::Mutex;

use chainkeeper_cli::cli::Cli;
use chainkeeper_cli::{CliError, Prompter, Ui, dispatch};
use chainkeeper_core::{
    AnalysisFinding, AnalyzeKind, AnalyzeReport, AuditEvent, AuditQuery, AuthorityKind,
    AuthorityName, AuthorityRecord, CertificateRecord, CertificateStatus, ChainkeeperError,
    ChainkeeperService, CreateAuthorityRequest, CreateOcspSignerRequest, DiffReport, DoctorReport,
    IndexReport, IndexStats, InitReport, InspectReport, IssueReport, IssueRequest, KeyAlgorithm,
    KeyUsage, PUBLISH_MANIFEST_VERSION, ProfileName, PublishManifest, PublishOptions,
    RevocationRecord, RevokeReport, SearchQuery, Serial, Severity, SubjectName, TenantId, TreeNode,
    TreeReport,
};
use serde_json::Value;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

pub const NOW: OffsetDateTime = datetime!(2024-06-01 00:00:00 UTC);

/// Table headers and rows captured by [`CaptureUi`].
pub type CapturedTable = (Vec<String>, Vec<Vec<String>>);

/// Every captured output line.
#[derive(Debug, Default)]
pub struct CaptureUi {
    pub info: Mutex<Vec<String>>,
    pub warnings: Mutex<Vec<String>>,
    pub errors: Mutex<Vec<String>>,
    pub tables: Mutex<Vec<CapturedTable>>,
    pub json: Mutex<Vec<Value>>,
}

impl Ui for CaptureUi {
    fn info(&self, message: &str) -> Result<(), CliError> {
        self.info.lock().expect("lock").push(message.to_owned());
        Ok(())
    }

    fn warn(&self, message: &str) -> Result<(), CliError> {
        self.warnings.lock().expect("lock").push(message.to_owned());
        Ok(())
    }

    fn error(&self, message: &str) -> Result<(), CliError> {
        self.errors.lock().expect("lock").push(message.to_owned());
        Ok(())
    }

    fn table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<(), CliError> {
        self.tables.lock().expect("lock").push((
            headers.iter().map(ToString::to_string).collect(),
            rows.to_vec(),
        ));
        Ok(())
    }

    fn json(&self, value: &Value) -> Result<(), CliError> {
        self.json.lock().expect("lock").push(value.clone());
        Ok(())
    }
}

impl CaptureUi {
    pub fn json_only(&self) -> Value {
        let documents = self.json.lock().expect("lock");
        assert_eq!(documents.len(), 1, "expected exactly one JSON document");
        documents[0].clone()
    }

    pub fn all_text(&self) -> String {
        let mut text = String::new();
        for line in self.info.lock().expect("lock").iter() {
            text.push_str(line);
            text.push('\n');
        }
        for line in self.warnings.lock().expect("lock").iter() {
            text.push_str(line);
            text.push('\n');
        }
        for line in self.errors.lock().expect("lock").iter() {
            text.push_str(line);
            text.push('\n');
        }
        for (headers, rows) in self.tables.lock().expect("lock").iter() {
            text.push_str(&headers.join(" "));
            text.push('\n');
            for row in rows {
                text.push_str(&row.join(" "));
                text.push('\n');
            }
        }
        text
    }
}

/// Configurable service double.
pub struct TestService {
    pub items: Vec<CertificateRecord>,
    pub tree: TreeReport,
    pub events: Vec<AuditEvent>,
    pub doctor_error: bool,
    pub fail_issue: bool,
    pub fail_tree: bool,
    pub last_issue: Mutex<Option<IssueRequest>>,
    pub last_search: Mutex<Option<SearchQuery>>,
}

impl Default for TestService {
    fn default() -> Self {
        Self {
            items: vec![sample_record("00AA", "api.example.test", "tls-server")],
            tree: sample_tree(),
            events: vec![sample_event()],
            doctor_error: false,
            fail_issue: false,
            fail_tree: false,
            last_issue: Mutex::new(None),
            last_search: Mutex::new(None),
        }
    }
}

impl ChainkeeperService for TestService {
    fn init(
        &self,
        request: &chainkeeper_core::InitRequest,
    ) -> Result<InitReport, ChainkeeperError> {
        Ok(InitReport {
            tenant_id: request.tenant_id.clone(),
            root: PathBuf::from("/repo"),
            created_paths: vec![PathBuf::from("/repo/tenant.yaml")],
            commit: Some("abc123".to_owned()),
        })
    }

    fn create_root(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(authority(request))
    }

    fn create_intermediate(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(authority(request))
    }

    fn create_ocsp_signer(
        &self,
        request: &CreateOcspSignerRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(AuthorityRecord {
            name: request.name.clone(),
            kind: AuthorityKind::OcspSigner,
            parent: Some(request.parent.clone()),
            algorithm: request.algorithm,
            validity_days: request.validity_days,
            path_len: 0,
            created_at: NOW,
            cert_path: PathBuf::from("authorities/ocsp-signer/cert.pem"),
            chain_path: PathBuf::from("authorities/ocsp-signer/chain.pem"),
        })
    }

    fn issue(&self, request: &IssueRequest) -> Result<IssueReport, ChainkeeperError> {
        *self.last_issue.lock().expect("lock") = Some(request.clone());
        if self.fail_issue {
            return Err(ChainkeeperError::storage("issuance failed"));
        }
        let mut record = sample_record("00AB", &request.subject.cn, request.profile.as_str());
        record.profile = request.profile.clone();
        record.sans.clone_from(&request.sans);
        record.replaces.clone_from(&request.replaces);
        Ok(IssueReport {
            cert_path: record.path.clone(),
            certificate: record,
            key_path: request.key_out.clone(),
            commit: Some("abc123".to_owned()),
        })
    }

    fn revoke(
        &self,
        request: &chainkeeper_core::RevokeRequest,
    ) -> Result<RevokeReport, ChainkeeperError> {
        Ok(RevokeReport {
            revocation: RevocationRecord {
                version: chainkeeper_core::CONFIG_VERSION,
                serial: request.serial.clone(),
                authority: AuthorityName::new("tls")?,
                reason: request.reason,
                comment: request.comment.clone(),
                revoked_at: NOW,
                crl_number: 7,
            },
            crl: None,
            commit: Some("abc123".to_owned()),
        })
    }

    fn inspect(&self, serial: &Serial) -> Result<InspectReport, ChainkeeperError> {
        Ok(InspectReport {
            certificate: sample_record(serial.as_str(), "api.example.test", "tls-server"),
            status: CertificateStatus::Active,
            cert_pem: None,
            chain_pem: None,
        })
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        *self.last_search.lock().expect("lock") = Some(query.clone());
        Ok(self.items.clone())
    }

    fn count(&self, _query: &SearchQuery) -> Result<u64, ChainkeeperError> {
        Ok(u64::try_from(self.items.len()).unwrap_or(u64::MAX))
    }

    fn tree(&self) -> Result<TreeReport, ChainkeeperError> {
        if self.fail_tree {
            return Err(ChainkeeperError::validation(
                "authority references a missing parent",
            ));
        }
        Ok(self.tree.clone())
    }

    fn analyze(&self, kind: AnalyzeKind) -> Result<AnalyzeReport, ChainkeeperError> {
        Ok(AnalyzeReport {
            kind,
            generated_at: NOW,
            findings: vec![AnalysisFinding {
                code: "CERT_EXPIRING".to_owned(),
                severity: Severity::Warning,
                message: "certificate expires soon".to_owned(),
                object_id: Some("00AA".to_owned()),
            }],
        })
    }

    fn audit(&self, _query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        Ok(self.events.clone())
    }

    fn doctor(&self) -> Result<DoctorReport, ChainkeeperError> {
        let findings = if self.doctor_error {
            vec![chainkeeper_core::DoctorFinding {
                code: "CRL_MISSING".to_owned(),
                severity: Severity::Error,
                message: "no CRL".to_owned(),
                object_id: Some("tls".to_owned()),
            }]
        } else {
            Vec::new()
        };
        Ok(DoctorReport {
            healthy: findings.is_empty(),
            checked_at: NOW,
            findings,
        })
    }

    fn diff(
        &self,
        request: &chainkeeper_core::DiffRequest,
    ) -> Result<DiffReport, ChainkeeperError> {
        Ok(DiffReport {
            from: request.from.clone(),
            to: Some("HEAD".to_owned()),
            added: vec![PathBuf::from("crl/tls.crl")],
            modified: vec![PathBuf::from("root.pem")],
            removed: vec![PathBuf::from("old.pem")],
        })
    }

    fn publish(&self, _options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        Ok(PublishManifest {
            version: PUBLISH_MANIFEST_VERSION,
            generated_at: NOW,
            source_commit: Some("abc123".to_owned()),
            tenant_id: TenantId::new("acme")?,
            artifacts: vec![chainkeeper_core::PublishArtifact {
                path: PathBuf::from("root.pem"),
                sha256: "00".repeat(32),
                bytes: 10,
            }],
        })
    }

    fn rebuild_index(&self) -> Result<IndexReport, ChainkeeperError> {
        Ok(index_report(Vec::new()))
    }

    fn repair_index(&self) -> Result<IndexReport, ChainkeeperError> {
        Ok(index_report(vec![Serial::new("00AA")?]))
    }
}

/// Parses arguments and dispatches against `service`.
///
/// # Errors
///
/// Returns command failures as [`CliError`].
pub fn run(
    service: &TestService,
    ui: &CaptureUi,
    args: &[&str],
    interactive: bool,
) -> Result<u8, CliError> {
    let cli = Cli::parse_from(std::iter::once("ck").chain(args.iter().copied()))
        .map_err(|error| CliError::usage(error.to_string()))?;
    let prompt = Prompter::new(interactive, cli.yes);
    dispatch(&cli, service, ui, prompt, NOW)
}

/// Parses arguments without dispatch.
///
/// # Errors
///
/// Returns the clap error.
pub fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::parse_from(std::iter::once("ck").chain(args.iter().copied()))
}

/// Sample certificate metadata.
#[must_use]
pub fn sample_record(serial: &str, cn: &str, profile: &str) -> CertificateRecord {
    CertificateRecord {
        serial: Serial::new(serial).expect("serial"),
        subject: SubjectName::new(cn),
        issuer: "CN=Chainkeeper Test TLS".to_owned(),
        profile: ProfileName::new(profile).expect("profile"),
        authority: AuthorityName::new("tls").expect("authority"),
        algorithm: KeyAlgorithm::EcdsaP256,
        sans: vec![chainkeeper_core::San::Dns("api.example.test".to_owned())],
        ekus: Vec::new(),
        key_usages: vec![KeyUsage::DigitalSignature],
        issued_at: datetime!(2024-01-01 00:00:00 UTC),
        expires_at: datetime!(2025-01-01 00:00:00 UTC),
        path: PathBuf::from(format!("certificates/active/{serial}.pem")),
        revoked_at: None,
        revocation_reason: None,
        replaces: None,
    }
}

fn authority(request: &CreateAuthorityRequest) -> AuthorityRecord {
    AuthorityRecord {
        name: request.name.clone(),
        kind: request.kind,
        parent: request.parent.clone(),
        algorithm: request.algorithm,
        validity_days: request.validity_days,
        path_len: request.path_len,
        created_at: NOW,
        cert_path: PathBuf::from(format!("authorities/{}/cert.pem", request.name)),
        chain_path: PathBuf::from(format!("authorities/{}/chain.pem", request.name)),
    }
}

fn sample_tree() -> TreeReport {
    let tls = TreeNode {
        name: AuthorityName::new("tls").expect("name"),
        kind: AuthorityKind::Intermediate,
        expires_at: Some(NOW + Duration::days(3650)),
        children: Vec::new(),
    };
    TreeReport {
        roots: vec![TreeNode {
            name: AuthorityName::new("root").expect("name"),
            kind: AuthorityKind::Root,
            expires_at: Some(NOW + Duration::days(7300)),
            children: vec![
                tls,
                TreeNode {
                    name: AuthorityName::new("smime").expect("name"),
                    kind: AuthorityKind::Intermediate,
                    expires_at: Some(NOW + Duration::days(3650)),
                    children: Vec::new(),
                },
            ],
        }],
    }
}

fn sample_event() -> AuditEvent {
    AuditEvent {
        id: chainkeeper_core::EventId::new("01J00000000000000000000001").expect("event"),
        seq: 1,
        timestamp: NOW,
        action: chainkeeper_core::AuditAction::CertIssued,
        object_type: "certificate".to_owned(),
        object_id: "00AA".to_owned(),
        summary: "issued certificate 00AA".to_owned(),
        actor: "ck".to_owned(),
        details: Value::Null,
    }
}

fn index_report(moved: Vec<Serial>) -> IndexReport {
    IndexReport {
        generated_at: NOW,
        schema_version: chainkeeper_core::CONFIG_VERSION,
        stats: IndexStats::default(),
        moved,
    }
}
