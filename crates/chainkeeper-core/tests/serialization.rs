//! Serialization contracts for configuration and record types.

use std::fmt::Debug;
use std::path::PathBuf;

use chainkeeper_core::{
    AuditEvent, AuditQuery, AuthorityConfig, AuthorityKind, AuthorityName, AuthorityRecord,
    CONFIG_VERSION, CertificateRecord, CrlRecord, DoctorFinding, DoctorReport, EventId, GitChange,
    GitChangeKind, GitStatus, IndexStats, KeyAlgorithm, KeyUsage, NewAuditEvent,
    PUBLISH_MANIFEST_VERSION, Policy, ProfileName, PublishArtifact, PublishManifest,
    RevocationReason, RevocationRecord, SearchQuery, Serial, ServerHealth, Severity, SubjectName,
    TenantConfig, TenantId, builtin_profiles,
};
use chainkeeper_testkit::CertificateFixtures;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use time::OffsetDateTime;
use time::macros::datetime;

const fn now() -> OffsetDateTime {
    datetime!(2024-05-01 12:00:00 UTC)
}

fn tenant_config() -> TenantConfig {
    TenantConfig {
        version: CONFIG_VERSION,
        tenant_id: TenantId::new("corp-a").expect("valid"),
        display_name: "Corp A".to_owned(),
        created_at: now(),
        default_profile: ProfileName::new("tls-server").expect("valid"),
        ocsp_url: Some("https://ocsp.example.test".to_owned()),
        ca_issuers_url_template: Some("https://pki.example.test/{authority}/ca.pem".to_owned()),
        crl_url_template: Some("https://pki.example.test/{authority}/crl.pem".to_owned()),
    }
}

fn authority_config() -> AuthorityConfig {
    AuthorityConfig::new(
        AuthorityName::new("root").expect("valid"),
        AuthorityKind::Root,
        None,
        KeyAlgorithm::EcdsaP256,
        7300,
        2,
        vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        now(),
    )
}

fn revocation_record() -> RevocationRecord {
    RevocationRecord {
        version: CONFIG_VERSION,
        serial: Serial::new("00FF").expect("valid"),
        authority: AuthorityName::new("tls").expect("valid"),
        reason: RevocationReason::KeyCompromise,
        comment: Some("key lost".to_owned()),
        revoked_at: now(),
        crl_number: 7,
    }
}

fn audit_event() -> AuditEvent {
    AuditEvent::from_new(
        NewAuditEvent::new(
            now(),
            chainkeeper_core::AuditAction::CertIssued,
            "certificate",
            "00FF",
            "issued certificate",
            "tester",
        )
        .with_details(json!({"profile": "tls-server"})),
        EventId::new("01J00000000000000000000001").expect("valid"),
        1,
    )
}

fn authority_record() -> AuthorityRecord {
    AuthorityRecord::from_config(
        &authority_config(),
        PathBuf::from("authorities/root/cert.pem"),
        PathBuf::from("authorities/root/chain.pem"),
    )
}

fn crl_record() -> CrlRecord {
    CrlRecord {
        version: CONFIG_VERSION,
        authority: AuthorityName::new("tls").expect("valid"),
        number: 3,
        this_update: now(),
        next_update: now() + time::Duration::days(7),
        revoked_serials: vec![Serial::new("00FF").expect("valid")],
        der_path: PathBuf::from("crls/tls.crl.der"),
        pem_path: PathBuf::from("crls/tls.crl.pem"),
    }
}

fn git_status() -> GitStatus {
    GitStatus {
        branch: Some("main".to_owned()),
        head: Some("a".repeat(40)),
        clean: false,
        changes: vec![GitChange {
            path: PathBuf::from("certificates/active/00FF.pem"),
            kind: GitChangeKind::Added,
        }],
        untracked: Vec::new(),
    }
}

fn publish_manifest() -> PublishManifest {
    PublishManifest {
        version: PUBLISH_MANIFEST_VERSION,
        generated_at: now(),
        source_commit: Some("a".repeat(40)),
        tenant_id: TenantId::new("corp-a").expect("valid"),
        artifacts: vec![PublishArtifact {
            path: PathBuf::from("root.pem"),
            sha256: "0".repeat(64),
            bytes: 512,
        }],
    }
}

fn assert_round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let yaml = serde_yaml_ng::to_string(value).expect("yaml serialization");
    let from_yaml: T = serde_yaml_ng::from_str(&yaml).expect("yaml deserialization");
    assert_eq!(&from_yaml, value, "yaml round trip failed for {value:?}");

    let json = serde_json::to_string(value).expect("json serialization");
    let from_json: T = serde_json::from_str(&json).expect("json deserialization");
    assert_eq!(&from_json, value, "json round trip failed for {value:?}");
}

#[test]
fn config_and_record_types_round_trip() {
    let fixtures = CertificateFixtures::generate(now()).expect("fixtures");
    assert_round_trip(&tenant_config());
    assert_round_trip(&Policy::default());
    assert_round_trip(&builtin_profiles().remove(0));
    assert_round_trip(&authority_config());
    assert_round_trip(&fixtures.leaf.record);
    assert_round_trip(&revocation_record());
    assert_round_trip(&audit_event());
    assert_round_trip(&authority_record());
    assert_round_trip(&crl_record());
    assert_round_trip(&git_status());
    assert_round_trip(&IndexStats::default());
    assert_round_trip(&SearchQuery::default());
    assert_round_trip(&AuditQuery::default());
    assert_round_trip(&publish_manifest());
    assert_round_trip(&ServerHealth::ok("a".repeat(40), true));
}

#[test]
fn timestamps_are_rfc3339_utc_with_second_precision() {
    let fixtures = CertificateFixtures::generate(now()).expect("fixtures");
    let yaml = serde_yaml_ng::to_string(&fixtures.leaf.record).expect("yaml");
    assert!(yaml.contains("2024-05-01T12:00:00Z"), "{yaml}");
    assert!(!yaml.contains(".123"), "{yaml}");
}

#[test]
fn yaml_configs_reject_unknown_fields() {
    let mut tenant = serde_yaml_ng::to_string(&tenant_config()).expect("yaml");
    tenant.push_str("unexpected_field: true\n");
    assert!(serde_yaml_ng::from_str::<TenantConfig>(&tenant).is_err());

    let mut policy = serde_yaml_ng::to_string(&Policy::default()).expect("yaml");
    policy.push_str("unexpected_field: true\n");
    assert!(serde_yaml_ng::from_str::<Policy>(&policy).is_err());

    let mut profile = serde_yaml_ng::to_string(&builtin_profiles().remove(0)).expect("yaml");
    profile.push_str("unexpected_field: true\n");
    assert!(serde_yaml_ng::from_str::<chainkeeper_core::Profile>(&profile).is_err());

    let mut authority = serde_yaml_ng::to_string(&authority_config()).expect("yaml");
    authority.push_str("unexpected_field: true\n");
    assert!(serde_yaml_ng::from_str::<AuthorityConfig>(&authority).is_err());
}

#[test]
fn unsupported_config_version_is_rejected() {
    let mut config = tenant_config();
    config.version = CONFIG_VERSION + 1;
    assert!(config.validate().is_err());

    let policy = Policy {
        version: CONFIG_VERSION + 1,
        ..Policy::default()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn identifiers_reject_invalid_values_on_deserialize() {
    let yaml = "version: 1\nserial: \"../etc/passwd\"\nauthority: tls\nreason: unspecified\nrevoked_at: 2024-05-01T12:00:00Z\ncrl_number: 1\n";
    assert!(serde_yaml_ng::from_str::<RevocationRecord>(yaml).is_err());
}

#[test]
fn doctor_report_ordering_fields_round_trip() {
    let report = DoctorReport {
        healthy: false,
        checked_at: now(),
        findings: vec![DoctorFinding {
            code: "CRL_STALE".to_owned(),
            severity: Severity::Warning,
            message: "CRL next update has passed".to_owned(),
            object_id: Some("tls".to_owned()),
        }],
    };
    assert_round_trip(&report);
}

#[test]
fn subject_names_reject_unknown_fields() {
    let mut subject = serde_yaml_ng::to_string(&SubjectName::new("example.test")).expect("yaml");
    subject.push_str("unexpected_field: true\n");
    assert!(serde_yaml_ng::from_str::<SubjectName>(&subject).is_err());
}

#[test]
fn certificate_record_status_uses_serialized_times() {
    let record: CertificateRecord = serde_json::from_str(
        r#"{
            "serial": "00FF",
            "subject": {"cn": "example.test"},
            "issuer": "CN=Root",
            "profile": "tls-server",
            "authority": "tls",
            "algorithm": "ecdsa-p256",
            "sans": [{"type": "dns", "value": "example.test"}],
            "ekus": ["serverAuth"],
            "key_usages": ["digitalSignature"],
            "issued_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-06-01T00:00:00Z",
            "path": "certificates/active/00FF.pem"
        }"#,
    )
    .expect("record deserializes");
    assert_eq!(
        record.status(datetime!(2024-05-01 00:00:00 UTC)),
        chainkeeper_core::CertificateStatus::Active
    );
    assert_eq!(
        record.status(datetime!(2024-07-01 00:00:00 UTC)),
        chainkeeper_core::CertificateStatus::Expired
    );
}
