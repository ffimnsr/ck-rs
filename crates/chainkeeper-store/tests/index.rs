//! Index schema, rebuild, search, repair, and drift tests.

mod common;

use std::sync::Arc;
use std::time::Instant;

use chainkeeper_core::{
    AuditAction, AuditEvent, AuditQuery, AuthorityRecord, CertificateStatus, CertificateStore as _,
    CrlRecord, ErrorKind, EventId, IndexRecords, IndexStore as _, IndexedCrl, KeyAlgorithm,
    ProfileName, RevocationReason, RevocationRecord, San, SearchQuery, Serial,
};
use chainkeeper_store::SqliteIndex;
use chainkeeper_testkit::FakeClock;
use rusqlite::Connection;
use time::Duration;

use common::{CertSpec, TestRepo, now, record};

fn records_for(repo: &TestRepo) -> IndexRecords {
    let alpha = record(&CertSpec::new(1, "alpha.example.test").email("alpha@example.test"));
    let beta = record(
        &CertSpec::new(2, "beta.example.test").sans(vec![San::Dns("api.example.test".to_owned())]),
    );
    let revocation = RevocationRecord {
        version: 1,
        serial: beta.serial.clone(),
        authority: chainkeeper_core::AuthorityName::new("tls").expect("authority"),
        reason: RevocationReason::KeyCompromise,
        comment: Some("lost".to_owned()),
        revoked_at: now(),
        crl_number: 3,
    };
    let authority = AuthorityRecord::from_config(
        &repo.fixtures.root.material.config,
        "authorities/root/cert.pem".into(),
        "authorities/root/chain.pem".into(),
    );
    let profile = chainkeeper_core::builtin_profiles().remove(0);
    let audit = AuditEvent {
        id: EventId::new("01J00000000000000000000001").expect("id"),
        seq: 1,
        timestamp: now(),
        action: AuditAction::CertIssued,
        object_type: "certificate".to_owned(),
        object_id: "0001".to_owned(),
        summary: "issued".to_owned(),
        actor: "tester".to_owned(),
        details: serde_json::json!({"serial": "0001"}),
    };
    let crl = IndexedCrl {
        record: CrlRecord {
            version: 1,
            authority: chainkeeper_core::AuthorityName::new("tls").expect("authority"),
            number: 3,
            this_update: now(),
            next_update: now() + Duration::days(7),
            revoked_serials: vec![beta.serial.clone()],
            der_path: "crls/tls.crl.der".into(),
            pem_path: "crls/tls.crl.pem".into(),
        },
        sha256: "00".repeat(32),
    };

    IndexRecords {
        certificates: vec![alpha, beta],
        revocations: vec![revocation],
        authorities: vec![authority],
        profiles: vec![profile],
        crls: vec![crl],
        audit_events: vec![audit],
    }
}

fn file_index(path: &std::path::Path, clock: &Arc<FakeClock>) -> SqliteIndex {
    SqliteIndex::open_with_clock(path, clock.clone()).expect("index opens")
}

#[test]
fn migrations_create_tables_and_reopening_is_idempotent() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("cache").join("index.sqlite");
    let clock = Arc::new(FakeClock::new(now()));
    let index = file_index(&path, &clock);
    assert_eq!(
        chainkeeper_core::IndexStore::schema_version(&index).expect("version"),
        1
    );

    let connection = Connection::open(&path).expect("open sqlite");
    for table in [
        "meta",
        "certificates",
        "revocations",
        "intermediates",
        "profiles",
        "audit_events",
        "crls",
        "certificates_fts",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [table],
                |row| row.get(0),
            )
            .expect("query");
        assert_eq!(count, 1, "{table}");
    }
    drop(connection);
    drop(index);

    let reopened = file_index(&path, &clock);
    assert_eq!(
        chainkeeper_core::IndexStore::schema_version(&reopened).expect("version"),
        1
    );
}

#[test]
fn newer_schema_versions_are_rejected() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("index.sqlite");
    let clock = Arc::new(FakeClock::new(now()));
    let index = file_index(&path, &clock);
    drop(index);
    let connection = Connection::open(&path).expect("open");
    connection
        .execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '99')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )
        .expect("write version");
    drop(connection);

    let error = SqliteIndex::open_with_clock(&path, clock).expect_err("newer version");
    assert_eq!(error.kind(), ErrorKind::Index);
}

#[test]
fn rebuild_is_reproducible_after_deleting_the_database() {
    let repo = TestRepo::new();
    let records = records_for(&repo);
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("index.sqlite");
    let clock = Arc::new(FakeClock::new(now()));

    let index = file_index(&path, &clock);
    index.rebuild(&records).expect("first rebuild");
    let first_all = index.query(&SearchQuery::default()).expect("query");
    let first_revoked = index
        .query(&SearchQuery {
            status: Some(CertificateStatus::Revoked),
            ..SearchQuery::default()
        })
        .expect("query");
    let first_audit = index.list_audit(&AuditQuery::default()).expect("audit");
    let first_stats = chainkeeper_core::IndexStore::stats(&index).expect("stats");
    assert_eq!(first_stats.certificates, 2);
    assert_eq!(first_stats.revocations, 1);
    assert_eq!(first_stats.authorities, 1);
    assert_eq!(first_stats.audit_events, 1);

    drop(index);
    std::fs::remove_file(&path).expect("remove index");
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }

    let rebuilt = file_index(&path, &clock);
    rebuilt.rebuild(&records).expect("second rebuild");
    assert_eq!(
        rebuilt.query(&SearchQuery::default()).expect("query"),
        first_all
    );
    assert_eq!(
        rebuilt
            .query(&SearchQuery {
                status: Some(CertificateStatus::Revoked),
                ..SearchQuery::default()
            })
            .expect("query"),
        first_revoked
    );
    assert_eq!(
        rebuilt.list_audit(&AuditQuery::default()).expect("audit"),
        first_audit
    );
    assert_eq!(
        chainkeeper_core::IndexStore::stats(&rebuilt).expect("stats"),
        first_stats
    );
}

#[test]
fn index_upserts_mark_revocations_and_keep_search_working() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let certificate = record(&CertSpec::new(5, "revocable.example.test"));
    index.upsert_certificate(&certificate).expect("cert");
    let revocation = RevocationRecord {
        version: 1,
        serial: certificate.serial.clone(),
        authority: certificate.authority.clone(),
        reason: RevocationReason::AffiliationChanged,
        comment: None,
        revoked_at: now(),
        crl_number: 1,
    };
    index.upsert_revocation(&revocation).expect("revocation");

    let revoked = index
        .query(&SearchQuery {
            status: Some(CertificateStatus::Revoked),
            ..SearchQuery::default()
        })
        .expect("query");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].serial, certificate.serial);
    assert_eq!(
        revoked[0].revocation_reason,
        Some(RevocationReason::AffiliationChanged)
    );

    let text = index
        .query(&SearchQuery {
            text: Some("revocable".to_owned()),
            ..SearchQuery::default()
        })
        .expect("query");
    assert_eq!(text.len(), 1);
}

#[allow(clippy::too_many_lines)]
#[test]
fn search_matches_cn_email_san_status_profile_authority_and_expiry() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let certificates = vec![
        record(&CertSpec::new(1, "leaf.example.test").email("alice@example.test")),
        record(
            &CertSpec::new(2, "api.example.test")
                .profile("tls-client")
                .sans(vec![San::Dns("api.internal.test".to_owned())]),
        ),
        record(&CertSpec::new(3, "expired.example.test").days(-1)),
        record(
            &CertSpec::new(4, "soon.example.test")
                .days(10)
                .authority("smime"),
        ),
        record(&CertSpec::new(5, "later.example.test").days(40)),
        record(&CertSpec::new(6, "revoked.example.test").revoked_at(now())),
    ];
    index
        .rebuild(&IndexRecords {
            certificates,
            ..IndexRecords::default()
        })
        .expect("rebuild");

    assert_eq!(index.count(&SearchQuery::default()).expect("count"), 6);

    let query = |query: SearchQuery| index.query(&query).expect("query");
    let serials = |records: &[chainkeeper_core::CertificateRecord]| {
        records
            .iter()
            .map(|record| record.serial.to_string())
            .collect::<Vec<_>>()
    };

    assert_eq!(
        serials(&query(SearchQuery {
            text: Some("leaf".to_owned()),
            ..SearchQuery::default()
        })),
        vec!["0001"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            text: Some("alice".to_owned()),
            ..SearchQuery::default()
        })),
        vec!["0001"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            text: Some("internal".to_owned()),
            ..SearchQuery::default()
        })),
        vec!["0002"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            status: Some(CertificateStatus::Active),
            ..SearchQuery::default()
        })),
        vec!["0004", "0005", "0001", "0002"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            profile: Some(ProfileName::new("tls-client").expect("profile")),
            ..SearchQuery::default()
        })),
        vec!["0002"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            authority: Some(chainkeeper_core::AuthorityName::new("smime").expect("authority")),
            ..SearchQuery::default()
        })),
        vec!["0004"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            expires_within_days: Some(30),
            ..SearchQuery::default()
        })),
        vec!["0004"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            expires_within_days: Some(30),
            include_expired: true,
            ..SearchQuery::default()
        })),
        vec!["0003", "0004"]
    );
    assert_eq!(
        serials(&query(SearchQuery {
            limit: Some(2),
            offset: 1,
            ..SearchQuery::default()
        })),
        vec!["0004", "0005"]
    );
    assert_eq!(
        query(SearchQuery {
            text: Some("leaf".to_owned()),
            limit: Some(0),
            ..SearchQuery::default()
        })
        .len(),
        0
    );
}

#[test]
fn offset_beyond_the_maximum_is_rejected() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let error = index
        .query(&SearchQuery {
            offset: 1_000_001,
            ..SearchQuery::default()
        })
        .expect_err("too large");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn repair_moves_expired_certificates_without_touching_contents() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(9, "soon.example.test").days(10);
    let issued = common::issued(&spec);
    let active_pem = repo.store.write_certificate(&issued).expect("write");
    let before = std::fs::read(&active_pem).expect("read pem");

    repo.clock.advance(Duration::days(20));
    let index = repo.index();
    let report = index.repair(&repo.store).expect("repair");
    assert_eq!(report.moved, vec![spec.serial()]);
    assert!(!active_pem.is_file());
    let expired_pem = repo
        .tenant
        .paths()
        .certificate_path_in(CertificateStatus::Expired, &spec.serial(), "pem")
        .expect("path");
    assert!(expired_pem.is_file());
    assert_eq!(std::fs::read(&expired_pem).expect("read"), before);

    let expired = index
        .query(&SearchQuery {
            status: Some(CertificateStatus::Expired),
            ..SearchQuery::default()
        })
        .expect("query");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].serial, spec.serial());
}

#[test]
fn corrupt_metadata_reports_the_path_and_line() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(11, "broken.example.test");
    repo.store
        .write_certificate(&common::issued(&spec))
        .expect("write");
    let metadata = repo
        .tenant
        .paths()
        .certificate_path(&spec.serial(), "yaml")
        .expect("path");
    std::fs::write(&metadata, "serial: []\n").expect("corrupt");

    let error = repo.store.load_index_records().expect_err("corrupt");
    let message = error.to_string();
    assert!(
        message.contains(&metadata.display().to_string()),
        "{message}"
    );
    assert!(message.contains("line"), "{message}");
}

#[test]
fn drift_reports_missing_extra_and_mismatched_rows() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let first = record(&CertSpec::new(1, "first.example.test"));
    let second = record(&CertSpec::new(2, "second.example.test"));
    index
        .rebuild(&IndexRecords {
            certificates: vec![first, second],
            ..IndexRecords::default()
        })
        .expect("rebuild");

    let changed = record(&CertSpec::new(1, "changed.example.test"));
    let added = record(&CertSpec::new(3, "added.example.test"));
    let findings = index
        .drift(&IndexRecords {
            certificates: vec![changed, added],
            ..IndexRecords::default()
        })
        .expect("drift");

    let mut codes: Vec<(String, String)> = findings
        .into_iter()
        .map(|finding| (finding.code, finding.object_id.unwrap_or_default()))
        .collect();
    codes.sort();
    assert_eq!(
        codes,
        vec![
            ("IDX_EXTRA".to_owned(), "0002".to_owned()),
            ("IDX_HASH_MISMATCH".to_owned(), "0001".to_owned()),
            ("IDX_MISSING".to_owned(), "0003".to_owned()),
        ]
    );
}

#[test]
fn breakdown_counts_by_status_profile_authority_and_algorithm() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let records = vec![
        record(&CertSpec::new(1, "one.example.test")),
        record(&CertSpec::new(2, "two.example.test").profile("tls-client")),
        record(
            &CertSpec::new(3, "three.example.test")
                .authority("smime")
                .profile("smime"),
        ),
    ];
    index
        .rebuild(&IndexRecords {
            certificates: records,
            ..IndexRecords::default()
        })
        .expect("rebuild");
    let breakdown = index.breakdown().expect("breakdown");
    assert_eq!(breakdown.totals.certificates, 3);
    assert_eq!(breakdown.by_status.get("active"), Some(&3));
    assert_eq!(breakdown.by_profile.get("tls-server"), Some(&1));
    assert_eq!(breakdown.by_profile.get("tls-client"), Some(&1));
    assert_eq!(breakdown.by_authority.get("smime"), Some(&1));
    assert_eq!(
        breakdown.by_algorithm.get(KeyAlgorithm::EcdsaP256.as_str()),
        Some(&3)
    );
}

#[test]
fn searching_one_thousand_certificates_is_fast() {
    let index =
        SqliteIndex::open_in_memory_with_clock(Arc::new(FakeClock::new(now()))).expect("index");
    let certificates: Vec<_> = (1..=1000)
        .map(|number| {
            record(&CertSpec::new(
                number,
                &format!("host-{number}.example.test"),
            ))
        })
        .collect();
    index
        .rebuild(&IndexRecords {
            certificates,
            ..IndexRecords::default()
        })
        .expect("rebuild");

    let started = Instant::now();
    let found = index
        .query(&SearchQuery {
            text: Some("host-999.example.test".to_owned()),
            ..SearchQuery::default()
        })
        .expect("query");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].serial, Serial::new("03E7").expect("serial"));
}
