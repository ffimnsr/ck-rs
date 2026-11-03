mod common;

use std::path::Path;
use std::sync::Arc;

use chainkeeper_core::{ChainkeeperError, PublishBuilder, PublishManifest, PublishOptions};
use chainkeeper_publish::{FileCrlManager, refresh_after_revocation};
use common::{Harness, TestSigners, leaf_serial, tls};

#[derive(Debug)]
struct FailingPublisher;

impl PublishBuilder for FailingPublisher {
    fn build(&self, _options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        Err(ChainkeeperError::publish("injected publish failure"))
    }

    fn validate_publish_dir(&self, _path: &Path) -> Result<(), ChainkeeperError> {
        Ok(())
    }
}

fn manager(h: &Harness) -> FileCrlManager {
    h.crl_manager(Arc::new(TestSigners))
}

#[test]
fn refresh_without_publish_directory_only_changes_crls() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let publish_dir = h.paths().publish_dir();
    std::fs::remove_dir(&publish_dir).expect("remove publish dir");

    let manager = manager(&h);
    let publisher = h.publisher();
    let changed = refresh_after_revocation(
        &authority,
        &manager,
        Some(&publisher),
        &publish_dir,
        h.paths(),
    )
    .expect("refresh succeeds");

    assert_eq!(changed.len(), 4);
    assert!(
        changed
            .iter()
            .all(|path| path.starts_with(h.paths().crls_dir()))
    );
    assert!(!publish_dir.exists());
    assert!(
        h.paths()
            .crl_path(&authority, "crl.der")
            .expect("path")
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(h.paths().crl_number_path(&authority)).expect("number"),
        "1\n"
    );
}

#[test]
fn refresh_with_publish_directory_rebuilds_artifacts() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let publish_dir = h.paths().publish_dir();
    let manager = manager(&h);
    let publisher = h.publisher();

    let changed = refresh_after_revocation(
        &authority,
        &manager,
        Some(&publisher),
        &publish_dir,
        h.paths(),
    )
    .expect("refresh succeeds");

    assert!(publish_dir.join("root.pem").is_file());
    assert!(publish_dir.join("chains/tls-server/000A.pem").is_file());
    assert!(publish_dir.join("crl/tls.crl").is_file());
    assert!(
        changed
            .iter()
            .any(|path| path == &publish_dir.join("crl/tls.crl"))
    );
    assert!(
        changed
            .iter()
            .any(|path| path == &publish_dir.join("chains/tls-server/000A.pem"))
    );
}

#[test]
fn second_refresh_reports_changed_crl_artifacts() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let publish_dir = h.paths().publish_dir();
    let manager = manager(&h);
    let publisher = h.publisher();

    refresh_after_revocation(
        &authority,
        &manager,
        Some(&publisher),
        &publish_dir,
        h.paths(),
    )
    .expect("first refresh");
    h.revoke(&leaf_serial().expect("serial"), &authority)
        .expect("revocation");

    let changed = refresh_after_revocation(
        &authority,
        &manager,
        Some(&publisher),
        &publish_dir,
        h.paths(),
    )
    .expect("second refresh");

    assert!(
        changed
            .iter()
            .any(|path| path == &publish_dir.join("crl/tls.crl"))
    );
    assert!(
        changed
            .iter()
            .any(|path| path == &publish_dir.join("crl/tls.crl.pem"))
    );
    assert_eq!(
        std::fs::read_to_string(h.paths().crl_number_path(&authority)).expect("number"),
        "2\n"
    );
}

#[test]
fn publish_failure_leaves_regenerated_crl_in_place() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let publish_dir = h.paths().publish_dir();
    let manager = manager(&h);
    let publisher = FailingPublisher;

    let error = refresh_after_revocation(
        &authority,
        &manager,
        Some(&publisher),
        &publish_dir,
        h.paths(),
    )
    .expect_err("publish failure returned");
    assert!(matches!(error, ChainkeeperError::Publish(_)));

    assert!(
        h.paths()
            .crl_path(&authority, "crl.der")
            .expect("path")
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(h.paths().crl_number_path(&authority)).expect("number"),
        "1\n"
    );
    assert!(!publish_dir.join("root.pem").exists());
}
