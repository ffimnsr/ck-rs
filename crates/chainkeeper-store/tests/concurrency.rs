//! Concurrent writer isolation tests.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chainkeeper_core::{CertificateStore as _, IndexStore as _, RepositoryLock as _, Serial};
use chainkeeper_store::FileRepositoryLock;

use common::{CertSpec, TestRepo};

#[test]
fn sixteen_concurrent_writers_lose_no_records() {
    let repo = Arc::new(TestRepo::new());
    let lock = Arc::new(FileRepositoryLock::new(repo.tenant.paths().clone()));
    let index = Arc::new(repo.index());
    let certificates: Vec<_> = (1..=16)
        .map(|number| {
            common::issued(&CertSpec::new(
                number,
                &format!("writer-{number}.example.test"),
            ))
        })
        .collect();

    let mut threads = Vec::new();
    for certificate in certificates {
        let store = repo.store.clone();
        let lock = Arc::clone(&lock);
        let index = Arc::clone(&index);
        threads.push(std::thread::spawn(move || {
            let _guard = lock
                .acquire_exclusive(Duration::from_secs(30))
                .expect("lock acquired");
            store
                .write_certificate(&certificate)
                .expect("certificate written");
            index
                .upsert_certificate(&certificate.record)
                .expect("certificate indexed");
        }));
    }
    for thread in threads {
        thread.join().expect("writer finished");
    }

    let listed = repo.store.list_certificates().expect("list");
    assert_eq!(listed.len(), 16);
    let unique: BTreeSet<Serial> = listed.into_iter().map(|record| record.serial).collect();
    assert_eq!(unique.len(), 16);

    let stats = chainkeeper_core::IndexStore::stats(&*index).expect("stats");
    assert_eq!(stats.certificates, 16);
}
