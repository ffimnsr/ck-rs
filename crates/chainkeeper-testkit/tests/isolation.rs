//! Isolation tests for [`TempTenant`].

use chainkeeper_testkit::TempTenant;

fn spawn_tenant() -> TempTenant {
    let tenant = TempTenant::new().expect("temp tenant");
    let root = tenant.root();
    for required in tenant.paths().required_directories() {
        assert!(
            required.starts_with(root),
            "{} escaped {}",
            required.display(),
            root.display()
        );
        assert!(required.is_dir(), "{} is missing", required.display());
    }
    tenant
}

#[test]
fn temp_tenants_use_disjoint_roots() {
    let first = std::thread::spawn(spawn_tenant);
    let second = std::thread::spawn(spawn_tenant);

    let first = first.join().expect("first worker");
    let second = second.join().expect("second worker");

    assert_ne!(first.root(), second.root());
    assert_ne!(first.paths().index_path(), second.paths().index_path());
}

#[test]
fn layout_contains_every_documented_directory() {
    let tenant = TempTenant::new().expect("temp tenant");
    let paths = tenant.paths();
    assert!(paths.profiles_dir().is_dir());
    assert!(paths.authorities_dir().is_dir());
    assert!(paths.revocations_dir().is_dir());
    assert!(paths.crls_dir().is_dir());
    assert!(paths.audit_events_dir().is_dir());
    assert!(paths.publish_dir().is_dir());
    assert!(paths.cache_dir().is_dir());
    assert!(paths.state_dir().is_dir());
}
