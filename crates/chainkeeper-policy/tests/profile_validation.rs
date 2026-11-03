//! Profile structure rules.

mod common;

use chainkeeper_core::{ProfileName, ProfileRegistry};
use chainkeeper_policy::{DefaultProfileRegistry, validate_profile_structure};

#[test]
fn rejects_broken_profiles() {
    let base = common::builtin("tls-server");

    let mut wrong_version = base.clone();
    wrong_version.version = 2;

    let mut zero_validity = base.clone();
    zero_validity.validity_days = 0;

    let mut too_long = base.clone();
    too_long.validity_days = 398;

    let mut no_key_usage = base.clone();
    no_key_usage.key_usage.clear();

    let mut no_eku = base.clone();
    no_eku.eku.clear();

    let mut wrong_authority = base.clone();
    wrong_authority.authority =
        chainkeeper_core::AuthorityName::new("smime").expect("valid authority");

    let mut unknown_authority = base.clone();
    unknown_authority.name = ProfileName::new("custom").expect("valid name");
    unknown_authority.authority =
        chainkeeper_core::AuthorityName::new("other").expect("valid authority");

    let mut required_without_types = base;
    required_without_types.san_required = true;
    required_without_types.san_types.clear();

    let cases = [
        ("wrong version", wrong_version),
        ("zero validity", zero_validity),
        ("validity above 397", too_long),
        ("no key usage", no_key_usage),
        ("no eku", no_eku),
        ("name/authority mismatch", wrong_authority),
        ("unknown authority", unknown_authority),
        ("required san without types", required_without_types),
    ];

    for (label, profile) in cases {
        assert!(
            validate_profile_structure(&profile).is_err(),
            "{label} was accepted"
        );
    }
}

#[test]
fn accepts_valid_variants() {
    let base = common::builtin("tls-server");

    let mut no_san_requirement = base.clone();
    no_san_requirement.san_required = false;
    no_san_requirement.san_types.clear();
    assert!(validate_profile_structure(&no_san_requirement).is_ok());

    let mut custom_name = base;
    custom_name.name = ProfileName::new("custom-profile").expect("valid name");
    custom_name.authority = chainkeeper_core::AuthorityName::new("tls").expect("valid authority");
    assert!(validate_profile_structure(&custom_name).is_ok());
}

#[test]
fn registry_validation_matches_the_free_function() {
    let registry = DefaultProfileRegistry::defaults();
    for profile in registry.list() {
        assert!(registry.validate(&profile).is_ok());
        assert!(validate_profile_structure(&profile).is_ok());
    }

    let mut broken = common::builtin("codesign");
    broken.validity_days = 0;
    assert!(registry.validate(&broken).is_err());
    assert_eq!(
        registry.validate(&broken).expect_err("invalid").kind(),
        chainkeeper_core::ErrorKind::Profile
    );
}

#[test]
fn validity_boundary_is_397_days() {
    let mut profile = common::builtin("tls-server");
    profile.validity_days = 397;
    assert!(validate_profile_structure(&profile).is_ok());
    profile.validity_days = 398;
    assert!(validate_profile_structure(&profile).is_err());
}
