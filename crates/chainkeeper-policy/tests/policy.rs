//! Policy defaults and limits.

mod common;

use chainkeeper_core::{KeyAlgorithm, Policy, builtin_profile_names};
use chainkeeper_policy::{
    DEFAULT_POLICY_YAML, default_policy, default_profiles, normalized_san_suffixes, validate_policy,
};

#[test]
fn default_policy_matches_the_decision_matrix() {
    let policy = default_policy();
    assert_eq!(policy.version, chainkeeper_core::CONFIG_VERSION);
    assert_eq!(policy.max_validity_days, 397);
    assert_eq!(policy.allowed_algorithms, KeyAlgorithm::ALL.to_vec());
    assert_eq!(policy.allowed_profiles, builtin_profile_names());
    assert!(policy.allow_custom_oid);
    assert!(!policy.allow_wildcards);
    assert_eq!(policy.max_sans, 100);
    assert_eq!(policy.allowed_san_suffixes, Vec::<String>::new());
    assert!(policy.cn_must_match_san);
    assert!(!policy.allow_critical_custom_oid);
}

#[test]
fn default_policy_yaml_matches_the_type_default() {
    let parsed: Policy = serde_yaml_ng::from_str(DEFAULT_POLICY_YAML).expect("policy parses");
    assert_eq!(parsed, Policy::default());
    assert_eq!(parsed, default_policy());
}

#[test]
fn default_profiles_are_all_allowed() {
    let policy = default_policy();
    for profile in default_profiles() {
        assert!(
            policy.permits_profile(&profile.name),
            "{} is not allowed",
            profile.name
        );
    }
}

#[test]
fn rejects_out_of_range_limits() {
    let base = common::base_policy();

    let cases = [
        (
            "zero validity",
            Policy {
                max_validity_days: 0,
                ..base.clone()
            },
        ),
        (
            "validity above 397",
            Policy {
                max_validity_days: 398,
                ..base.clone()
            },
        ),
        (
            "no algorithms",
            Policy {
                allowed_algorithms: Vec::new(),
                ..base.clone()
            },
        ),
        (
            "no profiles",
            Policy {
                allowed_profiles: Vec::new(),
                ..base.clone()
            },
        ),
        (
            "zero max sans",
            Policy {
                max_sans: 0,
                ..base.clone()
            },
        ),
        (
            "max sans above 1000",
            Policy {
                max_sans: 1001,
                ..base
            },
        ),
    ];

    for (label, policy) in cases {
        assert!(validate_policy(&policy).is_err(), "{label} was accepted");
    }
}

#[test]
fn accepts_limit_boundaries() {
    let mut policy = common::base_policy();
    policy.max_validity_days = 397;
    policy.max_sans = 1000;
    assert!(validate_policy(&policy).is_ok());

    policy.max_validity_days = 1;
    policy.max_sans = 1;
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn normalizes_san_suffixes() {
    let mut policy = common::base_policy();
    policy.allowed_san_suffixes = vec!["Example.COM".to_owned(), "corp.example.com".to_owned()];
    assert_eq!(
        normalized_san_suffixes(&policy).expect("valid suffixes"),
        vec!["example.com".to_owned(), "corp.example.com".to_owned()]
    );
    assert!(validate_policy(&policy).is_ok());
}

#[test]
fn rejects_malformed_san_suffixes() {
    for suffix in [
        "",
        ".example.com",
        "example.com.",
        "example..com",
        "exa mple.com",
        "*.example.com",
        "-example.com",
        "example-.com",
        "example_com",
    ] {
        let policy = Policy {
            allowed_san_suffixes: vec![suffix.to_owned()],
            ..common::base_policy()
        };
        assert!(validate_policy(&policy).is_err(), "{suffix:?} was accepted");
    }
}
