//! Issuance validation rules.

mod common;

use chainkeeper_core::{
    ChainkeeperError, CustomExtension, IssueRequest, KeyAlgorithm, Policy, ProfileName, San,
    SanType, SubjectName,
};
use chainkeeper_policy::{IssueContext, PolicyValidator};

fn dns(value: &str) -> San {
    San::Dns(value.to_owned())
}

#[test]
fn valid_tls_request_passes() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let request = common::dns_request("tls-server", "example.com");
    common::validate(&policy, &profile, &request).expect("request is valid");
}

#[test]
fn request_profile_must_match_resolved_profile() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-client");
    let request = common::dns_request("tls-server", "example.com");
    assert!(common::validate(&policy, &profile, &request).is_err());
}

#[test]
fn profile_must_be_allowed_by_policy() {
    let mut policy = common::base_policy();
    policy
        .allowed_profiles
        .retain(|name| name.as_str() != "tls-server");
    let profile = common::builtin("tls-server");
    let request = common::dns_request("tls-server", "example.com");
    let error = common::validate(&policy, &profile, &request).expect_err("profile denied");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Policy);
}

#[test]
fn algorithm_rules_cover_default_and_override() {
    let profile = common::builtin("tls-server");
    let request = common::dns_request("tls-server", "example.com");

    let mut policy = common::base_policy();
    policy.allowed_algorithms = vec![KeyAlgorithm::EcdsaP256];
    common::validate(&policy, &profile, &request).expect("profile algorithm is allowed");

    let override_request = IssueRequest {
        algorithm: Some(KeyAlgorithm::Ed25519),
        ..request.clone()
    };
    assert!(common::validate(&policy, &profile, &override_request).is_err());

    policy.allowed_algorithms = vec![KeyAlgorithm::Ed25519];
    assert!(common::validate(&policy, &profile, &request).is_err());

    let allowed_override = IssueRequest {
        algorithm: Some(KeyAlgorithm::Ed25519),
        ..request
    };
    // The profile algorithm must stay allowed even when the request overrides it.
    assert!(common::validate(&policy, &profile, &allowed_override).is_err());

    policy.allowed_algorithms = vec![KeyAlgorithm::EcdsaP256, KeyAlgorithm::Ed25519];
    common::validate(&policy, &profile, &allowed_override).expect("override is allowed");
}

#[test]
fn validity_rules_cover_requests_and_issuer_lifetime() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let request = common::dns_request("tls-server", "example.com");

    for days in [1, 90, 397] {
        let valid = IssueRequest {
            validity_days: Some(days),
            ..request.clone()
        };
        common::validate(&policy, &profile, &valid).expect("validity is within policy");
    }

    for days in [0, 398] {
        let invalid = IssueRequest {
            validity_days: Some(days),
            ..request.clone()
        };
        assert!(
            common::validate(&policy, &profile, &invalid).is_err(),
            "validity {days} was accepted"
        );
    }

    let mut short_issuer = common::base_policy();
    short_issuer.max_validity_days = 397;
    let context = IssueContext::with_issuer_remaining_days(30);

    let within = IssueRequest {
        validity_days: Some(30),
        ..request.clone()
    };
    PolicyValidator::validate_issue_with(&short_issuer, &profile, &within, context)
        .expect("validity fits the issuer");

    let beyond = IssueRequest {
        validity_days: Some(31),
        ..request
    };
    let error = PolicyValidator::validate_issue_with(&short_issuer, &profile, &beyond, context)
        .expect_err("validity exceeds the issuer");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Policy);
}

#[test]
fn validity_uses_profile_default_when_request_is_silent() {
    let mut policy = common::base_policy();
    policy.max_validity_days = 90;
    let mut profile = common::builtin("tls-server");
    profile.validity_days = 397;
    let request = common::dns_request("tls-server", "example.com");
    assert!(common::validate(&policy, &profile, &request).is_err());

    profile.validity_days = 90;
    common::validate(&policy, &profile, &request).expect("profile validity fits");
}

#[test]
fn subject_rules_cover_cn_country_and_email() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");

    let mut empty_cn = common::dns_request("tls-server", "example.com");
    empty_cn.subject.cn.clear();
    assert!(common::validate(&policy, &profile, &empty_cn).is_err());

    for country in ["us", "USA", "1A", " U"] {
        let mut request = common::dns_request("tls-server", "example.com");
        request.subject.country = Some(country.to_owned());
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "country {country:?} was accepted"
        );
    }

    let mut valid_country = common::dns_request("tls-server", "example.com");
    valid_country.subject.country = Some("US".to_owned());
    common::validate(&policy, &profile, &valid_country).expect("US is valid");

    for email in ["", "user", "@example.com", "user@", "a@b@c"] {
        let mut request = common::dns_request("tls-server", "example.com");
        request.subject.email = Some(email.to_owned());
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "email {email:?} was accepted"
        );
    }

    let mut valid_email = common::dns_request("tls-server", "example.com");
    valid_email.subject.email = Some("user@example.com".to_owned());
    common::validate(&policy, &profile, &valid_email).expect("email is valid");
}

#[test]
fn san_count_and_requiredness_are_enforced() {
    let profile = common::builtin("tls-server");

    let mut policy = common::base_policy();
    policy.max_sans = 1;
    let two_sans = common::request_with(
        "tls-server",
        "example.com",
        vec![dns("example.com"), dns("www.example.com")],
    );
    assert!(common::validate(&policy, &profile, &two_sans).is_err());

    let single = common::dns_request("tls-server", "example.com");
    common::validate(&policy, &profile, &single).expect("one SAN fits max_sans");

    let missing = common::request_with("tls-server", "example.com", Vec::new());
    assert!(common::validate(&common::base_policy(), &profile, &missing).is_err());

    let mut codesign_policy = common::base_policy();
    codesign_policy.cn_must_match_san = false;
    let codesign = common::builtin("codesign");
    let no_san = common::request_with("codesign", "Release Signer", Vec::new());
    common::validate(&codesign_policy, &codesign, &no_san).expect("codesign does not need SANs");
}

#[test]
fn san_types_must_match_the_profile() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let email = common::request_with(
        "tls-server",
        "example.com",
        vec![San::Email("user@example.com".to_owned())],
    );
    assert!(common::validate(&policy, &profile, &email).is_err());

    let client = common::builtin("tls-client");
    let client_request = common::request_with(
        "tls-client",
        "user@example.com",
        vec![San::Email("user@example.com".to_owned())],
    );
    common::validate(&policy, &client, &client_request).expect("tls-client accepts email SANs");
}

#[test]
fn dns_names_are_validated() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let long_label = "a".repeat(64);
    let long_name = format!("{}.com", "a".repeat(250));

    for name in [
        "Example.com",
        "exa mple.com",
        "example..com",
        ".example.com",
        "example.com.",
        "-example.com",
        "example-.com",
        "under_score.example",
        long_label.as_str(),
        long_name.as_str(),
    ] {
        let request = common::dns_request("tls-server", name);
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "{name:?} was accepted"
        );
    }
}

#[test]
fn wildcard_rules_are_enforced() {
    let profile = common::builtin("tls-server");

    let mut allowed = common::base_policy();
    allowed.allow_wildcards = true;
    let wildcard = common::dns_request("tls-server", "*.example.com");
    common::validate(&allowed, &profile, &wildcard).expect("wildcard is enabled");

    let denied = common::base_policy();
    assert!(common::validate(&denied, &profile, &wildcard).is_err());

    for name in ["*", "a.*.example.com", "**.example.com"] {
        let request = common::dns_request("tls-server", name);
        assert!(
            common::validate(&allowed, &profile, &request).is_err(),
            "{name:?} was accepted"
        );
    }

    let mut codesign_policy = common::base_policy();
    codesign_policy.allow_wildcards = true;
    codesign_policy.cn_must_match_san = false;
    let codesign = common::builtin("codesign");
    let codesign_request = common::request_with("codesign", "signer", vec![dns("*.example.com")]);
    assert!(common::validate(&codesign_policy, &codesign, &codesign_request).is_err());
}

#[test]
fn ip_and_email_sans_are_validated() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");

    for value in ["192.0.2", "192.0.2.1/24", "not-an-ip"] {
        let request = common::request_with(
            "tls-server",
            "example.com",
            vec![dns("example.com"), San::Ip(value.to_owned())],
        );
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "{value:?} was accepted"
        );
    }

    let valid = common::request_with(
        "tls-server",
        "example.com",
        vec![dns("example.com"), San::Ip("192.0.2.1".to_owned())],
    );
    common::validate(&policy, &profile, &valid).expect("valid IP SAN");

    let client = common::builtin("tls-client");
    for value in ["", "user", "@example.com", "a@b@c", "user@exa mple.com"] {
        let request = common::request_with("tls-client", value, vec![San::Email(value.to_owned())]);
        assert!(
            common::validate(&policy, &client, &request).is_err(),
            "{value:?} was accepted"
        );
    }
}

#[test]
fn uri_sans_are_validated() {
    let mut profile = common::builtin("tls-client");
    profile.san_types = vec![SanType::Uri];
    let mut policy = common::base_policy();
    policy.cn_must_match_san = false;

    for value in [
        "http://example.com",
        "https://",
        "spiffe:example.org",
        "urn:",
        "not a uri",
    ] {
        let request = common::request_with("tls-client", "svc", vec![San::Uri(value.to_owned())]);
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "{value:?} was accepted"
        );
    }

    let valid = common::request_with(
        "tls-client",
        "svc",
        vec![San::Uri("spiffe://example.org/svc".to_owned())],
    );
    common::validate(&policy, &profile, &valid).expect("spiffe URI is valid");
}

#[test]
fn san_suffixes_restrict_dns_names() {
    let mut policy = common::base_policy();
    policy.allowed_san_suffixes = vec!["example.com".to_owned()];
    let profile = common::builtin("tls-server");

    for name in ["example.com", "www.example.com"] {
        let request = common::dns_request("tls-server", name);
        common::validate(&policy, &profile, &request).expect("name uses an allowed suffix");
    }

    for name in ["evil.com", "notexample.com", "example.com.evil.com"] {
        let request = common::dns_request("tls-server", name);
        assert!(
            common::validate(&policy, &profile, &request).is_err(),
            "{name:?} was accepted"
        );
    }

    policy.allow_wildcards = true;
    let wildcard = common::dns_request("tls-server", "*.example.com");
    common::validate(&policy, &profile, &wildcard).expect("wildcard suffix is checked after '*.'");
}

#[test]
fn common_name_must_match_a_san() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");

    let mismatched =
        common::request_with("tls-server", "other.example.com", vec![dns("example.com")]);
    assert!(common::validate(&policy, &profile, &mismatched).is_err());

    let exact_case = common::request_with("tls-server", "Example.com", vec![dns("example.com")]);
    assert!(common::validate(&policy, &profile, &exact_case).is_err());

    let mut disabled = common::base_policy();
    disabled.cn_must_match_san = false;
    common::validate(&disabled, &profile, &mismatched).expect("matching is disabled");

    let client = common::builtin("tls-client");
    let email_cn = common::request_with(
        "tls-client",
        "user@example.com",
        vec![San::Email("user@example.com".to_owned())],
    );
    common::validate(&policy, &client, &email_cn).expect("CN matches the email SAN");
}

#[test]
fn custom_extensions_require_profile_and_policy_opt_in() {
    let request = IssueRequest {
        custom_extensions: vec![CustomExtension::utf8("1.2.3.4", "value")],
        ..common::dns_request("tls-server", "example.com")
    };
    let policy = common::base_policy();
    let mut profile = common::builtin("tls-server");

    let error = common::validate(&policy, &profile, &request).expect_err("profile opts out");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Policy);

    profile.allow_custom_oid = true;
    common::validate(&policy, &profile, &request).expect("profile opts in");

    let mut disabled = common::base_policy();
    disabled.allow_custom_oid = false;
    assert!(common::validate(&disabled, &profile, &request).is_err());
}

#[test]
fn request_profile_name_is_checked() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let request = IssueRequest {
        profile: ProfileName::new("tls-client").expect("valid"),
        ..common::dns_request("tls-server", "example.com")
    };
    assert!(common::validate(&policy, &profile, &request).is_err());
}

#[test]
fn errors_name_the_rejected_field_and_value() {
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let request = common::request_with(
        "tls-server",
        "example.com",
        vec![dns("example.com"), San::Dns("BAD NAME".to_owned())],
    );
    let error: ChainkeeperError =
        common::validate(&policy, &profile, &request).expect_err("bad SAN");
    let message = error.to_string();
    assert!(
        message.contains("DNS subject alternative name"),
        "{message}"
    );
    assert!(message.contains("BAD NAME"), "{message}");
}

#[test]
fn subject_builder_does_not_bypass_policy() {
    let policy: Policy = common::base_policy();
    let profile = common::builtin("tls-server");
    let request = common::dns_request("tls-server", "example.com");
    let subject: SubjectName = request.subject.clone();
    subject.validate().expect("core subject validation passes");
    common::validate(&policy, &profile, &request).expect("request passes policy");
}
