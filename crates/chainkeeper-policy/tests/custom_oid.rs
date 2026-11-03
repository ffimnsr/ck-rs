//! Custom OID validation rules.

mod common;

use chainkeeper_core::{CustomExtension, Policy, PolicyEngine};
use chainkeeper_policy::{PolicyValidator, RESERVED_OIDS, validate_custom_extensions};

const fn validator() -> PolicyValidator {
    PolicyValidator::new()
}

fn extension(oid: &str) -> CustomExtension {
    CustomExtension::utf8(oid, "value")
}

#[test]
fn accepts_valid_utf8_and_hex_values() {
    let policy = common::base_policy();
    for oid in ["1.2.3.4", "1.3.6.1.4.1.311.21.10", "2.999.1.0"] {
        validator()
            .validate_custom_extension(&policy, &extension(oid))
            .expect("valid OID");

        let hex = CustomExtension {
            oid: oid.to_owned(),
            critical: false,
            value_utf8: None,
            value_hex: Some("00ff10".to_owned()),
        };
        validator()
            .validate_custom_extension(&policy, &hex)
            .expect("valid hex");
    }
}

#[test]
fn rejects_malformed_oids() {
    let policy = common::base_policy();
    for oid in [
        "", "1", "1.", ".1.2", "1..2", "1.2.a", "01.2", "1.02", "3.1", "1.40", "1.2.3.04",
    ] {
        assert!(
            validator()
                .validate_custom_extension(&policy, &extension(oid))
                .is_err(),
            "{oid:?} was accepted"
        );
    }
}

#[test]
fn rejects_reserved_oids() {
    let policy = common::base_policy();
    for oid in RESERVED_OIDS {
        let error = validator()
            .validate_custom_extension(&policy, &extension(oid))
            .expect_err("reserved OID is rejected");
        assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Policy);
    }
}

#[test]
fn rejects_duplicate_oids_in_one_request() {
    let policy = common::base_policy();
    let duplicate = [extension("1.2.3.4"), extension("1.2.3.4")];
    assert!(validate_custom_extensions(&policy, &duplicate).is_err());

    let distinct = [extension("1.2.3.4"), extension("1.2.3.5")];
    validate_custom_extensions(&policy, &distinct).expect("distinct OIDs");
}

#[test]
fn rejects_custom_oids_when_disabled() {
    let policy = Policy {
        allow_custom_oid: false,
        ..common::base_policy()
    };
    let error = validator()
        .validate_custom_extension(&policy, &extension("1.2.3.4"))
        .expect_err("custom OIDs are disabled");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Policy);
}

#[test]
fn requires_exactly_one_value_encoding() {
    let policy = common::base_policy();

    let both = CustomExtension {
        oid: "1.2.3.4".to_owned(),
        critical: false,
        value_utf8: Some("value".to_owned()),
        value_hex: Some("00ff".to_owned()),
    };
    assert!(
        validator()
            .validate_custom_extension(&policy, &both)
            .is_err()
    );

    let neither = CustomExtension {
        oid: "1.2.3.4".to_owned(),
        critical: false,
        value_utf8: None,
        value_hex: None,
    };
    assert!(
        validator()
            .validate_custom_extension(&policy, &neither)
            .is_err()
    );
}

#[test]
fn rejects_malformed_hex_values() {
    let policy = common::base_policy();
    for hex in ["0", "0g", "abc", "zz"] {
        let extension = CustomExtension {
            oid: "1.2.3.4".to_owned(),
            critical: false,
            value_utf8: None,
            value_hex: Some(hex.to_owned()),
        };
        assert!(
            validator()
                .validate_custom_extension(&policy, &extension)
                .is_err(),
            "{hex:?} was accepted"
        );
    }
}

#[test]
fn enforces_value_size_boundaries() {
    let policy = common::base_policy();

    let utf8_max = CustomExtension::utf8("1.2.3.4", "a".repeat(1024));
    validator()
        .validate_custom_extension(&policy, &utf8_max)
        .expect("1024 byte UTF-8 value");

    let utf8_over = CustomExtension::utf8("1.2.3.4", "a".repeat(1025));
    assert!(
        validator()
            .validate_custom_extension(&policy, &utf8_over)
            .is_err()
    );

    let hex_max = CustomExtension {
        oid: "1.2.3.4".to_owned(),
        critical: false,
        value_utf8: None,
        value_hex: Some("ab".repeat(4096)),
    };
    validator()
        .validate_custom_extension(&policy, &hex_max)
        .expect("4096 decoded bytes");

    let hex_over = CustomExtension {
        oid: "1.2.3.4".to_owned(),
        critical: false,
        value_utf8: None,
        value_hex: Some("ab".repeat(4097)),
    };
    assert!(
        validator()
            .validate_custom_extension(&policy, &hex_over)
            .is_err()
    );
}

#[test]
fn critical_extensions_require_policy_opt_in() {
    let mut policy = common::base_policy();
    let critical = CustomExtension {
        oid: "1.2.3.4".to_owned(),
        critical: true,
        value_utf8: Some("value".to_owned()),
        value_hex: None,
    };
    assert!(
        validator()
            .validate_custom_extension(&policy, &critical)
            .is_err()
    );

    policy.allow_critical_custom_oid = true;
    validator()
        .validate_custom_extension(&policy, &critical)
        .expect("critical extensions are enabled");
}

#[test]
fn errors_name_the_field_and_value() {
    let policy = common::base_policy();
    let error = validator()
        .validate_custom_extension(&policy, &extension("1.02"))
        .expect_err("invalid OID");
    let message = error.to_string();
    assert!(message.contains("custom extension OID"), "{message}");
    assert!(message.contains("1.02"), "{message}");
    assert_eq!(error.object_id(), Some("1.02"));
}
