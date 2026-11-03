//! Exact assertions for the six built-in profiles.

mod common;

use chainkeeper_core::{
    CONFIG_VERSION, ExtendedKeyUsage, KeyAlgorithm, KeyUsage, Profile, ProfileName,
    ProfileRegistry, SanType, builtin_profiles,
};
use chainkeeper_policy::{
    DEFAULT_AUTHORITY_NAMES, DefaultProfileRegistry, builtin_profile_yaml,
    builtin_profile_yaml_files, default_profiles, load_default_profiles,
};

fn expected_profiles() -> Vec<Profile> {
    let profile = |name: &str, authority: &str| Profile {
        version: CONFIG_VERSION,
        name: ProfileName::new(name).expect("valid name"),
        authority: chainkeeper_core::AuthorityName::new(authority).expect("valid authority"),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 397,
        key_usage: Vec::new(),
        eku: Vec::new(),
        san_required: false,
        san_types: Vec::new(),
        allow_custom_oid: false,
    };

    vec![
        Profile {
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            eku: vec![ExtendedKeyUsage::ServerAuth],
            san_required: true,
            san_types: vec![SanType::Dns, SanType::Ip],
            ..profile("tls-server", "tls")
        },
        Profile {
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::ClientAuth],
            san_required: true,
            san_types: vec![SanType::Dns, SanType::Email, SanType::Ip],
            ..profile("tls-client", "tls")
        },
        Profile {
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            eku: vec![ExtendedKeyUsage::ClientAuth, ExtendedKeyUsage::ServerAuth],
            san_required: true,
            san_types: vec![SanType::Dns, SanType::Ip],
            ..profile("mtls", "tls")
        },
        Profile {
            algorithm: KeyAlgorithm::Rsa3072,
            key_usage: vec![
                KeyUsage::DigitalSignature,
                KeyUsage::KeyEncipherment,
                KeyUsage::ContentCommitment,
            ],
            eku: vec![ExtendedKeyUsage::EmailProtection],
            san_required: true,
            san_types: vec![SanType::Email],
            ..profile("smime", "smime")
        },
        Profile {
            algorithm: KeyAlgorithm::Rsa3072,
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::CodeSigning],
            ..profile("codesign", "codesign")
        },
        Profile {
            validity_days: 90,
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::OcspSigning],
            ..profile("ocsp", "ocsp")
        },
    ]
}

#[test]
fn built_in_profiles_match_the_specification() {
    assert_eq!(default_profiles(), expected_profiles());
}

#[test]
fn core_profiles_stay_in_sync() {
    assert_eq!(builtin_profiles(), default_profiles());
}

#[test]
fn every_profile_authority_is_a_default_authority() {
    for profile in default_profiles() {
        assert!(
            DEFAULT_AUTHORITY_NAMES.contains(&profile.authority.as_str()),
            "{} uses unknown authority {}",
            profile.name,
            profile.authority
        );
    }
}

#[test]
fn every_embedded_yaml_document_parses() {
    let documents = builtin_profile_yaml_files();
    assert_eq!(documents.len(), 6);
    for (stem, yaml) in documents {
        let profile: Profile = serde_yaml_ng::from_str(yaml).expect("embedded profile parses");
        assert_eq!(profile.name.as_str(), *stem);
        assert_eq!(builtin_profile_yaml(stem), Some(*yaml));
    }
    assert_eq!(builtin_profile_yaml("missing"), None);
}

#[test]
fn registry_serves_every_embedded_profile() {
    let registry = DefaultProfileRegistry::defaults();
    let mut listed = registry.list();
    listed.sort_by(|left, right| left.name.cmp(&right.name));
    let mut expected = load_default_profiles().expect("embedded profiles load");
    expected.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(listed, expected);
    for profile in expected {
        assert_eq!(registry.get(&profile.name).expect("known profile"), profile);
    }
}

#[test]
fn every_profile_algorithm_is_supported() {
    for profile in default_profiles() {
        assert!(
            KeyAlgorithm::ALL.contains(&profile.algorithm),
            "{} uses unsupported algorithm {}",
            profile.name,
            profile.algorithm
        );
    }
}
