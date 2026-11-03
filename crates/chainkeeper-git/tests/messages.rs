//! Commit message formats.

use chainkeeper_core::{AuthorityName, ProfileName, RevocationReason, Serial, TenantId};
use chainkeeper_git::CommitMessage;

fn authority(value: &str) -> AuthorityName {
    AuthorityName::new(value).expect("valid authority")
}

fn serial(value: &str) -> Serial {
    Serial::new(value).expect("valid serial")
}

fn profile(value: &str) -> ProfileName {
    ProfileName::new(value).expect("valid profile")
}

#[test]
fn messages_match_the_contract_exactly() {
    let cases = [
        (
            CommitMessage::init(&TenantId::new("acme").expect("tenant")),
            "feat(ck): initialize tenant acme",
        ),
        (
            CommitMessage::root(&authority("root")),
            "feat(ck): create root authority root",
        ),
        (
            CommitMessage::intermediate(&authority("tls")),
            "feat(ck): create intermediate authority tls",
        ),
        (
            CommitMessage::ocsp_signer(&authority("ocsp-signer")),
            "feat(ck): create ocsp signer ocsp-signer",
        ),
        (
            CommitMessage::issue(&serial("00FF"), &profile("tls-server")),
            "feat(ck): issue certificate 00FF profile tls-server",
        ),
        (
            CommitMessage::revoke(&serial("00FF"), RevocationReason::KeyCompromise),
            "feat(ck): revoke certificate 00FF reason keyCompromise",
        ),
        (
            CommitMessage::replace(&serial("00FF"), &serial("00AA")),
            "feat(ck): replace certificate 00FF with 00AA",
        ),
        (
            CommitMessage::crl(&authority("tls"), 7),
            "feat(ck): regenerate crl tls number 7",
        ),
        (
            CommitMessage::publish("0123456789abcdef0123456789abcdef01234567"),
            "chore(ck): publish artifacts from 0123456789abcdef0123456789abcdef01234567",
        ),
        (CommitMessage::rebuild_index(), "chore(ck): rebuild index"),
    ];

    for (message, expected) in cases {
        assert_eq!(message.as_str(), expected);
        assert_eq!(message.to_string(), expected);
        assert!(!message.as_str().ends_with(char::is_whitespace));
        assert!(!message.as_str().contains('\n'));
        assert!(
            message.as_str().starts_with("feat(ck):") || message.as_str().starts_with("chore(ck):")
        );
    }
}

#[test]
fn into_string_preserves_text() {
    let message = CommitMessage::rebuild_index();
    assert_eq!(message.clone().into_string(), message.to_string());
}
