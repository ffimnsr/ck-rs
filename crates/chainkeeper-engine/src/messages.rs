//! Commit message builders.
//!
//! The formats mirror `chainkeeper_git::CommitMessage`, which is the product
//! contract. The engine does not depend on the Git crate at runtime because it
//! only needs the strings, and a test keeps both definitions aligned.

use chainkeeper_core::{AuthorityName, ProfileName, RevocationReason, Serial};

/// Root authority creation.
pub fn root(name: &AuthorityName) -> String {
    format!("feat(ck): create root authority {name}")
}

/// Intermediate authority creation.
pub fn intermediate(name: &AuthorityName) -> String {
    format!("feat(ck): create intermediate authority {name}")
}

/// Dedicated OCSP signer creation.
pub fn ocsp_signer(name: &AuthorityName) -> String {
    format!("feat(ck): create ocsp signer {name}")
}

/// Certificate issuance.
pub fn issue(serial: &Serial, profile: &ProfileName) -> String {
    format!("feat(ck): issue certificate {serial} profile {profile}")
}

/// Certificate revocation.
pub fn revoke(serial: &Serial, reason: RevocationReason) -> String {
    format!(
        "feat(ck): revoke certificate {serial} reason {}",
        reason.as_str()
    )
}

/// Certificate replacement.
pub fn replace(old: &Serial, new: &Serial) -> String {
    format!("feat(ck): replace certificate {old} with {new}")
}

/// Publication of generated artifacts.
pub fn publish(source_commit: &str) -> String {
    format!("chore(ck): publish artifacts from {source_commit}")
}

/// Index rebuild.
pub fn rebuild_index() -> String {
    "chore(ck): rebuild index".to_owned()
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{AuthorityName, ProfileName, RevocationReason, Serial};
    use chainkeeper_git::CommitMessage;

    use super::{intermediate, issue, ocsp_signer, publish, rebuild_index, replace, revoke, root};

    #[test]
    fn messages_match_the_git_crate() {
        let name = AuthorityName::new("tls").expect("name");
        let serial = Serial::new("00FF").expect("serial");
        let profile = ProfileName::new("tls-server").expect("profile");

        assert_eq!(root(&name), CommitMessage::root(&name).into_string());
        assert_eq!(
            intermediate(&name),
            CommitMessage::intermediate(&name).into_string()
        );
        assert_eq!(
            ocsp_signer(&name),
            CommitMessage::ocsp_signer(&name).into_string()
        );
        assert_eq!(
            issue(&serial, &profile),
            CommitMessage::issue(&serial, &profile).into_string()
        );
        assert_eq!(
            revoke(&serial, RevocationReason::KeyCompromise),
            CommitMessage::revoke(&serial, RevocationReason::KeyCompromise).into_string()
        );
        assert_eq!(
            replace(&serial, &serial),
            CommitMessage::replace(&serial, &serial).into_string()
        );
        assert_eq!(
            publish("abc123"),
            CommitMessage::publish("abc123").into_string()
        );
        assert_eq!(
            rebuild_index(),
            CommitMessage::rebuild_index().into_string()
        );
    }
}
