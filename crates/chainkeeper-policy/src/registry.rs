//! Profile registry backed by the embedded default profiles.

use std::collections::BTreeMap;

use chainkeeper_core::{ChainkeeperError, Profile, ProfileName, ProfileRegistry};

use crate::defaults::load_default_profiles;
use crate::validate::validate_profile_structure;

/// Profile registry that validates entries and serves them by name.
#[derive(Debug, Clone)]
pub struct DefaultProfileRegistry {
    profiles: BTreeMap<ProfileName, Profile>,
}

impl Default for DefaultProfileRegistry {
    /// Builds a registry containing the six embedded profiles.
    fn default() -> Self {
        Self::defaults()
    }
}

impl DefaultProfileRegistry {
    /// Builds a registry containing the six embedded profiles.
    ///
    /// # Panics
    ///
    /// Panics only when the embedded YAML is malformed, which is a build defect.
    #[must_use]
    pub fn defaults() -> Self {
        Self::try_defaults().expect("embedded default profiles are valid")
    }

    /// Builds a registry containing the six embedded profiles.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Profile`] when an embedded profile is
    /// malformed.
    pub fn try_defaults() -> Result<Self, ChainkeeperError> {
        Ok(Self::with_profiles(load_default_profiles()?))
    }

    /// Builds a registry from an explicit profile list.
    #[must_use]
    pub fn with_profiles(profiles: impl IntoIterator<Item = Profile>) -> Self {
        Self {
            profiles: profiles
                .into_iter()
                .map(|profile| (profile.name.clone(), profile))
                .collect(),
        }
    }

    /// Inserts or replaces a profile.
    pub fn register(&mut self, profile: Profile) {
        self.profiles.insert(profile.name.clone(), profile);
    }
}

impl ProfileRegistry for DefaultProfileRegistry {
    fn get(&self, name: &ProfileName) -> Result<Profile, ChainkeeperError> {
        self.profiles
            .get(name)
            .cloned()
            .ok_or_else(|| ChainkeeperError::not_found("profile", name.as_str()))
    }

    fn list(&self) -> Vec<Profile> {
        self.profiles.values().cloned().collect()
    }

    fn validate(&self, profile: &Profile) -> Result<(), ChainkeeperError> {
        validate_profile_structure(profile)
    }
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{ProfileName, ProfileRegistry};

    use super::DefaultProfileRegistry;

    #[test]
    fn lists_every_builtin_profile() {
        let registry = DefaultProfileRegistry::defaults();
        assert_eq!(registry.list().len(), 6);
        for name in [
            "tls-server",
            "tls-client",
            "mtls",
            "smime",
            "codesign",
            "ocsp",
        ] {
            let name = ProfileName::new(name).expect("valid name");
            assert!(registry.get(&name).is_ok(), "{name}");
        }
    }

    #[test]
    fn unknown_profiles_are_not_found() {
        let registry = DefaultProfileRegistry::defaults();
        let name = ProfileName::new("missing").expect("valid name");
        let error = registry.get(&name).expect_err("missing profile");
        assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);
    }

    #[test]
    fn validate_rejects_broken_profiles() {
        let registry = DefaultProfileRegistry::defaults();
        let mut profile = registry.list().remove(0);
        profile.eku.clear();
        assert!(registry.validate(&profile).is_err());
    }
}
