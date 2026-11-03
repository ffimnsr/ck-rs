#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Deterministic policy and profile engine.
//!
//! This crate owns the six built-in certificate profiles, the default policy,
//! and every pure validation step that runs before key generation. It performs
//! no I/O of its own: profile and policy YAML are embedded at build time and
//! parsed on demand.
//!
//! [`PolicyValidator`] implements [`chainkeeper_core::PolicyEngine`], and
//! [`DefaultProfileRegistry`] implements
//! [`chainkeeper_core::ProfileRegistry`].

mod defaults;
mod dns;
mod doctor;
mod engine;
mod oid;
mod registry;
mod validate;

pub use defaults::{
    BUILTIN_PROFILE_YAML, DEFAULT_POLICY_YAML, builtin_profile_yaml, builtin_profile_yaml_files,
    default_policy, default_profiles, load_default_policy, load_default_profiles,
};
pub use dns::{
    is_wildcard_dns, validate_dns_name, validate_email, validate_email_field, validate_ip,
    validate_uri,
};
pub use doctor::cross_validate;
pub use engine::{IssueContext, PolicyValidator};
pub use oid::{Oid, RESERVED_OIDS};
pub use registry::DefaultProfileRegistry;
pub use validate::{
    DEFAULT_AUTHORITY_NAMES, normalized_san_suffixes, validate_custom_extension,
    validate_custom_extensions, validate_issue_request, validate_policy,
    validate_profile_against_policy, validate_profile_structure,
};
