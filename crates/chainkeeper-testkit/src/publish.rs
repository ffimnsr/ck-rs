//! Fake publication builder.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use chainkeeper_core::{
    ChainkeeperError, PUBLISH_MANIFEST_VERSION, PublishArtifact, PublishBuilder, PublishManifest,
    PublishOptions, TenantId,
};

fn test_tenant() -> TenantId {
    TenantId::new("test-tenant").expect("test tenant id is valid")
}

/// Publication builder that returns a fixed manifest.
#[derive(Debug)]
pub struct FakePublishBuilder {
    tenant_id: TenantId,
    generated_at: time::OffsetDateTime,
    builds: AtomicU64,
}

impl FakePublishBuilder {
    /// Creates a builder for the `test-tenant` tenant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tenant_id: test_tenant(),
            generated_at: time::macros::datetime!(2024-01-01 00:00:00 UTC),
            builds: AtomicU64::new(0),
        }
    }

    /// Number of builds performed.
    #[must_use]
    pub fn build_count(&self) -> u64 {
        self.builds.load(Ordering::SeqCst)
    }
}

impl Default for FakePublishBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishBuilder for FakePublishBuilder {
    fn build(&self, options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        if !options.output_dir.is_dir() {
            return Err(ChainkeeperError::publish(format!(
                "publish directory {} does not exist",
                options.output_dir.display()
            )));
        }
        Ok(PublishManifest {
            version: PUBLISH_MANIFEST_VERSION,
            generated_at: self.generated_at,
            source_commit: None,
            tenant_id: self.tenant_id.clone(),
            artifacts: vec![PublishArtifact {
                path: "root.pem".into(),
                sha256: "0".repeat(64),
                bytes: 0,
            }],
        })
    }

    fn validate_publish_dir(&self, path: &Path) -> Result<(), ChainkeeperError> {
        if path.is_dir() {
            Ok(())
        } else {
            Err(ChainkeeperError::publish(format!(
                "{} is not a publish directory",
                path.display()
            )))
        }
    }
}
