//! Revocation-driven CRL and publish refresh.

use std::path::{Path, PathBuf};

use chainkeeper_core::{
    AuthorityName, ChainkeeperError, CrlManager, PublishBuilder, PublishOptions, RepositoryPaths,
};

use crate::crl::crl_paths;
use crate::{diff, manifest};

/// Regenerates the CRL for `authority` and, when a publish directory exists,
/// rebuilds published artifacts.
///
/// CRL files are written before publishing starts, so a publish failure leaves
/// the regenerated CRL in place and returns the publish error.
///
/// # Errors
///
/// Returns the CRL or publish error that stopped the refresh.
pub fn refresh_after_revocation(
    authority: &AuthorityName,
    crl: &dyn CrlManager,
    publish: Option<&dyn PublishBuilder>,
    publish_dir: &Path,
    paths: &RepositoryPaths,
) -> Result<Vec<PathBuf>, ChainkeeperError> {
    crl.update_for_authority(authority)?;
    let mut changed = crl_paths(paths, authority)?;

    let Some(publish) = publish else {
        return Ok(changed);
    };
    if !publish_dir.is_dir() {
        return Ok(changed);
    }

    let previous = manifest::read(publish_dir)?;
    let next = publish.build(&PublishOptions::new(publish_dir.to_path_buf()))?;
    match previous {
        Some(previous) => {
            let paths = diff::changed_paths(&previous, &next);
            for relative in paths
                .added
                .into_iter()
                .chain(paths.modified)
                .chain(paths.removed)
            {
                changed.push(publish_dir.join(relative));
            }
        }
        None => {
            for artifact in next.artifacts {
                changed.push(publish_dir.join(artifact.path));
            }
        }
    }
    changed.push(publish_dir.join(crate::MANIFEST_FILE));
    Ok(changed)
}
