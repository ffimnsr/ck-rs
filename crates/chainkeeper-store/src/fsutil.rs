//! Filesystem helpers shared by the canonical store.
//!
//! Every helper takes an absolute path owned by a [`chainkeeper_core::RepositoryPaths`]
//! and never resolves the current working directory or the environment.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use chainkeeper_core::{ChainkeeperError, RepositoryPaths};

/// Unix mode applied to every directory the store creates.
pub const DIRECTORY_MODE: u32 = 0o700;

/// Creates `path` and its parents, then forces mode `0700` on Unix.
pub fn ensure_directory(path: &Path) -> Result<(), ChainkeeperError> {
    if !path.is_dir() {
        std::fs::create_dir_all(path).map_err(|error| {
            ChainkeeperError::storage(format!("could not create {}: {error}", path.display()))
        })?;
    }
    set_mode(path, DIRECTORY_MODE)
}

/// Applies a Unix mode to `path`. No-op on non-Unix targets.
#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> Result<(), ChainkeeperError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not set mode {mode:o} on {}: {error}",
            path.display()
        ))
    })
}

/// Applies a Unix mode to `path`. No-op on non-Unix targets.
#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _mode: u32) -> Result<(), ChainkeeperError> {
    Ok(())
}

/// Returns true for editor swap files, temporary files, and hidden files.
pub fn is_ignorable(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return true;
    };
    name.starts_with('.')
        || name.ends_with('~')
        || name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("tmp"))
}

/// Returns true when the file name ends with `extension`, ignoring case.
pub fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

/// Lists a directory in deterministic lexical order, skipping hidden and
/// temporary files.
pub fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>, ChainkeeperError> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not read directory {}: {error}",
            directory.display()
        ))
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ChainkeeperError::storage(format!(
                "could not read directory {}: {error}",
                directory.display()
            ))
        })?;
        if is_ignorable(&entry.file_name()) {
            continue;
        }
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

/// Returns the repository-relative form of an absolute path inside `paths`.
pub fn relative_path(path: &Path, paths: &RepositoryPaths) -> Result<PathBuf, ChainkeeperError> {
    let relative = path.strip_prefix(paths.root()).map_err(|_| {
        ChainkeeperError::storage(format!(
            "{} is outside the repository root {}",
            path.display(),
            paths.root().display()
        ))
    })?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ChainkeeperError::storage(format!(
            "{} is not a valid repository-relative path",
            relative.display()
        )));
    }
    Ok(relative.to_path_buf())
}

/// Reads a file, mapping a missing file to [`ChainkeeperError::NotFound`].
pub fn read_file(path: &Path, object: &str) -> Result<Vec<u8>, ChainkeeperError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            ChainkeeperError::not_found(object, &path.display().to_string()),
        ),
        Err(error) => Err(ChainkeeperError::storage(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}
