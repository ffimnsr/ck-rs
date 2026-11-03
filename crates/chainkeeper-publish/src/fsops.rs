//! Symlink-safe filesystem helpers for publishing.

use std::collections::BTreeSet;
use std::io::ErrorKind as IoErrorKind;
use std::path::{Component, Path, PathBuf};

use chainkeeper_core::{ChainkeeperError, FileMode, atomic_write};

fn publish(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::publish(message)
}

/// Creates `path` and its parents.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when a directory cannot be created.
pub fn create_directory(path: &Path) -> Result<(), ChainkeeperError> {
    std::fs::create_dir_all(path).map_err(|error| {
        publish(format!(
            "could not create directory {}: {error}",
            path.display()
        ))
    })
}

/// Atomically writes `bytes` to `path`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when the write fails.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<(), ChainkeeperError> {
    atomic_write(path, bytes, FileMode::Public)
}

/// Reads `path`, returning `None` when it does not exist.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when the file exists but cannot be
/// read.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, ChainkeeperError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == IoErrorKind::NotFound => Ok(None),
        Err(error) => Err(ChainkeeperError::storage(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}

/// Rejects absolute, parent-traversing, and empty relative paths.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when `path` is not a safe relative
/// path.
pub fn safe_relative(path: &Path) -> Result<PathBuf, ChainkeeperError> {
    if path.as_os_str().is_empty() {
        return Err(publish("publish artifact path must not be empty"));
    }
    if path.is_absolute() {
        return Err(publish(format!(
            "publish artifact path {} must be relative",
            path.display()
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) | Component::CurDir
        )
    }) {
        return Err(publish(format!(
            "publish artifact path {} must not traverse directories",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

/// Returns the safe relative form of `path` inside `root`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when `path` is outside `root` or is
/// not a safe relative path.
pub fn relative_to(root: &Path, path: &Path) -> Result<PathBuf, ChainkeeperError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        publish(format!(
            "{} is outside the repository root {}",
            path.display(),
            root.display()
        ))
    })?;
    safe_relative(relative)
}

/// Creates every parent directory of `path`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when a directory cannot be created.
pub fn ensure_parent(path: &Path) -> Result<(), ChainkeeperError> {
    let parent = path
        .parent()
        .ok_or_else(|| publish(format!("{} has no parent directory", path.display())))?;
    create_directory(parent)
}

/// Moves `source` over `destination`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when the move fails.
pub fn move_file(source: &Path, destination: &Path) -> Result<(), ChainkeeperError> {
    ensure_parent(destination)?;
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(publish(format!(
                "refusing to replace directory {}",
                destination.display()
            )));
        }
        Ok(_) => {
            std::fs::remove_file(destination).map_err(|error| {
                publish(format!(
                    "could not replace {}: {error}",
                    destination.display()
                ))
            })?;
        }
        Err(error) if error.kind() == IoErrorKind::NotFound => {}
        Err(error) => {
            return Err(publish(format!(
                "could not inspect {}: {error}",
                destination.display()
            )));
        }
    }
    std::fs::rename(source, destination).map_err(|error| {
        publish(format!(
            "could not move {} to {}: {error}",
            source.display(),
            destination.display()
        ))
    })
}

/// Lists a directory in deterministic lexical order.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when the directory cannot be read.
pub fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>, ChainkeeperError> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
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
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

/// Walks a directory and returns `(relative, absolute)` file pairs.
///
/// Symlinks of any kind are rejected rather than followed.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when the tree contains a symlink or
/// cannot be read.
pub fn walk_files(root: &Path) -> Result<Vec<(PathBuf, PathBuf)>, ChainkeeperError> {
    let mut files = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for path in sorted_entries(&directory)? {
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                publish(format!("could not inspect {}: {error}", path.display()))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(publish(format!(
                    "publish tree contains symlink {}",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                directories.push(path);
            } else if metadata.is_file() {
                let relative = path.strip_prefix(root).map_err(|_| {
                    publish(format!("{} is outside the publish tree", path.display()))
                })?;
                files.push((relative.to_path_buf(), path));
            } else {
                return Err(publish(format!(
                    "publish tree contains unsupported entry {}",
                    path.display()
                )));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

/// Removes files and directories not listed in `keep`.
///
/// Symlinks are removed instead of followed. Empty directories left behind are
/// pruned. The root directory itself is preserved.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when an entry cannot be removed.
pub fn prune(destination: &Path, keep: &BTreeSet<PathBuf>) -> Result<(), ChainkeeperError> {
    let mut directories = Vec::new();
    let mut stack = vec![destination.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for path in sorted_entries(&directory)? {
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                publish(format!("could not inspect {}: {error}", path.display()))
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(path.clone());
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(destination)
                .map_err(|_| publish(format!("{} is outside the publish tree", path.display())))?;
            if !keep.contains(relative) {
                std::fs::remove_file(&path).map_err(|error| {
                    publish(format!(
                        "could not remove stale {}: {error}",
                        path.display()
                    ))
                })?;
            }
        }
    }

    directories.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    for directory in directories {
        if directory == destination {
            continue;
        }
        match std::fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == IoErrorKind::NotFound => {}
            Err(error) if error.kind() == IoErrorKind::DirectoryNotEmpty => {}
            Err(error) => {
                return Err(publish(format!(
                    "could not remove empty directory {}: {error}",
                    directory.display()
                )));
            }
        }
    }
    Ok(())
}
