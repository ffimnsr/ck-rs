//! Best-effort rollback of files created by an aborted operation.
//!
//! Only paths created by the current operation are removed. Pre-existing files
//! are never deleted, and moved files are restored to their original location.

use std::path::{Path, PathBuf};

use chainkeeper_core::Serial;

/// Bookkeeping for one mutating operation.
#[derive(Debug, Default)]
pub struct Rollback {
    created: Vec<PathBuf>,
    moved: Vec<(PathBuf, PathBuf)>,
    moved_certificates: Vec<Serial>,
    index_dirty: bool,
}

impl Rollback {
    /// Records a path this operation created.
    pub fn created(&mut self, path: impl Into<PathBuf>) {
        self.created.push(path.into());
    }

    /// Records a path this operation may have created, keeping pre-existing
    /// files intact.
    pub fn created_if_absent(&mut self, path: &Path) {
        if !path.exists() {
            self.created(path.to_path_buf());
        }
    }

    /// Records a rename so it can be reversed.
    pub fn moved(&mut self, from: impl Into<PathBuf>, to: impl Into<PathBuf>) {
        self.moved.push((from.into(), to.into()));
    }

    /// Records that a certificate was moved between status directories.
    pub fn certificate_moved(&mut self, serial: Serial) {
        self.moved_certificates.push(serial);
    }

    /// Certificates whose status directories must be restored.
    pub fn moved_certificates(&self) -> &[Serial] {
        &self.moved_certificates
    }

    /// Marks that index rows were written and must be rebuilt on rollback.
    pub const fn mark_index_dirty(&mut self) {
        self.index_dirty = true;
    }

    /// Whether index rows were written.
    pub const fn index_dirty(&self) -> bool {
        self.index_dirty
    }

    /// Removes created files and restores moved files.
    pub fn undo(&mut self) {
        for path in self.created.drain(..).rev() {
            let _ = std::fs::remove_file(&path);
        }
        for (from, to) in self.moved.drain(..).rev() {
            if to.exists() {
                let _ = std::fs::rename(&to, &from);
            }
        }
    }
}
