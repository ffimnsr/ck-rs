//! Git repository wrapper.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chainkeeper_core::{
    ChainkeeperError, GitChange, GitChangeKind, GitRepository, GitStatus, TenantConfig,
};
use git2::{
    Delta, DiffFindOptions, DiffOptions, ErrorCode, IndexAddOption, Oid, Repository,
    RepositoryInitOptions, StatusOptions,
};
use time::OffsetDateTime;
use time::UtcOffset;

use crate::identity::{GitIdentity, resolve_signature};
use crate::ignore::{assert_index_has_no_private_keys, ensure_gitignore};
use crate::message::CommitMessage;
use crate::signing::{CommitSigner, GpgCommitSigner, signing_enabled};

/// Revision name that selects the working tree in diff calls.
pub const WORKTREE: &str = "WORKTREE";

/// One entry returned by [`GitRepo::log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLogEntry {
    /// Full commit SHA.
    pub commit: String,
    /// Commit message.
    pub message: String,
    /// Author display name.
    pub author: String,
    /// Author email address.
    pub email: String,
    /// Commit time.
    pub time: OffsetDateTime,
}

fn git(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::git(message)
}

/// Repository bound to a working tree root.
pub struct GitRepo {
    root: PathBuf,
    identity: Option<GitIdentity>,
    signer: Option<Arc<dyn CommitSigner>>,
}

impl fmt::Debug for GitRepo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitRepo")
            .field("root", &self.root)
            .field("identity", &self.identity)
            .field("signer", &self.signer.is_some())
            .finish()
    }
}

impl GitRepo {
    /// Creates a handle for a repository root that may not exist yet.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            identity: None,
            signer: None,
        }
    }

    /// Creates a handle and verifies that the repository exists.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the path is not a repository.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ChainkeeperError> {
        let repo = Self::new(root);
        repo.repository()?;
        Ok(repo)
    }

    /// Overrides the identity used for commits.
    #[must_use]
    pub fn with_identity(mut self, identity: GitIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Overrides the commit signer. Production uses [`GpgCommitSigner`].
    #[must_use]
    pub fn with_commit_signer(mut self, signer: Arc<dyn CommitSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Working tree root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Initialises a repository with an explicit identity.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the repository or the initial
    /// commit cannot be created.
    pub fn init_at(
        path: impl Into<PathBuf>,
        identity: GitIdentity,
    ) -> Result<Self, ChainkeeperError> {
        let repo = Self::new(path).with_identity(identity);
        GitRepository::init(&repo, repo.root())?;
        Ok(repo)
    }

    /// Returns the last `limit` commits, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the history cannot be walked.
    pub fn log(&self, limit: usize) -> Result<Vec<GitLogEntry>, ChainkeeperError> {
        let repository = self.repository()?;
        let mut walk = repository
            .revwalk()
            .map_err(|error| git(format!("could not start git history walk: {error}")))?;
        walk.push_head()
            .map_err(|error| git(format!("could not walk git history: {error}")))?;

        let mut entries = Vec::new();
        for oid in walk.take(limit) {
            let oid = oid.map_err(|error| git(format!("could not read git history: {error}")))?;
            let commit = repository
                .find_commit(oid)
                .map_err(|error| git(format!("could not read commit {oid}: {error}")))?;
            let author = commit.author();
            let time = OffsetDateTime::from_unix_timestamp(commit.time().seconds())
                .map_err(|error| git(format!("invalid commit time: {error}")))?
                .to_offset(UtcOffset::UTC);
            entries.push(GitLogEntry {
                commit: oid.to_string(),
                message: commit.message().unwrap_or_default().to_owned(),
                author: author.name().unwrap_or_default().to_owned(),
                email: author.email().unwrap_or_default().to_owned(),
                time,
            });
        }
        Ok(entries)
    }

    fn repository(&self) -> Result<Repository, ChainkeeperError> {
        Repository::open(&self.root).map_err(|error| {
            git(format!(
                "could not open git repository {}: {error}",
                self.root.display()
            ))
        })
    }

    /// Normalises a caller supplied path to a repository-relative path.
    ///
    /// Absolute paths must resolve inside the repository. Parent components and
    /// prefixes are rejected, so a path can never escape the working tree.
    pub(crate) fn relative_path(&self, path: &Path) -> Result<PathBuf, ChainkeeperError> {
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.root).map_err(|_| {
                git(format!(
                    "path {} is outside repository {}",
                    path.display(),
                    self.root.display()
                ))
            })?
        } else {
            path
        };

        let mut clean = PathBuf::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => clean.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(git(format!(
                        "path {} escapes the repository",
                        path.display()
                    )));
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(git("commit path must name a file"));
        }
        Ok(clean)
    }

    fn is_tracked(repository: &Repository, relative: &Path) -> Result<bool, ChainkeeperError> {
        let Some(head) = Self::head_parent(repository)? else {
            return Ok(false);
        };
        let tree = head
            .tree()
            .map_err(|error| git(format!("could not read HEAD tree: {error}")))?;
        Ok(tree.get_path(relative).is_ok())
    }

    fn collect_files(
        &self,
        relative: &Path,
        files: &mut BTreeSet<PathBuf>,
    ) -> Result<(), ChainkeeperError> {
        let directory = self.root.join(relative);
        let entries = fs::read_dir(&directory).map_err(|error| {
            git(format!(
                "could not read directory {}: {error}",
                directory.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                git(format!(
                    "could not read directory {}: {error}",
                    directory.display()
                ))
            })?;
            let name = entry.file_name();
            if name == ".git" {
                continue;
            }
            let child = relative.join(name);
            let path = entry.path();
            if path.is_dir() {
                self.collect_files(&child, files)?;
            } else if path.is_file() {
                files.insert(child);
            }
        }
        Ok(())
    }

    fn head_parent(repository: &Repository) -> Result<Option<git2::Commit<'_>>, ChainkeeperError> {
        match repository.head() {
            Ok(head) => head
                .peel_to_commit()
                .map(Some)
                .map_err(|error| git(format!("could not read HEAD commit: {error}"))),
            Err(error) if matches!(error.code(), ErrorCode::UnbornBranch | ErrorCode::NotFound) => {
                Ok(None)
            }
            Err(error) => Err(git(format!("could not read HEAD: {error}"))),
        }
    }

    fn update_head(repository: &Repository, oid: Oid) -> Result<(), ChainkeeperError> {
        if let Ok(mut head) = repository.head() {
            head.set_target(oid, "commit")
                .map_err(|error| git(format!("could not update {HEAD_REF}: {error}")))?;
            return Ok(());
        }
        let reference = repository
            .find_reference("HEAD")
            .ok()
            .and_then(|head| head.symbolic_target().ok().flatten().map(str::to_owned))
            .unwrap_or_else(|| "refs/heads/main".to_owned());
        repository
            .reference(&reference, oid, true, "commit")
            .map_err(|error| git(format!("could not update {reference}: {error}")))?;
        Ok(())
    }

    fn commit_signed_or_plain(
        &self,
        repository: &Repository,
        signature: &git2::Signature<'_>,
        message: &str,
        tree: &git2::Tree<'_>,
        parents: &[&git2::Commit<'_>],
    ) -> Result<String, ChainkeeperError> {
        if !signing_enabled(repository)? {
            let oid = repository
                .commit(Some(HEAD_REF), signature, signature, message, tree, parents)
                .map_err(|error| git(format!("could not create commit: {error}")))?;
            return Ok(oid.to_string());
        }

        let buffer = repository
            .commit_create_buffer(signature, signature, message, tree, parents)
            .map_err(|error| git(format!("could not prepare signed commit: {error}")))?;
        let content = std::str::from_utf8(buffer.as_ref())
            .map_err(|error| git(format!("prepared commit is not UTF-8: {error}")))?;

        let signer = match &self.signer {
            Some(signer) => Arc::clone(signer),
            None => Arc::new(GpgCommitSigner::from_repository(repository)?),
        };
        let detached = signer.sign(content.as_bytes())?;
        let oid = repository
            .commit_signed(content, &detached, None)
            .map_err(|error| git(format!("could not create signed commit: {error}")))?;
        Self::update_head(repository, oid)?;
        Ok(oid.to_string())
    }

    fn create_commit(
        &self,
        repository: &Repository,
        message: &str,
        tree: &git2::Tree<'_>,
        parents: &[&git2::Commit<'_>],
    ) -> Result<String, ChainkeeperError> {
        let signature = resolve_signature(repository, self.identity.as_ref())?;
        self.commit_signed_or_plain(repository, &signature, message, tree, parents)
    }

    fn read_tenant_id(root: &Path) -> Result<chainkeeper_core::TenantId, ChainkeeperError> {
        let path = root.join("tenant.yaml");
        let bytes = fs::read(&path).map_err(|error| {
            git(format!(
                "could not read {} to determine the tenant id: {error}",
                path.display()
            ))
        })?;
        let tenant: TenantConfig = serde_yaml_ng::from_slice(&bytes)
            .map_err(|error| git(format!("could not parse {}: {error}", path.display())))?;
        Ok(tenant.tenant_id)
    }
}

const HEAD_REF: &str = "HEAD";

impl GitRepository for GitRepo {
    fn init(&self, path: &Path) -> Result<(), ChainkeeperError> {
        fs::create_dir_all(path).map_err(|error| {
            git(format!(
                "could not create repository root {}: {error}",
                path.display()
            ))
        })?;

        let repository =
            Repository::init_opts(path, RepositoryInitOptions::new().initial_head("main"))
                .map_err(|error| {
                    git(format!(
                        "could not initialise git repository {}: {error}",
                        path.display()
                    ))
                })?;

        if repository.head().is_ok() {
            return Err(git(format!(
                "git repository {} already has commits",
                path.display()
            )));
        }

        ensure_gitignore(path).map_err(|error| error.with_context("git init"))?;
        let tenant = Self::read_tenant_id(path)?;
        let message = CommitMessage::init(&tenant);

        let mut index = repository
            .index()
            .map_err(|error| git(format!("could not read git index: {error}")))?;
        index
            .add_all(["*"], IndexAddOption::DEFAULT, None)
            .map_err(|error| git(format!("could not stage repository files: {error}")))?;
        assert_index_has_no_private_keys(&index)?;
        index
            .write()
            .map_err(|error| git(format!("could not write git index: {error}")))?;

        let tree_id = index
            .write_tree()
            .map_err(|error| git(format!("could not write git tree: {error}")))?;
        let tree = repository
            .find_tree(tree_id)
            .map_err(|error| git(format!("could not read git tree: {error}")))?;
        self.create_commit(&repository, message.as_str(), &tree, &[])?;
        Ok(())
    }

    fn head_commit(&self) -> Result<String, ChainkeeperError> {
        let repository = self.repository()?;
        let head = repository.head().map_err(|error| {
            if matches!(error.code(), ErrorCode::UnbornBranch | ErrorCode::NotFound) {
                ChainkeeperError::not_found("commit", HEAD_REF)
            } else {
                git(format!("could not read HEAD: {error}"))
            }
        })?;
        let commit = head
            .peel_to_commit()
            .map_err(|error| git(format!("could not read HEAD commit: {error}")))?;
        Ok(commit.id().to_string())
    }

    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String, ChainkeeperError> {
        if message.trim().is_empty() {
            return Err(git("commit message must not be empty"));
        }

        let repository = self.repository()?;

        // Directories are expanded, and tracked paths that disappeared are
        // staged as deletions so a move between canonical status directories
        // commits atomically. A missing untracked path is still rejected.
        let mut additions = BTreeSet::new();
        let mut removals = BTreeSet::new();
        for path in paths {
            let relative = self.relative_path(path)?;
            let absolute = self.root.join(&relative);
            if absolute.is_file() {
                additions.insert(relative);
            } else if absolute.is_dir() {
                self.collect_files(&relative, &mut additions)?;
            } else if Self::is_tracked(&repository, &relative)? {
                removals.insert(relative);
            } else {
                return Err(git(format!(
                    "required path {} does not exist",
                    relative.display()
                )));
            }
        }
        if additions.is_empty() && removals.is_empty() {
            return Err(git("commit requires at least one path"));
        }

        let mut index = repository
            .index()
            .map_err(|error| git(format!("could not read git index: {error}")))?;
        for relative in &additions {
            index
                .add_path(relative)
                .map_err(|error| git(format!("could not stage {}: {error}", relative.display())))?;
        }
        for relative in &removals {
            if let Err(error) = index.remove_path(relative)
                && error.code() != ErrorCode::NotFound
            {
                return Err(git(format!(
                    "could not stage deletion of {}: {error}",
                    relative.display()
                )));
            }
        }
        assert_index_has_no_private_keys(&index)?;
        index
            .write()
            .map_err(|error| git(format!("could not write git index: {error}")))?;

        let tree_id = index
            .write_tree()
            .map_err(|error| git(format!("could not write git tree: {error}")))?;
        let tree = repository
            .find_tree(tree_id)
            .map_err(|error| git(format!("could not read git tree: {error}")))?;
        let parent = Self::head_parent(&repository)?;
        let parents: Vec<&git2::Commit<'_>> = parent.iter().collect();
        self.create_commit(&repository, message, &tree, &parents)
    }

    fn diff(&self, from: &str, to: &str) -> Result<Vec<GitChange>, ChainkeeperError> {
        let repository = self.repository()?;
        let from_commit = repository
            .find_commit(
                Oid::from_str(from)
                    .map_err(|error| git(format!("invalid commit {from:?}: {error}")))?,
            )
            .map_err(|error| git(format!("commit {from} not found: {error}")))?;
        let from_tree = from_commit
            .tree()
            .map_err(|error| git(format!("could not read tree for {from}: {error}")))?;

        let mut diff = if to == WORKTREE {
            let mut options = DiffOptions::new();
            options.include_untracked(true).recurse_untracked_dirs(true);
            repository
                .diff_tree_to_workdir_with_index(Some(&from_tree), Some(&mut options))
                .map_err(|error| git(format!("could not diff working tree: {error}")))?
        } else {
            let to_commit = repository
                .find_commit(
                    Oid::from_str(to)
                        .map_err(|error| git(format!("invalid commit {to:?}: {error}")))?,
                )
                .map_err(|error| git(format!("commit {to} not found: {error}")))?;
            let to_tree = to_commit
                .tree()
                .map_err(|error| git(format!("could not read tree for {to}: {error}")))?;
            repository
                .diff_tree_to_tree(Some(&from_tree), Some(&to_tree), None)
                .map_err(|error| git(format!("could not diff commits: {error}")))?
        };

        let mut find = DiffFindOptions::new();
        find.renames(true);
        diff.find_similar(Some(&mut find))
            .map_err(|error| git(format!("could not detect renames: {error}")))?;

        let mut changes = Vec::new();
        for delta in diff.deltas() {
            let kind = match delta.status() {
                Delta::Added | Delta::Untracked => GitChangeKind::Added,
                Delta::Deleted => GitChangeKind::Deleted,
                Delta::Modified => GitChangeKind::Modified,
                Delta::Renamed => GitChangeKind::Renamed,
                _ => continue,
            };
            let file = if kind == GitChangeKind::Deleted {
                delta.old_file()
            } else {
                delta.new_file()
            };
            if let Some(path) = file.path() {
                changes.push(GitChange {
                    path: path.to_path_buf(),
                    kind,
                });
            }
        }
        changes.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.kind.cmp(&right.kind))
        });
        Ok(changes)
    }

    fn status(&self) -> Result<GitStatus, ChainkeeperError> {
        let repository = self.repository()?;
        let head = repository
            .head()
            .ok()
            .and_then(|head| head.target().map(|oid| oid.to_string()));
        let branch = repository
            .head()
            .ok()
            .and_then(|head| head.shorthand().ok().map(str::to_owned));

        let mut options = StatusOptions::new();
        options
            .include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(false);
        let statuses = repository
            .statuses(Some(&mut options))
            .map_err(|error| git(format!("could not read git status: {error}")))?;

        let mut changes = Vec::new();
        let mut untracked = Vec::new();
        for entry in statuses.iter() {
            let Ok(path) = entry.path() else {
                continue;
            };
            let status = entry.status();
            let path = PathBuf::from(path);
            if status.is_wt_new() {
                untracked.push(path);
                continue;
            }
            let kind = if status.is_index_renamed() || status.is_wt_renamed() {
                GitChangeKind::Renamed
            } else if status.is_index_deleted() || status.is_wt_deleted() {
                GitChangeKind::Deleted
            } else if status.is_index_new() {
                GitChangeKind::Added
            } else if status.is_index_modified()
                || status.is_wt_modified()
                || status.is_index_typechange()
                || status.is_wt_typechange()
            {
                GitChangeKind::Modified
            } else {
                continue;
            };
            changes.push(GitChange { path, kind });
        }
        changes.sort_by(|left, right| left.path.cmp(&right.path));
        untracked.sort();

        Ok(GitStatus {
            branch,
            head,
            clean: changes.is_empty() && untracked.is_empty(),
            changes,
            untracked,
        })
    }

    fn is_clean(&self) -> Result<bool, ChainkeeperError> {
        Ok(self.status()?.clean)
    }
}
