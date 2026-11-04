//! Git change detection.
//!
//! The watcher reacts to `.git/HEAD` and `.git/refs` events and also polls
//! `HEAD` every interval. Bursts are debounced, unchanged commits are ignored,
//! and a reload failure leaves the previous snapshot untouched.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chainkeeper_core::{ChainkeeperError, Clock, GitRepository};
use chainkeeper_git::GitRepo;
use notify::{RecursiveMode, Watcher as _};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::sync::watch;

/// Debounce window applied to bursts of filesystem events.
pub const DEBOUNCE: Duration = Duration::from_millis(250);

/// Watcher configuration derived from [`crate::ServerConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchConfig {
    /// How often `HEAD` is polled.
    pub poll_interval: Duration,
    /// Remote to fetch from when `sync_remote` is enabled.
    pub remote: Option<String>,
    /// Branch fetched from the remote.
    pub branch: String,
    /// Whether the watcher fetches and fast-forwards.
    pub sync_remote: bool,
}

/// Callback invoked after a new commit is detected.
pub trait ReloadHook: Send + Sync {
    /// Rebuilds artifacts and reloads the served state.
    ///
    /// # Errors
    ///
    /// Returns any error from rebuilding or reloading.
    fn reload(&self) -> Result<(), ChainkeeperError>;
}

impl<F> ReloadHook for F
where
    F: Fn() -> Result<(), ChainkeeperError> + Send + Sync,
{
    fn reload(&self) -> Result<(), ChainkeeperError> {
        self()
    }
}

/// Outcome of one change check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchOutcome {
    /// Whether a reload happened.
    pub changed: bool,
    /// Commit that is served after the check.
    pub commit: String,
}

/// Last observed watcher state, exposed through `/api/v1/health`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchHealth {
    /// Commit served by the last successful reload.
    pub last_commit: Option<String>,
    /// Time of the last successful reload.
    pub last_reload_at: Option<OffsetDateTime>,
    /// Most recent failure, cleared by the next success.
    pub last_error: Option<String>,
    /// Number of successful reloads.
    pub reloads: u64,
}

/// Shared watcher status.
#[derive(Debug, Default)]
pub struct WatchStatus {
    inner: RwLock<WatchHealth>,
}

impl WatchStatus {
    /// Creates an empty status.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a copy of the current state.
    #[must_use]
    pub fn health(&self) -> WatchHealth {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn record_success(&self, commit: &str, at: OffsetDateTime) {
        let mut health = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        health.last_commit = Some(commit.to_owned());
        health.last_reload_at = Some(at);
        health.last_error = None;
        health.reloads = health.reloads.saturating_add(1);
    }

    fn record_error(&self, error: &ChainkeeperError) {
        let mut health = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        health.last_error = Some(error.to_string());
    }
}

/// Git commit watcher.
pub struct Watcher {
    repo: GitRepo,
    config: WatchConfig,
    reload: Arc<dyn ReloadHook>,
    clock: Arc<dyn Clock>,
    last_oid: Mutex<Option<String>>,
    status: Arc<WatchStatus>,
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Watcher")
            .field("root", &self.repo.root())
            .field("config", &self.config)
            .field("status", &self.status.health())
            .finish_non_exhaustive()
    }
}

impl Watcher {
    /// Creates a watcher anchored on the current `HEAD`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when `HEAD` cannot be read.
    pub fn new(
        repo: GitRepo,
        config: WatchConfig,
        clock: Arc<dyn Clock>,
        reload: Arc<dyn ReloadHook>,
    ) -> Result<Self, ChainkeeperError> {
        let head = repo.head_commit()?;
        Ok(Self {
            repo,
            config,
            reload,
            clock,
            last_oid: Mutex::new(Some(head)),
            status: Arc::new(WatchStatus::new()),
        })
    }

    /// Shared status for the health endpoint.
    #[must_use]
    pub fn status(&self) -> Arc<WatchStatus> {
        Arc::clone(&self.status)
    }

    /// Checks `HEAD` once, synchronising and reloading when it moved.
    ///
    /// # Errors
    ///
    /// Returns a Git error when `HEAD` or the remote cannot be read, and the
    /// reload error when rebuilding fails. The previous commit is kept so the
    /// next check retries.
    pub fn check_once(&self) -> Result<WatchOutcome, ChainkeeperError> {
        let result = self.check_inner();
        if let Err(error) = &result {
            self.status.record_error(error);
        }
        result
    }

    fn check_inner(&self) -> Result<WatchOutcome, ChainkeeperError> {
        let head = if self.config.sync_remote {
            let remote = self.config.remote.as_deref().ok_or_else(|| {
                ChainkeeperError::config("sync_remote requires a configured remote")
            })?;
            self.repo
                .fetch_and_fast_forward(remote, &self.config.branch)?
                .commit
        } else {
            self.repo.head_commit()?
        };

        let previous = self
            .last_oid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if previous.as_deref() == Some(head.as_str()) {
            return Ok(WatchOutcome {
                changed: false,
                commit: head,
            });
        }

        self.reload.reload()?;
        *self
            .last_oid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(head.clone());
        self.status.record_success(&head, self.clock.now());
        Ok(WatchOutcome {
            changed: true,
            commit: head,
        })
    }

    /// Runs until `shutdown` is signalled.
    ///
    /// # Errors
    ///
    /// Returns a Git error when the notify watcher cannot be created.
    pub async fn run(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ChainkeeperError> {
        let (events, mut receiver) = mpsc::unbounded_channel();
        let mut notify_watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if let Ok(event) = event {
                    let _ = events.send(event);
                }
            })
            .map_err(|error| {
                ChainkeeperError::git(format!("could not start git watcher: {error}"))
            })?;

        for path in watch_paths(self.repo.root()) {
            if let Err(error) = notify_watcher.watch(&path, RecursiveMode::Recursive) {
                tracing::warn!(path = %path.display(), %error, "could not watch git path");
            }
        }

        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                _ = interval.tick() => self.check_logged(),
                event = receiver.recv() => {
                    if event.is_none() {
                        return Ok(());
                    }
                    tokio::select! {
                        () = tokio::time::sleep(DEBOUNCE) => {}
                        _ = shutdown.changed() => return Ok(()),
                    }
                    while receiver.try_recv().is_ok() {}
                    self.check_logged();
                }
            }
        }
    }

    fn check_logged(&self) {
        match self.check_once() {
            Ok(outcome) if outcome.changed => {
                tracing::info!(commit = %outcome.commit, "repository reloaded");
            }
            Ok(_) => tracing::debug!("repository unchanged"),
            Err(error) => tracing::warn!(%error, "repository reload failed"),
        }
    }
}

fn watch_paths(root: &std::path::Path) -> Vec<PathBuf> {
    let git = root.join(".git");
    vec![git.join("HEAD"), git.join("refs")]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chainkeeper_core::{GitRepository, SystemClock};
    use chainkeeper_git::{GitIdentity, GitRepo};

    use super::{WatchConfig, Watcher};

    fn repository() -> (tempfile::TempDir, GitRepo) {
        let directory = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            directory.path().join("tenant.yaml"),
            "version: 1\ntenant_id: acme\ndisplay_name: Acme\ncreated_at: 2024-05-01T12:00:00Z\ndefault_profile: tls-server\n",
        )
        .expect("tenant");
        let raw = git2::Repository::init_opts(
            directory.path(),
            git2::RepositoryInitOptions::new().initial_head("main"),
        )
        .expect("raw repository");
        raw.config()
            .expect("config")
            .set_bool("commit.gpgsign", false)
            .expect("disable signing");
        let identity =
            GitIdentity::new("Chainkeeper Tests", "tests@example.com").expect("identity");
        let repo = GitRepo::new(directory.path()).with_identity(identity);
        GitRepository::init(&repo, directory.path()).expect("repository");
        (directory, repo)
    }

    fn commit(repo: &GitRepo, root: &std::path::Path, name: &str) {
        std::fs::write(root.join(name), "content\n").expect("write file");
        GitRepository::commit(repo, "test: commit", &[std::path::PathBuf::from(name)])
            .expect("commit");
    }

    fn watcher(root: &std::path::Path, config: WatchConfig, counter: Arc<AtomicUsize>) -> Watcher {
        let reload: Arc<dyn super::ReloadHook> = Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let repo = GitRepo::open(root).expect("watch repository");
        Watcher::new(repo, config, Arc::new(SystemClock), reload).expect("watcher")
    }

    fn config(sync_remote: bool) -> WatchConfig {
        WatchConfig {
            poll_interval: std::time::Duration::from_secs(60),
            remote: None,
            branch: "main".to_owned(),
            sync_remote,
        }
    }

    #[test]
    fn unchanged_commit_does_not_reload() {
        let (directory, _repo) = repository();
        let counter = Arc::new(AtomicUsize::new(0));
        let watcher = watcher(directory.path(), config(false), Arc::clone(&counter));

        let outcome = watcher.check_once().expect("check");

        assert!(!outcome.changed);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn new_commit_triggers_one_reload() {
        let (directory, repo) = repository();
        let counter = Arc::new(AtomicUsize::new(0));
        let watcher = watcher(directory.path(), config(false), Arc::clone(&counter));
        watcher.check_once().expect("initial check");

        commit(&repo, directory.path(), "note.txt");
        let outcome = watcher.check_once().expect("check");

        assert!(outcome.changed);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(watcher.status().health().reloads, 1);

        let outcome = watcher.check_once().expect("check");
        assert!(!outcome.changed);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_reload_keeps_previous_commit_and_retries() {
        let (directory, repo) = repository();
        let attempts = Arc::new(AtomicUsize::new(0));
        let reload: Arc<dyn super::ReloadHook> = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(chainkeeper_core::ChainkeeperError::publish(
                    "rebuild failed",
                ))
            })
        };
        let watcher = Watcher::new(
            GitRepo::open(directory.path()).expect("watch repository"),
            config(false),
            Arc::new(SystemClock),
            reload,
        )
        .expect("watcher");
        commit(&repo, directory.path(), "note.txt");

        assert!(watcher.check_once().is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(watcher.status().health().last_error.is_some());

        assert!(watcher.check_once().is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dirty_tree_blocks_remote_sync_without_reloading() {
        let (directory, _repo) = repository();
        let counter = Arc::new(AtomicUsize::new(0));
        let watcher = watcher(
            directory.path(),
            WatchConfig {
                remote: Some("origin".to_owned()),
                sync_remote: true,
                ..config(false)
            },
            Arc::clone(&counter),
        );
        std::fs::write(directory.path().join("tenant.yaml"), "dirty\n").expect("dirty tree");

        let error = watcher.check_once().expect_err("dirty tree");
        assert!(error.to_string().contains("dirty"), "{error}");
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
