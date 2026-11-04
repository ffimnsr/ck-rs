//! Production runtime wiring for the read-only server.
//!
//! [`build_state`] composes the canonical store, Git repository, publish
//! builder, snapshot provider, OCSP responder, and Git watcher. The binary and
//! the integration tests use the same function so both exercise the real
//! object graph.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use chainkeeper_core::{
    AuditLog, AuthorityName, CertificateStore, ChainkeeperError, Clock, GitRepository, IdGenerator,
    OcspResponder, ProductionIdGenerator, PublishBuilder, PublishOptions, RepositoryLock,
    RepositoryPaths, ServerStateProvider, Signer, SystemClock,
};
use chainkeeper_engine::FileSigners;
use chainkeeper_git::GitRepo;
use chainkeeper_ocsp::{FileOcspResponder, OcspDependencies};
use chainkeeper_publish::{FilePublishBuilder, PublishDependencies};
use chainkeeper_store::{FileRepositoryLock, FileStore};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::config::ServerConfig;
use crate::snapshot::{RepositoryDeps, RepositoryStateProvider};
use crate::state::AppState;
use crate::watcher::{ReloadHook, WatchConfig, Watcher};
use crate::{router, serve};

/// Authority name of the dedicated OCSP signer.
pub const OCSP_SIGNER: &str = "ocsp-signer";

/// Every component the server serves.
pub struct Runtime {
    config: ServerConfig,
    provider: Arc<RepositoryStateProvider>,
    publish: Arc<FilePublishBuilder>,
    watcher: Arc<Watcher>,
    ocsp: Arc<FileOcspResponder>,
    state: AppState,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Runtime")
            .field("config", &self.config)
            .field("watcher", &self.watcher)
            .finish_non_exhaustive()
    }
}

/// Resolves only the dedicated OCSP signer key.
///
/// The read-only server must never open root or intermediate key material, so
/// every other authority is rejected before touching the filesystem.
struct OcspSigners {
    inner: FileSigners,
}

impl chainkeeper_ocsp::AuthoritySigners for OcspSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        if authority.as_str() != OCSP_SIGNER {
            return Err(ChainkeeperError::not_found(
                "OCSP signer authority",
                authority.as_str(),
            ));
        }
        self.inner.signer_for(authority)
    }
}

impl std::fmt::Debug for OcspSigners {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcspSigners")
            .finish_non_exhaustive()
    }
}

/// Builds the complete runtime state for `config`.
///
/// The configuration must already be validated by [`ServerConfig::validate`].
///
/// # Errors
///
/// Returns a storage, Git, publish, or snapshot error when the repository
/// cannot be served.
pub fn build_state(config: &ServerConfig) -> Result<Runtime> {
    let paths = RepositoryPaths::new(&config.repo)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> = Arc::new(ProductionIdGenerator);
    let store = Arc::new(FileStore::with_clock(paths.clone(), Arc::clone(&clock)));
    let lock: Arc<dyn RepositoryLock> = Arc::new(FileRepositoryLock::new(paths.clone()));
    let audit = Arc::new(chainkeeper_audit::FileAuditLog::new(
        paths.clone(),
        Arc::clone(&lock),
        Arc::clone(&ids),
    ));
    let git = Arc::new(GitRepo::open(&config.repo)?);
    let publish_dir = config.resolved_publish_dir();

    let deps = RepositoryDeps {
        clock: Arc::clone(&clock),
        store: Arc::clone(&store) as Arc<dyn CertificateStore>,
        audit: audit as Arc<dyn AuditLog>,
        git: Arc::clone(&git) as Arc<dyn GitRepository>,
        publish_dir: publish_dir.clone(),
    };
    let provider = Arc::new(RepositoryStateProvider::open(deps)?);

    let publish = Arc::new(FilePublishBuilder::new(
        PublishDependencies::new(
            Arc::clone(&clock),
            Arc::clone(&store) as Arc<dyn CertificateStore>,
            Arc::clone(&git) as Arc<dyn GitRepository>,
            paths.clone(),
        )
        .with_allowed_root(publish_root(&publish_dir)),
    ));

    let ocsp = build_ocsp(config, paths, Arc::clone(&clock), Arc::clone(&store));
    let options = PublishOptions {
        output_dir: publish_dir.clone(),
        clean: true,
        dry_run: false,
        no_commit: true,
    };
    let reload: Arc<dyn ReloadHook> = {
        let provider = Arc::clone(&provider);
        let publish = Arc::clone(&publish);
        let ocsp = Arc::clone(&ocsp);
        Arc::new(move || {
            publish.build(&options)?;
            provider.reload()?;
            // A missing OCSP signer must not break repository reloads; the
            // readiness probe reports it separately.
            if let Err(error) = ocsp.reload() {
                tracing::warn!(error = %error, "ocsp state reload failed");
            }
            Ok(())
        })
    };
    let watcher = Arc::new(Watcher::new(
        GitRepo::open(&config.repo)?,
        WatchConfig {
            poll_interval: config.poll_interval,
            remote: config.remote.clone(),
            branch: config.branch.clone(),
            sync_remote: config.sync_remote,
        },
        Arc::clone(&clock),
        reload,
    )?);

    let state = AppState::new(
        Arc::clone(&provider) as Arc<dyn chainkeeper_core::ServerStateProvider>,
        Arc::clone(&ocsp) as Arc<dyn OcspResponder>,
        publish_dir,
    )
    .with_watcher(watcher.status());

    Ok(Runtime {
        config: config.clone(),
        provider,
        publish,
        watcher,
        ocsp,
        state,
    })
}

fn publish_root(publish_dir: &Path) -> PathBuf {
    let root = publish_dir
        .parent()
        .map_or_else(|| publish_dir.to_path_buf(), Path::to_path_buf);
    if let Err(error) = std::fs::create_dir_all(&root) {
        tracing::warn!(error = %error, path = %root.display(), "could not create publish root");
    }
    root
}

fn build_ocsp(
    config: &ServerConfig,
    paths: RepositoryPaths,
    clock: Arc<dyn Clock>,
    store: Arc<FileStore>,
) -> Arc<FileOcspResponder> {
    let mut signers = FileSigners::from_env(paths.clone());
    if let Some(path) = &config.ocsp_key_path {
        match AuthorityName::new(OCSP_SIGNER) {
            Ok(name) => signers = signers.with_key_path(name, path.clone()),
            Err(error) => tracing::warn!(error = %error, "invalid OCSP signer name"),
        }
    }
    let responder = FileOcspResponder::new(OcspDependencies::new(
        clock,
        store as Arc<dyn CertificateStore>,
        Arc::new(OcspSigners { inner: signers }),
        paths,
        AuthorityName::new(OCSP_SIGNER).expect("constant OCSP signer name is valid"),
    ));
    if let Err(error) = responder.reload() {
        tracing::warn!(error = %error, "ocsp responder is not ready");
    }
    Arc::new(responder)
}

impl Runtime {
    /// Validated configuration.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Application state used by the router.
    #[must_use]
    pub const fn state(&self) -> &AppState {
        &self.state
    }

    /// Snapshot provider.
    #[must_use]
    pub const fn provider(&self) -> &Arc<RepositoryStateProvider> {
        &self.provider
    }

    /// Publish builder used by reloads.
    #[must_use]
    pub const fn publish(&self) -> &Arc<FilePublishBuilder> {
        &self.publish
    }

    /// Git watcher.
    #[must_use]
    pub const fn watcher(&self) -> &Arc<Watcher> {
        &self.watcher
    }

    /// OCSP responder.
    #[must_use]
    pub const fn ocsp(&self) -> &Arc<FileOcspResponder> {
        &self.ocsp
    }

    /// Router for this state.
    pub fn app(&self) -> axum::Router {
        router(self.state.clone())
    }

    /// Serves this runtime on `listener` until `shutdown` resolves.
    ///
    /// The watcher task is signalled and awaited before returning.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when accepting connections fails.
    pub async fn serve<F>(&self, listener: TcpListener, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let watcher_task = tokio::spawn(Arc::clone(&self.watcher).run(shutdown_rx));
        let result = serve(listener, router(self.state.clone()), shutdown).await;
        let _ = shutdown_tx.send(true);
        if let Err(error) = watcher_task.await {
            tracing::warn!(%error, "watcher task failed");
        }
        result.context("server error")
    }

    /// Serves this runtime until the process is signalled.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when binding or accepting connections fails.
    pub async fn run_until_signalled(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind)
            .await
            .with_context(|| format!("could not bind {}", self.config.bind))?;
        let address = listener.local_addr()?;
        if !address.ip().is_loopback() {
            tracing::warn!(%address, "serving on a non-loopback address");
        }
        println!("ck-server listening on http://{address}");
        self.serve(listener, shutdown_signal()).await
    }
}

/// Waits for Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "could not listen for ctrl-c");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!(%error, "could not listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    println!("shutting down");
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{AuthorityName, RepositoryPaths};
    use chainkeeper_engine::FileSigners;
    use chainkeeper_ocsp::AuthoritySigners as _;

    use super::{OCSP_SIGNER, OcspSigners};

    #[test]
    fn ocsp_signers_reject_ca_key_material() {
        let directory = tempfile::tempdir().expect("temporary repository");
        let paths = RepositoryPaths::new(directory.path()).expect("paths");
        let signers = OcspSigners {
            inner: FileSigners::from_env(paths),
        };
        for name in ["root", "tls", "smime", "codesign", "ocsp"] {
            let authority = AuthorityName::new(name).expect("authority name");
            let Err(error) = signers.signer_for(&authority) else {
                panic!("CA key material must be rejected")
            };
            assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);
        }
        // The dedicated signer is the only authority whose key may be read.
        let signer = AuthorityName::new(OCSP_SIGNER).expect("signer name");
        assert!(signers.signer_for(&signer).is_err(), "no key on disk yet");
    }
}
