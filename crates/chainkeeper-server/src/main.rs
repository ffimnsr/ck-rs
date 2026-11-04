//! `ck-server` read-only PKI server entry point.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use chainkeeper_core::{
    AuditLog, CertificateStore, Clock, GitRepository, IdGenerator, OcspResponder,
    ProductionIdGenerator, PublishBuilder, RepositoryLock, RepositoryPaths, ServerStateProvider,
    SystemClock, init_tracing,
};
use chainkeeper_git::GitRepo;
use chainkeeper_server::config::ServerConfig;
use chainkeeper_server::snapshot::{RepositoryDeps, RepositoryStateProvider};
use chainkeeper_server::watcher::WatchConfig;
use chainkeeper_server::{AppState, NotReadyOcsp, ReloadHook, Watcher, router, serve};
use chainkeeper_store::{FileRepositoryLock, FileStore};
use clap::{CommandFactory, FromArgMatches, Parser};
use tokio::sync::watch;

fn version_string() -> String {
    let dirty = if option_env!("VERGEN_GIT_DIRTY") == Some("true") {
        "-dirty"
    } else {
        ""
    };
    format!(
        "{} (commit {}{dirty}, {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
        option_env!("VERGEN_CARGO_TARGET_TRIPLE").unwrap_or("unknown"),
    )
}

#[derive(Debug, Parser)]
#[command(name = "ck-server", about = "Chainkeeper read-only PKI server")]
struct Cli {
    /// Address to bind the HTTP listener to.
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,

    /// Repository root to serve.
    #[arg(long, value_name = "PATH")]
    repo: Option<PathBuf>,

    /// External publish directory rebuilt by the server.
    #[arg(long, value_name = "PATH")]
    publish_dir: Option<PathBuf>,

    /// Configuration file, default `server.yaml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Disable coloured output.
    #[arg(long)]
    no_color: bool,
}

struct Runtime {
    provider: Arc<RepositoryStateProvider>,
    publish: Arc<chainkeeper_publish::FilePublishBuilder>,
    publish_dir: PathBuf,
}

fn load_config(cli: &Cli) -> Result<ServerConfig> {
    let path = cli
        .config
        .clone()
        .or_else(|| std::env::var_os("CHAINKEEPER_SERVER_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("server.yaml"));
    let mut config =
        ServerConfig::read(&path).with_context(|| format!("could not load {}", path.display()))?;
    if let Some(bind) = &cli.bind {
        config.bind = bind.parse().context("invalid --bind address")?;
    }
    if let Some(repo) = &cli.repo {
        config.repo.clone_from(repo);
    }
    if let Some(publish_dir) = &cli.publish_dir {
        config.publish_dir.clone_from(publish_dir);
    }
    config.validate().context("invalid server configuration")?;
    Ok(config)
}

fn build_runtime(config: &ServerConfig) -> Result<Runtime> {
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
    let publish = Arc::new(chainkeeper_publish::FilePublishBuilder::new(
        chainkeeper_publish::PublishDependencies::new(
            clock,
            store as Arc<dyn CertificateStore>,
            git as Arc<dyn GitRepository>,
            paths,
        ),
    ));
    Ok(Runtime {
        provider,
        publish,
        publish_dir,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = Cli::command().version(version_string());
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let config = load_config(&cli)?;

    init_tracing()?;
    if cli.no_color {
        tracing::debug!("colour output disabled");
    }

    let runtime = build_runtime(&config)?;
    let ocsp = Arc::new(NotReadyOcsp);

    let options = chainkeeper_core::PublishOptions {
        output_dir: runtime.publish_dir.clone(),
        clean: true,
        dry_run: false,
        no_commit: true,
    };
    let reload: Arc<dyn ReloadHook> = {
        let provider = Arc::clone(&runtime.provider);
        let publish = Arc::clone(&runtime.publish);
        let ocsp = Arc::clone(&ocsp);
        Arc::new(move || {
            publish.build(&options)?;
            provider.reload()?;
            ocsp.reload()?;
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
        Arc::new(SystemClock),
        reload,
    )?);

    let state = AppState::new(
        Arc::clone(&runtime.provider) as Arc<dyn ServerStateProvider>,
        ocsp as Arc<dyn OcspResponder>,
        runtime.publish_dir.clone(),
    )
    .with_watcher(watcher.status());

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("could not bind {}", config.bind))?;
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        tracing::warn!(%address, "serving on a non-loopback address");
    }
    println!("ck-server listening on http://{address}");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let watcher_task = tokio::spawn(Arc::clone(&watcher).run(shutdown_rx.clone()));

    let result = serve(listener, router(state), shutdown_signal()).await;
    let _ = shutdown_tx.send(true);
    if let Err(error) = watcher_task.await {
        tracing::warn!(%error, "watcher task failed");
    }
    result.context("server error")
}

async fn shutdown_signal() {
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
