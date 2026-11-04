//! Server configuration.
//!
//! Configuration comes from `server.yaml` with environment variable overrides.
//! Every value has a safe default, and validation rejects a repository that is
//! not under Git or a publish directory inside the repository tree.

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use chainkeeper_core::ChainkeeperError;
use serde::Deserialize;

/// Listen address used when configuration does not set one.
pub const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// Publish directory, relative to the repository root.
pub const DEFAULT_PUBLISH_DIR: &str = ".chainkeeper/publish";
/// Git polling interval used when configuration does not set one.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(15);
/// Branch watched by default.
pub const DEFAULT_BRANCH: &str = "main";
/// Environment variable holding the OCSP signer key path.
pub const OCSP_KEY_ENV: &str = "CHAINKEEPER_OCSP_KEY_PATH";

const POLL_ENV: &str = "CHAINKEEPER_POLL_INTERVAL";
const BIND_ENV: &str = "CHAINKEEPER_BIND";
const REPO_ENV: &str = "CHAINKEEPER_REPO";
const PUBLISH_ENV: &str = "CHAINKEEPER_PUBLISH_DIR";
const REMOTE_ENV: &str = "CHAINKEEPER_REMOTE";
const BRANCH_ENV: &str = "CHAINKEEPER_BRANCH";
const SYNC_ENV: &str = "CHAINKEEPER_SYNC_REMOTE";
const CONFIG_ENV: &str = "CHAINKEEPER_SERVER_CONFIG";

/// Validated runtime configuration for `ck-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Address the HTTP listener binds to.
    pub bind: SocketAddr,
    /// Repository root that is served.
    pub repo: PathBuf,
    /// Publish directory, absolute or relative to `repo`.
    pub publish_dir: PathBuf,
    /// How often the Git watcher polls for new commits.
    pub poll_interval: Duration,
    /// Remote fetched when `sync_remote` is enabled.
    pub remote: Option<String>,
    /// Branch fetched and watched.
    pub branch: String,
    /// Whether the watcher fetches and fast-forwards the remote.
    pub sync_remote: bool,
    /// Path to the dedicated OCSP signer key.
    pub ocsp_key_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    bind: Option<String>,
    repo: Option<PathBuf>,
    publish_dir: Option<PathBuf>,
    poll_interval: Option<PollInterval>,
    remote: Option<String>,
    branch: Option<String>,
    sync_remote: Option<bool>,
    ocsp_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PollInterval {
    Seconds(u64),
    Text(String),
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            repo: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            publish_dir: PathBuf::from(DEFAULT_PUBLISH_DIR),
            poll_interval: DEFAULT_POLL_INTERVAL,
            remote: None,
            branch: DEFAULT_BRANCH.to_owned(),
            sync_remote: false,
            ocsp_key_path: None,
        }
    }
}

fn config(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::config(message)
}

fn parse_bind(value: &str) -> Result<SocketAddr, ChainkeeperError> {
    value
        .parse()
        .map_err(|error| config(format!("invalid bind address {value:?}: {error}")))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, ChainkeeperError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(config(format!(
            "invalid boolean {other:?} for {key}, expected true or false"
        ))),
    }
}

fn parse_interval(value: &str) -> Result<Duration, ChainkeeperError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(config("poll interval must not be empty"));
    }
    let (digits, multiplier) = match trimmed.as_bytes().last() {
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 3600),
        _ => (trimmed, 1),
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|error| config(format!("invalid poll interval {value:?}: {error}")))?;
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| config("poll interval is too large"))?;
    if seconds == 0 {
        return Err(config("poll interval must be greater than zero"));
    }
    Ok(Duration::from_secs(seconds))
}

fn normalize(path: &Path) -> PathBuf {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() {
                    clean.push(component.as_os_str());
                }
            }
            other => clean.push(other.as_os_str()),
        }
    }
    clean
}

fn absolute(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize(path)
    } else {
        normalize(&base.join(path))
    }
}

impl ServerConfig {
    /// Loads `server.yaml` from `path`, or defaults when it is missing.
    ///
    /// Environment variables are applied after the file.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the file is unreadable or
    /// malformed, or a value fails validation.
    pub fn load(path: &Path) -> Result<Self, ChainkeeperError> {
        let settings = Self::read(path)?;
        settings.validate()?;
        Ok(settings)
    }

    /// Reads `server.yaml` from `path` without validating the paths.
    ///
    /// Callers apply command line overrides before [`Self::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the file is unreadable or
    /// malformed.
    pub fn read(path: &Path) -> Result<Self, ChainkeeperError> {
        let yaml = match std::fs::read_to_string(path) {
            Ok(yaml) => Some(yaml),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(config(format!(
                    "could not read {}: {error}",
                    path.display()
                )));
            }
        };
        Self::from_yaml(yaml.as_deref(), |key| std::env::var_os(key))
    }

    /// Loads the configuration named by `CHAINKEEPER_SERVER_CONFIG`, falling
    /// back to `server.yaml` in the current directory.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when loading fails.
    pub fn load_default() -> Result<Self, ChainkeeperError> {
        let path = std::env::var_os(CONFIG_ENV)
            .map_or_else(|| PathBuf::from("server.yaml"), PathBuf::from);
        Self::load(&path)
    }

    /// Builds a configuration from YAML plus an environment lookup.
    ///
    /// The lookup is injectable so tests never mutate process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the YAML or a value is invalid.
    pub fn from_yaml(
        yaml: Option<&str>,
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, ChainkeeperError> {
        let raw = match yaml {
            Some(text) if !text.trim().is_empty() => serde_yaml_ng::from_str::<RawConfig>(text)
                .map_err(|error| {
                    config(format!("could not parse server configuration: {error}"))
                })?,
            _ => RawConfig::default(),
        };

        let mut settings = Self::default();
        if let Some(bind) = raw.bind {
            settings.bind = parse_bind(&bind)?;
        }
        if let Some(repo) = raw.repo {
            settings.repo = repo;
        }
        if let Some(publish_dir) = raw.publish_dir {
            settings.publish_dir = publish_dir;
        }
        if let Some(interval) = raw.poll_interval {
            settings.poll_interval = match interval {
                PollInterval::Seconds(seconds) => {
                    if seconds == 0 {
                        return Err(config("poll interval must be greater than zero"));
                    }
                    Duration::from_secs(seconds)
                }
                PollInterval::Text(text) => parse_interval(&text)?,
            };
        }
        settings.remote = raw.remote;
        if let Some(branch) = raw.branch {
            settings.branch = branch;
        }
        if let Some(sync_remote) = raw.sync_remote {
            settings.sync_remote = sync_remote;
        }
        settings.ocsp_key_path = raw.ocsp_key_path;

        let value = |key: &str| -> Result<Option<String>, ChainkeeperError> {
            lookup(key)
                .map(|raw| {
                    raw.into_string()
                        .map_err(|_| config(format!("{key} is not valid UTF-8")))
                })
                .transpose()
        };
        if let Some(text) = value(BIND_ENV)? {
            settings.bind = parse_bind(&text)?;
        }
        if let Some(text) = value(REPO_ENV)? {
            settings.repo = PathBuf::from(text);
        }
        if let Some(text) = value(PUBLISH_ENV)? {
            settings.publish_dir = PathBuf::from(text);
        }
        if let Some(text) = value(POLL_ENV)? {
            settings.poll_interval = parse_interval(&text)?;
        }
        if let Some(text) = value(REMOTE_ENV)? {
            settings.remote = Some(text);
        }
        if let Some(text) = value(BRANCH_ENV)? {
            settings.branch = text;
        }
        if let Some(text) = value(SYNC_ENV)? {
            settings.sync_remote = parse_bool(SYNC_ENV, &text)?;
        }
        if let Some(text) = value(OCSP_KEY_ENV)? {
            settings.ocsp_key_path = Some(PathBuf::from(text));
        }
        Ok(settings)
    }

    /// Absolute repository root.
    #[must_use]
    pub fn resolved_repo(&self) -> PathBuf {
        let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        absolute(&self.repo, &base)
    }

    /// Absolute publish directory.
    #[must_use]
    pub fn resolved_publish_dir(&self) -> PathBuf {
        absolute(&self.publish_dir, &self.resolved_repo())
    }

    /// Validates every configured path.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the repository is missing, not
    /// a Git repository, or the publish directory is unsafe.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        let repo = self.resolved_repo();
        if !repo.is_dir() {
            return Err(config(format!(
                "repository {} is not a directory",
                repo.display()
            )));
        }
        if !repo.join(".git").exists() {
            return Err(config(format!(
                "repository {} is not a git repository",
                repo.display()
            )));
        }
        if self.poll_interval.is_zero() {
            return Err(config("poll interval must be greater than zero"));
        }
        if self.branch.trim().is_empty() {
            return Err(config("branch must not be empty"));
        }
        if self
            .remote
            .as_deref()
            .is_some_and(|remote| remote.trim().is_empty())
        {
            return Err(config("remote must not be empty when set"));
        }
        if self
            .ocsp_key_path
            .as_deref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(config("ocsp_key_path must not be empty when set"));
        }
        self.validate_publish_dir(&repo)
    }

    fn validate_publish_dir(&self, repo: &Path) -> Result<(), ChainkeeperError> {
        let publish = self.resolved_publish_dir();
        let Ok(relative) = publish.strip_prefix(repo) else {
            return Ok(());
        };
        let allowed = relative
            .components()
            .next()
            .is_some_and(|component| component.as_os_str() == ".chainkeeper");
        if allowed {
            Ok(())
        } else {
            Err(config(format!(
                "publish directory {} must be outside the repository or under .chainkeeper/",
                publish.display()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{DEFAULT_BIND, DEFAULT_POLL_INTERVAL, ServerConfig, parse_interval};

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    #[test]
    fn defaults_apply_without_configuration() {
        let config = ServerConfig::from_yaml(None, no_env).expect("defaults");
        assert_eq!(config.bind.to_string(), DEFAULT_BIND);
        assert_eq!(config.publish_dir, PathBuf::from(".chainkeeper/publish"));
        assert_eq!(config.poll_interval, DEFAULT_POLL_INTERVAL);
        assert_eq!(config.branch, "main");
        assert!(!config.sync_remote);
        assert!(config.remote.is_none());
    }

    #[test]
    fn yaml_values_are_overridden_by_environment() {
        let yaml = "bind: 127.0.0.1:9000\nbranch: trunk\nsync_remote: true\npoll_interval: 30s\n";
        let config = ServerConfig::from_yaml(Some(yaml), |key| match key {
            "CHAINKEEPER_BIND" => Some(OsString::from("127.0.0.1:9100")),
            "CHAINKEEPER_SYNC_REMOTE" => Some(OsString::from("false")),
            _ => None,
        })
        .expect("configuration");
        assert_eq!(config.bind.to_string(), "127.0.0.1:9100");
        assert_eq!(config.branch, "trunk");
        assert!(!config.sync_remote);
        assert_eq!(config.poll_interval, Duration::from_secs(30));
    }

    #[test]
    fn poll_interval_accepts_suffixes() {
        assert_eq!(
            parse_interval("15").expect("seconds"),
            Duration::from_secs(15)
        );
        assert_eq!(
            parse_interval("2m").expect("minutes"),
            Duration::from_secs(120)
        );
        assert_eq!(
            parse_interval("1h").expect("hours"),
            Duration::from_secs(3600)
        );
        assert!(parse_interval("0").is_err());
        assert!(parse_interval("fast").is_err());
    }

    #[test]
    fn invalid_boolean_is_rejected() {
        let error = ServerConfig::from_yaml(None, |key| {
            (key == "CHAINKEEPER_SYNC_REMOTE").then(|| OsString::from("sometimes"))
        })
        .expect_err("invalid boolean");
        assert!(error.to_string().contains("invalid boolean"), "{error}");
    }

    #[test]
    fn unknown_yaml_keys_are_rejected() {
        assert!(ServerConfig::from_yaml(Some("watchers: 2\n"), no_env).is_err());
    }

    fn repository() -> (tempfile::TempDir, ServerConfig) {
        let directory = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(directory.path().join(".git")).expect("git marker");
        let config = ServerConfig {
            repo: directory.path().to_path_buf(),
            publish_dir: PathBuf::from(".chainkeeper/publish"),
            ..ServerConfig::default()
        };
        (directory, config)
    }

    #[test]
    fn publish_directory_under_chainkeeper_is_allowed() {
        let (_directory, config) = repository();
        config.validate().expect("valid configuration");
    }

    #[test]
    fn publish_directory_outside_repository_is_allowed() {
        let (_directory, mut config) = repository();
        config.publish_dir = PathBuf::from("/var/www/chainkeeper");
        config.validate().expect("external publish directory");
    }

    #[test]
    fn publish_directory_inside_repository_is_rejected() {
        let (_directory, mut config) = repository();
        config.publish_dir = PathBuf::from("public");
        let error = config.validate().expect_err("unsafe publish directory");
        assert!(error.to_string().contains(".chainkeeper"), "{error}");
    }

    #[test]
    fn missing_repository_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let config = ServerConfig {
            repo: directory.path().join("missing"),
            ..ServerConfig::default()
        };
        let error = config.validate().expect_err("missing repository");
        assert!(error.to_string().contains("not a directory"), "{error}");
    }

    #[test]
    fn non_git_repository_is_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let config = ServerConfig {
            repo: directory.path().to_path_buf(),
            ..ServerConfig::default()
        };
        let error = config.validate().expect_err("not a git repository");
        assert!(error.to_string().contains("git repository"), "{error}");
    }

    #[test]
    fn publish_dir_escaping_chainkeeper_is_rejected() {
        let (_directory, mut config) = repository();
        config.publish_dir = PathBuf::from(".chainkeeper/../public");
        let error = config.validate().expect_err("escapes chainkeeper");
        assert!(error.to_string().contains(".chainkeeper"), "{error}");
    }
}
