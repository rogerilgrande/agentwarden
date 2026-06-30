//! Runtime configuration, assembled from environment variables over defaults.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::anyhow;

use crate::types::AdminKey;

/// Server configuration. Built by [`Config::from_env`].
#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) policy_path: PathBuf,
    pub(crate) addr: SocketAddr,
    /// Hot-reload interval in seconds; `0` disables the reload daemon.
    pub(crate) reload_secs: u64,
    /// When set, `POST /reload` requires a matching `x-admin-key` header. The
    /// redacting `Debug` on `AdminKey` keeps it out of the startup log.
    pub(crate) admin_key: Option<AdminKey>,
}

impl Config {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            policy_path: env_str("AGENTWARDEN_POLICY")?
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("policy.toml")),
            addr: env_parsed("AGENTWARDEN_ADDR")?
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8080))),
            reload_secs: env_parsed("AGENTWARDEN_RELOAD_SECS")?.unwrap_or(5),
            admin_key: parse_admin_key(env_str("AGENTWARDEN_ADMIN_KEY")?)?,
        })
    }
}

/// Validate the configured admin key. A set-but-empty value would enable
/// `/reload` yet authorize a request that sends no key (empty equals empty), so
/// it is rejected loudly here rather than silently failing open at request time.
fn parse_admin_key(raw: Option<String>) -> anyhow::Result<Option<AdminKey>> {
    match raw {
        Some(key) if key.trim().is_empty() => Err(anyhow!(
            "AGENTWARDEN_ADMIN_KEY is set but empty; unset it to disable /reload"
        )),
        Some(key) => Ok(Some(AdminKey::new(key))),
        None => Ok(None),
    }
}

/// Read an env var, distinguishing "unset" (`Ok(None)`) from "set but unreadable".
fn env_str(key: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(key) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow!("{key}: {e}")),
    }
}

/// Like [`env_str`], but parse the value and fail loudly on a malformed one
/// rather than silently falling back to the default.
fn env_parsed<T>(key: &str) -> anyhow::Result<Option<T>>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match env_str(key)? {
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|e| anyhow!("{key}: invalid value {v:?}: {e}")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_admin_key_is_rejected() {
        assert!(parse_admin_key(Some(String::new())).is_err());
        assert!(parse_admin_key(Some("   ".to_owned())).is_err());
    }

    #[test]
    fn unset_admin_key_disables_auth() {
        assert!(matches!(parse_admin_key(None), Ok(None)));
    }

    #[test]
    fn a_real_admin_key_is_accepted() {
        assert!(matches!(
            parse_admin_key(Some("s3cret".to_owned())),
            Ok(Some(_))
        ));
    }
}
