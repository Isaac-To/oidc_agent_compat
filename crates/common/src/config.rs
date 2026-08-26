//! Configuration structs and validation for both components.
//!
//! The relay and the central proxy each load a TOML config file at startup.
//! This module defines the schema, parses it, and validates it before the
//! component starts serving traffic.
//!
//! # Security
//!
//! - The relay rejects `0.0.0.0` as a listen address (must be loopback).
//! - Secrets are never stored as literals in config; the OIDC client secret
//!   is referenced by environment-variable name (`client_secret_env`).
//!   Provider API keys are managed through the central admin API and are
//!   encrypted at rest with `OAC_PROVIDER_ENCRYPTION_KEY`.
//!
//! # Example (relay)
//!
//! ```toml
//! listen_addr = "127.0.0.1:8787"
//! database_url = "sqlite://~/.oidc-agent-compat/relay.db"
//!
//! [oidc]
//! issuer = "https://idp.example.com"
//! client_id = "relay-client"
//! client_secret_env = "OIDC_CLIENT_SECRET"
//! redirect_uri = "http://127.0.0.1:0/callback"
//! scopes = ["openid", "email", "profile"]
//!
//! [central]
//! url = "https://central.example.com"
//! ca_cert_path = "/etc/oac/ca.pem"
//! client_cert_path = "~/.oac/client.pem"
//! client_key_path = "~/.oac/client.key"
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Configuration for the laptop relay component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayConfig {
    /// The loopback address to listen on (e.g. `127.0.0.1:8787`).
    pub listen_addr: SocketAddr,
    /// The database URL (SQLite for v1, e.g. `sqlite://~/.oac/relay.db`).
    pub database_url: String,
    /// OIDC relying-party settings.
    pub oidc: OidcConfig,
    /// Central proxy connection settings (mTLS).
    pub central: CentralConnectionConfig,
    /// When true, allows non-loopback listen addresses (for containerized
    /// dev environments). Defaults to false for production safety.
    #[serde(default)]
    pub dev_mode: bool,
    /// Local API key session lifetime in hours. Keys minted after OIDC login
    /// expire after this long and the user must re-run `oac-relay login`.
    /// Defaults to 24 hours. `None` means keys never expire and is intended
    /// only for explicit compatibility configurations. The dev-mode seeded
    /// key is exempt.
    ///
    /// This implements the documented v1 security posture: no OIDC tokens
    /// are stored; the local key is the only credential kept on the laptop,
    /// and this bounds how long it remains valid.
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: Option<u64>,
}

/// Configuration for the central proxy component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CentralConfig {
    /// The address to listen on (e.g. `0.0.0.0:8443` behind a load balancer).
    pub listen_addr: SocketAddr,
    /// The database URL (Postgres for prod, SQLite for dev).
    pub database_url: String,
    /// OIDC relying-party settings (for token validation).
    pub oidc: OidcConfig,
    /// mTLS server settings.
    pub mtls: MtlsServerConfig,
    /// Admin API settings. Optional; if absent, the admin API is disabled.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// Pricing settings for cost tracking. Optional; if absent, costs are
    /// not computed (cost_usd is always 0.0 in the audit log).
    #[serde(default)]
    pub pricing: Option<PricingConfig>,
    /// When true, allows requests without relay-forwarded identity headers
    /// (for the containerized dev stack). Defaults to false for production
    /// safety.
    #[serde(default)]
    pub dev_mode: bool,
    /// Maximum requests per rate-limit window per client IP in production.
    /// Defaults to 60.
    #[serde(default = "default_rate_limit_requests")]
    pub rate_limit_requests: u32,
    /// Rate-limit window in seconds. Defaults to 60.
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
}

/// Admin API configuration.
///
/// The admin API is authenticated via the IdP through the relay (same
/// OIDC login flow as regular users). Access is authorized by checking
/// the user's group memberships against the configured `admin_group`.
/// No static admin token is used — the admin's OIDC identity is the auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminConfig {
    /// The group name that grants admin API access. Users who belong to
    /// this group (via their IdP groups/roles claims) may call the admin
    /// API; all others are denied (403).
    pub admin_group: String,
}

/// Pricing configuration for cost tracking.
///
/// Maps model names to per-1K-token prices so the central proxy can compute
/// the cost of each request and record it in the audit log + usage counters.
/// Prices can also be auto-fetched from the backend's `/v1/models` endpoint
/// (e.g. OpenRouter); manual entries act as overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Per-model price entries. These act as **overrides** — they take
    /// precedence over any prices auto-fetched from the backend.
    #[serde(default)]
    pub models: Vec<ModelPriceConfig>,
    /// Auto-fetch interval in seconds. If `0`, auto-fetch is disabled and
    /// only manual config prices are used. Defaults to 3600 (1 hour).
    #[serde(default = "default_fetch_interval")]
    pub fetch_interval_secs: u64,
}

/// Default auto-fetch interval (1 hour).
fn default_fetch_interval() -> u64 {
    3600
}

/// Default production requests per rate-limit window.
fn default_rate_limit_requests() -> u32 {
    60
}

/// Default production rate-limit window in seconds.
fn default_rate_limit_window_secs() -> u64 {
    60
}

/// Default local OIDC session lifetime (24 hours).
fn default_session_ttl_hours() -> Option<u64> {
    Some(24)
}

/// A single model's pricing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelPriceConfig {
    /// The model name (must match the `model` field in request bodies).
    pub model: String,
    /// Price per 1K input (prompt) tokens in USD.
    pub input_per_1k_usd: f64,
    /// Price per 1K output (completion) tokens in USD.
    pub output_per_1k_usd: f64,
}

/// OIDC relying-party configuration shared by both components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConfig {
    /// The issuer URL (e.g. `https://idp.example.com`).
    pub issuer: String,
    /// The client ID registered with the IdP.
    pub client_id: String,
    /// The name of the environment variable holding the client secret.
    pub client_secret_env: String,
    /// The redirect URI (loopback, e.g. `http://127.0.0.1:0/callback`).
    pub redirect_uri: String,
    /// The OIDC scopes to request.
    pub scopes: Vec<String>,
}

/// Central proxy connection settings for the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CentralConnectionConfig {
    /// The central proxy URL (e.g. `https://central.example.com`).
    pub url: String,
    /// Path to the company CA certificate (PEM).
    pub ca_cert_path: PathBuf,
    /// Path to the relay's mTLS client certificate (PEM).
    pub client_cert_path: PathBuf,
    /// Path to the relay's mTLS client private key (PEM).
    pub client_key_path: PathBuf,
}

/// mTLS server configuration for the central proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsServerConfig {
    /// Path to the company CA certificate (PEM).
    pub ca_cert_path: PathBuf,
    /// Path to the server certificate (PEM).
    pub server_cert_path: PathBuf,
    /// Path to the server private key (PEM).
    pub server_key_path: PathBuf,
}

impl RelayConfig {
    /// Parses a `RelayConfig` from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the TOML is malformed or fails validation.
    ///
    /// # Example
    ///
    /// ```
    /// use oidc_agent_common::config::RelayConfig;
    /// let toml = r#"
    /// listen_addr = "127.0.0.1:8787"
    /// database_url = "sqlite://relay.db"
    /// [oidc]
    /// issuer = "https://idp.example.com"
    /// client_id = "relay"
    /// client_secret_env = "SECRET"
    /// redirect_uri = "http://127.0.0.1:0/callback"
    /// scopes = ["openid"]
    /// [central]
    /// url = "https://central.example.com"
    /// ca_cert_path = "/ca.pem"
    /// client_cert_path = "/client.pem"
    /// client_key_path = "/client.key"
    /// "#;
    /// let cfg = RelayConfig::from_toml(toml).unwrap();
    /// assert_eq!(cfg.listen_addr.port(), 8787);
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let cfg: Self =
            toml::from_str(toml_str).map_err(|e| Error::Config(format!("toml parse: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates the config, returning an error if any field is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if:
    /// - `listen_addr` is not a loopback address (unless `dev_mode` is true).
    /// - `oidc.issuer` is empty or not a valid URL.
    /// - `oidc.client_id` is empty.
    /// - `oidc.client_secret_env` is empty.
    /// - `oidc.redirect_uri` does not start with `http://127.0.0.1`.
    /// - `central.url` is empty or not `https://`.
    pub fn validate(&self) -> Result<()> {
        if !self.dev_mode {
            validate_loopback(&self.listen_addr)?;
        }
        validate_oidc(&self.oidc)?;
        if !self.dev_mode {
            validate_central_url(&self.central.url)?;
        }
        if let Some(ttl) = self.session_ttl_hours {
            // 0 would expire keys immediately (login would be useless);
            // 876_000 hours = 100 years is the sanity ceiling.
            if ttl == 0 || ttl > 876_000 {
                return Err(Error::Config(format!(
                    "session_ttl_hours must be between 1 and 876000, got {ttl}"
                )));
            }
        }
        Ok(())
    }
}

impl CentralConfig {
    /// Parses a `CentralConfig` from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the TOML is malformed or fails validation.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let cfg: Self =
            toml::from_str(toml_str).map_err(|e| Error::Config(format!("toml parse: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates the config.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if OIDC fields are invalid.
    pub fn validate(&self) -> Result<()> {
        validate_oidc(&self.oidc)?;
        if self.rate_limit_requests == 0 {
            return Err(Error::Config(
                "rate_limit_requests must be greater than zero".into(),
            ));
        }
        if self.rate_limit_window_secs == 0 {
            return Err(Error::Config(
                "rate_limit_window_secs must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

/// Validates that a socket address is loopback (127.0.0.0/8 or ::1).
fn validate_loopback(addr: &SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        return Err(Error::Config(format!(
            "listen_addr {addr} must be a loopback address (127.0.0.0/8 or ::1); \
             binding to non-loopback addresses is forbidden for the relay"
        )));
    }
    Ok(())
}

/// Validates OIDC config fields.
fn validate_oidc(oidc: &OidcConfig) -> Result<()> {
    if oidc.issuer.is_empty() {
        return Err(Error::Config("oidc.issuer must not be empty".into()));
    }
    if !oidc.issuer.starts_with("https://") && !oidc.issuer.starts_with("http://") {
        return Err(Error::Config(format!(
            "oidc.issuer must be an http(s) URL, got: {}",
            oidc.issuer
        )));
    }
    if oidc.client_id.is_empty() {
        return Err(Error::Config("oidc.client_id must not be empty".into()));
    }
    if oidc.client_secret_env.is_empty() {
        return Err(Error::Config(
            "oidc.client_secret_env must not be empty".into(),
        ));
    }
    if !oidc.redirect_uri.starts_with("http://127.0.0.1") {
        return Err(Error::Config(format!(
            "oidc.redirect_uri must be a loopback http URL (http://127.0.0.1:...), got: {}",
            oidc.redirect_uri
        )));
    }
    Ok(())
}

/// Validates the central proxy URL is https.
fn validate_central_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(Error::Config("central.url must not be empty".into()));
    }
    if !url.starts_with("https://") {
        return Err(Error::Config(format!(
            "central.url must be https://, got: {url}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_relay_toml() -> &'static str {
        r#"
listen_addr = "127.0.0.1:8787"
database_url = "sqlite://relay.db"
[oidc]
issuer = "https://idp.example.com"
client_id = "relay"
client_secret_env = "SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid", "email"]
[central]
url = "https://central.example.com"
ca_cert_path = "/ca.pem"
client_cert_path = "/client.pem"
client_key_path = "/client.key"
"#
    }

    fn valid_central_toml() -> &'static str {
        r#"
listen_addr = "0.0.0.0:8443"
database_url = "postgres://central"
[oidc]
issuer = "https://idp.example.com"
client_id = "central"
client_secret_env = "SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid"]
[mtls]
ca_cert_path = "/ca.pem"
server_cert_path = "/server.pem"
server_key_path = "/server.key"
"#
    }

    #[test]
    fn relay_config_parses_valid_toml() {
        let cfg = RelayConfig::from_toml(valid_relay_toml()).expect("valid config");
        assert_eq!(cfg.listen_addr.port(), 8787);
        assert_eq!(cfg.oidc.client_id, "relay");
        assert_eq!(cfg.central.url, "https://central.example.com");
    }

    #[test]
    fn central_config_parses_valid_toml() {
        let cfg = CentralConfig::from_toml(valid_central_toml()).expect("valid config");
        assert_eq!(cfg.database_url, "postgres://central");
        assert_eq!(cfg.rate_limit_requests, 60);
        assert_eq!(cfg.rate_limit_window_secs, 60);
    }

    #[test]
    fn central_rejects_zero_rate_limit_settings() {
        let toml = valid_central_toml().replace(
            "database_url = \"postgres://central\"",
            "database_url = \"postgres://central\"\nrate_limit_requests = 0",
        );
        let err = CentralConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("rate_limit_requests"), "{err}");

        let toml = valid_central_toml().replace(
            "database_url = \"postgres://central\"",
            "database_url = \"postgres://central\"\nrate_limit_window_secs = 0",
        );
        let err = CentralConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("rate_limit_window_secs"), "{err}");
    }

    #[test]
    fn relay_rejects_non_loopback_listen_addr() {
        let toml = valid_relay_toml().replace("127.0.0.1:8787", "0.0.0.0:8787");
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[test]
    fn relay_dev_mode_allows_non_loopback() {
        let toml = valid_relay_toml()
            .replace("127.0.0.1:8787", "0.0.0.0:8787")
            .replace(
                "database_url = \"sqlite://relay.db\"",
                "database_url = \"sqlite://relay.db\"\ndev_mode = true",
            );
        let cfg = RelayConfig::from_toml(&toml).expect("dev_mode allows non-loopback");
        assert_eq!(
            cfg.listen_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert!(cfg.dev_mode);
        assert_eq!(cfg.session_ttl_hours, Some(24));
    }

    #[test]
    fn relay_session_ttl_parses_and_validates() {
        let toml = valid_relay_toml().replace(
            "database_url = \"sqlite://relay.db\"",
            "database_url = \"sqlite://relay.db\"\nsession_ttl_hours = 24",
        );
        let cfg = RelayConfig::from_toml(&toml).expect("valid ttl");
        assert_eq!(cfg.session_ttl_hours, Some(24));
    }

    #[test]
    fn relay_rejects_zero_session_ttl() {
        let toml = valid_relay_toml().replace(
            "database_url = \"sqlite://relay.db\"",
            "database_url = \"sqlite://relay.db\"\nsession_ttl_hours = 0",
        );
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("session_ttl_hours"), "{err}");
    }

    #[test]
    fn relay_rejects_absurd_session_ttl() {
        let toml = valid_relay_toml().replace(
            "database_url = \"sqlite://relay.db\"",
            "database_url = \"sqlite://relay.db\"\nsession_ttl_hours = 9000000",
        );
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("session_ttl_hours"), "{err}");
    }

    #[test]
    fn relay_rejects_empty_issuer() {
        let toml = valid_relay_toml().replace("https://idp.example.com", "");
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("issuer"), "{err}");
    }

    #[test]
    fn relay_rejects_non_http_issuer() {
        let toml = valid_relay_toml().replace("https://idp.example.com", "ftp://bad");
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("http(s)"), "{err}");
    }

    #[test]
    fn relay_rejects_non_loopback_redirect_uri() {
        let toml = valid_relay_toml().replace(
            "http://127.0.0.1:0/callback",
            "https://evil.example.com/callback",
        );
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[test]
    fn relay_rejects_non_https_central_url() {
        let toml = valid_relay_toml().replace("https://central.example.com", "http://central");
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("https"), "{err}");
    }

    #[test]
    fn relay_rejects_empty_client_id() {
        let toml = valid_relay_toml().replace("client_id = \"relay\"", "client_id = \"\"");
        let err = RelayConfig::from_toml(&toml).unwrap_err();
        assert!(err.to_string().contains("client_id"), "{err}");
    }

    #[test]
    fn malformed_toml_returns_config_error() {
        let err = RelayConfig::from_toml("not valid toml {{{").unwrap_err();
        assert!(err.to_string().contains("toml parse"), "{err}");
    }
}
