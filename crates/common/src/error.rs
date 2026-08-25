//! Unified error type for all components.
//!
//! This module defines a single [`Error`] enum that wraps every error kind
//! that can occur across the relay and the central proxy. Using one type
//! avoids error-conversion boilerplate at component boundaries and keeps
//! the error surface auditable.
//!
//! # Design
//!
//! - [`Error`] implements [`std::error::Error`] via [`thiserror`] and is
//!   `Clone`-free (errors are one-shot).
//! - Each variant carries enough context to produce a useful log message
//!   without leaking secrets (see [`Display`][std::fmt::Display] impls).
//! - The [`Result`] alias shortens signatures across the codebase.

use thiserror::Error;

/// The unified result type used across all components.
pub type Result<T> = std::result::Result<T, Error>;

/// Every error that can occur in the OIDC agent compatibility server.
///
/// Variants are grouped by subsystem so that callers can match on the
/// relevant category without inspecting the full enum.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration is missing, malformed, or fails validation.
    #[error("configuration error: {0}")]
    Config(String),

    /// An OIDC protocol error (discovery, token exchange, ID-token validation).
    #[error("oidc error: {0}")]
    Oidc(String),

    /// A database or migration error.
    #[error("database error: {0}")]
    Database(String),

    /// A database error from sea-orm, preserving the source for error
    /// chaining. Use [`Error::database`] to add a context prefix.
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),

    /// An HTTP client or server error.
    #[error("http error: {0}")]
    Http(String),

    /// An HTTP client error from reqwest, preserving the source for error
    /// chaining. Use [`Error::http`] to add a context prefix.
    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// A cryptographic error (key generation, hashing, comparison).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// An mTLS / TLS error (cert loading, handshake, validation).
    #[error("tls error: {0}")]
    Tls(String),

    /// A secret-store error (Vault, AWS Secrets Manager, etc.).
    #[error("secret store error: {0}")]
    SecretStore(String),

    /// Authentication failed (invalid local key, expired token, etc.).
    #[error("authentication error: {0}")]
    Auth(String),

    /// Authorization failed (the user is authenticated but not permitted to
    /// perform the requested action, e.g. model not in allowlist, endpoint
    /// restricted, device revoked, quota exceeded).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// An I/O error (file system, network).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A catch-all for errors that don't fit another category.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Creates a [`Error::Config`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn config(msg: impl std::fmt::Display) -> Self {
        Self::Config(msg.to_string())
    }

    /// Creates a [`Error::Oidc`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn oidc(msg: impl std::fmt::Display) -> Self {
        Self::Oidc(msg.to_string())
    }

    /// Creates a [`Error::Crypto`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn crypto(msg: impl std::fmt::Display) -> Self {
        Self::Crypto(msg.to_string())
    }

    /// Creates a [`Error::Auth`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn auth(msg: impl std::fmt::Display) -> Self {
        Self::Auth(msg.to_string())
    }

    /// Creates a [`Error::Forbidden`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn forbidden(msg: impl std::fmt::Display) -> Self {
        Self::Forbidden(msg.to_string())
    }

    /// Creates a [`Error::Internal`] from any [`Display`][std::fmt::Display] value.
    #[must_use]
    pub fn internal(msg: impl std::fmt::Display) -> Self {
        Self::Internal(msg.to_string())
    }

    /// Creates a [`Error::Database`] with a context prefix from any
    /// [`Display`][std::fmt::Display] value.
    ///
    /// Prefer this over `Error::Database(format!("...: {e}"))` when you have a
    /// concrete `sea_orm::DbErr` — use `?` or `.map_err(Error::from)` to get
    /// [`Error::Db`] (which preserves the source), or this helper when you
    /// need a descriptive prefix.
    #[must_use]
    pub fn database(msg: impl std::fmt::Display) -> Self {
        Self::Database(msg.to_string())
    }

    /// Creates a [`Error::Http`] with a context prefix from any
    /// [`Display`][std::fmt::Display] value.
    ///
    /// Prefer this over `Error::Http(format!("...: {e}"))` when you have a
    /// concrete `reqwest::Error` — use `?` or `.map_err(Error::from)` to get
    /// [`Error::Reqwest`] (which preserves the source), or this helper when
    /// you need a descriptive prefix.
    #[must_use]
    pub fn http(msg: impl std::fmt::Display) -> Self {
        Self::Http(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_do_not_leak_secrets() {
        let err = Error::Auth("invalid bearer token".to_string());
        assert_eq!(
            err.to_string(),
            "authentication error: invalid bearer token"
        );
    }

    #[test]
    fn constructors_produce_correct_variants() {
        assert!(matches!(Error::config("x"), Error::Config(_)));
        assert!(matches!(Error::oidc("x"), Error::Oidc(_)));
        assert!(matches!(Error::crypto("x"), Error::Crypto(_)));
        assert!(matches!(Error::auth("x"), Error::Auth(_)));
        assert!(matches!(Error::internal("x"), Error::Internal(_)));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn serde_error_conversion() {
        let serde_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err: Error = serde_err.into();
        assert!(matches!(err, Error::Serde(_)));
    }
}
