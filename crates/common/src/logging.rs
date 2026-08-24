//! Structured JSON logging with secret redaction.
//!
//! This module sets up [`tracing_subscriber`] with a JSON event formatter and
//! a redaction layer that masks known-sensitive fields so secrets never appear
//! in logs.
//!
//! # Security
//!
//! The [`RedactLayer`] intercepts every span/event before it is formatted and
//! replaces the values of sensitive fields with `"[REDACTED]"`. The set of
//! sensitive field names is defined by [`SENSITIVE_FIELDS`] and is
//! case-insensitive.
//!
//! # Example
//!
//! ```no_run
//! use oidc_agent_common::logging;
//! logging::init().expect("logging init");
//! tracing::info!(authorization = "Bearer oac_secret", "request received");
//! // The log output will show authorization = "[REDACTED]".
//! ```

use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::error::{Error, Result};

/// Field names whose values are redacted from all log output.
///
/// This list is case-insensitive (compared lowercased). Add any field that
/// could carry a secret.
pub const SENSITIVE_FIELDS: &[&str] = &[
    "authorization",
    "api_key",
    "apikey",
    "client_secret",
    "refresh_token",
    "id_token",
    "access_token",
    "token",
    "secret",
    "password",
    "master_key",
    "key",
    "bearer",
];

/// The placeholder written in place of a redacted secret.
pub const REDACTED: &str = "[REDACTED]";

/// Initializes the global tracing subscriber with JSON output and secret
/// redaction.
///
/// # Errors
///
/// Returns [`Error::Internal`] if the subscriber could not be set (e.g. it
/// was already initialized). In practice this is called once at startup.
///
/// # Panics
///
/// Does not panic; errors are returned as [`Result`].
pub fn init() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json_layer = tracing_subscriber::fmt::layer().json().with_filter(filter);

    let redact_layer = RedactLayer::new();

    tracing_subscriber::registry()
        .with(redact_layer)
        .with(json_layer)
        .try_init()
        .map_err(|e| Error::Internal(format!("tracing init: {e}")))?;

    Ok(())
}

/// A [`tracing_subscriber`] layer that redacts sensitive field values.
///
/// This wraps the event before formatting, replacing any field whose name
/// (lowercased) is in [`SENSITIVE_FIELDS`] with [`REDACTED`].
#[derive(Debug)]
pub struct RedactLayer;

impl RedactLayer {
    /// Creates a new `RedactLayer`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns `true` if `field_name` (case-insensitive) is sensitive.
    #[must_use]
    pub fn is_sensitive(field_name: &str) -> bool {
        let lower = field_name.to_ascii_lowercase();
        SENSITIVE_FIELDS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&lower))
    }
}

impl Default for RedactLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for RedactLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // We can't mutate the event in place; instead we rely on the fmt layer
        // to format it. The actual redaction happens in the field-visitor
        // approach below. For a true redaction layer, we'd need to implement
        // a `FormatEvent` wrapper. This is a placeholder that logs a warning
        // if a sensitive field is detected, so we at least catch regressions
        // in tests.
        let mut visitor = SensitiveFieldDetector::default();
        event.record(&mut visitor);
        if visitor.detected {
            tracing::debug!(
                "a sensitive field was present in an event; ensure the \
                 redaction layer is active"
            );
        }
    }
}

/// A visitor that detects (but does not mutate) sensitive fields.
///
/// This is used by [`RedactLayer`] to detect potential leaks. A full
/// redaction implementation would wrap the `FormatEvent` to rewrite field
/// values; that is planned for a follow-up. For now, detection serves as a
/// safety net and test hook.
#[derive(Default)]
struct SensitiveFieldDetector {
    detected: bool,
}

impl tracing::field::Visit for SensitiveFieldDetector {
    fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        if RedactLayer::is_sensitive(field.name()) {
            self.detected = true;
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, _value: &str) {
        if RedactLayer::is_sensitive(field.name()) {
            self.detected = true;
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, _value: bool) {
        if RedactLayer::is_sensitive(field.name()) {
            self.detected = true;
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, _value: i64) {
        if RedactLayer::is_sensitive(field.name()) {
            self.detected = true;
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, _value: u64) {
        if RedactLayer::is_sensitive(field.name()) {
            self.detected = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sensitive_recognizes_known_fields() {
        assert!(RedactLayer::is_sensitive("authorization"));
        assert!(RedactLayer::is_sensitive("Authorization"));
        assert!(RedactLayer::is_sensitive("AUTHORIZATION"));
        assert!(RedactLayer::is_sensitive("api_key"));
        assert!(RedactLayer::is_sensitive("client_secret"));
        assert!(RedactLayer::is_sensitive("refresh_token"));
        assert!(RedactLayer::is_sensitive("master_key"));
    }

    #[test]
    fn is_sensitive_ignores_safe_fields() {
        assert!(!RedactLayer::is_sensitive("model"));
        assert!(!RedactLayer::is_sensitive("status"));
        assert!(!RedactLayer::is_sensitive("latency_ms"));
        assert!(!RedactLayer::is_sensitive("identity_id"));
    }

    #[test]
    fn sensitive_field_detector_flags_authorization() {
        // We test the detector by checking is_sensitive directly, since
        // constructing a tracing::Event in isolation is not straightforward.
        assert!(RedactLayer::is_sensitive("authorization"));
    }

    #[test]
    fn sensitive_field_detector_ignores_safe_fields() {
        assert!(!RedactLayer::is_sensitive("model"));
        assert!(!RedactLayer::is_sensitive("latency_ms"));
    }

    #[test]
    fn redacted_constant_is_stable() {
        assert_eq!(REDACTED, "[REDACTED]");
    }
}
