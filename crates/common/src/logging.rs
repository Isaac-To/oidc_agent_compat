//! Structured JSON logging with secret redaction.
//!
//! This module sets up [`tracing_subscriber`] with a JSON event formatter and
//! a redacting writer that masks known-sensitive fields so secrets never
//! appear in logs.
//!
//! # Security
//!
//! The [`RedactingMakeWriter`] intercepts log output at the writer level,
//! scanning each line for sensitive field names and replacing their values
//! with `"[REDACTED]"`. The set of sensitive field names is defined by
//! [`SENSITIVE_FIELDS`] and is case-insensitive.
//!
//! # Example
//!
//! ```no_run
//! use oidc_agent_common::logging;
//! logging::init().expect("logging init");
//! tracing::info!(authorization = "Bearer oac_secret", "request received");
//! // The log output will show authorization = "[REDACTED]".
//! ```

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use tracing_subscriber::Layer;
use tracing_subscriber::fmt::MakeWriter;
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

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(RedactingMakeWriter::new(io::stdout()))
        .with_filter(filter);

    tracing_subscriber::registry()
        .with(json_layer)
        .try_init()
        .map_err(|e| Error::Internal(format!("tracing init: {e}")))?;

    Ok(())
}

/// Returns `true` if `field_name` (case-insensitive) is sensitive.
#[must_use]
pub fn is_sensitive(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    SENSITIVE_FIELDS
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&lower))
}

/// A [`MakeWriter`] that wraps an inner writer and redacts sensitive field
/// values from each log line before writing.
///
/// This is the standard tracing-subscriber pattern for log redaction: we
/// intercept at the writer level, buffering each line, redacting sensitive
/// JSON fields, then writing the redacted output to the real writer.
pub struct RedactingMakeWriter<W> {
    inner: Arc<Mutex<W>>,
}

impl<W> RedactingMakeWriter<W> {
    /// Creates a new `RedactingMakeWriter` wrapping the given writer.
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl<W> Clone for RedactingMakeWriter<W> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<'a, W> MakeWriter<'a> for RedactingMakeWriter<W>
where
    W: io::Write + Send + 'a,
{
    type Writer = RedactingWriter<W>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: Arc::clone(&self.inner),
            buf: Mutex::new(Vec::new()),
        }
    }
}

/// A writer that buffers output, redacts sensitive fields on flush, and
/// writes to the inner writer.
pub struct RedactingWriter<W: io::Write> {
    inner: Arc<Mutex<W>>,
    buf: Mutex<Vec<u8>>,
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut buf = self
            .buf
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut buf = self
            .buf
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        if buf.is_empty() {
            return Ok(());
        }
        let output = String::from_utf8_lossy(&buf);
        let redacted = redact_json_fields(&output);
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        inner.write_all(redacted.as_bytes())?;
        inner.flush()?;
        buf.clear();
        Ok(())
    }
}

impl<W: io::Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Redacts sensitive field values in a JSON log line.
///
/// Scans for patterns like `"authorization":"value"` or `"authorization": "value"`
/// and replaces the value with `[REDACTED]`. This is a lightweight regex-free
/// approach that handles the standard JSON formatter's output.
///
/// # Panics
///
/// This function manually checks bounds before every index access; the
/// `indexing_slicing` lint is suppressed because the safety is enforced by
/// the control flow (every `bytes[i]` is preceded by a bounds check).
#[allow(clippy::indexing_slicing)]
fn redact_json_fields(json_line: &str) -> String {
    let bytes = json_line.as_bytes();
    let mut result = String::with_capacity(json_line.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = find_closing_quote(bytes, i) {
                let field_name = &json_line[i + 1..end];
                if is_sensitive(field_name) {
                    result.push_str(&json_line[i..=end]);
                    let mut j = end + 1;
                    while j < bytes.len() && (bytes[j].is_ascii_whitespace() || bytes[j] == b':') {
                        result.push(bytes[j] as char);
                        j += 1;
                    }
                    if j < bytes.len() {
                        let value_end = find_value_end(bytes, j);
                        result.push('"');
                        result.push_str(REDACTED);
                        result.push('"');
                        i = value_end;
                        continue;
                    }
                }
                result.push_str(&json_line[i..=end]);
                i = end + 1;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

/// Finds the index of the closing quote for a JSON string starting at `start`
/// (where `bytes[start] == b'"'`), handling escaped quotes.
#[allow(clippy::indexing_slicing)]
fn find_closing_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Finds the end of a JSON value starting at `start` (after the colon).
/// Handles strings, numbers, booleans, null, objects, and arrays.
#[allow(clippy::indexing_slicing)]
fn find_value_end(bytes: &[u8], start: usize) -> usize {
    if start >= bytes.len() {
        return start;
    }
    match bytes[start] {
        b'"' => find_closing_quote(bytes, start)
            .map(|e| e + 1)
            .unwrap_or(bytes.len()),
        b'{' | b'[' => {
            let open = bytes[start];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut depth = 1;
            let mut i = start + 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == open {
                    depth += 1;
                } else if bytes[i] == close {
                    depth -= 1;
                }
                i += 1;
            }
            i
        }
        _ => {
            let mut i = start;
            while i < bytes.len()
                && bytes[i] != b','
                && bytes[i] != b'}'
                && bytes[i] != b']'
                && !bytes[i].is_ascii_whitespace()
            {
                i += 1;
            }
            i
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sensitive_recognizes_known_fields() {
        assert!(is_sensitive("authorization"));
        assert!(is_sensitive("Authorization"));
        assert!(is_sensitive("AUTHORIZATION"));
        assert!(is_sensitive("api_key"));
        assert!(is_sensitive("client_secret"));
        assert!(is_sensitive("refresh_token"));
        assert!(is_sensitive("master_key"));
    }

    #[test]
    fn is_sensitive_ignores_safe_fields() {
        assert!(!is_sensitive("model"));
        assert!(!is_sensitive("status"));
        assert!(!is_sensitive("latency_ms"));
        assert!(!is_sensitive("identity_id"));
    }

    #[test]
    fn redacted_constant_is_stable() {
        assert_eq!(REDACTED, "[REDACTED]");
    }

    #[test]
    fn redact_json_fields_replaces_authorization_value() {
        let input = r#"{"authorization":"Bearer sk-secret","model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""authorization":"[REDACTED]""#));
        assert!(output.contains(r#""model":"gpt-4""#));
        assert!(!output.contains("sk-secret"));
    }

    #[test]
    fn redact_json_fields_handles_spaces_around_colon() {
        let input = r#"{"authorization": "Bearer sk-secret"}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""authorization": "[REDACTED]""#));
        assert!(!output.contains("sk-secret"));
    }

    #[test]
    fn redact_json_fields_preserves_non_sensitive_fields() {
        let input = r#"{"model":"gpt-4","status":200,"latency_ms":42}"#;
        let output = redact_json_fields(input);
        assert_eq!(output, input);
    }

    #[test]
    fn redact_json_fields_handles_multiple_sensitive_fields() {
        let input = r#"{"authorization":"Bearer tok","api_key":"sk-key","model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""authorization":"[REDACTED]""#));
        assert!(output.contains(r#""api_key":"[REDACTED]""#));
        assert!(output.contains(r#""model":"gpt-4""#));
        assert!(!output.contains("tok"));
        assert!(!output.contains("sk-key"));
    }

    #[test]
    fn redact_json_fields_handles_non_string_sensitive_values() {
        let input = r#"{"key":12345,"model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""key":"[REDACTED]""#));
        assert!(output.contains(r#""model":"gpt-4""#));
    }

    #[test]
    fn redact_json_fields_handles_escaped_quotes_in_value() {
        let input = r#"{"model":"gpt-4","authorization":"Bearer \"secret\""}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""authorization":"[REDACTED]""#));
        assert!(!output.contains("secret"));
    }
}
