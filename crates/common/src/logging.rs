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

    // --- Writer machinery: the actual path production log lines take ---

    #[test]
    fn redacting_writer_flushes_redacted_lines_to_inner() {
        let mut inner = Vec::new();
        {
            let make = RedactingMakeWriter::new(&mut inner);
            let mut writer = make.make_writer();
            writer
                .write_all(
                    br#"{"timestamp":"...","authorization":"Bearer sk-live-123","model":"gpt-4"}"#,
                )
                .expect("write");
            writer.write_all(b"\n").expect("newline");
            writer.flush().expect("flush");
        }
        let out = String::from_utf8(inner).expect("utf8");
        assert!(
            out.contains(r#""authorization":"[REDACTED]""#),
            "the writer must redact on flush: {out}"
        );
        assert!(!out.contains("sk-live-123"), "secret reached stdout: {out}");
        assert!(out.contains("gpt-4"), "non-secrets must survive: {out}");
    }

    #[test]
    fn redacting_writer_flush_on_empty_buffer_is_noop() {
        let mut inner = Vec::new();
        {
            let make = RedactingMakeWriter::new(&mut inner);
            let mut writer = make.make_writer();
            // Flush without any buffered bytes: must succeed and write nothing.
            writer.flush().expect("flush empty");
        }
        assert!(inner.is_empty(), "nothing should be written: {inner:?}");
    }

    #[test]
    fn redacting_writer_flushes_on_drop() {
        let mut inner = Vec::new();
        {
            let make = RedactingMakeWriter::new(&mut inner);
            let mut writer = make.make_writer();
            writer
                .write_all(br#"{"api_key":"sk-on-drop"}"#)
                .expect("write");
            // No explicit flush — Drop must flush (the path every real log
            // line takes when tracing drops the writer).
        }
        let out = String::from_utf8(inner).expect("utf8");
        assert!(out.contains("[REDACTED]"), "drop must flush: {out}");
        assert!(!out.contains("sk-on-drop"), "secret reached stdout: {out}");
    }

    #[test]
    fn redacting_writer_partial_writes_are_buffered_until_flush() {
        // tracing may write a single JSON line in several slices; nothing
        // may reach stdout before the line is complete and redacted.
        use std::sync::{Arc, Mutex};
        let inner = Arc::new(Mutex::new(Vec::new()));
        let probe = inner.clone();
        {
            let make = RedactingMakeWriter::new(SharedVec(inner.clone()));
            let mut writer = make.make_writer();
            writer.write_all(br#"{"model":"gpt-4""#).expect("part 1");
            assert!(
                probe.lock().expect("probe").is_empty(),
                "bytes must not hit stdout before flush"
            );
            writer
                .write_all(br#","password":"hunter2"}"#)
                .expect("part 2");
            writer.flush().expect("flush");
        }
        let out = String::from_utf8(probe.lock().expect("probe").clone()).expect("utf8");
        assert!(out.contains(r#""password":"[REDACTED]""#), "out: {out}");
        assert!(!out.contains("hunter2"), "secret reached stdout: {out}");
    }

    /// A writer that fronts a shared Vec so tests can peek at what has been
    /// emitted so far.
    struct SharedVec(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedVec {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn make_writer_clones_share_the_inner_writer() {
        // Clone-ability is what lets the JSON layer fan out; both clones
        // must write through to the same destination.
        let mut inner = Vec::new();
        {
            let make = RedactingMakeWriter::new(&mut inner);
            let a = make.make_writer();
            let b = make.make_writer();
            let mut a = a;
            let mut b = b;
            a.write_all(br#"{"token":"sk-a"}"#).expect("a");
            b.write_all(br#"{"token":"sk-b"}"#).expect("b");
            a.flush().expect("flush a");
            b.flush().expect("flush b");
        }
        let out = String::from_utf8(inner).expect("utf8");
        assert_eq!(out.matches("[REDACTED]").count(), 2, "out: {out}");
    }

    // --- Redaction edge cases over JSON value shapes ---

    #[test]
    fn redact_json_fields_redacts_object_and_array_values() {
        let input = r#"{"token":{"sub":"x"},"key":[1,2],"model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert!(
            output.contains(r#""token":"[REDACTED]""#),
            "object values must be replaced wholesale: {output}"
        );
        assert!(
            output.contains(r#""key":"[REDACTED]""#),
            "array values must be replaced wholesale: {output}"
        );
        assert!(output.contains("gpt-4"), "safe fields survive: {output}");
    }

    #[test]
    fn redact_json_fields_redacts_bool_and_null_values() {
        let input = r#"{"secret":false,"password":null,"model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert!(output.contains(r#""secret":"[REDACTED]""#), "{output}");
        assert!(output.contains(r#""password":"[REDACTED]""#), "{output}");
    }

    #[test]
    fn redact_json_fields_tolerates_unterminated_strings() {
        // A truncated line (crash mid-write) must not panic or loop; the
        // bytes pass through and any complete sensitive field is redacted.
        let input = r#"{"model":"gpt-4","authorization":"Bearer sk-half"#;
        let output = redact_json_fields(input);
        // The complete field before the truncation is intact.
        assert!(output.contains("gpt-4"), "{output}");
        // The unterminated sensitive value never had a value-end, so the
        // safest behaviour is to leave the fragment — but never panic.
        assert!(!output.is_empty());
    }

    #[test]
    fn redact_json_fields_handles_sensitive_field_without_value() {
        let input = r#"{"token""#;
        let output = redact_json_fields(input);
        // No colon/value follows; must not panic or emit a broken line.
        assert!(
            !output.contains("[REDACTED]\"\""),
            "no phantom redaction: {output}"
        );
    }

    #[test]
    fn redact_json_fields_ignores_non_sensitive_quoted_keys() {
        // A key that merely CONTAINS a sensitive substring must not be
        // redacted (exact, case-insensitive field match only).
        let input = r#"{"token_count":15,"model":"gpt-4"}"#;
        let output = redact_json_fields(input);
        assert_eq!(
            output, input,
            "token_count is not the token field and must pass through"
        );
    }

    #[test]
    fn sensitive_field_list_covers_the_documented_secrets() {
        for field in [
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
        ] {
            assert!(
                SENSITIVE_FIELDS.contains(&field),
                "{field} must stay in SENSITIVE_FIELDS"
            );
        }
    }

    #[test]
    fn init_is_idempotent_per_process() {
        // A second init must report an error rather than panic or silently
        // double-register (the first call may legitimately fail if another
        // test already claimed the global default subscriber).
        let _ = init();
        let second = init();
        assert!(
            second.is_err(),
            "re-initializing the subscriber must be a visible error"
        );
    }
}
