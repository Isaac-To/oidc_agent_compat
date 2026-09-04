//! Shared HTTP forwarding utilities for the relay and central proxies.
//!
//! Both proxies forward agent requests to an upstream (relay → central,
//! central → backend). The hop-by-hop header stripping (RFC 7230 §6.1),
//! forwardable-header allowlist, request-path sanitization (SSRF defense),
//! model extraction, SSE detection, and response-header filtering are
//! identical across the two crates. Centralizing them here eliminates the
//! copy-pasted implementations and — importantly — ensures the stricter
//! (relay) path-sanitization rules apply to both proxies.
//!
//! # Security
//!
//! - **Hop-by-hop header stripping** follows RFC 7230 §6.1, including any
//!   header named in the `Connection` header.
//! - **Path sanitization** rejects `..` (literal and percent-encoded),
//!   backslashes, double slashes, and absolute URLs — defending against
//!   path traversal and SSRF.
//! - No secrets are handled here; this module is purely structural.

use crate::error::{Error, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue};

/// Hop-by-hop headers that must be stripped when forwarding (RFC 7230 §6.1).
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// End-to-end headers that are safe to forward.
pub const FORWARDABLE_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
];

/// The maximum request body size accepted by either proxy (10 MB).
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// The SSE content-type token used to detect streaming responses.
const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// Returns `true` if the given `Content-Type` header value denotes an SSE
/// streaming response (case-insensitive, per RFC 7231 §3.1.1.1).
#[must_use]
pub fn is_sse_content_type(content_type: &str) -> bool {
    content_type.to_lowercase().contains(SSE_CONTENT_TYPE)
}

/// Extracts the `model` field from a JSON request body (for activity/audit
/// logging). Returns `None` if the body is not valid JSON or has no `model`
/// string field.
#[must_use]
pub fn extract_model(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("model")?.as_str().map(String::from)
}

/// Sanitizes the request path to prevent SSRF and path traversal.
///
/// Rejects paths containing:
/// - `..` (literal or URL-encoded as `%2e%2e` / `%2e.` / `.%2e`, case-insensitive)
/// - `\` (backslashes, which some upstreams normalize to `/`)
/// - `//` (double slashes)
/// - Absolute URLs (`http://` or `https://`)
///
/// # Errors
///
/// Returns [`Error::Http`] if the path is unsafe.
pub fn sanitize_path(path: &str) -> Result<String> {
    if path.contains("..") {
        return Err(Error::Http(format!("path contains '..': {path}")));
    }
    if path.contains('\\') {
        return Err(Error::Http(format!("path contains backslash: {path}")));
    }
    let path_lower = path.to_lowercase();
    if path_lower.contains("%2e%2e") || path_lower.contains("%2e.") || path_lower.contains(".%2e") {
        return Err(Error::Http(format!("path contains encoded '..': {path}")));
    }
    if path.contains("//") {
        return Err(Error::Http(format!("path contains '//': {path}")));
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return Err(Error::Http(format!("path is absolute URL: {path}")));
    }
    Ok(path.to_string())
}

/// Builds the set of headers to forward to the upstream, stripping hop-by-hop
/// headers and any headers named in the `Connection` header.
///
/// Only headers in [`FORWARDABLE_HEADERS`] are forwarded (allowlist model).
/// The `Authorization` header is intentionally not forwarded — each proxy
/// replaces it with its own upstream credential (relay identity headers or
/// the master key).
#[must_use]
pub fn build_forward_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    // Collect headers named in the Connection header (these are hop-by-hop).
    let connection_headers: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(|h| h.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let mut result = Vec::new();
    for name in FORWARDABLE_HEADERS {
        if let Some(value) = headers.get(*name) {
            // Skip if this header is named in Connection.
            if connection_headers.iter().any(|h| h == name) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::try_from(*name),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                result.push((n, v));
            }
        }
    }
    result
}

/// Returns `true` if the given header name (lowercased) should be stripped
/// from a response. Strips hop-by-hop headers and `content-length` (Axum
/// recomputes it from the actual body, and the upstream's value is wrong for
/// streaming responses where the body is re-framed).
#[must_use]
pub fn is_response_header_stripped(name_lower: &str) -> bool {
    HOP_BY_HOP_HEADERS.contains(&name_lower) || name_lower == "content-length"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_accepts_normal_paths() {
        assert_eq!(
            sanitize_path("/v1/chat/completions").unwrap(),
            "/v1/chat/completions"
        );
        assert_eq!(sanitize_path("/v1/models").unwrap(), "/v1/models");
    }

    #[test]
    fn sanitize_path_rejects_dot_dot() {
        assert!(sanitize_path("/v1/../etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_url_encoded_dot_dot() {
        assert!(sanitize_path("/v1/%2e%2e/etc/passwd").is_err());
        assert!(sanitize_path("/v1/%2E%2E/etc/passwd").is_err());
        assert!(sanitize_path("/v1/%2e./etc/passwd").is_err());
        assert!(sanitize_path("/v1/.%2e/etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_backslash() {
        assert!(sanitize_path("/v1/\\..\\etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_double_slash() {
        assert!(sanitize_path("/v1//chat").is_err());
    }

    #[test]
    fn sanitize_path_rejects_absolute_url() {
        assert!(sanitize_path("http://evil.example.com/v1").is_err());
        assert!(sanitize_path("https://evil.example.com/v1").is_err());
    }

    #[test]
    fn extract_model_from_valid_body() {
        let body = br#"{"model": "gpt-4", "messages": []}"#;
        assert_eq!(extract_model(body), Some("gpt-4".into()));
    }

    #[test]
    fn extract_model_from_body_without_model() {
        let body = br#"{"messages": []}"#;
        assert_eq!(extract_model(body), None);
    }

    #[test]
    fn extract_model_from_invalid_json() {
        let body = b"not json";
        assert_eq!(extract_model(body), None);
    }

    #[test]
    fn extract_model_non_string_field_returns_none() {
        // `model: 42` is present but not a string — activity logs must not
        // record a bogus model name.
        let body = br#"{"model": 42, "messages": []}"#;
        assert_eq!(extract_model(body), None);
    }

    #[test]
    fn build_forward_headers_only_forwards_the_allowlist() {
        // Anything outside FORWARDABLE_HEADERS must be dropped — including
        // identity-ish and auth headers a client might try to smuggle.
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("authorization", "Bearer oac_secret".parse().unwrap());
        headers.insert("x-oac-user-subject", "spoofed".parse().unwrap());
        headers.insert("cookie", "session=abc".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"accept"));
        assert!(
            !names.contains(&"authorization"),
            "credentials must not be forwarded"
        );
        assert!(
            !names.contains(&"x-oac-user-subject"),
            "identity headers are set by the proxies, never forwarded from clients"
        );
        assert!(!names.contains(&"cookie"), "cookies must not be forwarded");
    }

    #[test]
    fn build_forward_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("authorization", "Bearer oac_secret".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"transfer-encoding"));
        assert!(
            !names.contains(&"authorization"),
            "authorization must not be forwarded (replaced by upstream auth)"
        );
    }

    #[test]
    fn build_forward_headers_strips_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("connection", "accept".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();

        assert!(!names.contains(&"accept"));
        assert!(names.contains(&"content-type"));
    }

    #[test]
    fn hop_by_hop_headers_list_is_complete() {
        // RFC 7230 §6.1 canonical list.
        assert!(HOP_BY_HOP_HEADERS.contains(&"connection"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"keep-alive"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authenticate"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authorization"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"te"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"trailer"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"upgrade"));
    }

    #[test]
    fn is_sse_content_type_is_case_insensitive() {
        assert!(is_sse_content_type("text/event-stream"));
        assert!(is_sse_content_type("TEXT/EVENT-STREAM"));
        assert!(is_sse_content_type("text/event-stream; charset=utf-8"));
        assert!(!is_sse_content_type("application/json"));
    }

    #[test]
    fn is_response_header_stripped_covers_hop_by_hop_and_length() {
        assert!(is_response_header_stripped("connection"));
        assert!(is_response_header_stripped("transfer-encoding"));
        assert!(is_response_header_stripped("content-length"));
        assert!(!is_response_header_stripped("content-type"));
    }

    #[test]
    fn sanitize_path_accepts_root() {
        assert_eq!(sanitize_path("/").unwrap(), "/");
    }

    #[test]
    fn sanitize_path_accepts_empty_string() {
        // An empty path is not unsafe (no traversal, no double slash).
        assert_eq!(sanitize_path("").unwrap(), "");
    }

    #[test]
    fn sanitize_path_rejects_just_backslash() {
        assert!(sanitize_path(r#"\"#).is_err());
    }

    #[test]
    fn sanitize_path_rejects_just_dot_dot() {
        assert!(sanitize_path("..").is_err());
    }

    #[test]
    fn build_forward_headers_returns_empty_for_no_headers() {
        let headers = HeaderMap::new();
        let forwarded = build_forward_headers(&headers);
        assert!(forwarded.is_empty(), "no forwardable headers → empty vec");
    }

    #[test]
    fn build_forward_headers_skips_connection_named_forwardable() {
        // If the Connection header names a forwardable header (e.g.
        // "content-type"), that header must be stripped even though it is
        // on the allowlist.
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("connection", "content-type".parse().unwrap());
        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"content-type"),
            "a header named in Connection must be stripped"
        );
    }

    #[test]
    fn extract_model_handles_null_model() {
        let body = br#"{"model":null,"messages":[]}"#;
        assert_eq!(extract_model(body), None);
    }

    #[test]
    fn extract_model_handles_empty_body() {
        assert_eq!(extract_model(b""), None);
    }
}
