//! Forward handler for the central proxy.
//!
//! This handler receives authenticated relay requests and forwards them to
//! the OpenAI-compatible backend with the master key injected. It strips
//! hop-by-hop headers, replaces the incoming `Authorization` with the master
//! key, and passes streaming responses through as raw bytes.
//!
//! # Security
//!
//! - **Master key injection**: the incoming `Authorization` header (the relay's
//!   user token) is replaced with `Authorization: Bearer <master_key>`. The
//!   master key never appears in logs or errors.
//! - **Hop-by-hop header stripping** (RFC 7230 §6.1).
//! - **SSRF prevention**: the backend URL comes from config only; the request
//!   path is sanitized.
//! - **Raw byte SSE passthrough** for streaming responses.
//! - **Audit logging**: every request is recorded with device, user, model,
//!   status, latency, and token usage.

use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use oidc_agent_common::error::{Error, Result};

use super::AppState;
use crate::audit::AuditEntry;

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

/// Builds the HTTP client for forwarding to the backend.
///
/// # Security
///
/// - `rustls-tls` for certificate verification.
/// - No `danger_accept_invalid_certs`.
///
/// # Errors
///
/// Returns [`Error::Http`] if the client cannot be built.
pub fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Http(format!("build forward client: {e}")))
}

/// The proxy handler that forwards requests to the backend with the master key.
pub async fn proxy_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = Instant::now();
    let path = request.uri().path().to_string();

    match forward_request(&state, request).await {
        Ok((resp, model, status, stream, token_usage)) => {
            // Record audit entry.
            let latency_ms = start.elapsed().as_millis() as i64;
            let entry = AuditEntry {
                device_id: "relay".into(),      // TODO: extract from mTLS cert
                user_subject: "unknown".into(), // TODO: extract from user token
                model,
                backend: state.config.backend.name.clone(),
                status: status.as_u16() as i32,
                latency_ms,
                stream,
                prompt_tokens: token_usage.prompt,
                completion_tokens: token_usage.completion,
                total_tokens: token_usage.total,
            };
            if let Err(e) = state.audit.record(&entry).await {
                tracing::error!(error = %e, "failed to write audit log");
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, path = %path, "forward failed");
            let body = serde_json::json!({
                "error": {
                    "message": "upstream request failed",
                    "type": "central_proxy_error",
                }
            });
            (
                StatusCode::BAD_GATEWAY,
                [("content-type", "application/json")],
                body.to_string(),
            )
                .into_response()
        }
    }
}

/// Token usage extracted from the upstream response (if present).
#[derive(Default)]
struct TokenUsage {
    prompt: Option<i32>,
    completion: Option<i32>,
    total: Option<i32>,
}

/// Forwards a single request to the backend with the master key.
async fn forward_request(
    state: &AppState,
    request: axum::extract::Request,
) -> Result<(Response<Body>, Option<String>, StatusCode, bool, TokenUsage)> {
    let (parts, body) = request.into_parts();

    // Read the body and extract the model (for audit logging).
    let body_bytes = axum::body::to_bytes(body, super::MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Http(format!("read body: {e}")))?;
    let model = extract_model(&body_bytes);

    // Build the upstream URL.
    let sanitized = sanitize_path(parts.uri.path())?;
    let upstream_url = format!("{}{}", state.config.backend.base_url, sanitized);

    // Build the upstream request with sanitized headers + master key.
    let forward_headers = build_forward_headers(&parts.headers);
    let mut upstream = state
        .client
        .request(parts.method, &upstream_url)
        .body(body_bytes)
        .header("authorization", &**state.master_key);

    for (name, value) in &forward_headers {
        upstream = upstream.header(name, value);
    }

    // Send the request.
    let upstream_resp = upstream
        .send()
        .await
        .map_err(|e| Error::Http(format!("upstream request: {e}")))?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Check if this is a streaming response (SSE).
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_stream = content_type.contains("text/event-stream");

    if !is_stream {
        // Buffer the response and extract token usage.
        let resp_bytes = upstream_resp
            .bytes()
            .await
            .map_err(|e| Error::Http(format!("read upstream body: {e}")))?;
        let usage = extract_token_usage(&resp_bytes);
        let mut response_builder = Response::builder().status(status);
        for (name, value) in &resp_headers {
            let name_lower = name.as_str().to_lowercase();
            if !HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
                response_builder = response_builder.header(name, value);
            }
        }
        let resp = response_builder
            .body(Body::from(resp_bytes))
            .map_err(|e| Error::Http(format!("build response: {e}")))?;
        return Ok((resp, model, status, is_stream, usage));
    }

    // Streaming response: pass through as raw bytes.
    let mut response_builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        let name_lower = name.as_str().to_lowercase();
        if !HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
            response_builder = response_builder.header(name, value);
        }
    }
    let stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(stream);
    let resp = response_builder
        .body(body)
        .map_err(|e| Error::Http(format!("build stream response: {e}")))?;
    Ok((resp, model, status, is_stream, TokenUsage::default()))
}

/// Extracts the `model` field from a JSON request body (for audit logging).
fn extract_model(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("model")?.as_str().map(String::from)
}

/// Extracts token usage from a JSON response body (OpenAI format).
fn extract_token_usage(body: &[u8]) -> TokenUsage {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return TokenUsage::default(),
    };
    let usage = match value.get("usage") {
        Some(u) => u,
        None => return TokenUsage::default(),
    };
    TokenUsage {
        prompt: usage
            .get("prompt_tokens")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok()),
        completion: usage
            .get("completion_tokens")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok()),
        total: usage
            .get("total_tokens")
            .and_then(|v| v.as_i64())
            .and_then(|v| i32::try_from(v).ok()),
    }
}

/// Sanitizes the request path to prevent SSRF.
///
/// # Errors
///
/// Returns [`Error::Http`] if the path is unsafe.
fn sanitize_path(path: &str) -> Result<String> {
    if path.contains("..") {
        return Err(Error::Http(format!("path contains '..': {path}")));
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
fn build_forward_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    let connection_headers: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(|h| h.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let mut result = Vec::new();
    for name in FORWARDABLE_HEADERS {
        if let Some(value) = headers.get(*name) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_accepts_normal_paths() {
        assert_eq!(
            sanitize_path("/v1/chat/completions").unwrap(),
            "/v1/chat/completions"
        );
    }

    #[test]
    fn sanitize_path_rejects_dot_dot() {
        assert!(sanitize_path("/v1/../etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_double_slash() {
        assert!(sanitize_path("/v1//chat").is_err());
    }

    #[test]
    fn sanitize_path_rejects_absolute_url() {
        assert!(sanitize_path("http://evil.example.com/v1").is_err());
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
    fn extract_token_usage_from_openai_response() {
        let body = br#"{
            "choices": [],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }"#;
        let usage = extract_token_usage(body);
        assert_eq!(usage.prompt, Some(100));
        assert_eq!(usage.completion, Some(50));
        assert_eq!(usage.total, Some(150));
    }

    #[test]
    fn extract_token_usage_from_response_without_usage() {
        let body = br#"{"choices": []}"#;
        let usage = extract_token_usage(body);
        assert_eq!(usage.prompt, None);
        assert_eq!(usage.total, None);
    }

    #[test]
    fn extract_token_usage_from_invalid_json() {
        let body = b"not json";
        let usage = extract_token_usage(body);
        assert_eq!(usage.prompt, None);
    }

    #[test]
    fn build_forward_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("authorization", "Bearer relay-token".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();

        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"transfer-encoding"));
        assert!(
            !names.contains(&"authorization"),
            "authorization must not be forwarded (replaced by master key)"
        );
    }

    #[test]
    fn hop_by_hop_headers_list_is_complete() {
        assert!(HOP_BY_HOP_HEADERS.contains(&"connection"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"keep-alive"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authenticate"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authorization"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"te"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"trailer"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"upgrade"));
    }
}
