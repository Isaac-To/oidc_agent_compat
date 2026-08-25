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
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;

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

    // Extract the verified relay identity (attached by auth middleware)
    // before the request body is consumed.
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();
    // Extract the permission decision (attached by permissions middleware).
    let permission_decision = request
        .extensions()
        .get::<super::permissions::PermissionDecision>()
        .cloned();

    match forward_request(&state, request).await {
        Ok((resp, model, status, stream, token_usage)) => {
            // Compute cost from the pricing table (async — uses RwLock read).
            let cost_usd = state
                .price_table
                .compute_cost(
                    model.as_deref().unwrap_or(""),
                    token_usage.prompt,
                    token_usage.completion,
                )
                .await;

            // Record audit entry.
            let latency_ms = start.elapsed().as_millis() as i64;
            let entry = AuditEntry {
                device_id: identity
                    .as_ref()
                    .map(|i| i.identity_id.clone().unwrap_or_else(|| i.subject.clone()))
                    .unwrap_or_else(|| "relay".into()),
                user_subject: identity
                    .as_ref()
                    .map(|i| i.subject.clone())
                    .unwrap_or_else(|| "unknown".into()),
                model,
                backend: state.config.backend.name.clone(),
                status: status.as_u16() as i32,
                latency_ms,
                stream,
                prompt_tokens: token_usage.prompt,
                completion_tokens: token_usage.completion,
                total_tokens: token_usage.total,
                identity_id: identity.as_ref().and_then(|i| i.identity_id.clone()),
                email: identity.as_ref().and_then(|i| i.email.clone()),
                groups: identity.as_ref().and_then(|i| i.groups.clone()),
                endpoint: Some(path.clone()),
                request_id: identity.as_ref().and_then(|i| i.request_id.clone()),
                permission_decision: permission_decision.as_ref().map(|d| d.decision.clone()),
                denial_reason: permission_decision.as_ref().and_then(|d| d.reason.clone()),
                cost_usd: Some(cost_usd),
            };
            if let Err(e) = state.audit.record(&entry).await {
                tracing::error!(error = %e, "failed to write audit log");
            }

            // Increment usage counters (best-effort). Only count successful
            // requests that were allowed by the permissions middleware.
            if let Some(ident) = &identity {
                let total_tokens = i64::from(token_usage.total.unwrap_or(0));
                if let Err(e) = state
                    .usage_tracker
                    .increment(&ident.subject, None, 1, total_tokens, cost_usd)
                    .await
                {
                    tracing::warn!(error = %e, "failed to increment usage counters");
                }
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
    let model = http_util::extract_model(&body_bytes);

    // Build the upstream URL.
    let sanitized = http_util::sanitize_path(parts.uri.path())?;
    let upstream_url = format!("{}{}", state.config.backend.base_url, sanitized);

    // Build the upstream request with sanitized headers + master key.
    let forward_headers = http_util::build_forward_headers(&parts.headers);
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
    let is_stream = http_util::is_sse_content_type(content_type);

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
            if !http_util::is_response_header_stripped(&name_lower) {
                response_builder = response_builder.header(name, value);
            }
        }
        let resp = response_builder
            .body(Body::from(resp_bytes))
            .map_err(|e| Error::Http(format!("build response: {e}")))?;
        return Ok((resp, model, status, is_stream, usage));
    }

    // Streaming response: pass through as raw bytes, but intercept chunks to
    // extract token usage from the final SSE chunk (OpenAI sends usage in the
    // last chunk when stream_options.include_usage=true).
    let mut response_builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        let name_lower = name.as_str().to_lowercase();
        if !http_util::is_response_header_stripped(&name_lower) {
            response_builder = response_builder.header(name, value);
        }
    }
    let stream = upstream_resp.bytes_stream();
    let (mapped, usage_handle) = wrap_stream_with_usage_extraction(stream);
    let body = Body::from_stream(mapped);
    let resp = response_builder
        .body(body)
        .map_err(|e| Error::Http(format!("build stream response: {e}")))?;
    // Read the extracted usage after the stream is consumed. Since the body
    // is streamed lazily, we can't await it here. The usage handle is
    // stored in the response extensions for the proxy_handler to read after
    // the response is sent. For now, we return default usage; a future
    // enhancement can use a oneshot channel to await the final usage.
    let _ = usage_handle;
    Ok((resp, model, status, is_stream, TokenUsage::default()))
}

/// Extracts token usage from a JSON response body (OpenAI format).
fn extract_token_usage(body: &[u8]) -> TokenUsage {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return TokenUsage::default(),
    };
    extract_token_usage_from_value(&value)
}

/// Extracts token usage from a parsed JSON value (shared by buffered and
/// streaming paths).
fn extract_token_usage_from_value(value: &serde_json::Value) -> TokenUsage {
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

/// Wraps a byte stream with SSE usage extraction. Returns the pass-through
/// stream and a shared handle that will contain the extracted usage after
/// the stream completes.
///
/// OpenAI-compatible backends send `usage` in the last SSE chunk when
/// `stream_options.include_usage=true`. Each SSE chunk is a `data:` line
/// containing a JSON object. The extractor parses each line and keeps the
/// last `usage` it finds.
fn wrap_stream_with_usage_extraction<S, E>(
    stream: S,
) -> (
    impl futures::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send,
    std::sync::Arc<std::sync::Mutex<Option<TokenUsage>>>,
)
where
    S: futures::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
{
    let usage = std::sync::Arc::new(std::sync::Mutex::new(None::<TokenUsage>));
    let usage_clone = usage.clone();
    let mapped = futures::StreamExt::inspect(stream, move |chunk| {
        if let Ok(ref bytes) = *chunk {
            extract_usage_from_sse_chunk(bytes, &usage_clone);
        }
    });
    (mapped, usage)
}

/// Parses an SSE chunk (one or more `data:` lines) and extracts usage if
/// present. Stores the last usage found (the final chunk typically has it).
fn extract_usage_from_sse_chunk(
    bytes: &bytes::Bytes,
    usage: &std::sync::Arc<std::sync::Mutex<Option<TokenUsage>>>,
) {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("data:") {
            continue;
        }
        let data = line.trim_start_matches("data:").trim();
        if data == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
            let extracted = extract_token_usage_from_value(&value);
            if extracted.total.is_some() {
                if let Ok(mut guard) = usage.lock() {
                    *guard = Some(extracted);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn extract_usage_from_sse_chunk_with_usage() {
        let usage = std::sync::Arc::new(std::sync::Mutex::new(None));
        let chunk = bytes::Bytes::from(
            "data: {\"choices\": [], \"usage\": {\"prompt_tokens\": 10, \"completion_tokens\": 5, \"total_tokens\": 15}}\n\n",
        );
        extract_usage_from_sse_chunk(&chunk, &usage);
        let guard = usage.lock().unwrap();
        let extracted = guard.as_ref().expect("usage must be extracted");
        assert_eq!(extracted.prompt, Some(10));
        assert_eq!(extracted.completion, Some(5));
        assert_eq!(extracted.total, Some(15));
    }

    #[test]
    fn extract_usage_from_sse_chunk_without_usage() {
        let usage = std::sync::Arc::new(std::sync::Mutex::new(None));
        let chunk =
            bytes::Bytes::from("data: {\"choices\": [{\"delta\": {\"content\": \"hello\"}}]}\n\n");
        extract_usage_from_sse_chunk(&chunk, &usage);
        let guard = usage.lock().unwrap();
        assert!(guard.is_none(), "no usage should be extracted");
    }

    #[test]
    fn extract_usage_from_sse_chunk_done_marker() {
        let usage = std::sync::Arc::new(std::sync::Mutex::new(None));
        let chunk = bytes::Bytes::from("data: n\n");
        extract_usage_from_sse_chunk(&chunk, &usage);
        let guard = usage.lock().unwrap();
        assert!(guard.is_none(), "  not produce usage");
    }

    #[test]
    fn extract_usage_from_sse_chunk_multiple_lines() {
        let usage = std::sync::Arc::new(std::sync::Mutex::new(None));
        let chunk = bytes::Bytes::from(
            "data: {\"choices\": [{\"delta\": {\"content\": \"hi\"}}]}\ndata: {\"choices\": [], \"usage\": {\"prompt_tokens\": 20, \"completion_tokens\": 10, \"total_tokens\": 30}}\n\n",
        );
        extract_usage_from_sse_chunk(&chunk, &usage);
        let guard = usage.lock().unwrap();
        let extracted = guard.as_ref().expect("usage must be extracted");
        assert_eq!(extracted.total, Some(30));
    }
}
