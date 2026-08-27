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

use std::collections::HashSet;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;
use crate::optimizer::{self, OptimizationReport};

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
        Ok(outcome) => {
            let ForwardOutcome {
                resp,
                model,
                provider_name,
                status,
                stream,
                usage,
                deferred,
                saver_report,
            } = outcome;
            let context = AccountingContext {
                state: state.clone(),
                identity,
                permission_decision,
                path,
                model,
                provider_name,
                status,
                start,
                saver_report,
            };
            match deferred {
                // Streaming: the body (and its token usage) arrives after
                // this handler returns, so accounting is deferred until the
                // stream completes (or is dropped by a client disconnect,
                // in which case any partially-extracted usage is recorded).
                Some(deferred) => {
                    tokio::spawn(async move {
                        let _ = deferred.done.await;
                        let usage = deferred
                            .usage
                            .lock()
                            .ok()
                            .and_then(|mut guard| guard.take())
                            .unwrap_or_default();
                        record_request_outcome(&context, usage, stream).await;
                    });
                }
                None => {
                    record_request_outcome(&context, usage, stream).await;
                }
            }
            resp
        }
        Err(e) => {
            // A request-quota reservation is made before provider resolution
            // and forwarding. If forwarding fails before an outcome exists,
            // release that reservation so transient upstream failures do not
            // consume the user's daily request allowance permanently.
            if let (Some(ident), Some(decision)) = (&identity, &permission_decision) {
                if decision.request_reserved {
                    if let Err(release_error) =
                        state.usage_tracker.release_request(&ident.subject).await
                    {
                        tracing::error!(
                            error = %release_error,
                            "failed to release request quota reservation"
                        );
                    }
                }
            }
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

/// Everything needed to record the outcome of a forwarded request.
struct AccountingContext {
    /// The proxy state (stores, pricing table).
    state: AppState,
    /// The verified relay identity, if any.
    identity: Option<super::auth::VerifiedRelayIdentity>,
    /// The permission decision from the permissions middleware.
    permission_decision: Option<super::permissions::PermissionDecision>,
    /// The request path.
    path: String,
    /// The requested model, if parseable.
    model: Option<String>,
    /// The provider name that served the request.
    provider_name: String,
    /// The upstream response status.
    status: StatusCode,
    /// When the request arrived at the proxy handler.
    start: Instant,
    /// The token-saver optimisation report for this request, if applied.
    saver_report: Option<OptimizationReport>,
}

/// A handle for deferred accounting of a streaming response.
///
/// `usage` is populated as SSE chunks are inspected; `done` fires when the
/// response stream completes. If the stream is dropped instead (client
/// disconnect), the sender is dropped and `done` errors — callers treat
/// both outcomes as "record whatever usage was extracted".
struct DeferredAccounting {
    /// Shared usage handle populated as the stream is consumed.
    usage: SharedUsage,
    /// Fires on stream completion; errors if the stream is dropped.
    done: tokio::sync::oneshot::Receiver<()>,
}

/// The outcome of a successfully forwarded request.
struct ForwardOutcome {
    /// The response to return to the relay.
    resp: Response<Body>,
    /// The requested model (for audit logging).
    model: Option<String>,
    /// The provider that served the request.
    provider_name: String,
    /// The upstream status code.
    status: StatusCode,
    /// Whether the response is an SSE stream.
    stream: bool,
    /// Extracted usage (empty for streams — see `deferred`).
    usage: TokenUsage,
    /// For streaming responses: the deferred accounting handle.
    deferred: Option<DeferredAccounting>,
    /// The token-saver optimisation report for this request, if applied.
    saver_report: Option<OptimizationReport>,
}

/// Records the audit entry and increments the usage counters for a
/// completed request.
///
/// Shared by the buffered and streaming paths. For streams this runs after
/// the body has been fully consumed, so `latency_ms` covers the complete
/// stream duration.
async fn record_request_outcome(context: &AccountingContext, usage: TokenUsage, stream: bool) {
    // Compute cost from the pricing table (async — uses RwLock read).
    let cost_usd = context
        .state
        .price_table
        .compute_cost(
            context.model.as_deref().unwrap_or(""),
            usage.prompt,
            usage.completion,
        )
        .await;

    // Record audit entry.
    let latency_ms = context.start.elapsed().as_millis() as i64;
    let entry = AuditEntry {
        device_id: context
            .identity
            .as_ref()
            .map(|i| i.identity_id.clone().unwrap_or_else(|| i.subject.clone()))
            .unwrap_or_else(|| "relay".into()),
        user_subject: context
            .identity
            .as_ref()
            .map(|i| i.subject.clone())
            .unwrap_or_else(|| "unknown".into()),
        model: context.model.clone(),
        backend: context.provider_name.clone(),
        status: context.status.as_u16() as i32,
        latency_ms,
        stream,
        prompt_tokens: usage.prompt,
        completion_tokens: usage.completion,
        total_tokens: usage.total,
        identity_id: context
            .identity
            .as_ref()
            .and_then(|i| i.identity_id.clone()),
        email: context.identity.as_ref().and_then(|i| i.email.clone()),
        groups: context.identity.as_ref().and_then(|i| i.groups.clone()),
        endpoint: Some(context.path.clone()),
        request_id: context.identity.as_ref().and_then(|i| i.request_id.clone()),
        permission_decision: context
            .permission_decision
            .as_ref()
            .map(|d| d.decision.clone()),
        denial_reason: context
            .permission_decision
            .as_ref()
            .and_then(|d| d.reason.clone()),
        cost_usd: Some(cost_usd),
        // Token-saver accounting, derived from the pure optimizer report.
        // Only ever metrics/reason tags — never prompt content.
        token_saver_applied: context.saver_report.as_ref().map(|r| r.applied),
        tokens_saved: context.saver_report.as_ref().map(|r| r.tokens_saved as i64),
        // `messages_dropped` counts only whole messages that were actually
        // removed (dedup + budget + empty). Collapsed lines are NOT dropped
        // messages — the RTK pass preserves every distinct line (folded into
        // `[×N]` entries), so it never contributes to `messages_dropped`.
        messages_dropped: context.saver_report.as_ref().map(|r| {
            (r.dup_messages_dropped + r.budget_turns_dropped + r.empty_messages_dropped) as i64
        }),
        saver_reasons: context.saver_report.as_ref().map(|r| {
            let mut reasons = Vec::new();
            if r.dup_messages_dropped > 0 {
                reasons.push("dedup".to_string());
            }
            if r.budget_turns_dropped > 0 {
                reasons.push("budget_trim".to_string());
            }
            if r.empty_messages_dropped > 0 {
                reasons.push("empty_removed".to_string());
            }
            if r.collapsed_lines > 0 {
                reasons.push("rtk_collapse".to_string());
            }
            serde_json::to_string(&reasons).unwrap_or_default()
        }),
    };
    if let Err(e) = context.state.audit.record(&entry).await {
        tracing::error!(error = %e, "failed to write audit log");
    }

    // Increment usage counters (best-effort). Only count successful
    // requests that were allowed by the permissions middleware.
    if let Some(ident) = &context.identity {
        let total_tokens = i64::from(usage.total.unwrap_or(0));
        // Snapshot the user's groups (JSON array string) into the usage
        // counters so the admin quota endpoint can resolve the effective
        // policy without a separate identity lookup.
        if let Err(e) = context
            .state
            .usage_tracker
            .increment(
                &ident.subject,
                ident.groups.as_deref(),
                1,
                total_tokens,
                cost_usd,
            )
            .await
        {
            tracing::warn!(error = %e, "failed to increment usage counters");
        }
    }
}

/// Forwards a single request to a model-selected provider with an authorized
/// provider key. A 401 or 429 response causes one retry per remaining
/// authorized key, in priority order.
async fn forward_request(
    state: &AppState,
    request: axum::extract::Request,
) -> Result<ForwardOutcome> {
    let groups = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .and_then(|identity| identity.groups.as_deref())
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default();
    let (parts, body) = request.into_parts();

    // Read the body and extract the model (for audit logging).
    let body_bytes = axum::body::to_bytes(body, super::MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Http(format!("read body: {e}")))?;
    let model = http_util::extract_model(&body_bytes);

    // Apply the admin-controlled token-saver optimiser (if enabled for this
    // user's groups). The config comes from the resolved policy attached by
    // the permissions middleware — never from the client. The optimisation
    // is safe-by-construction (see `optimizer`): it drops only exact
    // duplicates, structurally-empty messages, and oldest whole turns under
    // a budget, and never rewrites kept content.
    let (body_bytes, saver_report) = match parts
        .extensions
        .get::<super::permissions::TokenSaverGrant>()
        .copied()
    {
        Some(grant) => {
            let (optimized, report) = optimizer::optimize_prompt(&body_bytes, grant.config);
            if report.applied {
                (optimized, Some(report))
            } else {
                (body_bytes, None)
            }
        }
        None => (body_bytes, None),
    };

    // Ask streaming backends to report token usage in the final SSE chunk
    // (OpenAI only sends `usage` when `stream_options.include_usage=true`).
    let body_bytes = inject_stream_usage_option(body_bytes);

    let sanitized = http_util::sanitize_path(parts.uri.path())?;
    let forward_headers = http_util::build_forward_headers(&parts.headers);
    let provider = state
        .provider_store
        .resolve_provider_for_model(model.as_deref())
        .await?
        .ok_or_else(|| Error::Config("no enabled provider matches the requested model".into()))?;
    let mut excluded_key_ids = HashSet::new();
    let mut key = state
        .provider_store
        .resolve_key(&provider.id, &groups, &excluded_key_ids)
        .await?
        .ok_or_else(|| {
            Error::Auth(format!(
                "no authorized enabled key for provider '{}'",
                provider.id
            ))
        })?;
    let upstream_resp = loop {
        excluded_key_ids.insert(key.id.clone());

        let upstream_url = format!("{}{}", provider.base_url.trim_end_matches('/'), sanitized);
        let mut upstream = state
            .client
            .request(parts.method.clone(), &upstream_url)
            .body(body_bytes.clone())
            .header("authorization", key.secret.as_str());
        for (name, value) in &forward_headers {
            upstream = upstream.header(name, value);
        }
        let response = upstream
            .send()
            .await
            .map_err(|e| Error::Http(format!("upstream request: {e}")))?;
        if (response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::TOO_MANY_REQUESTS)
            && if let Some(next_key) = state
                .provider_store
                .resolve_key(&provider.id, &groups, &excluded_key_ids)
                .await?
            {
                key = next_key;
                true
            } else {
                false
            }
        {
            continue;
        }
        break response;
    };

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
        return Ok(ForwardOutcome {
            resp,
            model,
            provider_name: provider.name,
            status,
            stream: is_stream,
            usage,
            deferred: None,
            saver_report,
        });
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
    let (mapped, usage_handle, done) = wrap_stream_with_usage_extraction(stream);
    let body = Body::from_stream(mapped);
    let resp = response_builder
        .body(body)
        .map_err(|e| Error::Http(format!("build stream response: {e}")))?;
    // The extracted usage becomes available only as the relay consumes the
    // stream, so accounting is deferred: the proxy handler spawns a task
    // that waits for stream completion and then records the audit entry
    // and increments the usage counters with the streamed totals.
    Ok(ForwardOutcome {
        resp,
        model,
        provider_name: provider.name,
        status,
        stream: is_stream,
        usage: TokenUsage::default(),
        deferred: Some(DeferredAccounting {
            usage: usage_handle,
            done,
        }),
        saver_report,
    })
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

/// Injects `stream_options.include_usage = true` into a streaming request
/// body so the backend reports token usage in the final SSE chunk.
///
/// OpenAI-compatible backends only include a `usage` object in streamed
/// responses when the request asks for it. Without this, streamed requests
/// would record zero tokens, breaking token quotas and cost reporting.
///
/// Bodies that are not JSON objects or do not set `"stream": true` are
/// returned unchanged. Existing object-valued `stream_options` fields from
/// the caller are preserved; malformed/non-object values are repaired.
fn inject_stream_usage_option(body: bytes::Bytes) -> bytes::Bytes {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    let is_stream = value
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_stream {
        return body;
    }
    let Some(obj) = value.as_object_mut() else {
        return body;
    };
    // Preserve any caller-supplied stream_options; only force
    // include_usage on (it adds one final chunk and does not change token
    // counts). An explicit include_usage=false is overridden — the proxy
    // needs usage reporting for quota enforcement and cost accounting.
    let stream_options = obj
        .entry("stream_options")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(options) = stream_options.as_object_mut() {
        if options
            .get("include_usage")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return body;
        }
        options.insert("include_usage".into(), serde_json::Value::Bool(true));
    } else {
        *stream_options = serde_json::json!({"include_usage": true});
    }
    match serde_json::to_vec(&value) {
        Ok(encoded) => encoded.into(),
        Err(_) => body,
    }
}

/// Shared handle holding the usage extracted from a stream so far.
type SharedUsage = std::sync::Arc<std::sync::Mutex<Option<TokenUsage>>>;

/// Wraps a byte stream with SSE usage extraction. Returns the pass-through
/// stream, a shared handle that will contain the extracted usage after the
/// stream completes, and a oneshot receiver that fires on completion.
///
/// OpenAI-compatible backends send `usage` in the last SSE chunk when
/// `stream_options.include_usage=true`. Each SSE chunk is a `data:` line
/// containing a JSON object. The extractor parses each chunk and keeps the
/// last `usage` it finds.
///
/// The completion signal fires both on normal end and on a stream error. If
/// the stream is dropped without ending (client disconnect), the sender is
/// dropped and the receiver errors — deferred accounting treats both
/// outcomes as "record whatever usage was extracted".
fn wrap_stream_with_usage_extraction<S, E>(
    stream: S,
) -> (
    impl futures::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send,
    SharedUsage,
    tokio::sync::oneshot::Receiver<()>,
)
where
    S: futures::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
    E: Send + 'static,
{
    let usage = std::sync::Arc::new(std::sync::Mutex::new(None::<TokenUsage>));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let usage_for_stream = usage.clone();
    // Box::pin makes the inner stream Unpin so `next()` is available inside
    // the unfold state machine regardless of the inner stream's pinness.
    let inner = Box::pin(stream);
    let mapped = futures::stream::unfold(
        (inner, usage_for_stream, Some(tx), Vec::new()),
        |(mut inner, usage, mut tx, mut buffer)| async move {
            use futures::StreamExt;
            match inner.next().await {
                Some(Ok(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    extract_usage_from_sse_buffer(&mut buffer, &usage, false);
                    Some((Ok(chunk), (inner, usage, tx, buffer)))
                }
                Some(Err(e)) => {
                    // Upstream error: signal completion so accounting runs
                    // with whatever usage was extracted so far.
                    extract_usage_from_sse_buffer(&mut buffer, &usage, true);
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                    Some((Err(e), (inner, usage, tx, buffer)))
                }
                None => {
                    // Stream ended normally.
                    extract_usage_from_sse_buffer(&mut buffer, &usage, true);
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                    None
                }
            }
        },
    );
    (mapped, usage, rx)
}

/// Extracts usage from complete SSE lines in a per-stream buffer.
///
/// HTTP body chunks are transport artifacts and may split an SSE line at any
/// byte boundary. This function retains incomplete trailing lines until the
/// next chunk arrives. At end-of-stream, `flush` parses one final unterminated
/// line as well.
fn extract_usage_from_sse_buffer(buffer: &mut Vec<u8>, usage: &SharedUsage, flush: bool) {
    while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = buffer.drain(..=newline).collect();
        extract_usage_from_sse_line(&line, usage);
    }
    if flush && !buffer.is_empty() {
        let line = std::mem::take(buffer);
        extract_usage_from_sse_line(&line, usage);
    }
}

/// Parses one complete SSE line and records a usage-bearing JSON object.
fn extract_usage_from_sse_line(line: &[u8], usage: &SharedUsage) {
    let Ok(line) = std::str::from_utf8(line) else {
        return;
    };
    let line = line.trim();
    if !line.starts_with("data:") {
        return;
    }
    let data = line.trim_start_matches("data:").trim();
    if data == "[DONE]" {
        return;
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

/// Parses an SSE chunk (one or more `data:` lines) and extracts usage if
/// present. Stores the last usage found (the final chunk typically has it).
#[cfg(test)]
fn extract_usage_from_sse_chunk(bytes: &bytes::Bytes, usage: &SharedUsage) {
    let mut buffer = bytes.to_vec();
    extract_usage_from_sse_buffer(&mut buffer, usage, true);
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

    #[test]
    fn inject_stream_usage_option_adds_option_to_streaming_body() {
        let body = bytes::Bytes::from(r#"{"model":"gpt-4o","stream":true,"messages":[]}"#);
        let injected = inject_stream_usage_option(body);
        let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(
            value["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
        // The rest of the body is preserved.
        assert_eq!(value["model"], "gpt-4o");
        assert_eq!(value["stream"], true);
    }

    #[test]
    fn inject_stream_usage_option_leaves_non_streaming_body_unchanged() {
        let body = bytes::Bytes::from(r#"{"model":"gpt-4o","stream":false,"messages":[]}"#);
        let result = inject_stream_usage_option(body.clone());
        assert_eq!(result, body, "non-streaming bodies must not be modified");
    }

    #[test]
    fn inject_stream_usage_option_leaves_non_json_body_unchanged() {
        let body = bytes::Bytes::from_static(b"not json at all");
        let result = inject_stream_usage_option(body.clone());
        assert_eq!(result, body, "non-JSON bodies must not be modified");
    }

    #[test]
    fn inject_stream_usage_option_leaves_json_array_unchanged() {
        let body = bytes::Bytes::from(r#"[{"stream":true}]"#);
        let result = inject_stream_usage_option(body.clone());
        assert_eq!(result, body, "non-object JSON bodies must not be modified");
    }

    #[test]
    fn inject_stream_usage_option_preserves_existing_stream_options() {
        let body =
            bytes::Bytes::from(r#"{"model":"gpt-4o","stream":true,"stream_options":{"other":1}}"#);
        let injected = inject_stream_usage_option(body);
        let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(
            value["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(value["stream_options"]["other"], 1, "existing fields kept");
    }

    #[test]
    fn inject_stream_usage_option_repairs_non_object_stream_options() {
        for raw in [
            r#"{"model":"gpt-4o","stream":true,"stream_options":null}"#,
            r#"{"model":"gpt-4o","stream":true,"stream_options":"invalid"}"#,
        ] {
            let injected = inject_stream_usage_option(bytes::Bytes::from(raw));
            let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
            assert_eq!(
                value["stream_options"]["include_usage"],
                serde_json::Value::Bool(true),
                "invalid stream_options must not disable usage accounting"
            );
        }
    }

    #[test]
    fn inject_stream_usage_option_preserves_existing_object_fields() {
        let body = bytes::Bytes::from(
            r#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true,"foo":"bar"}}"#,
        );
        let result = inject_stream_usage_option(body.clone());
        assert_eq!(
            result, body,
            "an already compliant body must be byte-stable"
        );
    }

    #[test]
    fn inject_stream_usage_option_overrides_explicit_disable() {
        // An explicit include_usage=false is overridden: the central proxy
        // needs usage reporting for token-quota enforcement and cost
        // accounting, so the operator's policy wins over the caller's
        // preference. (include_usage adds one final chunk and does not
        // change token counts.)
        let body = bytes::Bytes::from(
            r#"{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false}}"#,
        );
        let injected = inject_stream_usage_option(body);
        let value: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(
            value["stream_options"]["include_usage"],
            serde_json::Value::Bool(true)
        );
    }

    #[tokio::test]
    async fn stream_usage_extraction_signals_completion() {
        let chunks: Vec<std::result::Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from(
                "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
            )),
            Ok(bytes::Bytes::from(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n",
            )),
            Ok(bytes::Bytes::from("data: [DONE]\n\n")),
        ];
        let stream = futures::stream::iter(chunks);
        let (mapped, usage_handle, done) = wrap_stream_with_usage_extraction(stream);
        let collected: Vec<_> = futures::StreamExt::collect(mapped).await;
        assert_eq!(collected.len(), 3, "all chunks must pass through");

        // The completion signal must fire after the stream ends.
        done.await.expect("completion signal must fire");

        let guard = usage_handle.lock().unwrap();
        let usage = guard.as_ref().expect("usage must be extracted");
        assert_eq!(usage.prompt, Some(7));
        assert_eq!(usage.completion, Some(3));
        assert_eq!(usage.total, Some(10));
    }

    #[tokio::test]
    async fn stream_usage_extraction_signals_on_error() {
        let chunks: Vec<std::result::Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from(
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":0,\"total_tokens\":5}}\n\n",
            )),
            Err(std::io::Error::other("upstream broke")),
        ];
        let stream = futures::stream::iter(chunks);
        let (mapped, usage_handle, done) = wrap_stream_with_usage_extraction(stream);
        let collected: Vec<_> = futures::StreamExt::collect(mapped).await;
        assert_eq!(collected.len(), 2, "error chunk must pass through");

        done.await.expect("completion signal must fire on error");

        let guard = usage_handle.lock().unwrap();
        let usage = guard.as_ref().expect("partial usage must be kept");
        assert_eq!(usage.total, Some(5));
    }

    #[tokio::test]
    async fn stream_usage_extraction_handles_every_transport_split() {
        let payload = concat!(
            ": keep-alive\r\n\r\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":123,\"completion_tokens\":45,\"total_tokens\":168}}\r\n\r\n",
            "data: [DONE]\r\n\r\n"
        );

        // An HTTP body chunk is not an SSE frame. Test every split position
        // in the payload, including inside JSON names, numbers, CRLF, and
        // UTF-8-adjacent framing bytes. The wrapper must preserve bytes and
        // still extract the complete usage object.
        for split in 1..payload.len() {
            let (left, right) = payload.as_bytes().split_at(split);
            let chunks = vec![
                Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(left)),
                Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(right)),
            ];
            let (mapped, usage_handle, done) =
                wrap_stream_with_usage_extraction(futures::stream::iter(chunks));
            let output: Vec<bytes::Bytes> = futures::StreamExt::collect::<Vec<_>>(mapped)
                .await
                .into_iter()
                .map(|chunk| chunk.expect("test stream must not fail"))
                .collect();
            let output = output
                .into_iter()
                .flat_map(|chunk| chunk.to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                output,
                payload.as_bytes(),
                "split at {split} must preserve the exact SSE byte stream"
            );
            done.await.expect("completion signal must fire");
            let guard = usage_handle.lock().unwrap();
            let usage = guard
                .as_ref()
                .expect("usage must be extracted for every split");
            assert_eq!(usage.prompt, Some(123), "split at {split}");
            assert_eq!(usage.completion, Some(45), "split at {split}");
            assert_eq!(usage.total, Some(168), "split at {split}");
        }
    }
}
