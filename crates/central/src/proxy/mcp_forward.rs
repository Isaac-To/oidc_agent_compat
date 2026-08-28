//! MCP forward handler for the central proxy.
//!
//! Receives authenticated, permission-checked MCP Streamable-HTTP requests
//! from the relay and forwards them to the configured upstream MCP server,
//! injecting any per-server auth header. Like the OpenAI forward handler,
//! hop-by-hop headers are stripped and raw-byte responses (including SSE)
//! pass through unchanged.
//!
//! # Security
//!
//! - The upstream URL comes from the `mcp_servers` registry (admin-only);
//!   the permissions middleware already gatekept the caller for the
//!   requested server/tool.
//! - The per-server auth header is decrypted into `Zeroizing` memory for the
//!   duration of the request and never logged.
//! - Hop-by-hop headers are stripped (RFC 7230 §6.1).
//! - Every request is audited with server, tool, method, and a redacted
//!   argument preview.

use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use oidc_agent_common::error::Result;
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;
use crate::proxy::mcp_permissions::McpGrant;

/// Handles a single MCP request routed by `{server}`.
///
/// The `{server}` is the `mcp_servers` id. The MCP permissions middleware
/// has already validated the caller is allowed to reach this server.
pub async fn mcp_handler(
    State(state): State<AppState>,
    axum::extract::Path(server): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = Instant::now();
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();
    let grant = request.extensions().get::<McpGrant>().cloned();

    // Resolve the server here so a missing/disabled server yields 404 rather
    // than a generic 502.
    let resolved = match state.mcp_manager.resolve_server(&server).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32602, "message": "MCP server not found or disabled" },
            })
            .to_string();
            return (
                StatusCode::NOT_FOUND,
                [("content-type", "application/json")],
                body,
            )
                .into_response();
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_millis() as i64;
            tracing::error!(error = %e, server = %server, "failed to resolve MCP server");
            record_audit(&state, &identity, &grant, &server, StatusCode::BAD_GATEWAY, latency_ms, false).await;
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32603, "message": "MCP server lookup failed" },
            })
            .to_string();
            return (
                StatusCode::BAD_GATEWAY,
                [("content-type", "application/json")],
                body,
            )
                .into_response();
        }
    };

    match forward(&state, &server, &resolved, request).await {
        Ok(outcome) => {
            let (resp, status, stream) = outcome;
            let latency_ms = start.elapsed().as_millis() as i64;
            record_audit(&state, &identity, &grant, &server, status, latency_ms, stream).await;
            resp
        }
        Err(e) => {
            let status = StatusCode::BAD_GATEWAY;
            let latency_ms = start.elapsed().as_millis() as i64;
            tracing::error!(error = %e, server = %server, "MCP forward failed");
            record_audit(&state, &identity, &grant, &server, status, latency_ms, false).await;
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32603, "message": "upstream MCP request failed" },
            });
            (status, [("content-type", "application/json")], body.to_string()).into_response()
        }
    }
}

/// The outcome of a successful MCP forward.
type ForwardOutcome = (Response<Body>, StatusCode, bool);

/// Forwards one JSON-RPC request to the upstream MCP server.
async fn forward(
    state: &AppState,
    server: &str,
    resolved: &crate::mcp::ResolvedMcpServer,
    request: axum::extract::Request,
) -> Result<ForwardOutcome> {
    // Decompose the request; compute the upstream URL by appending the
    // path (minus the `/mcp/{server}` prefix) to the server's base URL.
    let (parts, body) = request.into_parts();
    let base = resolved.base_url.trim_end_matches('/').to_string();
    let suffix = mcp_path_suffix(parts.uri.path(), server);
    let url = format!("{base}{suffix}");

    let body_bytes = axum::body::to_bytes(body, http_util::MAX_BODY_SIZE).await.map_err(
        |e| oidc_agent_common::error::Error::Http(format!("read MCP request body: {e}")),
    )?;

    // Build the upstream header set: forwardable headers + the per-server
    // auth header (if any). Hop-by-hop headers are stripped.
    let mut headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)> =
        http_util::build_forward_headers(&parts.headers);
    if let Some(auth) = &resolved.auth_header {
        let header_line = auth.as_str();
        if let Some((name, value)) = header_line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if !name.is_empty() {
                if let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
                    if let Ok(value) = axum::http::HeaderValue::from_str(value) {
                        headers.push((name, value));
                    } else {
                        tracing::warn!(server = %server, "MCP server has an invalid auth header value; skipping");
                    }
                } else {
                    tracing::warn!(server = %server, "MCP server has an invalid auth header name; skipping");
                }
            }
        }
    }

    let reqwest_headers: reqwest::header::HeaderMap = headers
        .into_iter()
        .map(|(n, v)| {
            let name = reqwest::header::HeaderName::from_bytes(n.as_str().as_bytes())
                .map_err(|_| oidc_agent_common::error::Error::Http("invalid header".into()))?;
            let value = reqwest::header::HeaderValue::from_bytes(v.as_bytes())
                .map_err(|_| oidc_agent_common::error::Error::Http("invalid header value".into()))?;
            Ok((name, value))
        })
        .collect::<Result<reqwest::header::HeaderMap>>()?;

    // Resolve the upstream method (respect the incoming method; MCP is
    // usually POST).
    let method = parts.method.clone();
    let client = state.mcp_manager.client();

    let resp = client
        .request(method, &url)
        .headers(reqwest_headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("MCP upstream send: {e}")))?;

    let status = resp.status();
    let stream = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(http_util::is_sse_content_type)
        .unwrap_or(false);

    // Read the upstream bytes and rebuild an axum response preserving the
    // upstream status and headers.
    let upstream_headers = resp.headers().clone();
    let upstream_bytes = resp.bytes().await.map_err(|e| {
        oidc_agent_common::error::Error::Http(format!("read MCP upstream body: {e}"))
    })?;

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(upstream_bytes))
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("build MCP response: {e}")))?;
    *response.headers_mut() = upstream_headers;

    Ok((response, status, stream))
}

/// Returns the path suffix to append to the server base URL, stripping the
/// `/mcp/{server}` router prefix. Returns an empty string when nothing
/// follows.
fn mcp_path_suffix(path: &str, server: &str) -> String {
    let prefix = format!("/mcp/{server}");
    let rest = path.strip_prefix(&prefix).unwrap_or(path);
    if rest.is_empty() || rest == "/" {
        String::new()
    } else {
        rest.to_string()
    }
}

/// Records a single MCP audit entry.
async fn record_audit(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    grant: &Option<McpGrant>,
    server: &str,
    status: StatusCode,
    latency_ms: i64,
    stream: bool,
) {
    let entry = AuditEntry {
        device_id: identity
            .as_ref()
            .map(|i| i.identity_id.clone().unwrap_or_else(|| i.subject.clone()))
            .unwrap_or_else(|| "relay".into()),
        user_subject: identity
            .as_ref()
            .map(|i| i.subject.clone())
            .unwrap_or_else(|| "unknown".into()),
        model: None,
        backend: server.to_string(),
        status: status.as_u16() as i32,
        latency_ms,
        stream,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        identity_id: identity.as_ref().and_then(|i| i.identity_id.clone()),
        email: identity.as_ref().and_then(|i| i.email.clone()),
        groups: identity.as_ref().and_then(|i| i.groups.clone()),
        endpoint: Some(format!("/mcp/{server}")),
        request_id: identity.as_ref().and_then(|i| i.request_id.clone()),
        permission_decision: Some("allowed".to_string()),
        denial_reason: None,
        cost_usd: None,
        token_saver_applied: None,
        tokens_saved: None,
        messages_dropped: None,
        saver_reasons: None,
        mcp_server: Some(server.to_string()),
        mcp_tool: grant.as_ref().map(|g| g.tool.clone()),
        mcp_method: grant.as_ref().map(|g| g.method.clone()),
        mcp_args_preview: grant.as_ref().and_then(|g| g.args_preview.clone()),
    };
    if let Err(e) = state.audit.record(&entry).await {
        tracing::error!(error = %e, "failed to write MCP audit log");
    }
}