//! MCP forward handler for the relay proxy.
//!
//! Receives authenticated MCP Streamable-HTTP requests from the agent and
//! forwards them to the central proxy over mTLS, injecting the verified user
//! identity as `X-OAC-*` headers (the same security boundary as the OpenAI
//! path). MCP JSON-RPC bodies are forwarded verbatim; the local API key is
//! never forwarded.
//!
//! # Security
//!
//! - Hop-by-hop header stripping (RFC 7230 §6.1).
//! - Path sanitization (SSRF defense) via `http_util::sanitize_path`.
//! - Identity injection from the auth-middleware-verified identity only.
//! - Raw-byte SSE passthrough for streaming MCP responses.
//! - Relay-side activity logging with MCP server/tool/method correlation.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use oac_mcp::parse;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::http_util;
use oidc_agent_common::identity;

use super::AppState;

/// The relay MCP forward handler for `POST /mcp/{server}`.
///
/// The `{server}` is a url-encoded MCP server id. Central resolves it from
/// its registry; the relay merely tunnels the request with identity headers.
pub async fn mcp_handler(
    State(state): State<AppState>,
    axum::extract::Path(server): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> Response<Body> {
    run_handler(state, &server, request).await
}

/// The relay MCP forward handler for `POST /mcp` — the combined hub endpoint.
///
/// This is the single endpoint a user points their agent at. The relay
/// tunnels the JSON-RPC bytes to central `/mcp`; central fans out, enforces
/// per-tool policy, and aggregates. The relay only records activity metadata.
pub async fn mcp_hub_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    run_handler(state, "hub", request).await
}

/// Shared relay MCP tunnel: reads the body, records activity metadata, and
/// forwards to central with the verified identity headers.
async fn run_handler(
    state: AppState,
    server_label: &str,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = std::time::Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().to_string();
    let endpoint = request.uri().path().to_string();

    let identity = request
        .extensions()
        .get::<super::auth::VerifiedIdentity>()
        .cloned();

    // Read the body once and parse MCP metadata (server/tool/method) for the
    // activity log. Parsing is best-effort — malformed bodies still forward.
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, super::MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to read MCP body");
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                serde_json::json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "parse error" } }).to_string(),
            )
                .into_response();
        }
    };

    let (mcp_tool, mcp_method) = parse_mcp_meta(&body_bytes, server_label);

    let result = forward_request(&state, &parts, body_bytes, identity.as_ref(), &request_id).await;

    let latency_ms = start.elapsed().as_millis() as i64;
    let central_status = match &result {
        Ok(resp) => Some(resp.status().as_u16() as i32),
        Err(_) => None,
    };
    if let Some(ident) = &identity {
        let entry = crate::activity::RelayActivityEntry {
            identity_id: ident.identity_id.clone(),
            key_id: ident.key_id.clone(),
            method,
            endpoint,
            model: None,
            central_status,
            latency_ms,
            request_id: Some(request_id.clone()),
            mcp_server: Some(server_label.to_string()),
            mcp_tool,
            mcp_method,
        };
        if let Err(e) = state.activity.record(&entry).await {
            tracing::error!(error = %e, request_id = %request_id, "failed to write relay MCP activity log");
        }
    }

    match result {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, request_id = %request_id, "MCP forward failed");
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32603, "message": "upstream MCP request failed" },
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

/// Best-effort parse of the MCP tool and method from a request body.
///
/// Returns `(tool, method)`. For `tools/call` the tool name is returned;
/// for other request methods the tool is `None` and the method name is
/// surfaced (matching the central audit classification). On any parse
/// failure both are `None`.
fn parse_mcp_meta(body: &[u8], server: &str) -> (Option<String>, Option<String>) {
    match parse::extract_tool_call(body, server) {
        Ok(Some(call)) => {
            let method = Some(call.method.clone());
            let tool = if call.tool.is_empty() {
                None
            } else {
                Some(call.tool.clone())
            };
            (tool, method)
        }
        _ => (None, None),
    }
}

/// Forwards a single MCP request to the central proxy over mTLS.
///
/// Returns the upstream response.
async fn forward_request(
    state: &AppState,
    parts: &axum::http::request::Parts,
    body_bytes: axum::body::Bytes,
    identity: Option<&super::auth::VerifiedIdentity>,
    request_id: &str,
) -> Result<Response<Body>> {
    // Build the upstream URL from the request path (sanitized).
    let path = parts.uri.path();
    let sanitized = http_util::sanitize_path(path)?;
    let upstream_url = format!("{}{}", state.config.central.url, sanitized);

    let forward_headers = http_util::build_forward_headers(&parts.headers);
    let mut upstream = state
        .client
        .request(parts.method.clone(), &upstream_url)
        .body(body_bytes);

    for (name, value) in &forward_headers {
        upstream = upstream.header(name, value);
    }

    // Inject verified identity headers (never from client-supplied headers).
    if let Some(ident) = identity {
        if let Ok(v) = HeaderValue::from_str(&ident.subject) {
            upstream = upstream.header(identity::HEADER_USER_SUBJECT, v);
        }
        if let Some(email) = &ident.email {
            if let Ok(v) = HeaderValue::from_str(email) {
                upstream = upstream.header(identity::HEADER_USER_EMAIL, v);
            }
        }
        if let Some(groups) = &ident.groups {
            if let Ok(v) = HeaderValue::from_str(groups) {
                upstream = upstream.header(identity::HEADER_USER_GROUPS, v);
            }
        }
        if let Ok(v) = HeaderValue::from_str(&ident.identity_id) {
            upstream = upstream.header(identity::HEADER_IDENTITY_ID, v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(request_id) {
        upstream = upstream.header(identity::HEADER_REQUEST_ID, v);
    }

    let upstream_resp = upstream
        .send()
        .await
        .map_err(|e| Error::Http(format!("MCP upstream request: {e}")))?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_stream = http_util::is_sse_content_type(content_type);

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        let name_lower = name.as_str().to_lowercase();
        if !http_util::is_response_header_stripped(&name_lower) {
            response_builder = response_builder.header(name, value);
        }
    }

    if is_stream {
        let stream = upstream_resp.bytes_stream();
        let resp = response_builder
            .body(Body::from_stream(stream))
            .map_err(|e| Error::Http(format!("build MCP stream response: {e}")))?;
        Ok(resp)
    } else {
        let bytes = upstream_resp
            .bytes()
            .await
            .map_err(|e| Error::Http(format!("read MCP upstream response: {e}")))?;
        let resp = response_builder
            .body(Body::from(bytes))
            .map_err(|e| Error::Http(format!("build MCP response: {e}")))?;
        Ok(resp)
    }
}
