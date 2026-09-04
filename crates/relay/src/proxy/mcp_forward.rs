//! MCP forward handler for the relay proxy.
//!
//! Receives authenticated MCP Streamable-HTTP requests from the agent and
//! forwards them to the central proxy over mTLS, forwarding the incoming
//! `Authorization` header unchanged. MCP JSON-RPC bodies are forwarded
//! verbatim; the relay does not verify the token (central does, zero-trust).
//!
//! # Security
//!
//! - Hop-by-hop header stripping (RFC 7230 §6.1).
//! - Path sanitization (SSRF defense) via `http_util::sanitize_path`.
//! - The `Authorization` header is forwarded unchanged; central verifies it.
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
/// its registry; the relay merely tunnels the request with the bearer token.
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
/// forwards to central with the bearer token.
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

    let result = forward_request(&state, &parts, body_bytes, &request_id).await;

    let latency_ms = start.elapsed().as_millis() as i64;
    let central_status = match &result {
        Ok(resp) => Some(resp.status().as_u16() as i32),
        Err(_) => None,
    };
    if let Some(ident) = &identity {
        let entry = crate::activity::RelayActivityEntry {
            identity_id: ident.identity_id.clone().unwrap_or_default(),
            key_id: ident.key_id.clone().unwrap_or_default(),
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

    // Forward the incoming Authorization header (the agent's bearer token) to
    // the central proxy. The central proxy verifies it via its token store
    // (zero-trust). The relay does not verify the token locally.
    if let Some(auth) = parts.headers.get("authorization") {
        upstream = upstream.header("authorization", auth);
    }

    // Forward the request ID for end-to-end correlation.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::auth::VerifiedIdentity;
    use crate::proxy::{AppState, router};
    use axum::body::Body;
    use axum::http::StatusCode;
    use oidc_agent_common::config::{CentralConnectionConfig, OidcConfig, RelayConfig};
    use tower::ServiceExt;

    async fn test_state(dev_mode: bool) -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("relay-mcp-fwd");
        let db = crate::db::setup(&url).await.expect("db");
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            database_url: "sqlite://test.db".into(),
            oidc: OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "t".into(),
                client_secret_env: "T".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            central: CentralConnectionConfig {
                url: "http://127.0.0.1:1".into(),
                ca_cert_path: "/ca.pem".into(),
                client_cert_path: "/c.pem".into(),
                client_key_path: "/c.key".into(),
            },
            dev_mode,
        };
        AppState {
            config: config.clone(),
            // Use a plain client to avoid mTLS cert loading in non-dev mode.
            client: reqwest::Client::new(),
            listen_addr: "127.0.0.1:8787".parse().expect("addr"),
            activity: crate::activity::ActivityLogger::new(db),
        }
    }

    fn mcp_request_with_auth() -> axum::http::Request<Body> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp/fs")
            .header("content-type", "application/json")
            .header("authorization", "Bearer oac_test_token")
            .header("host", "127.0.0.1:8787")
            .body(Body::from(body))
            .expect("build request")
    }

    fn mcp_request_no_auth() -> axum::http::Request<Body> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp/fs")
            .header("content-type", "application/json")
            .header("host", "127.0.0.1:8787")
            .body(Body::from(body))
            .expect("build request")
    }

    #[tokio::test]
    async fn missing_auth_in_non_dev_mode_returns_401() {
        // In non-dev mode, the auth middleware rejects requests without
        // an Authorization header before they reach the MCP handler.
        let state = test_state(false).await;
        let app = router(state);
        let resp = app.oneshot(mcp_request_no_auth()).await.expect("router");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing Authorization in non-dev mode must get 401"
        );
    }

    #[tokio::test]
    async fn mcp_forward_upstream_failure_returns_bad_gateway() {
        // In dev mode, auth is skipped. The MCP handler forwards to
        // central at 127.0.0.1:1 (unreachable) → 502 Bad Gateway.
        let state = test_state(true).await;
        let app = router(state);
        let resp = app.oneshot(mcp_request_with_auth()).await.expect("router");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "upstream connection failure must return 502"
        );
    }

    #[tokio::test]
    async fn mcp_hub_forward_upstream_failure_returns_bad_gateway() {
        let state = test_state(true).await;
        let app = router(state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer oac_test_token")
                    .header("host", "127.0.0.1:8787")
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn parse_mcp_meta_returns_none_for_invalid_json() {
        let (tool, method) = parse_mcp_meta(b"not json", "fs");
        assert!(tool.is_none());
        assert!(method.is_none());
    }

    #[test]
    fn parse_mcp_meta_extracts_tool_and_method() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": {} },
        })
        .to_string();
        let (tool, method) = parse_mcp_meta(body.as_bytes(), "fs");
        assert_eq!(tool.as_deref(), Some("read_file"));
        assert_eq!(method.as_deref(), Some("tools/call"));
    }

    #[test]
    fn parse_mcp_meta_empty_tool_name_returns_none_for_both() {
        // tools/call with an empty name → Err(Malformed) from extract_tool_call,
        // so parse_mcp_meta returns (None, None) for both.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "", "arguments": {} },
        })
        .to_string();
        let (tool, method) = parse_mcp_meta(body.as_bytes(), "fs");
        assert!(tool.is_none(), "empty tool name → None");
        assert!(
            method.is_none(),
            "malformed tools/call → method is also None"
        );
    }

    #[test]
    fn verified_identity_minimal_all_none() {
        let id = VerifiedIdentity::minimal();
        assert!(id.identity_id.is_none());
        assert!(id.subject.is_none());
        assert!(id.email.is_none());
        assert!(id.groups.is_none());
        assert!(id.key_id.is_none());
    }

    #[test]
    fn parse_mcp_meta_extracts_method_for_non_tool_call() {
        // For tools/list (not tools/call), the tool is None but the method
        // is surfaced for activity logging.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        let (tool, method) = parse_mcp_meta(body.as_bytes(), "fs");
        assert!(tool.is_none(), "non-tools/call → no tool");
        assert_eq!(method.as_deref(), Some("tools/list"));
    }

    #[test]
    fn parse_mcp_meta_handles_notification() {
        // A notification (no id) is not a tool target — returns (None, None)
        // because extract_tool_call returns Ok(None).
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })
        .to_string();
        let (tool, method) = parse_mcp_meta(body.as_bytes(), "fs");
        assert!(tool.is_none());
        assert!(method.is_none(), "notification → not an enforcement target");
    }
}
