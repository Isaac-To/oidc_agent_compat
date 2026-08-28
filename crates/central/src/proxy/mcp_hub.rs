//! Combined MCP hub handler (`/mcp`).
//!
//! This is the single MCP endpoint a user configures in their agent. It
//! aggregates every centrally-hosted MCP server into one namespace:
//!
//! - **`initialize`** → forwards to the first enabled server reachable by
//!   the caller and returns its result (so the client negotiates a protocol
//!   version).
//! - **`tools/list`** → fans out to each enabled server the caller may
//!   reach, prefixes every tool name with `{server}__`, filters by the
//!   caller's per-tool policy, and aggregates the results.
//! - **`tools/call`** → splits the prefixed name into `(server, tool)`,
//!   enforces the caller's per-tool policy inline, and routes to that server.
//! - **`ping`** → returns an empty result.
//! - **notifications/*** → best-effort broadcast to all reachable servers.
//!
//! # Security
//!
//! - Enforcement happens here (on the central proxy, after auth) — a
//!   compromised relay cannot bypass per-tool policy.
//! - Every `tools/call` (allowed or denied) and every upstream error is
//!   recorded with the same [`McpGrant`]-based audit mapping as the
//!   per-server endpoint.

use std::collections::HashSet;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use oidc_agent_common::error::{Error, Result};
use oac_mcp::hub;
use oac_mcp::protocol::{
    METHOD_INITIALIZE, METHOD_PING, METHOD_TOOLS_CALL, METHOD_TOOLS_LIST,
};

use super::AppState;
use crate::proxy::mcp_permissions::{McpGrant, record_mcp_audit};

/// Handles a combined `/mcp` request.
pub async fn mcp_hub_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = Instant::now();
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();

    // Groups used for policy resolution.
    let groups: Vec<String> = identity
        .as_ref()
        .and_then(|i| i.groups.as_deref())
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();

    // Read the JSON-RPC body.
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, super::MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "hub: failed to read body");
            return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "parse error");
        }
    };

    // Parse the method.
    let parsed = oac_mcp::parse::parse_request_body(&body_bytes);
    let (method, id) = match parsed {
        Ok(Some(req)) => (req.method.clone(), req.id),
        Ok(None) => {
            // Not a request object (notification/response/batch). Try to
            // classify and forward/broadcast as appropriate; otherwise allow.
            return json_rpc_error(StatusCode::OK, -32600, "invalid request");
        }
        Err(_) => return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "parse error"),
    };

    // Determine the set of servers the caller may reach (for fan-out).
    let reachable = match state
        .policy_store
        .resolve_mcp_allowed_servers(&groups)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "hub: policy resolution failed");
            let _ = record_hub_audit(&state, &identity, &method, "", StatusCode::FORBIDDEN, start, None).await;
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };

    match method.as_str() {
        METHOD_TOOLS_CALL => {
            handle_tools_call(&state, &identity, &groups, id, &body_bytes, start).await
        }
        METHOD_TOOLS_LIST => {
            handle_tools_list(&state, &identity, &groups, &reachable, id, &body_bytes, start).await
        }
        METHOD_INITIALIZE => {
            handle_initialize(&state, &identity, &reachable, id, start).await
        }
        METHOD_PING => {
            let _ = record_hub_audit(&state, &identity, &method, "", StatusCode::OK, start, None).await;
            json_response(id, serde_json::json!({}))
        }
        m if m.starts_with("notifications/") => {
            // Best-effort broadcast; client does not expect a response.
            broadcast_notification(&state, &groups, &body_bytes).await;
            (StatusCode::ACCEPTED, Body::empty()).into_response()
        }
        _ => {
            // Unknown method: MCP JSON-RPC error -32601.
            let _ = record_hub_audit(&state, &identity, &method, "", StatusCode::OK, start, None).await;
            json_rpc_error(StatusCode::OK, -32601, "method not found")
        }
    }
}

/// Handles a `tools/call` on the hub: split the prefixed name, enforce the
/// per-tool policy, and route to the target server.
async fn handle_tools_call(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    groups: &[String],
    _id: Option<serde_json::Value>,
    raw_body: &[u8],
    start: Instant,
) -> Response<Body> {
    // Extract the tool name from the JSON-RPC body.
    let tool_name = oac_mcp::parse::extract_tool_call(raw_body, "hub")
        .ok()
        .flatten()
        .map(|call| call.tool);
    let Some(tool_name) = tool_name else {
        let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, "", StatusCode::BAD_REQUEST, start, None).await;
        return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "malformed tools/call");
    };

    // Split into server + tool.
    let Some((server, tool)) = hub::split_tool_name(&tool_name) else {
        let _ = record_hub_audit(
            state,
            identity,
            METHOD_TOOLS_CALL,
            &tool_name,
            StatusCode::BAD_REQUEST,
            start,
            None,
        )
        .await;
        return json_rpc_error(
            StatusCode::BAD_REQUEST,
            -32602,
            format!("tool name '{tool_name}' is missing a '{{server}}__' prefix"),
        );
    };

    // Enforce per-tool policy inline (deny-by-default).
    let allowed = match state
        .policy_store
        .resolve_mcp_tool_allowed(groups, server, tool)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, server = %server, tool = %tool, "hub: policy resolution failed");
            let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, &tool_name, StatusCode::FORBIDDEN, start, None).await;
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };
    if !allowed {
        // Record a denied audit entry (consistent with per-server endpoint).
        if let Some(identity) = identity {
            let grant = McpGrant {
                server: server.to_string(),
                method: METHOD_TOOLS_CALL.to_string(),
                tool: tool.to_string(),
                decision: "denied".to_string(),
                reason: Some(format!("tool '{tool}' is not allowed on MCP server '{server}'")),
                args_preview: None,
            };
            record_mcp_audit(
                state,
                identity,
                &grant,
                StatusCode::FORBIDDEN,
                start.elapsed().as_millis() as i64,
                false,
            )
            .await;
        }
        return json_rpc_error(
            StatusCode::FORBIDDEN,
            -32001,
            format!("tool '{tool}' is not allowed on MCP server '{server}'"),
        );
    }

    // Route to the server.
    let resolved = match state.mcp_manager.resolve_server(server).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, &tool_name, StatusCode::NOT_FOUND, start, None).await;
            return json_rpc_error(StatusCode::NOT_FOUND, -32602, format!("MCP server '{server}' not found or disabled"));
        }
        Err(e) => {
            tracing::error!(error = %e, server = %server, "hub: resolve failed");
            let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, &tool_name, StatusCode::BAD_GATEWAY, start, None).await;
            return json_rpc_error(StatusCode::BAD_GATEWAY, -32603, "upstream MCP request failed");
        }
    };

    // Rewrite the tool name in the body to the unprefixed name before
    // forwarding (the upstream knows its own tool names).
    let rewritten = rewrite_tool_name(raw_body, tool);
    match call_upstream(state, server, &resolved, &rewritten).await {
        Ok((resp, status, _stream)) => {
            let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, &tool_name, status, start, None).await;
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, server = %server, "hub: upstream call failed");
            let _ = record_hub_audit(state, identity, METHOD_TOOLS_CALL, &tool_name, StatusCode::BAD_GATEWAY, start, None).await;
            json_rpc_error(StatusCode::BAD_GATEWAY, -32603, "upstream MCP request failed")
        }
    }
}

/// Handles a `tools/list`: fan out to enabled reachable servers, prefix tool
/// names, filter by policy, and aggregate.
async fn handle_tools_list(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    groups: &[String],
    reachable: &Option<HashSet<String>>,
    _id: Option<serde_json::Value>,
    raw_body: &[u8],
    start: Instant,
) -> Response<Body> {
    // The set of tool entries allowed (None = all). Used to filter.
    let allowed_tools = match state
        .policy_store
        .resolve_mcp_allowed_tools(groups)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "hub: tools/list policy failed");
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };

    // Enabled servers, filtered to those reachable.
    let enabled = match state.mcp_manager.list_enabled_servers().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "hub: list servers failed");
            return json_rpc_error(StatusCode::BAD_GATEWAY, -32603, "server listing failed");
        }
    };
    let servers: Vec<&crate::mcp::McpServerInfo> = enabled
        .iter()
        .filter(|s| reachable.as_ref().map_or(true, |r| r.contains(&s.id)))
        .collect();

    let mut tools: serde_json::Value = serde_json::json!([]);
    let mut any = false;
    for server_info in servers {
        let resolved = match state.mcp_manager.resolve_server(&server_info.id).await {
            Ok(Some(r)) => r,
            _ => continue,
        };
        if let Ok((resp, status, _)) = call_upstream(state, &server_info.id, &resolved, raw_body).await {
            if status == StatusCode::OK {
                if let Ok(bytes) = axum::body::to_bytes(resp.into_body(), super::MAX_BODY_SIZE).await {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(list) = value.pointer("/result/tools").and_then(|v| v.as_array()) {
                            for tool in list {
                                if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                                    let prefixed = hub::join_tool_name(&server_info.id, name);
                                    // Filter by per-tool policy.
                                    if let Some(allowed) = &allowed_tools {
                                        if !allowed.contains(&prefixed) {
                                            continue;
                                        }
                                    }
                                    let mut t = tool.clone();
                                    if let Some(obj) = t.as_object_mut() {
                                        obj.insert("name".into(), serde_json::Value::String(prefixed.clone()));
                                        // Optional convenience: annotate with the source server.
                                        obj.insert("x-oac-server".into(), serde_json::Value::String(server_info.id.clone()));
                                    }
                                    tools.as_array_mut().expect("array").push(t);
                                }
                            }
                        }
                    }
                }
            }
        }
        any = true;
    }
    let _ = any;
    let _ = record_hub_audit(state, identity, METHOD_TOOLS_LIST, "", StatusCode::OK, start, Some(format!("{} tools", tools.as_array().map(|a| a.len()).unwrap_or(0)))).await;
    json_response(None, serde_json::json!({ "tools": tools }))
}

/// Handles `initialize`: forward to the first reachable server and return its
/// result; if none, return a default (protocol version).
async fn handle_initialize(
    state: &AppState,
    _identity: &Option<super::auth::VerifiedRelayIdentity>,
    reachable: &Option<HashSet<String>>,
    id: Option<serde_json::Value>,
    _start: Instant,
) -> Response<Body> {
    let enabled = match state.mcp_manager.list_enabled_servers().await {
        Ok(s) => s,
        Err(_) => Vec::new(),
    };
    for server_info in enabled {
        if reachable.as_ref().map_or(true, |r| r.contains(&server_info.id)) {
            if let Ok(Some(resolved)) = state.mcp_manager.resolve_server(&server_info.id).await {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "method": METHOD_INITIALIZE,
                    "params": { "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION, "capabilities": {}, "clientInfo": { "name": "oac-hub", "version": "1.0" } },
                })
                .to_string();
                if let Ok((resp, status, _)) = call_upstream(state, &server_info.id, &resolved, body.as_bytes()).await {
                    if status == StatusCode::OK {
                        if let Ok(bytes) = axum::body::to_bytes(resp.into_body(), super::MAX_BODY_SIZE).await {
                            if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                value["id"] = serde_json::Value::from(id.clone().unwrap_or(serde_json::Value::Null));
                                return json_response(id, value.get("result").cloned().unwrap_or(serde_json::json!({ "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION })));
                            }
                        }
                    }
                }
            }
        }
    }
    json_response(id, serde_json::json!({ "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION, "capabilities": {}, "serverInfo": { "name": "oac-hub", "version": "1.0" } }))
}

/// Broadcasts a notification to every reachable server (best-effort).
async fn broadcast_notification(state: &AppState, groups: &[String], raw_body: &[u8]) {
    let reachable = match state.policy_store.resolve_mcp_allowed_servers(groups).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let enabled = match state.mcp_manager.list_enabled_servers().await {
        Ok(s) => s,
        Err(_) => return,
    };
    for server_info in enabled {
        if reachable.as_ref().map_or(true, |r| r.contains(&server_info.id)) {
            if let Ok(Some(resolved)) = state.mcp_manager.resolve_server(&server_info.id).await {
                let _ = call_upstream(state, &server_info.id, &resolved, raw_body).await;
            }
        }
    }
}

/// Rewrites the `params.name` field of a `tools/call` body to the
/// unprefixed tool name, for forwarding to the upstream.
fn rewrite_tool_name(raw_body: &[u8], tool: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(raw_body).unwrap_or(serde_json::Value::Null);
    if let Some(params) = value.get_mut("params") {
        if let Some(obj) = params.as_object_mut() {
            obj.insert("name".into(), serde_json::Value::String(tool.to_string()));
        }
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| raw_body.to_vec())
}

/// Forwards a raw JSON-RPC body to a specific upstream MCP server, injecting
/// its auth header and stripping hop-by-hop headers.
async fn call_upstream(
    state: &AppState,
    _server: &str,
    resolved: &crate::mcp::ResolvedMcpServer,
    body: &[u8],
) -> Result<(Response<Body>, StatusCode, bool)> {
    let base = resolved.base_url.trim_end_matches('/').to_string();
    let url = format!("{base}/");

    // Build headers: forwardables are not needed for synthetic JSON-RPC; only
    // content-type + optional auth header.
    let mut headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)> = Vec::new();
    headers.push((
        axum::http::HeaderName::from_static("content-type"),
        axum::http::HeaderValue::from_static("application/json"),
    ));
    if let Some(auth) = &resolved.auth_header {
        if let Some((name, value)) = auth.as_str().split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if !name.is_empty() {
                if let Ok(n) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
                    if let Ok(v) = axum::http::HeaderValue::from_str(value) {
                        headers.push((n, v));
                    }
                }
            }
        }
    }

    let map: reqwest::header::HeaderMap = headers
        .into_iter()
        .map(|(n, v)| {
            let name =
                reqwest::header::HeaderName::from_bytes(n.as_str().as_bytes()).map_err(|_| {
                    Error::Http("invalid header".into())
                })?;
            let value = reqwest::header::HeaderValue::from_bytes(v.as_bytes())
                .map_err(|_| Error::Http("invalid header value".into()))?;
            Ok((name, value))
        })
        .collect::<Result<reqwest::header::HeaderMap>>()?;

    let resp = state
        .mcp_manager
        .client()
        .post(&url)
        .headers(map)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| Error::Http(format!("MCP upstream send: {e}")))?;

    let status = resp.status();
    let upstream_headers = resp.headers().clone();
    let stream = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(oidc_agent_common::http_util::is_sse_content_type)
        .unwrap_or(false);
    let bytes = resp.bytes().await.map_err(|e| {
        Error::Http(format!("read MCP upstream body: {e}"))
    })?;

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(bytes))
        .map_err(|e| Error::Http(format!("build MCP response: {e}")))?;
    *response.headers_mut() = upstream_headers;

    Ok((response, status, stream))
}

/// Records a hub audit entry.
async fn record_hub_audit(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    method: &str,
    tool: &str,
    status: StatusCode,
    start: Instant,
    note: Option<String>,
) -> Result<()> {
    if let Some(identity) = identity {
        let grant = McpGrant {
            server: "hub".to_string(),
            method: method.to_string(),
            tool: tool.to_string(),
            decision: if status.is_success() { "allowed".into() } else { "denied".into() },
            reason: note,
            args_preview: None,
        };
        record_mcp_audit(
            state,
            identity,
            &grant,
            status,
            start.elapsed().as_millis() as i64,
            false,
        )
        .await;
    }
    Ok(())
}

/// Builds a JSON-RPC error response with the given id = null (id lost for
/// errors in the hub path; acceptable).
fn json_rpc_error(status: StatusCode, code: i64, message: impl Into<String>) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": code, "message": message.into() },
    })
    .to_string();
    (
        status,
        [("content-type", "application/json")],
        body,
    )
        .into_response()
}

/// Builds a successful JSON-RPC response.
fn json_response(id: Option<serde_json::Value>, result: serde_json::Value) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(serde_json::Value::Null),
        "result": result,
    })
    .to_string();
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body,
    )
        .into_response()
}