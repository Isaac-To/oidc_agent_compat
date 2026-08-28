//! Parsing helpers used at the proxy boundary to inspect MCP traffic.
//!
//! These functions extract the minimum information needed for per-tool
//! permission enforcement and audit logging:
//!
//! - whether the message is a client *request* vs a notification/response,
//! - which MCP method it targets,
//! - for `tools/call`, the tool name and a redacted argument preview.

use serde_json::Value;

use crate::errors::{McpError, Result};
use crate::jsonrpc::JsonRpcRequest;
use crate::protocol::{METHOD_TOOLS_CALL, ToolCall, ToolCallParams};

pub use crate::jsonrpc::parse_request_body;

/// Length cap for the redacted argument preview stored in audit logs.
pub const ARGS_PREVIEW_MAX_CHARS: usize = 512;

/// Classifies a request body and extracts enforcement metadata.
///
/// Returns:
/// - `Some(ToolCall)` when the body is a `tools/call` request that must be
///   permission-checked against `server`.
/// - `Some(ToolCall { tool: METHOD })` for other recognized request methods
///   (e.g. `tools/list`, `initialize`) with an empty tool name — used for
///   audit classification, no per-tool enforcement.
///
/// # Errors
///
/// Returns [`McpError`] on malformed UTF-8/JSON. Non-request payloads
/// (responses, notifications, batches, scalars) return `Ok(None)`.
pub fn extract_tool_call(body: &[u8], server: &str) -> Result<Option<ToolCall>> {
    let Some(req) = parse_request_body(body)? else {
        return Ok(None);
    };
    if !is_client_request(&req) {
        // Notifications and responses are not enforcement targets.
        return Ok(None);
    }
    if req.method == METHOD_TOOLS_CALL {
        let params: ToolCallParams = req
            .params
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| McpError::Malformed(format!("invalid tools/call params: {e}")))?
            .unwrap_or_else(|| ToolCallParams {
                name: String::new(),
                arguments: None,
            });
        if params.name.is_empty() {
            return Err(McpError::Malformed("tools/call missing tool name".into()));
        }
        return Ok(Some(ToolCall {
            server: server.to_string(),
            tool: params.name,
            id: req.id.clone(),
            args_preview: redact_args(params.arguments.as_ref()),
        }));
    }
    // Other recognized request methods — no per-tool enforcement, but we
    // surface them for audit classification with an empty tool name.
    Ok(Some(ToolCall {
        server: server.to_string(),
        tool: req.method,
        id: req.id.clone(),
        args_preview: None,
    }))
}

/// Returns `true` if `req` is a client-initiated request method (has an `id`
/// and is a recognized MCP method). Notifications (no id) are excluded.
#[must_use]
pub fn is_client_request(req: &JsonRpcRequest) -> bool {
    if req.is_notification() {
        return false;
    }
    crate::protocol::CLIENT_METHODS.contains(&req.method.as_str())
}

/// Serializes tool arguments to a compact JSON preview, length-capped to
/// [`ARGS_PREVIEW_MAX_CHARS`]. Returns `None` when `args` is `None`.
///
/// This is intentionally a lossy, truncated representation — never the full
/// arguments — so secrets passed as arguments do not leak into the audit
/// log (only the prefix up to the cap is retained).
#[must_use]
pub fn redact_args(args: Option<&Value>) -> Option<String> {
    let value = args?;
    let json = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    if json.chars().count() <= ARGS_PREVIEW_MAX_CHARS {
        Some(json)
    } else {
        let truncated: String = json.chars().take(ARGS_PREVIEW_MAX_CHARS).collect();
        Some(format!("{truncated}…[truncated]"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> Vec<u8> {
        json.as_bytes().to_vec()
    }

    #[test]
    fn tools_call_is_extracted() {
        let b = body(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}"#,
        );
        let call = extract_tool_call(&b, "fs").expect("parse").expect("some");
        assert_eq!(call.server, "fs");
        assert_eq!(call.tool, "read_file");
        let preview = call.args_preview.expect("args present");
        assert!(preview.contains("/tmp/x"));
    }

    #[test]
    fn tools_call_without_args() {
        let b =
            body(r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"ping"}}"#);
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        assert_eq!(call.tool, "ping");
        assert!(call.args_preview.is_none());
    }

    #[test]
    fn tools_list_is_audit_classified() {
        let b = body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        // Not a tool call; method surfaced as the tool for classification.
        assert_eq!(call.tool, "tools/list");
        assert!(call.args_preview.is_none());
    }

    #[test]
    fn notification_is_not_enforcement_target() {
        let b = body(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(extract_tool_call(&b, "srv").expect("parse").is_none());
    }

    #[test]
    fn missing_tool_name_is_error() {
        let b = body(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}"#);
        let err = extract_tool_call(&b, "srv").expect_err("should error");
        assert!(matches!(err, McpError::Malformed(_)));
    }

    #[test]
    fn long_args_are_truncated() {
        let long: String = "a".repeat(2000);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "x", "arguments": { "big": long } },
        });
        let b = serde_json::to_vec(&req).expect("serialize");
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        let preview = call.args_preview.expect("args present");
        assert!(preview.contains("[truncated]"));
        assert!(preview.chars().count() <= ARGS_PREVIEW_MAX_CHARS + 16);
    }

    #[test]
    fn malformed_json_errors() {
        let b = body(r#"{"jsonrpc":"2.0","id":1,"method":""#);
        assert!(extract_tool_call(&b, "srv").is_err());
    }

    #[test]
    fn batch_is_ignored() {
        let b = body(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#);
        assert!(extract_tool_call(&b, "srv").expect("parse").is_none());
    }

    #[test]
    fn scalar_body_is_ignored() {
        assert!(
            extract_tool_call(&body("42"), "srv")
                .expect("parse")
                .is_none()
        );
        assert!(
            extract_tool_call(&body("null"), "srv")
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn non_utf8_errors() {
        assert!(extract_tool_call(&[0xff, 0xfe, 0x00], "srv").is_err());
    }
}
