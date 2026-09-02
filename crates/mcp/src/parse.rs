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
/// - `Some(ToolCall)` with `method == "tools/call"` and the tool name in
///   `tool` when the body is a `tools/call` request that must be
///   permission-checked against `server`.
/// - `Some(ToolCall { method, tool: "" })` for other recognized request
///   methods (e.g. `tools/list`, `initialize`) — used for audit
///   classification, no per-tool enforcement.
///
/// # Errors
///
/// Returns [`McpError`] on malformed UTF-8/JSON, or
/// [`McpError::BatchUnsupported`] for JSON-RPC batch (array) messages.
/// Non-request payloads (responses, notifications, scalars) return
/// `Ok(None)`.
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
            method: METHOD_TOOLS_CALL.to_string(),
            tool: params.name,
            id: req.id.clone(),
            args_preview: redact_args(params.arguments.as_ref()),
        }));
    }
    // Other recognized request methods — no per-tool enforcement, but we
    // surface them for audit classification with an empty tool name.
    Ok(Some(ToolCall {
        server: server.to_string(),
        method: req.method,
        tool: String::new(),
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
/// Before serialization, values for known-sensitive keys are replaced with
/// `"[REDACTED]"` so secrets passed as tool arguments (e.g.
/// `{"api_key": "sk-..."}`) do not leak into the audit log. The result is
/// then truncated to the character cap as a second line of defense.
///
/// This is intentionally a lossy representation — never the full arguments.
#[must_use]
pub fn redact_args(args: Option<&Value>) -> Option<String> {
    let value = args?;
    // Walk the JSON and redact known-sensitive keys before serializing.
    let redacted = redact_sensitive_values(value);
    let json = serde_json::to_string(&redacted).unwrap_or_else(|_| "{}".to_string());
    if json.chars().count() <= ARGS_PREVIEW_MAX_CHARS {
        Some(json)
    } else {
        let truncated: String = json.chars().take(ARGS_PREVIEW_MAX_CHARS).collect();
        Some(format!("{truncated}…[truncated]"))
    }
}

/// Keys whose values are redacted in tool-argument audit previews.
///
/// This is a conservative allowlist of common secret-bearing key names.
/// The match is case-sensitive on the exact key (not a substring match) to
/// avoid over-redacting unrelated fields.
const SENSITIVE_ARG_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "password",
    "secret",
    "authorization",
    "auth",
    "bearer",
    "credential",
    "credentials",
    "private_key",
    "private-key",
    "client_secret",
];

/// Returns `true` if `key` matches a known-sensitive argument key
/// (case-sensitive exact match).
fn is_sensitive_arg_key(key: &str) -> bool {
    SENSITIVE_ARG_KEYS.contains(&key)
}

/// Recursively walks a JSON value and replaces values for known-sensitive
/// keys with `"[REDACTED]"`. Objects and arrays are traversed; scalars are
/// returned unchanged.
fn redact_sensitive_values(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                if is_sensitive_arg_key(key) {
                    out.insert(key.clone(), Value::String("[REDACTED]".into()));
                } else {
                    out.insert(key.clone(), redact_sensitive_values(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_sensitive_values).collect()),
        _ => value.clone(),
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
        assert_eq!(call.method, "tools/call");
        assert_eq!(call.tool, "read_file");
        let preview = call.args_preview.expect("args present");
        assert!(preview.contains("/tmp/x"));
    }

    #[test]
    fn tools_call_without_args() {
        let b =
            body(r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"ping"}}"#);
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        assert_eq!(call.method, "tools/call");
        assert_eq!(call.tool, "ping");
        assert!(call.args_preview.is_none());
    }

    #[test]
    fn tools_list_is_audit_classified() {
        let b = body(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        // Not a tool call: method carries the classification, tool is empty.
        assert_eq!(call.method, "tools/list");
        assert!(call.tool.is_empty());
        assert!(call.args_preview.is_none());
    }

    #[test]
    fn initialize_is_audit_classified() {
        let b = body(
            r#"{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocol_version":"2025-06-18"}}"#,
        );
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        assert_eq!(call.method, "initialize");
        assert!(call.tool.is_empty());
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
    fn sensitive_keys_are_redacted_in_args_preview() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "x",
                "arguments": {
                    "api_key": "sk-secret-12345",
                    "password": "hunter2",
                    "token": "abc-token",
                    "normal_field": "visible",
                }
            }
        });
        let b = serde_json::to_vec(&req).expect("serialize");
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        let preview = call.args_preview.expect("args present");
        assert!(
            !preview.contains("sk-secret-12345"),
            "api_key value must be redacted: {preview}"
        );
        assert!(
            !preview.contains("hunter2"),
            "password value must be redacted: {preview}"
        );
        assert!(
            !preview.contains("abc-token"),
            "token value must be redacted: {preview}"
        );
        assert!(
            preview.contains("[REDACTED]"),
            "redacted values must show [REDACTED]: {preview}"
        );
        assert!(
            preview.contains("visible"),
            "non-sensitive values must be visible: {preview}"
        );
    }

    #[test]
    fn nested_sensitive_keys_are_redacted() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "x",
                "arguments": {
                    "config": {
                        "credentials": "secret-value",
                        "host": "example.com",
                    },
                    "items": [
                        { "api_key": "nested-secret" },
                        { "name": "item2" }
                    ]
                }
            }
        });
        let b = serde_json::to_vec(&req).expect("serialize");
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        let preview = call.args_preview.expect("args present");
        assert!(
            !preview.contains("secret-value"),
            "nested credentials must be redacted: {preview}"
        );
        assert!(
            !preview.contains("nested-secret"),
            "array-item api_key must be redacted: {preview}"
        );
        assert!(
            preview.contains("example.com"),
            "non-sensitive nested values must be visible: {preview}"
        );
        assert!(
            preview.contains("item2"),
            "non-sensitive array items must be visible: {preview}"
        );
    }

    #[test]
    fn redaction_is_key_exact_match_not_substring() {
        // A key like "api_key_url" should NOT be redacted (it's not in the
        // sensitive list — only exact matches are redacted).
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "x",
                "arguments": {
                    "api_key_url": "https://example.com/keys",
                    "key_id": "key-123"
                }
            }
        });
        let b = serde_json::to_vec(&req).expect("serialize");
        let call = extract_tool_call(&b, "srv").expect("parse").expect("some");
        let preview = call.args_preview.expect("args present");
        assert!(
            preview.contains("https://example.com/keys"),
            "non-exact key match must not be redacted: {preview}"
        );
        assert!(
            preview.contains("key-123"),
            "key_id is not in the sensitive list: {preview}"
        );
    }

    #[test]
    fn malformed_json_errors() {
        let b = body(r#"{"jsonrpc":"2.0","id":1,"method":""#);
        assert!(extract_tool_call(&b, "srv").is_err());
    }

    #[test]
    fn batch_is_rejected() {
        // A JSON-RPC batch (array) must be rejected, not silently passed
        // through — a batch can contain tools/call requests that would
        // bypass per-tool permission enforcement if forwarded verbatim.
        let b = body(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#);
        let err = extract_tool_call(&b, "srv").unwrap_err();
        assert!(
            matches!(err, crate::McpError::BatchUnsupported),
            "batch must be rejected with BatchUnsupported, got {err:?}"
        );
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
