//! Minimal JSON-RPC 2.0 framing types.
//!
//! MCP uses JSON-RPC 2.0 over HTTP (Streamable HTTP transport). The proxy
//! forwards request/response bytes verbatim; these types exist so the
//! boundary can inspect the method, id, and tool name for permission checks
//! and audit logging without round-tripping opaque strings.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request/notification object.
///
/// Mirrors the subset of JSON-RPC 2.0 that MCP clients send. Batch
/// (array) messages are rejected by [`parse_request_body`] with
/// [`crate::McpError::BatchUnsupported`] — see that function's docs for
/// the security rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The method name (e.g. `initialize`, `tools/call`). Notifications
    /// omit `id`.
    pub method: String,
    /// The request id. Notifications have no id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// The method parameters (optional for notifications).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Returns `true` if this is a notification (has no `id`).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The echoed request id.
    pub id: Value,
    /// The result payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error payload, if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObj>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorObj {
    /// A numeric error code.
    pub code: i64,
    /// A short, human-readable message.
    pub message: String,
    /// Optional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Parses a raw request body into a JSON-RPC request object.
///
/// Returns `Ok(None)` when the body is not a JSON-RPC *request* the proxy
/// needs to enforce (e.g. it is a response, an empty object, or a scalar).
/// Returns `Err(McpError::BatchUnsupported)` for JSON-RPC batch (array)
/// messages so the proxy boundary can reject them — silently passing a
/// batch through would bypass per-tool permission enforcement, since a
/// batch can contain `tools/call` requests that are never individually
/// inspected. Returns an error for malformed UTF-8 or malformed JSON.
///
/// # Errors
///
/// See [`crate::McpError`].
pub fn parse_request_body(body: &[u8]) -> Result<Option<JsonRpcRequest>, crate::McpError> {
    let text = std::str::from_utf8(body).map_err(|_| crate::McpError::InvalidUtf8)?;
    // A batch (array) is not a single request object. Strings, numbers, and
    // null are also invalid JSON-RPC requests.
    let value: Value =
        serde_json::from_str(text).map_err(|e| crate::McpError::InvalidJsonRpc(e.to_string()))?;
    match value {
        Value::Array(_) => Err(crate::McpError::BatchUnsupported),
        Value::Object(_) => {
            let req: JsonRpcRequest = serde_json::from_value(value).map_err(|e| {
                crate::McpError::Malformed(format!("missing jsonrpc/method fields: {e}"))
            })?;
            // Guard: MCP notifications are requests without an id; anything
            // we parse as a request must at least claim jsonrpc 2.0.
            if req.jsonrpc != "2.0" {
                return Err(crate::McpError::Malformed(
                    "jsonrpc version must be 2.0".into(),
                ));
            }
            Ok(Some(req))
        }
        // scalars: null, bool, number, string — not a request object.
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let req = parse_request_body(body).expect("parse").expect("some");
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn parse_notification_has_no_id() {
        let body = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req = parse_request_body(body).expect("parse").expect("some");
        assert!(req.is_notification());
        assert!(req.id.is_none());
    }

    #[test]
    fn parse_batch_returns_batch_unsupported() {
        let body = br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#;
        let err = parse_request_body(body).unwrap_err();
        assert!(matches!(err, crate::McpError::BatchUnsupported));
    }

    #[test]
    fn parse_scalar_returns_none() {
        assert!(parse_request_body(b"42").expect("parse").is_none());
        assert!(parse_request_body(b"null").expect("parse").is_none());
        assert!(parse_request_body(b"true").expect("parse").is_none());
        assert!(
            parse_request_body(b"\"a string\"")
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn parse_wrong_jsonrpc_version_errors() {
        let body = br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#;
        assert!(parse_request_body(body).is_err());
    }

    #[test]
    fn parse_missing_method_errors() {
        // An object with jsonrpc+id but no method fails to deserialize as
        // JsonRpcRequest → Malformed error.
        let body = br#"{"jsonrpc":"2.0","id":1}"#;
        assert!(parse_request_body(body).is_err());
    }

    #[test]
    fn parse_empty_object_errors() {
        // {} deserializes (method defaults to empty string? No — method is
        // required). It must error as Malformed.
        let body = b"{}";
        assert!(parse_request_body(body).is_err());
    }

    #[test]
    fn parse_invalid_utf8_errors() {
        assert!(parse_request_body(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn parse_invalid_json_errors() {
        assert!(parse_request_body(b"{not json}").is_err());
    }

    #[test]
    fn jsonrpc_response_serializes_with_skip_none() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            result: Some(serde_json::json!({"ok": true})),
            error: None,
        };
        let s = serde_json::to_string(&resp).expect("serialize");
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn jsonrpc_error_obj_round_trips() {
        let err = JsonRpcErrorObj {
            code: -32601,
            message: "method not found".into(),
            data: Some(serde_json::json!("extra")),
        };
        let s = serde_json::to_string(&err).expect("serialize");
        let back: JsonRpcErrorObj = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.code, -32601);
        assert_eq!(back.message, "method not found");
        assert!(back.data.is_some());
    }
}
