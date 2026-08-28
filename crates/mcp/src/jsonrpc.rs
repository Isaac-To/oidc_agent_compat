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
/// (array) messages are intentionally represented as `None` — see
/// [`crate::parse`].
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
/// needs to enforce (e.g. it is a response, an empty object, or a batch
/// that v1 does not support). Returns an error for malformed UTF-8 or
/// malformed JSON.
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
        Value::Array(_) => Ok(None),
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
