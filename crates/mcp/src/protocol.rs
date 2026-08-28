//! MCP protocol constants and handshake types.
//!
//! As of MCP spec 2025-06-18, clients use the Streamable HTTP transport:
//! JSON-RPC 2.0 over a single HTTP endpoint. The proxy treats the method
//! name and tool call as the enforcement surface.

use serde::{Deserialize, Serialize};

/// The current MCP protocol version negotiated in the `initialize` handshake
/// (`2025-06-18`). The proxy does not hard-enforce a version beyond 2.0
/// framing, but records what was negotiated.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The MCP `initialize` method (client → server).
pub const METHOD_INITIALIZE: &str = "initialize";

/// The MCP `notifications/initialized` notification.
pub const METHOD_INITIALIZED_NOTIFICATION: &str = "notifications/initialized";

/// The MCP `tools/list` method (client → server, server responds with the
/// available tools).
pub const METHOD_TOOLS_LIST: &str = "tools/list";

/// The MCP `tools/call` method (client → server, requests a tool execution).
/// This is the primary permission enforcement surface.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// The MCP `resources/list` method (client → server).
pub const METHOD_RESOURCES_LIST: &str = "resources/list";

/// The MCP `resources/read` method (client → server).
pub const METHOD_RESOURCES_READ: &str = "resources/read";

/// The MCP `prompts/list` method (client → server).
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";

/// The MCP `ping` method.
pub const METHOD_PING: &str = "ping";

/// A canonical set of client-initiated request methods the proxy recognizes
/// as "forwardable tool-related traffic". Notifications and responses are
/// excluded.
pub const CLIENT_METHODS: [&str; 7] = [
    METHOD_INITIALIZE,
    METHOD_TOOLS_LIST,
    METHOD_TOOLS_CALL,
    METHOD_RESOURCES_LIST,
    METHOD_RESOURCES_READ,
    METHOD_PROMPTS_LIST,
    METHOD_PING,
];

/// The `initialize` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// The MCP protocol version the client wants to use.
    pub protocol_version: String,
    /// Client capability declarations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    /// Client implementation info.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<serde_json::Value>,
}

/// The `tools/call` request parameters.
///
/// This is the type the permissions layer enforces on: the tool `name` and
/// (optionally) the `arguments`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    /// The name of the tool to invoke.
    pub name: String,
    /// The tool arguments (arbitrary JSON). Kept for redaction and audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
}

/// A parsed tool invocation extracted from a `tools/call` request.
///
/// The `server` field is the upstream MCP server endpoint the request is
/// routed to (inferred from the URL path by the proxy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// The MCP server name the tool belongs to.
    pub server: String,
    /// The tool name.
    pub tool: String,
    /// The JSON-RPC request id, if the call was a request (not a
    /// notification). Used for audit correlation but not persisted.
    pub id: Option<serde_json::Value>,
    /// A short, redacted preview of the arguments (length-capped), or
    /// `None` if no arguments were supplied.
    pub args_preview: Option<String>,
}