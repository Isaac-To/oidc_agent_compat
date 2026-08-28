//! Error types for MCP parsing and validation.

use thiserror::Error;

/// Errors that can occur while parsing or validating MCP/JSON-RPC traffic
/// at the proxy boundary.
#[derive(Debug, Error)]
pub enum McpError {
    /// The request body could not be decoded as UTF-8.
    #[error("request body is not valid UTF-8")]
    InvalidUtf8,
    /// The request body could not be parsed as JSON-RPC.
    #[error("invalid JSON-RPC: {0}")]
    InvalidJsonRpc(String),
    /// The JSON-RPC object has the wrong shape (e.g. missing id/method).
    #[error("malformed JSON-RPC request: {0}")]
    Malformed(String),
    /// The message is a batch (array) rather than a single object. Not
    /// supported for per-tool enforcement in v1.
    #[error("batch JSON-RPC messages are not supported")]
    BatchUnsupported,
    /// The JSON-RPC method is not a method MCP servers respond to (e.g. it
    /// is a response or a well-known unknown method).
    #[error("unrecognized JSON-RPC method: {0}")]
    UnknownMethod(String),
}

/// Convenience result alias for MCP parsing.
pub type Result<T> = std::result::Result<T, McpError>;
