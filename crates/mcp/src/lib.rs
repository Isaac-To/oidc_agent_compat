//! Model Context Protocol (MCP) shared types and parsing.
//!
//! This crate authoritatively defines the JSON-RPC 2.0 framing and the
//! MCP method/type subset that the relay and central proxy understand. It
//! intentionally does **not** depend on a heavyweight MCP SDK — it provides
//! just enough typed surface to enforce per-tool permissions and produce
//! audit metadata at the proxy boundary.
//!
//! # Design
//!
//! The relay and central forward MCP traffic as raw JSON-RPC bytes over
//! HTTP (MCP Streamable HTTP transport). To enforce per-tool permissions
//! and log tool usage, the boundary must parse enough of each request:
//!
//! - the JSON-RPC version + method (`initialize`, `tools/list`,
//!   `tools/call`, notifications),
//! - for `tools/call`, the tool name and (redacted) arguments.
//!
//! This crate provides those parse helpers plus MCP method constants and
//! the `initialize` handshake types. Everything else is passed through
//! verbatim.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::dbg_macro
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod errors;
pub mod hub;
pub mod jsonrpc;
pub mod parse;
pub mod protocol;

pub use errors::{McpError, Result};
