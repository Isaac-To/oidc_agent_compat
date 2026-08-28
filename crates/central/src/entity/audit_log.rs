//! The `audit_log` entity — an append-only log of every proxied request.

use sea_orm::entity::prelude::*;

/// An audit log entry for a single proxied request.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_log")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key)]
    pub id: String,
    /// The device ID that made the request.
    pub device_id: String,
    /// The user subject.
    pub user_subject: String,
    /// The model requested (from the request body, if parseable).
    pub model: Option<String>,
    /// The backend name.
    pub backend: String,
    /// The HTTP status code of the upstream response.
    pub status: i32,
    /// The request latency in milliseconds.
    pub latency_ms: i64,
    /// Whether the response was streamed.
    pub stream: bool,
    /// Token usage (prompt tokens), if reported by the upstream.
    pub prompt_tokens: Option<i32>,
    /// Token usage (completion tokens), if reported.
    pub completion_tokens: Option<i32>,
    /// Token usage (total tokens), if reported.
    pub total_tokens: Option<i32>,
    /// When the request was made.
    pub created_at: TimeDateTime,
    /// The relay-side identity database ID (enrichment).
    pub identity_id: Option<String>,
    /// The user email (enrichment).
    pub email: Option<String>,
    /// The group/role memberships as a JSON array string (enrichment).
    pub groups: Option<String>,
    /// The request endpoint/path (e.g. `/v1/chat/completions`).
    pub endpoint: Option<String>,
    /// The request ID for end-to-end correlation.
    pub request_id: Option<String>,
    /// The permission decision: `allowed` or `denied` (NULL if not yet
    /// enforced, e.g. before the permissions middleware existed).
    pub permission_decision: Option<String>,
    /// The reason a request was denied (set when permission_decision is
    /// `denied`).
    pub denial_reason: Option<String>,
    /// The estimated cost in USD (enrichment; populated in phase 3).
    pub cost_usd: Option<f64>,
    /// Whether the token saver optimised this request (enrichment).
    pub token_saver_applied: Option<bool>,
    /// Estimated tokens saved by the token saver for this request.
    pub tokens_saved: Option<i64>,
    /// Total whole messages dropped (duplicates + budget + empty).
    pub messages_dropped: Option<i64>,
    /// Human-readable reason tags for what the saver did, as JSON.
    pub saver_reasons: Option<String>,
    /// The MCP server id (for MCP traffic).
    pub mcp_server: Option<String>,
    /// The MCP tool name (for `tools/call`; otherwise empty).
    pub mcp_tool: Option<String>,
    /// The MCP JSON-RPC method (e.g. `tools/call`, `initialize`).
    pub mcp_method: Option<String>,
    /// A redacted, length-capped preview of the MCP tool arguments.
    pub mcp_args_preview: Option<String>,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
