//! The `mcp_servers` entity — centrally-hosted MCP server endpoints.

use sea_orm::entity::prelude::*;

/// A configured MCP server endpoint that central can forward MCP JSON-RPC
/// traffic to. Servers are managed through the admin API (not config file).
///
/// Optional per-server auth headers are encrypted at rest with AES-256-GCM
/// using the master encryption key (MEK); only `auth_ciphertext` and
/// `auth_nonce` are stored. The plaintext header is never persisted and
/// never returned by any API — it is resolved into the forwarding path only.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "mcp_servers")]
pub struct Model {
    /// Primary key — a short stable identifier (e.g. `github`, `slack`).
    #[sea_orm(primary_key)]
    pub id: String,
    /// Human-readable name for audit logs and admin display.
    pub name: String,
    /// Base URL of the MCP server's Streamable HTTP endpoint.
    pub base_url: String,
    /// Whether this server accepts traffic (disabled servers are skipped).
    pub enabled: bool,
    /// AES-256-GCM ciphertext of the optional auth header (e.g. the value of
    /// `Authorization`). Empty when the server needs no auth.
    pub auth_ciphertext: Vec<u8>,
    /// 12-byte GCM nonce for `auth_ciphertext`.
    pub auth_nonce: Vec<u8>,
    /// When this server was created.
    pub created_at: TimeDateTime,
    /// When this server was last updated.
    pub updated_at: TimeDateTime,
}

/// Relations (none for v1; server availability is resolved per-request).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}