//! The `mcp_server_policies` entity — per-group per-tool MCP policies.

use sea_orm::entity::prelude::*;

/// A per-group MCP authorization policy.
///
/// Each row maps a group name (from the IdP) to a per-server, per-tool
/// allowlist. The `allowed_tools` column holds a JSON array of
/// `"server:tool"` entries (e.g. `["github:list_files","slack:post_message"]`).
/// A `NULL` value means **all tools are allowed** on all servers that the
/// group can reach; an empty array means the group may reach no tools.
///
/// Server-level reachability is governed separately (all configured servers
/// are reachable in v1 unless filtered by policy at merge time).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "mcp_server_policies")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The group name (unique). Matches a group/role from the IdP.
    #[sea_orm(unique)]
    pub group_name: String,
    /// JSON array of allowed `"server:tool"` entries. `None` means all
    /// tools across all servers are allowed.
    pub allowed_tools: Option<String>,
    /// When this policy was created.
    pub created_at: TimeDateTime,
    /// When this policy was last updated.
    pub updated_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}