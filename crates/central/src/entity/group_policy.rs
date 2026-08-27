//! The `group_policies` entity — per-group authorization policies.

use sea_orm::entity::prelude::*;

/// A group authorization policy.
///
/// Each row maps a group name (from the IdP) to a set of restrictions:
/// allowed models, allowed endpoints, and daily quotas. A `NULL`
/// allowlist means "all allowed"; a `NULL` quota means "unlimited".
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "group_policies")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The group name (unique). Matches a group/role from the IdP.
    #[sea_orm(unique)]
    pub group_name: String,
    /// JSON array of allowed models (e.g. `["gpt-4o", "gpt-4o-mini"]`).
    /// `None` means all models are allowed.
    pub allowed_models: Option<String>,
    /// JSON array of allowed endpoints (e.g. `["/v1/chat/completions"]`).
    /// `None` means all endpoints are allowed.
    pub allowed_endpoints: Option<String>,
    /// Daily token quota (total tokens per day). `None` means unlimited.
    pub daily_token_quota: Option<i64>,
    /// Daily request quota (requests per day). `None` means unlimited.
    pub daily_request_quota: Option<i64>,
    /// Whether the safe token-saver optimiser is enabled for this group.
    pub token_saver_enabled: bool,
    /// Per-request input-token budget. When exceeded, the oldest whole turns
    /// are dropped (never truncated) until the request fits. `None` disables
    /// budget trimming.
    pub max_input_tokens: Option<i64>,
    /// When this policy was created.
    pub created_at: TimeDateTime,
    /// When this policy was last updated.
    pub updated_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
