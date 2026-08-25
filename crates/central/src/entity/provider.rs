//! The `providers` entity — runtime-managed OpenAI-compatible backends.

use sea_orm::entity::prelude::*;

/// A provider is an OpenAI-compatible backend that central can forward
/// requests to. Providers are managed at runtime via the admin API (not
/// config file). Each provider declares the models it serves so central
/// can route requests by model name.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "providers")]
pub struct Model {
    /// Primary key — a short stable identifier (e.g. "openai", "azure-east").
    #[sea_orm(primary_key)]
    pub id: String,
    /// Human-readable name for audit logs and admin display.
    pub name: String,
    /// Base URL of the OpenAI-compatible backend (e.g.
    /// `https://api.openai.com`).
    pub base_url: String,
    /// Whether this provider is enabled (disabled providers are skipped
    /// during routing).
    pub enabled: bool,
    /// Whether this is the default provider used when no provider matches
    /// the requested model. At most one provider should have this set.
    pub is_default: bool,
    /// JSON array of model name patterns this provider serves (e.g.
    /// `["gpt-4o", "gpt-4o-mini"]`). `None` means this provider serves
    /// all models (only sensible for a default/fallback provider).
    pub models: Option<String>,
    /// When this provider was created.
    pub created_at: TimeDateTime,
    /// When this provider was last updated.
    pub updated_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
