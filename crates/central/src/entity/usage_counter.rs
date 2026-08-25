//! The `usage_counters` entity — per-user cumulative usage tracking.

use sea_orm::entity::prelude::*;

/// A usage counter entry tracking a user's cumulative usage for a period.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "usage_counters")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The user subject.
    pub user_subject: String,
    /// The group name (optional, for group-level reporting).
    pub group_name: Option<String>,
    /// The period date (e.g. `2026-08-25` for daily).
    pub period_date: String,
    /// The period kind: `daily` or `monthly`.
    pub period_kind: String,
    /// Cumulative request count for the period.
    pub request_count: i64,
    /// Cumulative token count for the period.
    pub token_count: i64,
    /// Cumulative cost in USD for the period.
    pub cost_usd: f32,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
