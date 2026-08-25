//! The `admin_audit_log` entity — an append-only log of admin API mutations.

use sea_orm::entity::prelude::*;

/// An admin audit log entry recording a single admin API mutation.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "admin_audit_log")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The admin's subject (from the admin token).
    pub admin_subject: String,
    /// The action performed (e.g. `upsert_policy`, `delete_policy`).
    pub action: String,
    /// The target of the action (e.g. group name or device fingerprint).
    pub target: String,
    /// The request payload (JSON), if any.
    pub payload: Option<String>,
    /// When the action was performed.
    pub created_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
