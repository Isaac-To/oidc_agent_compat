//! The `identity` entity — a record of an employee authenticated via OIDC.

use sea_orm::entity::prelude::*;

/// An employee identity, derived from OIDC userinfo.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "identities")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The OIDC issuer URL (e.g. `https://idp.example.com`).
    pub issuer: String,
    /// The subject identifier from the IdP (the `sub` claim).
    pub subject: String,
    /// The employee's email, if provided by the IdP.
    pub email: Option<String>,
    /// The employee's display name, if provided.
    pub display_name: Option<String>,
    /// The employee's group memberships (JSON array), if provided.
    pub groups: Option<String>,
    /// When this identity was first recorded.
    pub created_at: TimeDateTime,
}

/// Relations (none for v1 — the relay no longer has an `api_keys` table
/// entity).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
