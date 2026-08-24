//! The `identity` entity — a record of an employee authenticated via OIDC.

use sea_orm::entity::prelude::*;

/// An employee identity, derived from OIDC userinfo.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "identities")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key)]
    pub id: Uuid,
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

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// One identity has many API keys.
    #[sea_orm(has_many = "super::api_key::Entity")]
    ApiKeys,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeys.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
