//! The `provider_key_access` entity — group-based ACL on provider keys.

use sea_orm::entity::prelude::*;

/// A group-based access control entry for a provider key. If a key has
/// rows in this table, only members of the listed groups may use that
/// key. If a key has no rows, any authenticated user may use it.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "provider_key_access")]
pub struct Model {
    /// The provider key this entry applies to.
    #[sea_orm(primary_key)]
    pub provider_key_id: String,
    /// The group name allowed to use the key.
    #[sea_orm(primary_key)]
    pub group_name: String,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
