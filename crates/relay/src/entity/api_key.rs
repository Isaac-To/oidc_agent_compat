//! The `api_key` entity — a locally-minted key bound to an identity.

use sea_orm::entity::prelude::*;

/// A local API key, stored as a SHA-256 hash (never plaintext).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key)]
    pub id: Uuid,
    /// The identity this key belongs to.
    pub identity_id: Uuid,
    /// The SHA-256 hash of the key (32 bytes, stored as a fixed-size binary).
    #[sea_orm(column_type = "Binary(32)")]
    pub key_hash: Vec<u8>,
    /// A human-readable label for the key (e.g. "codex").
    pub label: String,
    /// When the key was created.
    pub created_at: TimeDateTime,
    /// When the key was last used (updated on each proxied request).
    pub last_used_at: Option<TimeDateTime>,
}

/// Relations.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Each key belongs to one identity.
    #[sea_orm(
        belongs_to = "super::identity::Entity",
        from = "Column::IdentityId",
        to = "super::identity::Column::Id"
    )]
    Identity,
}

impl Related<super::identity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identity.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
