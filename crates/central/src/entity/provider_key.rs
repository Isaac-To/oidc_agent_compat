//! The `provider_keys` entity — API keys for a provider, encrypted at rest.

use sea_orm::entity::prelude::*;

/// An API key for a provider. The key material is encrypted at rest with
/// AES-256-GCM using the master encryption key (MEK) loaded from the
/// environment at startup. Only the encrypted `ciphertext` and `nonce` are
/// stored; plaintext is never persisted and never returned by any API.
///
/// Keys have a `priority` (lower = higher priority) used for primary +
/// fallback selection. Group-based access control is enforced via the
/// `provider_key_access` table: if a key has access rows, only members of
/// the listed groups may use it; if it has none, any authenticated user
/// may use it.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "provider_keys")]
pub struct Model {
    /// Primary key (UUID).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The provider this key belongs to.
    pub provider_id: String,
    /// Human-readable label (e.g. "prod-key-1").
    pub label: String,
    /// Priority for key selection (lower = higher priority).
    pub priority: i32,
    /// AES-256-GCM ciphertext of the API key.
    pub ciphertext: Vec<u8>,
    /// 12-byte GCM nonce.
    pub nonce: Vec<u8>,
    /// SHA-256 digest of the plaintext key (hex), for dedup detection.
    pub key_digest: String,
    /// Whether this key is enabled.
    pub enabled: bool,
    /// When this key was created.
    pub created_at: TimeDateTime,
    /// When this key was last updated.
    pub updated_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
