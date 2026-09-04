//! The `tokens` entity — central-minted opaque tokens (zero-trust).
//!
//! Each row stores the SHA-256 hash of a plaintext token minted by the
//! central proxy. The plaintext is returned to the relay at mint time and
//! never persisted. Verification is a DB lookup with constant-time hash
//! comparison (CWE-208).

use sea_orm::entity::prelude::*;

/// A central-minted opaque token.
///
/// Only the SHA-256 hash (`token_hash`) is stored; the plaintext is never
/// persisted. The token is identified by its `id` (UUID) for listing and
/// revocation.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "tokens")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The user subject (from the IdP).
    pub subject: String,
    /// The OIDC issuer.
    pub issuer: String,
    /// The user email, if known.
    pub email: Option<String>,
    /// The user display name, if known.
    pub display_name: Option<String>,
    /// The group/role memberships (JSON array string), if known.
    pub groups: Option<String>,
    /// The relay-side identity database ID, if known.
    pub identity_id: Option<String>,
    /// Human-readable label.
    pub label: String,
    /// SHA-256 hash of the plaintext token (32 bytes).
    #[sea_orm(column_type = "Binary(32)")]
    pub token_hash: Vec<u8>,
    /// When the token was minted.
    pub created_at: TimeDateTime,
    /// When the token expires (`None` = never).
    pub expires_at: Option<TimeDateTime>,
    /// When the token was last used (`None` = never).
    pub last_used_at: Option<TimeDateTime>,
    /// Whether the token has been revoked.
    pub revoked: bool,
    /// The SHA-256 fingerprint of the relay's mTLS cert that minted this token.
    /// None in dev mode. Used for device binding: a token minted on relay A
    /// cannot be used from relay B.
    pub device_fingerprint: Option<String>,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
