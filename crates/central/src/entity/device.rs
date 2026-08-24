//! The `device` entity — a registered relay device with an mTLS client cert.

use sea_orm::entity::prelude::*;

/// A registered relay device, identified by its mTLS client cert fingerprint.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    /// Primary key.
    #[sea_orm(primary_key)]
    pub id: String,
    /// The SHA-256 fingerprint of the device's mTLS client cert.
    pub cert_fingerprint: String,
    /// The user identity (subject) this device belongs to.
    pub user_subject: String,
    /// The user's email, if known.
    pub user_email: Option<String>,
    /// Whether this device is revoked (revoked certs are rejected).
    pub revoked: bool,
    /// When this device was registered.
    pub created_at: TimeDateTime,
    /// When this device was last seen.
    pub last_seen_at: Option<TimeDateTime>,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
