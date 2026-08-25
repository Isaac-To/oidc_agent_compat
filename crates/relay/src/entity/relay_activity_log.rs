//! The `relay_activity_log` entity — an append-only log of every request
//! forwarded by the relay.

use sea_orm::entity::prelude::*;

/// A relay-side activity log entry for a single forwarded request.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "relay_activity_log")]
pub struct Model {
    /// Primary key (UUID stored as text in SQLite).
    #[sea_orm(primary_key)]
    pub id: String,
    /// The identity that made the request.
    pub identity_id: String,
    /// The API key used.
    pub key_id: String,
    /// The HTTP method (GET, POST, etc.).
    pub method: String,
    /// The request endpoint/path (e.g. `/v1/chat/completions`).
    pub endpoint: String,
    /// The model requested (from the request body, if parseable).
    pub model: Option<String>,
    /// The HTTP status code returned by the central proxy.
    pub central_status: Option<i32>,
    /// The request latency in milliseconds.
    pub latency_ms: i64,
    /// The request ID for end-to-end correlation with the central audit log.
    pub request_id: Option<String>,
    /// When the request was made.
    pub created_at: TimeDateTime,
}

/// Relations (none for v1).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
