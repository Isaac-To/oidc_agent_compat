//! Relay-side activity logging.
//!
//! Every request forwarded by the relay is logged to the
//! `relay_activity_log` table with the identity, key, method, endpoint,
//! model, central response status, latency, and request ID. This provides
//! relay-side observability and correlates with the central audit log via
//! the shared `request_id`.
//!
//! # Security
//!
//! - The activity log is append-only (no update/delete operations are
//!   exposed; enforced at the DB level via triggers).
//! - No secrets (local API keys, master key) are ever logged.
//! - The log records who made the request, when, and the outcome.

use sea_orm::{
    ConnectionTrait, DatabaseConnection, EntityTrait, QueryOrder, QuerySelect, Statement, Value,
};
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::time_util;

/// A relay-side activity log entry for a single forwarded request.
#[derive(Debug, Clone)]
pub struct RelayActivityEntry {
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
    /// The request ID for end-to-end correlation.
    pub request_id: Option<String>,
}

/// The relay activity logger, backed by the relay's database.
#[derive(Clone)]
pub struct ActivityLogger {
    db: DatabaseConnection,
}

impl ActivityLogger {
    /// Creates a new `ActivityLogger`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Records a relay activity entry.
    ///
    /// # Security
    ///
    /// Uses parameterized queries to prevent SQL injection. No user-supplied
    /// data is interpolated into the SQL string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] if the insert fails.
    pub async fn record(&self, entry: &RelayActivityEntry) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = time_util::now_utc();
        let now_str = time_util::format_time(&now);

        let model_value = entry
            .model
            .as_ref()
            .map(|m| Value::String(Some(Box::new(m.clone()))))
            .unwrap_or(Value::String(None));
        let central_status_value = entry
            .central_status
            .map(|v| Value::Int(Some(v)))
            .unwrap_or(Value::Int(None));
        let request_id_value = entry
            .request_id
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));

        let sql = "INSERT INTO relay_activity_log \
             (id, identity_id, key_id, method, endpoint, model, central_status, \
             latency_ms, request_id, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    id.into(),
                    entry.identity_id.clone().into(),
                    entry.key_id.clone().into(),
                    entry.method.clone().into(),
                    entry.endpoint.clone().into(),
                    model_value,
                    central_status_value,
                    Value::BigInt(Some(entry.latency_ms)),
                    request_id_value,
                    now_str.into(),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("relay activity insert: {e}")))?;

        Ok(())
    }

    /// Lists the most recent relay activity entries, newest first.
    ///
    /// The result is bounded to 1,000 entries even if a larger value is
    /// supplied by a caller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] if the query fails.
    pub async fn list_activity(
        &self,
        limit: u32,
    ) -> Result<Vec<crate::entity::relay_activity_log::Model>> {
        crate::entity::relay_activity_log::Entity::find()
            .order_by_desc(crate::entity::relay_activity_log::Column::CreatedAt)
            .order_by_desc(crate::entity::relay_activity_log::Column::Id)
            .limit(u64::from(limit.min(1000)))
            .all(&self.db)
            .await
            .map_err(|e| Error::Database(format!("list relay activity: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> ActivityLogger {
        let url = oidc_agent_common::persistence::temp_sqlite_url("relay-activity");
        let db = crate::db::setup(&url).await.expect("db setup");
        ActivityLogger::new(db)
    }

    #[tokio::test]
    async fn record_inserts_entry() {
        let logger = setup_test_db().await;
        let entry = RelayActivityEntry {
            identity_id: "id-123".into(),
            key_id: "key-456".into(),
            method: "POST".into(),
            endpoint: "/v1/chat/completions".into(),
            model: Some("gpt-4".into()),
            central_status: Some(200),
            latency_ms: 150,
            request_id: Some("req-789".into()),
        };
        logger.record(&entry).await.expect("record");

        use crate::entity::relay_activity_log;
        use sea_orm::EntityTrait;
        let entries = relay_activity_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity_id, "id-123");
        assert_eq!(entries[0].key_id, "key-456");
        assert_eq!(entries[0].method, "POST");
        assert_eq!(entries[0].endpoint, "/v1/chat/completions");
        assert_eq!(entries[0].model.as_deref(), Some("gpt-4"));
        assert_eq!(entries[0].central_status, Some(200));
        assert_eq!(entries[0].latency_ms, 150);
        assert_eq!(entries[0].request_id.as_deref(), Some("req-789"));
    }

    #[tokio::test]
    async fn record_handles_null_fields() {
        let logger = setup_test_db().await;
        let entry = RelayActivityEntry {
            identity_id: "id-000".into(),
            key_id: "key-000".into(),
            method: "GET".into(),
            endpoint: "/v1/models".into(),
            model: None,
            central_status: None,
            latency_ms: 0,
            request_id: None,
        };
        logger.record(&entry).await.expect("record");

        use crate::entity::relay_activity_log;
        use sea_orm::EntityTrait;
        let entries = relay_activity_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].model.is_none());
        assert!(entries[0].central_status.is_none());
        assert!(entries[0].request_id.is_none());
    }

    #[tokio::test]
    async fn record_escapes_single_quotes() {
        let logger = setup_test_db().await;
        let entry = RelayActivityEntry {
            identity_id: "id'; DROP TABLE--".into(),
            key_id: "key-x".into(),
            method: "POST".into(),
            endpoint: "/v1/chat'; --".into(),
            model: Some("gpt-4'; --".into()),
            central_status: Some(200),
            latency_ms: 10,
            request_id: Some("req'; --".into()),
        };
        logger.record(&entry).await.expect("record");

        // Verify the table still exists (no SQL injection).
        use crate::entity::relay_activity_log;
        use sea_orm::EntityTrait;
        let entries = relay_activity_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity_id, "id'; DROP TABLE--");
        assert_eq!(entries[0].endpoint, "/v1/chat'; --");
    }

    #[tokio::test]
    async fn list_activity_honors_limit() {
        let logger = setup_test_db().await;
        for index in 0..3 {
            logger
                .record(&RelayActivityEntry {
                    identity_id: format!("identity-{index}"),
                    key_id: format!("key-{index}"),
                    method: "GET".into(),
                    endpoint: "/v1/models".into(),
                    model: None,
                    central_status: Some(200),
                    latency_ms: i64::from(index),
                    request_id: None,
                })
                .await
                .expect("record");
        }

        let entries = logger.list_activity(2).await.expect("list");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].created_at >= entries[1].created_at);
    }
}
