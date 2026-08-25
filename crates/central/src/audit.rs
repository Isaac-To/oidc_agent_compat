//! Audit logging for the central proxy.
//!
//! Every proxied request is logged to the `audit_log` table with the device
//! ID, user subject, model, backend, status, latency, and token usage. This
//! provides a tamper-evident record for enterprise compliance.
//!
//! # Security
//!
//! - The audit log is append-only (no update/delete operations are exposed).
//! - No secrets (master key, bearer tokens) are ever logged.
//! - The log records who made the request, when, and what it cost.

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, Value};
use time::PrimitiveDateTime;
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};

/// An audit log entry for a single proxied request.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// The device ID that made the request.
    pub device_id: String,
    /// The user subject.
    pub user_subject: String,
    /// The model requested (if parseable from the request body).
    pub model: Option<String>,
    /// The backend name.
    pub backend: String,
    /// The HTTP status code of the upstream response.
    pub status: i32,
    /// The request latency in milliseconds.
    pub latency_ms: i64,
    /// Whether the response was streamed.
    pub stream: bool,
    /// Token usage (prompt tokens), if reported.
    pub prompt_tokens: Option<i32>,
    /// Token usage (completion tokens), if reported.
    pub completion_tokens: Option<i32>,
    /// Token usage (total tokens), if reported.
    pub total_tokens: Option<i32>,
    /// The relay-side identity database ID (enrichment).
    pub identity_id: Option<String>,
    /// The user email (enrichment).
    pub email: Option<String>,
    /// The group/role memberships as a JSON array string (enrichment).
    pub groups: Option<String>,
    /// The request endpoint/path (e.g. `/v1/chat/completions`).
    pub endpoint: Option<String>,
    /// The request ID for end-to-end correlation.
    pub request_id: Option<String>,
    /// The permission decision: `allowed` or `denied`.
    pub permission_decision: Option<String>,
    /// The reason a request was denied (set when denied).
    pub denial_reason: Option<String>,
    /// The estimated cost in USD (enrichment; populated in phase 3).
    pub cost_usd: Option<f64>,
}

/// The audit logger, backed by the central proxy's database.
#[derive(Clone)]
pub struct AuditLogger {
    db: DatabaseConnection,
}

impl AuditLogger {
    /// Creates a new `AuditLogger`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Returns a reference to the underlying database connection.
    ///
    /// Used by integration tests to verify audit entries were recorded.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Records an audit entry.
    ///
    /// # Security
    ///
    /// Uses parameterized queries to prevent SQL injection. No user-supplied
    /// data is interpolated into the SQL string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] if the insert fails.
    pub async fn record(&self, entry: &AuditEntry) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = now_utc();
        let now_str = format_time(&now);

        // Use parameterized values — no string interpolation into SQL.
        let model_value = entry
            .model
            .as_ref()
            .map(|m| Value::String(Some(Box::new(m.clone()))))
            .unwrap_or(Value::String(None));
        let prompt_value = Value::Int(entry.prompt_tokens);
        let completion_value = Value::Int(entry.completion_tokens);
        let total_value = Value::Int(entry.total_tokens);
        let identity_id_value = entry
            .identity_id
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let email_value = entry
            .email
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let groups_value = entry
            .groups
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let endpoint_value = entry
            .endpoint
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let request_id_value = entry
            .request_id
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let permission_decision_value = entry
            .permission_decision
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let denial_reason_value = entry
            .denial_reason
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let cost_value = entry
            .cost_usd
            .map(|v| Value::Double(Some(v)))
            .unwrap_or(Value::Double(None));

        let sql = "INSERT INTO audit_log \
             (id, device_id, user_subject, model, backend, status, latency_ms, stream, \
             prompt_tokens, completion_tokens, total_tokens, created_at, \
             identity_id, email, groups, endpoint, request_id, \
             permission_decision, denial_reason, cost_usd) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
             $13, $14, $15, $16, $17, $18, $19, $20)";

        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    id.into(),
                    entry.device_id.clone().into(),
                    entry.user_subject.clone().into(),
                    model_value,
                    entry.backend.clone().into(),
                    Value::Int(Some(entry.status)),
                    Value::BigInt(Some(entry.latency_ms)),
                    Value::Bool(Some(entry.stream)),
                    prompt_value,
                    completion_value,
                    total_value,
                    now_str.into(),
                    identity_id_value,
                    email_value,
                    groups_value,
                    endpoint_value,
                    request_id_value,
                    permission_decision_value,
                    denial_reason_value,
                    cost_value,
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("audit insert: {e}")))?;

        Ok(())
    }
}

/// Returns the current UTC time as a `PrimitiveDateTime`.
fn now_utc() -> PrimitiveDateTime {
    let offset = time::OffsetDateTime::now_utc();
    PrimitiveDateTime::new(offset.date(), offset.time())
}

/// Formats a `PrimitiveDateTime` for SQLite.
fn format_time(t: &PrimitiveDateTime) -> String {
    t.format(time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second]"
    ))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> AuditLogger {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-audit-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        let db = crate::db::setup(&url).await.expect("db setup");
        AuditLogger::new(db)
    }

    #[tokio::test]
    async fn record_inserts_entry() {
        let logger = setup_test_db().await;
        let entry = AuditEntry {
            device_id: "dev-123".into(),
            user_subject: "user-456".into(),
            model: Some("gpt-4".into()),
            backend: "openai".into(),
            status: 200,
            latency_ms: 150,
            stream: false,
            prompt_tokens: Some(100),
            completion_tokens: Some(50),
            total_tokens: Some(150),
            identity_id: Some("id-123".into()),
            email: Some("user@example.com".into()),
            groups: Some(r#"["engineering"]"#.into()),
            endpoint: Some("/v1/chat/completions".into()),
            request_id: Some("req-123".into()),
            permission_decision: Some("allowed".into()),
            denial_reason: None,
            cost_usd: Some(0.0021),
        };
        logger.record(&entry).await.expect("record");

        // Verify the entry was inserted.
        use crate::entity::audit_log;
        use sea_orm::EntityTrait;
        let entries = audit_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].device_id, "dev-123");
        assert_eq!(entries[0].model.as_deref(), Some("gpt-4"));
        assert_eq!(entries[0].status, 200);
        assert_eq!(entries[0].total_tokens, Some(150));
        // Enrichment columns.
        assert_eq!(entries[0].identity_id.as_deref(), Some("id-123"));
        assert_eq!(entries[0].email.as_deref(), Some("user@example.com"));
        assert_eq!(entries[0].groups.as_deref(), Some(r#"["engineering"]"#));
        assert_eq!(entries[0].endpoint.as_deref(), Some("/v1/chat/completions"));
        assert_eq!(entries[0].request_id.as_deref(), Some("req-123"));
        assert_eq!(entries[0].permission_decision.as_deref(), Some("allowed"));
        assert!(entries[0].denial_reason.is_none());
        assert_eq!(entries[0].cost_usd, Some(0.0021));
    }

    #[tokio::test]
    async fn record_handles_null_fields() {
        let logger = setup_test_db().await;
        let entry = AuditEntry {
            device_id: "dev-789".into(),
            user_subject: "user-012".into(),
            model: None,
            backend: "openai".into(),
            status: 500,
            latency_ms: 0,
            stream: true,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            identity_id: None,
            email: None,
            groups: None,
            endpoint: None,
            request_id: None,
            permission_decision: None,
            denial_reason: None,
            cost_usd: None,
        };
        logger.record(&entry).await.expect("record");

        use crate::entity::audit_log;
        use sea_orm::EntityTrait;
        let entries = audit_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].model.is_none());
        assert!(entries[0].total_tokens.is_none());
        assert!(entries[0].stream);
    }

    #[tokio::test]
    async fn record_escapes_single_quotes() {
        let logger = setup_test_db().await;
        let entry = AuditEntry {
            device_id: "dev'; DROP TABLE--".into(),
            user_subject: "user'.x".into(),
            model: Some("gpt-4'; --".into()),
            backend: "openai".into(),
            status: 200,
            latency_ms: 10,
            stream: false,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            identity_id: None,
            email: None,
            groups: None,
            endpoint: None,
            request_id: None,
            permission_decision: None,
            denial_reason: None,
            cost_usd: None,
        };
        logger.record(&entry).await.expect("record");

        // Verify the table still exists (no SQL injection).
        use crate::entity::audit_log;
        use sea_orm::EntityTrait;
        let entries = audit_log::Entity::find()
            .all(&logger.db)
            .await
            .expect("load");
        assert_eq!(entries.len(), 1, "entry must be inserted despite quotes");
    }
}
