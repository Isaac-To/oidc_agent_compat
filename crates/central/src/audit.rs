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
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::time_util;

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
    /// Whether the token saver optimised this request.
    pub token_saver_applied: Option<bool>,
    /// Estimated tokens saved by the token saver for this request.
    pub tokens_saved: Option<i64>,
    /// Total whole messages dropped (duplicates + budget + empty).
    pub messages_dropped: Option<i64>,
    /// Human-readable reason tags for what the saver did, as JSON.
    pub saver_reasons: Option<String>,
    /// The MCP server id (for MCP traffic).
    pub mcp_server: Option<String>,
    /// The MCP tool name (for `tools/call`; otherwise empty).
    pub mcp_tool: Option<String>,
    /// The MCP JSON-RPC method (e.g. `tools/call`, `initialize`).
    pub mcp_method: Option<String>,
    /// A redacted, length-capped preview of the MCP tool arguments.
    pub mcp_args_preview: Option<String>,
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
        let now = time_util::now_utc();
        let now_str = time_util::format_time(&now);

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
        let saver_applied_value = entry
            .token_saver_applied
            .map(|v| Value::Bool(Some(v)))
            .unwrap_or(Value::Bool(None));
        let tokens_saved_value = entry
            .tokens_saved
            .map(|v| Value::BigInt(Some(v)))
            .unwrap_or(Value::BigInt(None));
        let messages_dropped_value = entry
            .messages_dropped
            .map(|v| Value::BigInt(Some(v)))
            .unwrap_or(Value::BigInt(None));
        let saver_reasons_value = entry
            .saver_reasons
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let mcp_server_value = entry
            .mcp_server
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let mcp_tool_value = entry
            .mcp_tool
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let mcp_method_value = entry
            .mcp_method
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));
        let mcp_args_preview_value = entry
            .mcp_args_preview
            .as_ref()
            .map(|v| Value::String(Some(Box::new(v.clone()))))
            .unwrap_or(Value::String(None));

        let sql = "INSERT INTO audit_log \
             (id, device_id, user_subject, model, backend, status, latency_ms, stream, \
             prompt_tokens, completion_tokens, total_tokens, created_at, \
             identity_id, email, groups, endpoint, request_id, \
             permission_decision, denial_reason, cost_usd, \
             token_saver_applied, tokens_saved, messages_dropped, saver_reasons, \
             mcp_server, mcp_tool, mcp_method, mcp_args_preview) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
             $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, \
             $25, $26, $27, $28)";

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
                    saver_applied_value,
                    tokens_saved_value,
                    messages_dropped_value,
                    saver_reasons_value,
                    mcp_server_value,
                    mcp_tool_value,
                    mcp_method_value,
                    mcp_args_preview_value,
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("audit insert: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> AuditLogger {
        let url = oidc_agent_common::persistence::temp_sqlite_url("audit");
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
            token_saver_applied: Some(true),
            tokens_saved: Some(42),
            messages_dropped: Some(3),
            saver_reasons: Some(r#"["dedup"]"#.into()),
            mcp_server: Some("github".into()),
            mcp_tool: Some("list_files".into()),
            mcp_method: Some("tools/call".into()),
            mcp_args_preview: Some(r#"{"path":"/x"}"#.into()),
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
            token_saver_applied: None,
            tokens_saved: None,
            messages_dropped: None,
            saver_reasons: None,
            mcp_server: None,
            mcp_tool: None,
            mcp_method: None,
            mcp_args_preview: None,
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
            token_saver_applied: None,
            tokens_saved: None,
            messages_dropped: None,
            saver_reasons: None,
            mcp_server: None,
            mcp_tool: None,
            mcp_method: None,
            mcp_args_preview: None,
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
