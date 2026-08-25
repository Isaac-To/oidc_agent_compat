//! Admin API for managing group policies, devices, and querying audit logs.
//!
//! The admin API is mounted at `/admin/v1/` and protected by mTLS (in
//! production) plus a static admin token. Every mutating endpoint writes
//! to the append-only `admin_audit_log` for accountability.
//!
//! # Endpoints
//!
//! - `GET    /admin/v1/group-policies` — list all policies
//! - `GET    /admin/v1/group-policies/:name` — get one policy
//! - `PUT    /admin/v1/group-policies/:name` — upsert a policy
//! - `DELETE /admin/v1/group-policies/:name` — delete a policy
//! - `GET    /admin/v1/devices` — list devices
//! - `POST   /admin/v1/devices/:fingerprint/revoke` — revoke a device
//! - `POST   /admin/v1/devices/:fingerprint/reinstate` — reinstate a device
//! - `GET    /admin/v1/audit` — query the audit log

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use oidc_agent_common::config::AdminConfig;
use oidc_agent_common::error::{Error, Result};

use crate::audit::AuditLogger;
use crate::device_store::DeviceStore;
use crate::policy::PolicyStore;

/// The shared application state for the admin API.
#[derive(Clone)]
pub struct AdminState {
    /// The policy store.
    pub policy_store: PolicyStore,
    /// The device store.
    pub device_store: DeviceStore,
    /// The audit logger (for querying the audit log).
    pub audit: AuditLogger,
    /// The admin token (resolved from the env var at startup).
    pub admin_token: String,
}

/// Builds the Axum router for the admin API.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/v1/group-policies", get(list_policies))
        .route(
            "/admin/v1/group-policies/:name",
            get(get_policy).put(upsert_policy).delete(delete_policy),
        )
        .route("/admin/v1/devices", get(list_devices))
        .route(
            "/admin/v1/devices/:fingerprint/revoke",
            post(revoke_device),
        )
        .route(
            "/admin/v1/devices/:fingerprint/reinstate",
            post(reinstate_device),
        )
        .route("/admin/v1/audit", get(query_audit))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}

/// Resolves the admin token from the environment variable named in
/// `AdminConfig.admin_token_env`.
///
/// # Errors
///
/// Returns [`Error::Config`] if the env var is not set or empty.
pub fn resolve_admin_token(config: &AdminConfig) -> Result<String> {
    let token = std::env::var(&config.admin_token_env).map_err(|_| {
        Error::config(format!(
            "admin token env var '{}' is not set",
            config.admin_token_env
        ))
    })?;
    if token.is_empty() {
        return Err(Error::config(format!(
            "admin token env var '{}' is empty",
            config.admin_token_env
        )));
    }
    Ok(token)
}

/// The admin auth middleware.
///
/// Validates the `Authorization: Bearer <admin-token>` header using
/// constant-time comparison. In production, mTLS provides an additional
/// transport-level auth layer.
async fn admin_auth_middleware(
    State(state): State<AdminState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let bearer = auth_header.and_then(oidc_agent_common::keys::extract_bearer);

    let bearer = match bearer {
        Some(b) => b,
        None => {
            tracing::warn!("admin API request without valid Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Constant-time comparison to prevent timing attacks.
    let token_bytes = state.admin_token.as_bytes();
    let bearer_bytes = bearer.as_bytes();
    if token_bytes.len() != bearer_bytes.len()
        || !bool::from(token_bytes.ct_eq(bearer_bytes))
    {
        tracing::warn!("admin API request with invalid token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

// --- Group policy handlers ---

/// Response for a single group policy.
#[derive(Debug, Serialize)]
pub struct GroupPolicyResponse {
    /// The group name.
    pub group_name: String,
    /// Allowed models (None = all).
    pub allowed_models: Option<Vec<String>>,
    /// Allowed endpoints (None = all).
    pub allowed_endpoints: Option<Vec<String>>,
    /// Daily token quota (None = unlimited).
    pub daily_token_quota: Option<i64>,
    /// Daily request quota (None = unlimited).
    pub daily_request_quota: Option<i64>,
}

impl From<crate::entity::group_policy::Model> for GroupPolicyResponse {
    fn from(m: crate::entity::group_policy::Model) -> Self {
        Self {
            group_name: m.group_name,
            allowed_models: m
                .allowed_models
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            allowed_endpoints: m
                .allowed_endpoints
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            daily_token_quota: m.daily_token_quota,
            daily_request_quota: m.daily_request_quota,
        }
    }
}

/// Error response type for admin handlers.
type HandlerResult<T> = std::result::Result<T, (StatusCode, String)>;

/// Converts an [`Error`] into a 500 error response tuple.
fn internal_error(e: Error) -> (StatusCode, String) {
    tracing::error!(error = %e, "admin API error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn list_policies(
    State(state): State<AdminState>,
) -> HandlerResult<axum::Json<Vec<GroupPolicyResponse>>> {
    let policies = state
        .policy_store
        .list_policies()
        .await
        .map_err(internal_error)?;
    Ok(axum::Json(
        policies.into_iter().map(GroupPolicyResponse::from).collect(),
    ))
}

async fn get_policy(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> HandlerResult<axum::Json<GroupPolicyResponse>> {
    let policy = state
        .policy_store
        .get_policy(&name)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("policy '{name}' not found")))?;
    Ok(axum::Json(GroupPolicyResponse::from(policy)))
}

/// Request body for upserting a group policy.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpsertPolicyRequest {
    /// Allowed models (None = all).
    pub allowed_models: Option<Vec<String>>,
    /// Allowed endpoints (None = all).
    pub allowed_endpoints: Option<Vec<String>>,
    /// Daily token quota (None = unlimited).
    pub daily_token_quota: Option<i64>,
    /// Daily request quota (None = unlimited).
    pub daily_request_quota: Option<i64>,
}

async fn upsert_policy(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    axum::Json(body): axum::Json<UpsertPolicyRequest>,
) -> HandlerResult<axum::Json<GroupPolicyResponse>> {
    let models_json = body
        .allowed_models
        .as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_default());
    let endpoints_json = body
        .allowed_endpoints
        .as_ref()
        .map(|e| serde_json::to_string(e).unwrap_or_default());

    let policy = state
        .policy_store
        .upsert_policy(
            &name,
            models_json.as_deref(),
            endpoints_json.as_deref(),
            body.daily_token_quota,
            body.daily_request_quota,
        )
        .await
        .map_err(internal_error)?;

    record_admin_audit(
        &state.audit.db(),
        "admin",
        "upsert_policy",
        &name,
        Some(&serde_json::to_string(&body).unwrap_or_default()),
    )
    .await;

    Ok(axum::Json(GroupPolicyResponse::from(policy)))
}

async fn delete_policy(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> HandlerResult<StatusCode> {
    let deleted = state
        .policy_store
        .delete_policy(&name)
        .await
        .map_err(internal_error)?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, format!("policy '{name}' not found")));
    }
    record_admin_audit(&state.audit.db(), "admin", "delete_policy", &name, None).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Device handlers ---

/// Response for a device.
#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    /// The cert fingerprint.
    pub cert_fingerprint: String,
    /// The user subject.
    pub user_subject: String,
    /// The user email.
    pub user_email: Option<String>,
    /// Whether the device is revoked.
    pub revoked: bool,
}

impl From<crate::entity::device::Model> for DeviceResponse {
    fn from(m: crate::entity::device::Model) -> Self {
        Self {
            cert_fingerprint: m.cert_fingerprint,
            user_subject: m.user_subject,
            user_email: m.user_email,
            revoked: m.revoked,
        }
    }
}

async fn list_devices(
    State(state): State<AdminState>,
) -> HandlerResult<axum::Json<Vec<DeviceResponse>>> {
    let devices = state
        .device_store
        .list_devices()
        .await
        .map_err(internal_error)?;
    Ok(axum::Json(
        devices.into_iter().map(DeviceResponse::from).collect(),
    ))
}

async fn revoke_device(
    State(state): State<AdminState>,
    Path(fingerprint): Path<String>,
) -> HandlerResult<StatusCode> {
    let revoked = state
        .device_store
        .revoke(&fingerprint)
        .await
        .map_err(internal_error)?;
    if !revoked {
        return Err((
            StatusCode::NOT_FOUND,
            format!("device '{fingerprint}' not found"),
        ));
    }
    record_admin_audit(&state.audit.db(), "admin", "revoke_device", &fingerprint, None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn reinstate_device(
    State(state): State<AdminState>,
    Path(fingerprint): Path<String>,
) -> HandlerResult<StatusCode> {
    let reinstated = state
        .device_store
        .reinstate(&fingerprint)
        .await
        .map_err(internal_error)?;
    if !reinstated {
        return Err((
            StatusCode::NOT_FOUND,
            format!("device '{fingerprint}' not found"),
        ));
    }
    record_admin_audit(&state.audit.db(), "admin", "reinstate_device", &fingerprint, None).await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Audit query handler ---

/// Query parameters for the audit log endpoint.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Filter by user subject.
    pub subject: Option<String>,
    /// Maximum number of entries to return (default 100, max 1000).
    pub limit: Option<u32>,
}

async fn query_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditQuery>,
) -> HandlerResult<axum::Json<serde_json::Value>> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let limit = params.limit.unwrap_or(100).min(1000) as usize;
    let mut query = crate::entity::audit_log::Entity::find();
    if let Some(subject) = params.subject {
        query = query.filter(
            crate::entity::audit_log::Column::UserSubject.eq(subject),
        );
    }
    let entries = query
        .all(state.audit.db())
        .await
        .map_err(|e| internal_error(Error::Database(format!("query audit: {e}"))))?;
    let limited: Vec<_> = entries.into_iter().take(limit).collect();
    // Serialize manually since the entity model doesn't derive Serialize.
    let serialized: Vec<serde_json::Value> = limited
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "user_subject": e.user_subject,
                "identity_id": e.identity_id,
                "email": e.email,
                "groups": e.groups,
                "model": e.model,
                "backend": e.backend,
                "endpoint": e.endpoint,
                "request_id": e.request_id,
                "status": e.status,
                "latency_ms": e.latency_ms,
                "stream": e.stream,
                "prompt_tokens": e.prompt_tokens,
                "completion_tokens": e.completion_tokens,
                "total_tokens": e.total_tokens,
                "permission_decision": e.permission_decision,
                "denial_reason": e.denial_reason,
                "cost_usd": e.cost_usd,
                "created_at": e.created_at.format(time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]:[second]"
                )).unwrap_or_default(),
            })
        })
        .collect();
    Ok(axum::Json(serde_json::Value::Array(serialized)))
}

// --- Helpers ---

/// Records an admin audit log entry (best-effort).
async fn record_admin_audit(
    db: &sea_orm::DatabaseConnection,
    admin_subject: &str,
    action: &str,
    target: &str,
    payload: Option<&str>,
) {
    use sea_orm::ConnectionTrait;
    let id = uuid::Uuid::new_v4().to_string();
    let now = time::OffsetDateTime::now_utc();
    let now_str = now
        .format(time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_default();
    let payload_val = payload
        .map(|p| sea_orm::Value::String(Some(Box::new(p.to_string()))))
        .unwrap_or(sea_orm::Value::String(None));
    let sql = "INSERT INTO admin_audit_log \
         (id, admin_subject, action, target, payload, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)";
    if let Err(e) = db
        .execute(sea_orm::Statement::from_sql_and_values(
            db.get_database_backend(),
            sql,
            vec![
                id.into(),
                admin_subject.to_string().into(),
                action.to_string().into(),
                target.to_string().into(),
                payload_val,
                now_str.into(),
            ],
        ))
        .await
    {
        tracing::error!(error = %e, "failed to write admin audit log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_state() -> AdminState {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-admin-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        let db = crate::db::setup(&url).await.expect("db setup");
        AdminState {
            policy_store: PolicyStore::new(db.clone()),
            device_store: DeviceStore::new(db.clone()),
            audit: AuditLogger::new(db),
            admin_token: "test-admin-token".into(),
        }
    }

    #[tokio::test]
    async fn upsert_and_get_policy_via_store() {
        let state = setup_test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", Some(r#"["gpt-4o"]"#), None, None, None)
            .await
            .expect("upsert");

        let policy = state
            .policy_store
            .get_policy("engineering")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(policy.group_name, "engineering");
    }

    #[tokio::test]
    async fn admin_audit_records_mutation() {
        let state = setup_test_state().await;
        record_admin_audit(state.audit.db(), "admin", "test_action", "target", None).await;

        use crate::entity::admin_audit_log;
        use sea_orm::EntityTrait;
        let entries = admin_audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "test_action");
        assert_eq!(entries[0].target, "target");
    }
}
