//! Admin API for managing group policies, devices, and querying audit logs.
//!
//! The admin API is mounted at `/admin/v1/` and authenticated via the IdP
//! through the relay — the same OIDC login flow used by regular users.
//! Authorization is enforced by checking the caller's group memberships
//! against the configured `admin_group` in `AdminConfig`. No static admin
//! token is used; the admin's OIDC identity is the authentication.
//!
//! # Request flow
//!
//! Admin requests flow through the relay (which authenticates the user via
//! OIDC and forwards identity headers including `x-oac-user-groups`), so
//! the central admin middleware can verify group membership without any
//! separate credential.
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

use oidc_agent_common::config::AdminConfig;
use oidc_agent_common::error::{Error, Result};

use crate::audit::AuditLogger;
use crate::device_store::DeviceStore;
use crate::policy::PolicyStore;
use crate::provider::{ProviderKeyInfo, ProviderKeyUpdate, ProviderStore};
use crate::usage::UsageTracker;

/// The shared application state for the admin API.
#[derive(Clone)]
pub struct AdminState {
    /// The policy store.
    pub policy_store: PolicyStore,
    /// The runtime provider and encrypted key store.
    pub provider_store: ProviderStore,
    /// The device store.
    pub device_store: DeviceStore,
    /// The audit logger (for querying the audit log).
    pub audit: AuditLogger,
    /// The usage tracker (for querying usage and quotas).
    pub usage_tracker: UsageTracker,
    /// The admin group name (from config). Users in this group may call
    /// the admin API.
    pub admin_group: String,
}

/// Builds the Axum router for the admin API.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/v1/group-policies", get(list_policies))
        .route(
            "/admin/v1/group-policies/{name}",
            get(get_policy).put(upsert_policy).delete(delete_policy),
        )
        .route("/admin/v1/devices", get(list_devices))
        .route(
            "/admin/v1/devices/{fingerprint}/revoke",
            post(revoke_device),
        )
        .route(
            "/admin/v1/devices/{fingerprint}/reinstate",
            post(reinstate_device),
        )
        .route("/admin/v1/audit", get(query_audit))
        .route("/admin/v1/usage", get(query_usage))
        .route("/admin/v1/quotas/{subject}", get(get_quota))
        .route(
            "/admin/v1/providers",
            get(list_providers).post(create_provider),
        )
        .route(
            "/admin/v1/providers/{id}",
            get(get_provider)
                .put(update_provider)
                .delete(delete_provider),
        )
        .route(
            "/admin/v1/providers/{id}/default",
            post(set_default_provider),
        )
        .route(
            "/admin/v1/providers/{id}/keys",
            get(list_keys).post(add_key),
        )
        .route(
            "/admin/v1/providers/{id}/keys/{key_id}",
            get(get_key).put(update_key).delete(delete_key),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}

/// The admin auth middleware.
///
/// Authenticates the caller via the relay-forwarded identity headers
/// (`x-oac-user-subject`, `x-oac-user-groups`) — the same mechanism used by
/// the proxy auth middleware. The caller must belong to the configured
/// `admin_group`; otherwise the request is denied with 403.
///
/// # Security
///
/// - Identity headers are set by the relay ONLY from its auth-middleware-
///   verified identity (never from the incoming request headers), so a
///   client cannot spoof them over the mTLS channel.
/// - Group membership comes from the IdP's signed ID token / TLS-protected
///   userinfo response, extracted at login time.
/// - No static token is used; the admin's OIDC identity is the auth.
async fn admin_auth_middleware(
    State(state): State<AdminState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let headers = request.headers();

    // Require the relay-forwarded user subject.
    let subject = headers
        .get("x-oac-user-subject")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if subject.is_empty() {
        tracing::warn!("admin API request without X-OAC-User-Subject");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Parse the user's groups (JSON array string).
    let groups_json = headers
        .get("x-oac-user-groups")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("[]");

    let groups: Vec<String> = serde_json::from_str(groups_json).unwrap_or_default();

    // Check group membership.
    if !groups.contains(&state.admin_group) {
        tracing::warn!(
            user_subject = %subject,
            admin_group = %state.admin_group,
            "admin API request denied: user not in admin group"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::info!(user_subject = %subject, "admin API request authorized");
    Ok(next.run(request).await)
}

// --- Provider handlers ---

/// Public provider metadata returned by the admin API.
#[derive(Debug, Serialize)]
pub struct ProviderResponse {
    /// Stable provider identifier.
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// OpenAI-compatible backend base URL.
    pub base_url: String,
    /// Whether the provider is enabled.
    pub enabled: bool,
    /// Whether this is the default fallback provider.
    pub is_default: bool,
    /// Exact model names served by this provider; `None` means all models.
    pub models: Option<Vec<String>>,
}

impl From<crate::entity::provider::Model> for ProviderResponse {
    fn from(provider: crate::entity::provider::Model) -> Self {
        Self {
            id: provider.id,
            name: provider.name,
            base_url: provider.base_url,
            enabled: provider.enabled,
            is_default: provider.is_default,
            models: provider
                .models
                .as_deref()
                .and_then(|models| serde_json::from_str(models).ok()),
        }
    }
}

/// Request body for creating a provider.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateProviderRequest {
    /// Stable provider identifier.
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// OpenAI-compatible backend base URL.
    pub base_url: String,
    /// Whether the provider accepts traffic.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether this is the default fallback provider.
    #[serde(default)]
    pub is_default: bool,
    /// Exact model names served by this provider; `None` means all models.
    pub models: Option<Vec<String>>,
}

/// Request body for updating a provider.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateProviderRequest {
    /// Human-readable provider name.
    pub name: String,
    /// OpenAI-compatible backend base URL.
    pub base_url: String,
    /// Whether the provider accepts traffic.
    pub enabled: bool,
    /// Whether this is the default fallback provider.
    pub is_default: bool,
    /// Exact model names served by this provider; `None` means all models.
    pub models: Option<Vec<String>>,
}

/// Returns `true` for serde defaults on enabled fields.
fn default_true() -> bool {
    true
}

async fn list_providers(
    State(state): State<AdminState>,
) -> HandlerResult<axum::Json<Vec<ProviderResponse>>> {
    let providers = state
        .provider_store
        .list_providers()
        .await
        .map_err(internal_error)?;
    Ok(axum::Json(
        providers.into_iter().map(ProviderResponse::from).collect(),
    ))
}

async fn create_provider(
    State(state): State<AdminState>,
    axum::Json(body): axum::Json<CreateProviderRequest>,
) -> HandlerResult<axum::Json<ProviderResponse>> {
    let input = crate::provider::ProviderInput {
        id: body.id.clone(),
        name: body.name,
        base_url: body.base_url,
        enabled: body.enabled,
        is_default: body.is_default,
        models: body.models,
    };
    let provider = state
        .provider_store
        .upsert_provider(&input)
        .await
        .map_err(internal_error)?;
    record_admin_audit(
        state.audit.db(),
        "admin",
        "upsert_provider",
        &input.id,
        None,
    )
    .await;
    Ok(axum::Json(ProviderResponse::from(provider)))
}

async fn get_provider(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> HandlerResult<axum::Json<ProviderResponse>> {
    let provider = state
        .provider_store
        .get_provider(&id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("provider '{id}' not found")))?;
    Ok(axum::Json(ProviderResponse::from(provider)))
}

async fn update_provider(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<UpdateProviderRequest>,
) -> HandlerResult<axum::Json<ProviderResponse>> {
    if state
        .provider_store
        .get_provider(&id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, format!("provider '{id}' not found")));
    }
    let input = crate::provider::ProviderInput {
        id: id.clone(),
        name: body.name,
        base_url: body.base_url,
        enabled: body.enabled,
        is_default: body.is_default,
        models: body.models,
    };
    let provider = state
        .provider_store
        .upsert_provider(&input)
        .await
        .map_err(internal_error)?;
    record_admin_audit(state.audit.db(), "admin", "upsert_provider", &id, None).await;
    Ok(axum::Json(ProviderResponse::from(provider)))
}

async fn delete_provider(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> HandlerResult<StatusCode> {
    let deleted = state
        .provider_store
        .delete_provider(&id)
        .await
        .map_err(internal_error)?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, format!("provider '{id}' not found")));
    }
    record_admin_audit(state.audit.db(), "admin", "delete_provider", &id, None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_default_provider(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> HandlerResult<StatusCode> {
    state
        .provider_store
        .set_default_provider(&id)
        .await
        .map_err(internal_error)?;
    record_admin_audit(state.audit.db(), "admin", "set_default_provider", &id, None).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Public provider-key metadata returned by the admin API. It intentionally
/// contains no plaintext or encrypted key material.
#[derive(Debug, Serialize)]
pub struct ProviderKeyResponse {
    /// Key identifier.
    pub id: String,
    /// Provider identifier.
    pub provider_id: String,
    /// Human-readable label.
    pub label: String,
    /// Selection priority; lower values are preferred.
    pub priority: i32,
    /// SHA-256 digest of the key.
    pub key_digest: String,
    /// Whether the key is enabled.
    pub enabled: bool,
    /// Groups allowed to use the key. Empty means unrestricted.
    pub allowed_groups: Vec<String>,
}

impl From<ProviderKeyInfo> for ProviderKeyResponse {
    fn from(key: ProviderKeyInfo) -> Self {
        Self {
            id: key.id,
            provider_id: key.provider_id,
            label: key.label,
            priority: key.priority,
            key_digest: key.key_digest,
            enabled: key.enabled,
            allowed_groups: key.allowed_groups,
        }
    }
}

/// Request body for adding a provider key. The `key` field is accepted only
/// on this request and is never returned or written to audit payloads.
#[derive(Debug, Deserialize)]
pub struct AddProviderKeyRequest {
    /// Plaintext provider API key.
    pub key: String,
    /// Human-readable key label.
    pub label: String,
    /// Selection priority; lower values are preferred.
    #[serde(default)]
    pub priority: i32,
    /// Groups allowed to use the key. Empty means unrestricted.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

/// Request body for updating provider-key metadata and access rules.
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateProviderKeyRequest {
    /// Human-readable key label.
    pub label: String,
    /// Selection priority; lower values are preferred.
    pub priority: i32,
    /// Whether the key is enabled.
    pub enabled: bool,
    /// Groups allowed to use the key. Empty means unrestricted.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

async fn list_keys(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> HandlerResult<axum::Json<Vec<ProviderKeyResponse>>> {
    if state
        .provider_store
        .get_provider(&id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, format!("provider '{id}' not found")));
    }
    let keys = state
        .provider_store
        .list_keys(&id)
        .await
        .map_err(internal_error)?;
    Ok(axum::Json(
        keys.into_iter().map(ProviderKeyResponse::from).collect(),
    ))
}

async fn get_key(
    State(state): State<AdminState>,
    Path((id, key_id)): Path<(String, String)>,
) -> HandlerResult<axum::Json<ProviderKeyResponse>> {
    let key = state
        .provider_store
        .get_key(&id, &key_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("provider key '{key_id}' not found"),
            )
        })?;
    let groups = state
        .provider_store
        .key_access_groups(&key.id)
        .await
        .map_err(internal_error)?;
    Ok(axum::Json(ProviderKeyResponse::from(
        crate::provider::ProviderKeyInfo {
            id: key.id,
            provider_id: key.provider_id,
            label: key.label,
            priority: key.priority,
            key_digest: key.key_digest,
            enabled: key.enabled,
            allowed_groups: groups,
            created_at: key.created_at,
            updated_at: key.updated_at,
        },
    )))
}

async fn add_key(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<AddProviderKeyRequest>,
) -> HandlerResult<axum::Json<ProviderKeyResponse>> {
    if state
        .provider_store
        .get_provider(&id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, format!("provider '{id}' not found")));
    }
    let key = state
        .provider_store
        .add_key(
            &id,
            &body.label,
            &body.key,
            body.priority,
            &body.allowed_groups,
        )
        .await
        .map_err(internal_error)?;
    record_admin_audit(state.audit.db(), "admin", "add_provider_key", &id, None).await;
    Ok(axum::Json(ProviderKeyResponse::from(key)))
}

async fn update_key(
    State(state): State<AdminState>,
    Path((provider_id, key_id)): Path<(String, String)>,
    axum::Json(body): axum::Json<UpdateProviderKeyRequest>,
) -> HandlerResult<axum::Json<ProviderKeyResponse>> {
    let update = ProviderKeyUpdate {
        label: body.label,
        priority: body.priority,
        enabled: body.enabled,
        allowed_groups: body.allowed_groups,
    };
    if state
        .provider_store
        .get_key(&provider_id, &key_id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            format!("provider key '{key_id}' not found"),
        ));
    }
    let key = state
        .provider_store
        .update_key(&provider_id, &key_id, &update)
        .await
        .map_err(internal_error)?;
    record_admin_audit(
        state.audit.db(),
        "admin",
        "update_provider_key",
        &key_id,
        None,
    )
    .await;
    Ok(axum::Json(ProviderKeyResponse::from(key)))
}

async fn delete_key(
    State(state): State<AdminState>,
    Path((provider_id, key_id)): Path<(String, String)>,
) -> HandlerResult<StatusCode> {
    if state
        .provider_store
        .get_provider(&provider_id)
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            format!("provider '{provider_id}' not found"),
        ));
    }
    let deleted = state
        .provider_store
        .delete_key(&provider_id, &key_id)
        .await
        .map_err(internal_error)?;
    if !deleted {
        return Err((
            StatusCode::NOT_FOUND,
            format!("provider key '{key_id}' not found"),
        ));
    }
    record_admin_audit(
        state.audit.db(),
        "admin",
        "delete_provider_key",
        &key_id,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
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
        policies
            .into_iter()
            .map(GroupPolicyResponse::from)
            .collect(),
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

    // Record admin audit entry. The admin subject comes from the request
    // headers (set by the relay from the verified OIDC identity).
    let admin_subject = "admin"; // The actual subject is in the headers; we
    // record a generic label here. A future
    // enhancement could extract it from the
    // request extensions.
    record_admin_audit(
        state.audit.db(),
        admin_subject,
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
    record_admin_audit(state.audit.db(), "admin", "delete_policy", &name, None).await;
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
    record_admin_audit(
        state.audit.db(),
        "admin",
        "revoke_device",
        &fingerprint,
        None,
    )
    .await;
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
    record_admin_audit(
        state.audit.db(),
        "admin",
        "reinstate_device",
        &fingerprint,
        None,
    )
    .await;
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
        query = query.filter(crate::entity::audit_log::Column::UserSubject.eq(subject));
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

// --- Usage & quota handlers ---

/// Response for a usage query.
#[derive(Debug, Serialize)]
pub struct UsageResponse {
    /// The user subject.
    pub user_subject: String,
    /// The period date (e.g. `2026-08-25`).
    pub period_date: String,
    /// Cumulative request count.
    pub request_count: i64,
    /// Cumulative token count.
    pub token_count: i64,
    /// Cumulative cost in USD.
    pub cost_usd: f64,
}

/// Query parameters for the usage endpoint.
#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    /// Filter by user subject. If omitted, returns all users.
    pub subject: Option<String>,
}

async fn query_usage(
    State(state): State<AdminState>,
    Query(params): Query<UsageQuery>,
) -> HandlerResult<axum::Json<Vec<UsageResponse>>> {
    if let Some(subject) = params.subject {
        let usage = state
            .usage_tracker
            .get_usage(&subject)
            .await
            .map_err(internal_error)?;
        match usage {
            Some(u) => Ok(axum::Json(vec![UsageResponse {
                user_subject: u.user_subject,
                period_date: u.period_date,
                request_count: u.request_count,
                token_count: u.token_count,
                cost_usd: u.cost_usd,
            }])),
            None => Ok(axum::Json(vec![])),
        }
    } else {
        let all = state
            .usage_tracker
            .get_all_usage()
            .await
            .map_err(internal_error)?;
        Ok(axum::Json(
            all.into_iter()
                .map(|u| UsageResponse {
                    user_subject: u.user_subject,
                    period_date: u.period_date,
                    request_count: u.request_count,
                    token_count: u.token_count,
                    cost_usd: u.cost_usd,
                })
                .collect(),
        ))
    }
}

/// Response for a quota status query.
#[derive(Debug, Serialize)]
pub struct QuotaResponse {
    /// The user subject.
    pub user_subject: String,
    /// The user's groups (JSON array string).
    pub groups: Option<String>,
    /// Daily request quota (None = unlimited).
    pub daily_request_quota: Option<i64>,
    /// Daily token quota (None = unlimited).
    pub daily_token_quota: Option<i64>,
    /// Current request count for today.
    pub request_count: i64,
    /// Current token count for today.
    pub token_count: i64,
    /// Current cost for today.
    pub cost_usd: f64,
}

async fn get_quota(
    State(state): State<AdminState>,
    Path(subject): Path<String>,
) -> HandlerResult<axum::Json<QuotaResponse>> {
    // Get current usage.
    let usage = state
        .usage_tracker
        .get_usage(&subject)
        .await
        .map_err(internal_error)?;

    // Resolve the user's policy. We don't have the user's groups here (the
    // admin API doesn't receive relay-forwarded groups for the *target*
    // user), so we return the quotas as None unless we can look them up.
    // A future enhancement could store the user's groups in the usage_counters
    // table. For now, return the usage counts and let the admin cross-reference.
    Ok(axum::Json(QuotaResponse {
        user_subject: subject.clone(),
        groups: None,
        daily_request_quota: None,
        daily_token_quota: None,
        request_count: usage.as_ref().map(|u| u.request_count).unwrap_or(0),
        token_count: usage.as_ref().map(|u| u.token_count).unwrap_or(0),
        cost_usd: usage.as_ref().map(|u| u.cost_usd).unwrap_or(0.0),
    }))
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

/// Validates the admin config at startup. Currently a no-op since the
/// config is simple (just a group name), but reserved for future
/// validation logic.
///
/// # Errors
///
/// Returns [`Error::Config`] if the admin group is empty.
pub fn validate_admin_config(config: &AdminConfig) -> Result<()> {
    if config.admin_group.is_empty() {
        return Err(Error::config("admin.admin_group must not be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    async fn setup_test_state() -> AdminState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("admin");
        let db = crate::db::setup(&url).await.expect("db setup");
        AdminState {
            policy_store: PolicyStore::new(db.clone()),
            provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
            device_store: DeviceStore::new(db.clone()),
            audit: AuditLogger::new(db.clone()),
            usage_tracker: UsageTracker::new(db),
            admin_group: "oac-admins".into(),
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

    #[test]
    fn validate_admin_config_rejects_empty_group() {
        let config = AdminConfig {
            admin_group: "".into(),
        };
        assert!(validate_admin_config(&config).is_err());
    }

    #[test]
    fn validate_admin_config_accepts_nonempty_group() {
        let config = AdminConfig {
            admin_group: "oac-admins".into(),
        };
        assert!(validate_admin_config(&config).is_ok());
    }
}
