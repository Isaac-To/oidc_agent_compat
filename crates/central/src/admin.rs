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
        .route("/admin/v1/token-saver", get(query_token_saver_summary))
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
    mut request: axum::extract::Request,
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

    // Attach the verified admin identity so handlers can attribute admin
    // audit entries to the actual caller instead of a generic label.
    let admin_subject = subject.to_string();
    request.extensions_mut().insert(AdminIdentity {
        subject: admin_subject,
    });

    Ok(next.run(request).await)
}

/// The authenticated admin identity, attached by [`admin_auth_middleware`].
///
/// Extracted by mutating handlers via [`axum::extract::FromRequestParts`] so
/// admin audit entries record who performed each action.
#[derive(Debug, Clone)]
pub struct AdminIdentity {
    /// The admin's user subject (from the relay-forwarded, mTLS-protected
    /// identity headers).
    pub subject: String,
}

impl axum::extract::FromRequestParts<AdminState> for AdminIdentity {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &AdminState,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AdminIdentity>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
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
    admin: AdminIdentity,
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
        &admin.subject,
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
    admin: AdminIdentity,
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
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "upsert_provider",
        &id,
        None,
    )
    .await;
    Ok(axum::Json(ProviderResponse::from(provider)))
}

async fn delete_provider(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "delete_provider",
        &id,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_default_provider(
    State(state): State<AdminState>,
    admin: AdminIdentity,
    Path(id): Path<String>,
) -> HandlerResult<StatusCode> {
    state
        .provider_store
        .set_default_provider(&id)
        .await
        .map_err(internal_error)?;
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "set_default_provider",
        &id,
        None,
    )
    .await;
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
    admin: AdminIdentity,
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
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "add_provider_key",
        &id,
        None,
    )
    .await;
    Ok(axum::Json(ProviderKeyResponse::from(key)))
}

async fn update_key(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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
        &admin.subject,
        "update_provider_key",
        &key_id,
        None,
    )
    .await;
    Ok(axum::Json(ProviderKeyResponse::from(key)))
}

async fn delete_key(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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
        &admin.subject,
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
    /// Whether the safe token-saver is enabled for this group.
    pub token_saver_enabled: bool,
    /// Per-request input-token budget (None = no budget trimming).
    pub max_input_tokens: Option<i64>,
    /// Whether the RTK-adapted repeated-line collapse pass is enabled.
    pub collapse_repeated_lines: bool,
    /// Whether ANSI escape sequences are stripped from message content.
    pub strip_ansi: bool,
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
            token_saver_enabled: m.token_saver_enabled,
            max_input_tokens: m.max_input_tokens,
            collapse_repeated_lines: m.collapse_repeated_lines,
            strip_ansi: m.strip_ansi,
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
    /// Whether the safe token-saver is enabled for this group.
    #[serde(default)]
    pub token_saver_enabled: bool,
    /// Per-request input-token budget (None = no budget trimming).
    #[serde(default)]
    pub max_input_tokens: Option<i64>,
    /// Whether the RTK-adapted repeated-line collapse pass is enabled.
    #[serde(default)]
    pub collapse_repeated_lines: bool,
    /// Whether ANSI escape sequences are stripped from message content.
    #[serde(default)]
    pub strip_ansi: bool,
}

async fn upsert_policy(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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

    // Validate: a token-saver budget must be a positive integer when set.
    if body.max_input_tokens.is_some_and(|v| v <= 0) {
        return Err((
            StatusCode::BAD_REQUEST,
            "max_input_tokens must be a positive integer".into(),
        ));
    }

    let policy = state
        .policy_store
        .upsert_policy_full(
            &name,
            models_json.as_deref(),
            endpoints_json.as_deref(),
            body.daily_token_quota,
            body.daily_request_quota,
            body.token_saver_enabled,
            body.max_input_tokens,
            body.collapse_repeated_lines,
            body.strip_ansi,
        )
        .await
        .map_err(internal_error)?;

    // Record admin audit entry, attributed to the verified admin identity
    // (set by the relay from the OIDC login; attached to the request
    // extensions by the admin auth middleware).
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "upsert_policy",
        &name,
        Some(&serde_json::to_string(&body).unwrap_or_default()),
    )
    .await;

    Ok(axum::Json(GroupPolicyResponse::from(policy)))
}

async fn delete_policy(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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
    record_admin_audit(
        state.audit.db(),
        &admin.subject,
        "delete_policy",
        &name,
        None,
    )
    .await;
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
    admin: AdminIdentity,
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
        &admin.subject,
        "revoke_device",
        &fingerprint,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn reinstate_device(
    State(state): State<AdminState>,
    admin: AdminIdentity,
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
        &admin.subject,
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
    /// Number of newest entries to skip (default 0).
    pub offset: Option<u32>,
}

async fn query_audit(
    State(state): State<AdminState>,
    Query(params): Query<AuditQuery>,
) -> HandlerResult<axum::Json<serde_json::Value>> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
    let limit = params.limit.unwrap_or(100).min(1000) as u64;
    let offset = u64::from(params.offset.unwrap_or(0));
    let mut query = crate::entity::audit_log::Entity::find();
    if let Some(subject) = params.subject {
        query = query.filter(crate::entity::audit_log::Column::UserSubject.eq(subject));
    }
    let entries = query
        .order_by_desc(crate::entity::audit_log::Column::CreatedAt)
        .order_by_desc(crate::entity::audit_log::Column::Id)
        .limit(limit)
        .offset(offset)
        .all(state.audit.db())
        .await
        .map_err(|e| internal_error(Error::Database(format!("query audit: {e}"))))?;
    // Serialize manually since the entity model doesn't derive Serialize.
    let serialized: Vec<serde_json::Value> = entries
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
                "token_saver_applied": e.token_saver_applied,
                "tokens_saved": e.tokens_saved,
                "messages_dropped": e.messages_dropped,
                "saver_reasons": e.saver_reasons,
                "created_at": e.created_at.format(time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]:[second]"
                )).unwrap_or_default(),
            })
        })
        .collect();
    Ok(axum::Json(serde_json::Value::Array(serialized)))
}

/// Response for the token-saver summary endpoint.
///
/// Aggregates per-group engagement so an admin can "watch what is going on":
/// how many requests were optimised, how many tokens were saved, and how
/// many messages were dropped, alongside the current on/off configuration.
#[derive(Debug, Serialize)]
pub struct TokenSaverSummaryResponse {
    /// Per-group rows.
    pub groups: Vec<TokenSaverGroupSummary>,
    /// Totals across all groups.
    pub total_requests_optimized: i64,
    /// Total tokens saved across all optimised requests.
    pub total_tokens_saved: i64,
    /// Total messages dropped across all optimised requests.
    pub total_messages_dropped: i64,
}

/// Per-group token-saver summary + configuration.
#[derive(Debug, Serialize)]
pub struct TokenSaverGroupSummary {
    /// The group name.
    pub group: String,
    /// Whether the token saver is enabled for the group.
    pub enabled: bool,
    /// The per-request input-token budget (None = no budget trimming).
    pub max_input_tokens: Option<i64>,
    /// Number of requests optimised for this group (where the saver applied).
    pub requests_optimized: i64,
    /// Tokens saved for this group.
    pub tokens_saved: i64,
    /// Messages dropped for this group.
    pub messages_dropped: i64,
}

async fn query_token_saver_summary(
    State(state): State<AdminState>,
) -> HandlerResult<axum::Json<TokenSaverSummaryResponse>> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    // Pull the group policies to report configuration.
    let policies = state
        .policy_store
        .list_policies()
        .await
        .map_err(internal_error)?;

    // Aggregate over the audit log, grouping by group. We attribute a row to
    // its first stored group (groups are a JSON array string). Because an
    // admin consumes this as a coarse engagement report, using the first
    // group is a reasonable, explicit approximation.
    let entries = crate::entity::audit_log::Entity::find()
        .filter(crate::entity::audit_log::Column::TokenSaverApplied.eq(true))
        .all(state.audit.db())
        .await
        .map_err(|e| internal_error(Error::Database(format!("query saver summary: {e}"))))?;

    let mut per_group: std::collections::HashMap<String, TokenSaverGroupSummary> =
        std::collections::HashMap::new();
    let mut total_requests = 0i64;
    let mut total_tokens = 0i64;
    let mut total_dropped = 0i64;

    for e in &entries {
        let group = e
            .groups
            .as_deref()
            .and_then(|g| serde_json::from_str::<Vec<String>>(g).ok())
            .and_then(|v| v.first().cloned())
            .unwrap_or_else(|| "unknown".to_string());
        let row = per_group
            .entry(group.clone())
            .or_insert_with(|| TokenSaverGroupSummary {
                group: group.clone(),
                enabled: false,
                max_input_tokens: None,
                requests_optimized: 0,
                tokens_saved: 0,
                messages_dropped: 0,
            });
        row.requests_optimized += 1;
        row.tokens_saved += e.tokens_saved.unwrap_or(0);
        row.messages_dropped += e.messages_dropped.unwrap_or(0);
        total_requests += 1;
        total_tokens += e.tokens_saved.unwrap_or(0);
        total_dropped += e.messages_dropped.unwrap_or(0);
    }

    // Overlay configuration from the current policies.
    for p in &policies {
        let row = per_group
            .entry(p.group_name.clone())
            .or_insert_with(|| TokenSaverGroupSummary {
                group: p.group_name.clone(),
                enabled: p.token_saver_enabled,
                max_input_tokens: p.max_input_tokens,
                requests_optimized: 0,
                tokens_saved: 0,
                messages_dropped: 0,
            });
        row.enabled = p.token_saver_enabled;
        row.max_input_tokens = p.max_input_tokens;
    }

    let mut groups: Vec<TokenSaverGroupSummary> = per_group.into_values().collect();
    groups.sort_by(|a, b| a.group.cmp(&b.group));

    Ok(axum::Json(TokenSaverSummaryResponse {
        groups,
        total_requests_optimized: total_requests,
        total_tokens_saved: total_tokens,
        total_messages_dropped: total_dropped,
    }))
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
    // Get current usage (including the groups snapshot recorded with it).
    let usage = state
        .usage_tracker
        .get_usage(&subject)
        .await
        .map_err(internal_error)?;

    // Parse the groups snapshot and resolve the effective policy so the
    // admin sees the same quotas the permissions middleware enforces.
    // Without a usage row (user has not made a request today) the groups
    // are unknown, so the quotas are reported as unset.
    let groups: Vec<String> = usage
        .as_ref()
        .and_then(|u| u.group_name.as_deref())
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();
    let policy = state
        .policy_store
        .resolve_policy(&groups)
        .await
        .map_err(internal_error)?;

    Ok(axum::Json(QuotaResponse {
        user_subject: subject,
        groups: usage.as_ref().and_then(|u| u.group_name.clone()),
        daily_request_quota: policy.daily_request_quota,
        daily_token_quota: policy.daily_token_quota,
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

    #[tokio::test]
    async fn store_getters_yield_usable_connections() {
        // The admin endpoints share one DB; the getters are the seam the
        // handlers use, so pin that they return working connections.
        let url = oidc_agent_common::persistence::temp_sqlite_url("admin-getters");
        let db = crate::db::setup(&url).await.expect("db setup");
        let usage_tracker = UsageTracker::new(db.clone());
        let device_store = DeviceStore::new(db.clone());
        let policy_store = PolicyStore::new(db);

        use sea_orm::{ConnectionTrait, Statement};
        for conn in [usage_tracker.db(), device_store.db(), policy_store.db()] {
            let row = conn
                .query_one(Statement::from_string(
                    conn.get_database_backend(),
                    "SELECT 1 AS one".to_string(),
                ))
                .await
                .expect("getter connection must be usable")
                .expect("row");
            assert_eq!(row.try_get::<i64>("", "one").unwrap_or(0), 1);
        }
    }

    #[tokio::test]
    async fn admin_audit_records_caller_identity_via_middleware() {
        use sea_orm::EntityTrait;
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state.clone());

        // Upsert a policy as alice (member of the admin group).
        let request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri("/admin/v1/group-policies/engineering")
            .header("content-type", "application/json")
            .header("x-oac-user-subject", "alice")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::from(
                r#"{"allowed_models": ["gpt-4o"]}"#.to_string(),
            ))
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // The admin audit entry must be attributed to alice, not "admin".
        let entries = crate::entity::admin_audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("load");
        assert_eq!(entries.len(), 1, "one audit entry expected");
        assert_eq!(
            entries[0].admin_subject, "alice",
            "audit entries must record the verified admin subject"
        );
        assert_eq!(entries[0].action, "upsert_policy");
    }

    #[tokio::test]
    async fn admin_middleware_rejects_non_admin_group() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);

        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/admin/v1/group-policies")
            .header("x-oac-user-subject", "mallory")
            .header("x-oac-user-groups", r#"["engineering"]"#)
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "non-admin group must be rejected"
        );
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

    #[tokio::test]
    async fn get_quota_resolves_policy_from_groups_snapshot() {
        let state = setup_test_state().await;
        // Give engineering a token quota and a request quota.
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(5000), Some(100))
            .await
            .expect("policy");
        // Record usage with a groups snapshot (JSON array string).
        state
            .usage_tracker
            .increment("quota-target", Some(r#"["engineering"]"#), 3, 750, 0.02)
            .await
            .expect("usage");

        // Call the handler directly (the admin auth middleware is not
        // under test here).
        let axum::Json(response) = get_quota(State(state), Path("quota-target".to_string()))
            .await
            .expect("handler");
        assert_eq!(response.user_subject, "quota-target");
        assert_eq!(
            response.groups.as_deref(),
            Some(r#"["engineering"]"#),
            "the groups snapshot must be reported"
        );
        assert_eq!(
            response.daily_token_quota,
            Some(5000),
            "quotas must be resolved from the groups snapshot"
        );
        assert_eq!(response.daily_request_quota, Some(100));
        assert_eq!(response.request_count, 3);
        assert_eq!(response.token_count, 750);
    }

    #[tokio::test]
    async fn get_quota_without_usage_returns_unset_quotas() {
        let state = setup_test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(5000), None)
            .await
            .expect("policy");

        // No usage row for this subject — groups unknown.
        let axum::Json(response) = get_quota(State(state), Path("no-usage".to_string()))
            .await
            .expect("handler");
        assert_eq!(response.groups, None);
        assert_eq!(response.daily_token_quota, None);
        assert_eq!(response.daily_request_quota, None);
        assert_eq!(response.request_count, 0);
        assert_eq!(response.token_count, 0);
    }

    #[tokio::test]
    async fn quota_route_requires_admin_and_returns_resolved_status() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(5000), Some(100))
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("route-target", Some(r#"["engineering"]"#), 4, 900, 0.25)
            .await
            .expect("usage");

        let app = router(state.clone());
        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/admin/v1/quotas/route-target")
            .header("x-oac-user-subject", "admin-user")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("read body");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("JSON body");
        assert_eq!(body["user_subject"], "route-target");
        assert_eq!(body["groups"], r#"["engineering"]"#);
        assert_eq!(body["daily_request_quota"], 100);
        assert_eq!(body["daily_token_quota"], 5000);
        assert_eq!(body["request_count"], 4);
        assert_eq!(body["token_count"], 900);
        assert_eq!(body["cost_usd"], 0.25);

        let app = router(state);
        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/admin/v1/quotas/route-target")
            .header("x-oac-user-subject", "ordinary-user")
            .header("x-oac-user-groups", r#"["engineering"]"#)
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_query_applies_limit_and_offset_in_database() {
        use crate::audit::AuditEntry;

        let state = setup_test_state().await;
        for subject in ["audit-a", "audit-b", "audit-c"] {
            state
                .audit
                .record(&AuditEntry {
                    device_id: "device".into(),
                    user_subject: subject.into(),
                    model: None,
                    backend: "provider".into(),
                    status: 200,
                    latency_ms: 1,
                    stream: false,
                    prompt_tokens: None,
                    completion_tokens: None,
                    total_tokens: None,
                    identity_id: None,
                    email: None,
                    groups: None,
                    endpoint: Some("/v1/models".into()),
                    request_id: None,
                    permission_decision: Some("allowed".into()),
                    denial_reason: None,
                    cost_usd: Some(0.0),
                    token_saver_applied: None,
                    tokens_saved: None,
                    messages_dropped: None,
                    saver_reasons: None,
                    mcp_server: None,
                    mcp_tool: None,
                    mcp_method: None,
                    mcp_args_preview: None,
                })
                .await
                .expect("record audit entry");
        }

        let axum::Json(page) = query_audit(
            State(state.clone()),
            Query(AuditQuery {
                subject: None,
                limit: Some(2),
                offset: Some(0),
            }),
        )
        .await
        .expect("first page");
        let first_page = page.as_array().expect("array");
        assert_eq!(first_page.len(), 2);

        let axum::Json(next_page) = query_audit(
            State(state),
            Query(AuditQuery {
                subject: None,
                limit: Some(2),
                offset: Some(2),
            }),
        )
        .await
        .expect("second page");
        let next_page = next_page.as_array().expect("array");
        assert_eq!(next_page.len(), 1);
        assert_ne!(first_page[0]["id"], next_page[0]["id"]);
    }

    #[tokio::test]
    async fn admin_can_enable_token_saver_via_api() {
        use tower::ServiceExt;
        let state = setup_test_state().await;
        let app = router(state.clone());

        // Admin (alice) enables the token saver for `engineering` with a
        // budget.
        let request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri("/admin/v1/group-policies/engineering")
            .header("content-type", "application/json")
            .header("x-oac-user-subject", "alice")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::from(
                r#"{"token_saver_enabled": true, "max_input_tokens": 8000}"#.to_string(),
            ))
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // The response body must echo the saver config.
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["token_saver_enabled"], true);
        assert_eq!(json["max_input_tokens"], 8000);

        // The resolved policy reflects it (persisted to the policy store).
        let policy = state
            .policy_store
            .get_policy("engineering")
            .await
            .expect("get")
            .expect("exists");
        assert!(policy.token_saver_enabled);
        assert_eq!(policy.max_input_tokens, Some(8000));
    }

    #[tokio::test]
    async fn admin_rejects_invalid_token_saver_budget() {
        use tower::ServiceExt;
        let state = setup_test_state().await;
        let app = router(state.clone());

        // A non-positive budget must be rejected.
        let request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri("/admin/v1/group-policies/engineering")
            .header("content-type", "application/json")
            .header("x-oac-user-subject", "alice")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::from(
                r#"{"token_saver_enabled": true, "max_input_tokens": -5}"#.to_string(),
            ))
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "negative budget must be rejected"
        );
    }

    #[tokio::test]
    async fn admin_rejects_zero_token_saver_budget() {
        use tower::ServiceExt;
        let state = setup_test_state().await;
        let app = router(state);

        // Zero would expire/trim everything immediately — reject with a
        // message an admin can act on.
        let request = axum::http::Request::builder()
            .method(axum::http::Method::PUT)
            .uri("/admin/v1/group-policies/engineering")
            .header("content-type", "application/json")
            .header("x-oac-user-subject", "alice")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::from(
                r#"{"token_saver_enabled": true, "max_input_tokens": 0}"#.to_string(),
            ))
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("max_input_tokens must be a positive integer"),
            "the error must tell the admin exactly what to fix: {text}"
        );
    }

    #[tokio::test]
    async fn admin_middleware_rejects_malformed_groups_header() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);

        // A groups header that is not a JSON array must fail closed (403),
        // never be interpreted as membership.
        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/admin/v1/group-policies")
            .header("x-oac-user-subject", "mallory")
            .header("x-oac-user-groups", "not-json")
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "malformed groups must deny, not default-open"
        );
    }

    #[tokio::test]
    async fn admin_middleware_rejects_empty_subject() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);

        let request = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/admin/v1/group-policies")
            .header("x-oac-user-subject", "")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::empty())
            .expect("build request");
        let response = app.oneshot(request).await.expect("router run");
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    // --- Group policy CRUD via the router ---

    /// Builds an admin-authenticated JSON request with a body.
    fn admin_json(method: &str, uri: &str, body: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-oac-user-subject", "alice")
            .header("x-oac-user-groups", r#"["oac-admins"]"#)
            .body(axum::body::Body::from(body.to_string()))
            .expect("build request")
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn policy_crud_round_trip_via_router() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state.clone());

        // Empty list first — an admin should see [] not an error.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/group-policies")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(
            json.as_array().expect("array").len(),
            0,
            "a fresh deployment must list zero policies, not error"
        );

        // Upsert with every field set; the response must echo them all.
        let resp = app
            .clone()
            .oneshot(admin_json(
                "PUT",
                "/admin/v1/group-policies/engineering",
                r#"{"allowed_models": ["gpt-4o"], "allowed_endpoints": ["/v1/chat/completions"], "daily_token_quota": 5000, "daily_request_quota": 100, "token_saver_enabled": true, "max_input_tokens": 8000, "collapse_repeated_lines": true}"#,
            ))
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["group_name"], "engineering");
        assert_eq!(json["allowed_models"], serde_json::json!(["gpt-4o"]));
        assert_eq!(
            json["allowed_endpoints"],
            serde_json::json!(["/v1/chat/completions"])
        );
        assert_eq!(json["daily_token_quota"], 5000);
        assert_eq!(json["daily_request_quota"], 100);
        assert_eq!(json["token_saver_enabled"], true);
        assert_eq!(json["max_input_tokens"], 8000);
        assert_eq!(json["collapse_repeated_lines"], true);

        // GET the single policy back.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/group-policies/engineering")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["group_name"], "engineering");

        // List now contains it.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/group-policies")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        let json = body_json(resp).await;
        assert_eq!(json.as_array().expect("array").len(), 1);

        // The admin audit entry for the upsert carries the payload so the
        // change is reviewable after the fact.
        use sea_orm::EntityTrait;
        let entries = crate::entity::admin_audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit");
        let upsert = entries
            .iter()
            .find(|e| e.action == "upsert_policy")
            .expect("upsert audit entry");
        let payload = upsert.payload.as_deref().expect("payload recorded");
        assert!(payload.contains("allowed_models"), "payload: {payload}");

        // DELETE removes it.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/admin/v1/group-policies/engineering")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);

        // GET after delete → 404 with the group name in the message.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/group-policies/engineering")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let text = body_text(resp).await;
        assert!(
            text.contains("engineering"),
            "404 must name the missing policy: {text}"
        );

        // DELETE again → 404 (idempotence is for the success path only).
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/admin/v1/group-policies/engineering")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        // The delete was audited too.
        let entries = crate::entity::admin_audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit");
        assert!(
            entries.iter().any(|e| e.action == "delete_policy"),
            "delete must be audited"
        );
    }

    // --- Device admin endpoints ---

    #[tokio::test]
    async fn device_admin_flow_list_revoke_reinstate() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        state
            .device_store
            .upsert_device("fp-admin-1", "laptop-alice", Some("alice@example.com"))
            .await
            .expect("register device");
        let app = router(state.clone());

        // List shows the device with its fields.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/devices")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        let devices = json.as_array().expect("array");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["cert_fingerprint"], "fp-admin-1");
        assert_eq!(devices[0]["user_subject"], "laptop-alice");
        assert_eq!(devices[0]["user_email"], "alice@example.com");
        assert_eq!(devices[0]["revoked"], false);

        // Revoke → 204, and the store reflects it.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/devices/fp-admin-1/revoke")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
        assert_eq!(
            state
                .device_store
                .is_revoked("fp-admin-1")
                .await
                .expect("check"),
            Some(true)
        );

        // Revoking an already-revoked device is idempotent (204) — an admin
        // re-running a playbook must not see a spurious error.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/devices/fp-admin-1/revoke")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);

        // Revoking an UNKNOWN fingerprint → 404 naming the device.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/devices/fp-ghost/revoke")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let text = body_text(resp).await;
        assert!(
            text.contains("fp-ghost"),
            "404 must name the device: {text}"
        );

        // Reinstate → 204 and active again.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/devices/fp-admin-1/reinstate")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
        assert_eq!(
            state
                .device_store
                .is_revoked("fp-admin-1")
                .await
                .expect("check"),
            Some(false)
        );

        // Reinstate an unknown fingerprint → 404.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/devices/fp-ghost/reinstate")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        // Both mutations were attributed to the calling admin.
        use sea_orm::EntityTrait;
        let entries = crate::entity::admin_audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit");
        let revoke = entries
            .iter()
            .find(|e| e.action == "revoke_device")
            .expect("revoke audit");
        assert_eq!(revoke.admin_subject, "alice");
        assert!(entries.iter().any(|e| e.action == "reinstate_device"));
    }

    // --- Audit query endpoint ---

    #[tokio::test]
    async fn audit_query_filters_by_subject_via_router() {
        use crate::audit::AuditEntry;
        use tower::ServiceExt;

        let state = setup_test_state().await;
        for subject in ["u-a", "u-b"] {
            state
                .audit
                .record(&AuditEntry {
                    device_id: "dev".into(),
                    user_subject: subject.into(),
                    model: Some("gpt-4o".into()),
                    backend: "mock".into(),
                    status: 200,
                    latency_ms: 3,
                    stream: false,
                    prompt_tokens: Some(10),
                    completion_tokens: Some(5),
                    total_tokens: Some(15),
                    identity_id: None,
                    email: Some("u@example.com".into()),
                    groups: Some(r#"["engineering"]"#.into()),
                    endpoint: Some("/v1/chat/completions".into()),
                    request_id: Some("req-1".into()),
                    permission_decision: Some("allowed".into()),
                    denial_reason: None,
                    cost_usd: Some(0.01),
                    token_saver_applied: None,
                    tokens_saved: None,
                    messages_dropped: None,
                    saver_reasons: None,
                    mcp_server: None,
                    mcp_tool: None,
                    mcp_method: None,
                    mcp_args_preview: None,
                })
                .await
                .expect("record");
        }
        let app = router(state);

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/audit?subject=u-a")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        let rows = json.as_array().expect("array");
        assert_eq!(rows.len(), 1, "subject filter must narrow the result");
        assert_eq!(rows[0]["user_subject"], "u-a");
        assert_eq!(rows[0]["model"], "gpt-4o");
        assert_eq!(rows[0]["status"], 200);
        assert_eq!(rows[0]["total_tokens"], 15);
        assert_eq!(rows[0]["request_id"], "req-1");
        // created_at serializes as a non-empty timestamp string.
        assert!(
            rows[0]["created_at"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "created_at must be present: {}",
            rows[0]["created_at"]
        );

        // No filter → both rows, newest first.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/audit")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        let json = body_json(resp).await;
        assert_eq!(json.as_array().expect("array").len(), 2);
    }

    // --- Token-saver summary endpoint ---

    #[tokio::test]
    async fn token_saver_summary_aggregates_and_overlays_config() {
        use crate::audit::AuditEntry;
        use tower::ServiceExt;

        let state = setup_test_state().await;
        // engineering: two optimised requests.
        for (saved, dropped) in [(100_i64, 2_i64), (50, 1)] {
            state
                .audit
                .record(&AuditEntry {
                    device_id: "dev".into(),
                    user_subject: "eng-user".into(),
                    model: None,
                    backend: "mock".into(),
                    status: 200,
                    latency_ms: 1,
                    stream: false,
                    prompt_tokens: None,
                    completion_tokens: None,
                    total_tokens: None,
                    identity_id: None,
                    email: None,
                    groups: Some(r#"["engineering"]"#.into()),
                    endpoint: Some("/v1/chat/completions".into()),
                    request_id: None,
                    permission_decision: Some("allowed".into()),
                    denial_reason: None,
                    cost_usd: None,
                    token_saver_applied: Some(true),
                    tokens_saved: Some(saved),
                    messages_dropped: Some(dropped),
                    saver_reasons: Some(r#"["dedup"]"#.into()),
                    mcp_server: None,
                    mcp_tool: None,
                    mcp_method: None,
                    mcp_args_preview: None,
                })
                .await
                .expect("record");
        }
        // sales: optimised traffic but no policy row (e.g. policy deleted).
        state
            .audit
            .record(&AuditEntry {
                device_id: "dev".into(),
                user_subject: "sales-user".into(),
                model: None,
                backend: "mock".into(),
                status: 200,
                latency_ms: 1,
                stream: false,
                prompt_tokens: None,
                completion_tokens: None,
                total_tokens: None,
                identity_id: None,
                email: None,
                groups: Some(r#"["sales"]"#.into()),
                endpoint: Some("/v1/chat/completions".into()),
                request_id: None,
                permission_decision: Some("allowed".into()),
                denial_reason: None,
                cost_usd: None,
                token_saver_applied: Some(true),
                tokens_saved: Some(10),
                messages_dropped: Some(0),
                saver_reasons: None,
                mcp_server: None,
                mcp_tool: None,
                mcp_method: None,
                mcp_args_preview: None,
            })
            .await
            .expect("record");
        // An optimised row with NO groups at all → bucketed as "unknown".
        state
            .audit
            .record(&AuditEntry {
                device_id: "dev".into(),
                user_subject: "groupless".into(),
                model: None,
                backend: "mock".into(),
                status: 200,
                latency_ms: 1,
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
                token_saver_applied: Some(true),
                tokens_saved: Some(5),
                messages_dropped: Some(0),
                saver_reasons: None,
                mcp_server: None,
                mcp_tool: None,
                mcp_method: None,
                mcp_args_preview: None,
            })
            .await
            .expect("record");
        // A non-optimised row must be excluded from the summary entirely.
        state
            .audit
            .record(&AuditEntry {
                device_id: "dev".into(),
                user_subject: "plain-user".into(),
                model: None,
                backend: "mock".into(),
                status: 200,
                latency_ms: 1,
                stream: false,
                prompt_tokens: None,
                completion_tokens: None,
                total_tokens: None,
                identity_id: None,
                email: None,
                groups: Some(r#"["engineering"]"#.into()),
                endpoint: None,
                request_id: None,
                permission_decision: None,
                denial_reason: None,
                cost_usd: None,
                token_saver_applied: Some(false),
                tokens_saved: Some(0),
                messages_dropped: Some(0),
                saver_reasons: None,
                mcp_server: None,
                mcp_tool: None,
                mcp_method: None,
                mcp_args_preview: None,
            })
            .await
            .expect("record");

        // Policies: engineering configured; quiet-group has a policy but no
        // traffic (must still appear with zeros so admins see the config).
        state
            .policy_store
            .upsert_policy_full(
                "engineering",
                None,
                None,
                None,
                None,
                true,
                Some(8000),
                true,
                false,
            )
            .await
            .expect("policy");
        state
            .policy_store
            .upsert_policy_full(
                "quiet-group",
                None,
                None,
                None,
                None,
                false,
                None,
                false,
                false,
            )
            .await
            .expect("policy");

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/token-saver")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;

        // Totals: 100+50+10+5 = 165 saved; 3 dropped; 4 optimised requests.
        assert_eq!(json["total_requests_optimized"], 4);
        assert_eq!(json["total_tokens_saved"], 165);
        assert_eq!(json["total_messages_dropped"], 3);

        let groups = json["groups"].as_array().expect("groups array");
        // Clippy-clean lookup helper (test builds allow expect_used).
        fn group_row<'a>(groups: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
            groups
                .iter()
                .find(|g| g["group"] == name)
                .unwrap_or_else(|| {
                    let names: Vec<String> = groups
                        .iter()
                        .filter_map(|g| g["group"].as_str().map(str::to_string))
                        .collect();
                    unreachable!("group {name} missing; have {names:?}")
                })
        }

        let eng = group_row(groups, "engineering");
        assert_eq!(eng["enabled"], true, "config overlay must show enabled");
        assert_eq!(eng["max_input_tokens"], 8000);
        assert_eq!(eng["requests_optimized"], 2);
        assert_eq!(eng["tokens_saved"], 150);
        assert_eq!(eng["messages_dropped"], 3);

        let sales = group_row(groups, "sales");
        assert_eq!(sales["requests_optimized"], 1);
        assert_eq!(sales["tokens_saved"], 10);
        assert_eq!(
            sales["enabled"], false,
            "traffic without a policy must report disabled"
        );

        let unknown = group_row(groups, "unknown");
        assert_eq!(unknown["requests_optimized"], 1);
        assert_eq!(unknown["tokens_saved"], 5);

        let quiet = group_row(groups, "quiet-group");
        assert_eq!(quiet["requests_optimized"], 0, "policy-only group row");
        assert_eq!(quiet["tokens_saved"], 0);
        assert_eq!(quiet["enabled"], false);

        // Groups are sorted by name for stable admin reading.
        let names: Vec<&str> = groups.iter().filter_map(|g| g["group"].as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "groups must be sorted: {names:?}");
    }

    #[tokio::test]
    async fn token_saver_summary_empty_state_is_clean() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/token-saver")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["total_requests_optimized"], 0);
        assert_eq!(json["total_tokens_saved"], 0);
        assert_eq!(json["total_messages_dropped"], 0);
        assert_eq!(
            json["groups"].as_array().expect("array").len(),
            0,
            "no policies + no traffic → empty groups list"
        );
    }

    // --- Usage endpoint ---

    #[tokio::test]
    async fn usage_endpoint_reports_per_subject_and_all() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        state
            .usage_tracker
            .increment("usage-a", Some(r#"["engineering"]"#), 2, 200, 0.5)
            .await
            .expect("usage a");
        state
            .usage_tracker
            .increment("usage-b", None, 1, 50, 0.25)
            .await
            .expect("usage b");

        let app = router(state.clone());

        // Filtered by subject.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/usage?subject=usage-a")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        let rows = json.as_array().expect("array");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["user_subject"], "usage-a");
        assert_eq!(rows[0]["request_count"], 2);
        assert_eq!(rows[0]["token_count"], 200);

        // Unknown subject → empty array, not 404 (an admin polling for a
        // user with no traffic today should get a clean empty answer).
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/usage?subject=nobody")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json.as_array().expect("array").len(), 0);

        // Unfiltered → all users.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/usage")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        let json = body_json(resp).await;
        assert_eq!(json.as_array().expect("array").len(), 2);
    }

    // --- Provider endpoint edge cases not covered by the integration file ---

    #[test]
    fn create_provider_request_defaults_enabled_to_true() {
        // Omitting `enabled` must default to true (a provider that silently
        // arrives disabled would look like a routing outage to users).
        let body: CreateProviderRequest =
            serde_json::from_str(r#"{"id":"p","name":"P","base_url":"https://p.example.com"}"#)
                .expect("parse");
        assert!(body.enabled, "enabled defaults to true");
        assert!(!body.is_default, "is_default defaults to false");
        assert_eq!(body.models, None, "models defaults to None (all models)");
    }

    #[tokio::test]
    async fn get_key_returns_metadata_with_access_groups() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        state
            .provider_store
            .upsert_provider(&crate::provider::ProviderInput {
                id: "openai".into(),
                name: "OpenAI".into(),
                base_url: "https://api.openai.com".into(),
                enabled: true,
                is_default: false,
                models: None,
            })
            .await
            .expect("provider");
        let key = state
            .provider_store
            .add_key(
                "openai",
                "production",
                "sk-get-key-test-secret",
                3,
                &["engineering".to_string()],
            )
            .await
            .expect("key");

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(format!("/admin/v1/providers/openai/keys/{}", key.id))
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["id"], key.id);
        assert_eq!(json["label"], "production");
        assert_eq!(json["priority"], 3);
        assert_eq!(json["allowed_groups"], serde_json::json!(["engineering"]));
        assert_eq!(
            json["key_digest"].as_str().map(str::len),
            Some(64),
            "the digest is a sha256 hex string"
        );
        assert!(
            !json.to_string().contains("sk-get-key-test-secret"),
            "key material must never be returned"
        );
    }

    #[tokio::test]
    async fn delete_key_on_missing_provider_names_the_provider() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);

        // The provider-existence check runs before the key lookup, so the
        // 404 must name the PROVIDER (what the admin actually got wrong).
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/admin/v1/providers/ghost/keys/whatever")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let text = body_text(resp).await;
        assert!(
            text.contains("provider 'ghost' not found"),
            "the 404 must name the provider: {text}"
        );
    }

    #[tokio::test]
    async fn update_provider_unknown_returns_404_and_list_keys_unknown_404() {
        use tower::ServiceExt;

        let state = setup_test_state().await;
        let app = router(state);

        // PUT on a provider that does not exist → 404 (never creates via PUT).
        let resp = app
            .clone()
            .oneshot(admin_json(
                "PUT",
                "/admin/v1/providers/ghost",
                r#"{"name": "Ghost", "base_url": "https://ghost.example.com", "enabled": true, "is_default": false, "models": null}"#,
            ))
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        // Listing keys of an unknown provider → 404.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/admin/v1/providers/ghost/keys")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        // set-default on an unknown provider → 500 from the store error
        // (the store rejects defaulting a provider that does not exist).
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/v1/providers/ghost/default")
                    .header("x-oac-user-subject", "alice")
                    .header("x-oac-user-groups", r#"["oac-admins"]"#)
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "defaulting a missing provider must not silently succeed"
        );
    }
}
