//! Permissions middleware for the central proxy.
//!
//! This middleware enforces group-based authorization policies after the
//! relay identity has been verified by [`auth_middleware`]. It:
//!
//! 1. Extracts the `VerifiedRelayIdentity` from request extensions.
//! 2. Parses the user's groups (JSON array string).
//! 3. Resolves the effective policy via [`PolicyStore::resolve_policy`].
//! 4. Checks device revocation and auto-registers the device.
//! 5. Checks the endpoint against the policy's allowlist.
//! 6. Checks the model against the policy's allowlist.
//! 7. Checks the daily request and token quotas against the accumulated
//!    usage counters (pre-flight; a single request may overshoot).
//! 8. On denial, writes an audit entry with `permission_decision="denied"`
//!    and returns `403 Forbidden` (or `429 Too Many Requests` for quotas).
//! 9. On allow, inserts a `PermissionDecision` into extensions for the
//!    forward handler to log.
//!
//! # Dev mode
//!
//! In `dev_mode`, if no policies exist for any of the user's groups, the
//! request is allowed (so the dev stack works without policy config). If
//! policies *do* exist, they are enforced even in dev mode.

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;

/// The permission decision attached to request extensions after the
/// permissions middleware runs.
#[derive(Debug, Clone)]
pub struct PermissionDecision {
    /// `"allowed"` or `"denied"`.
    pub decision: String,
    /// The reason for denial (set when `decision == "denied"`).
    pub reason: Option<String>,
}

/// The permissions middleware.
///
/// Enforces model allowlists and endpoint restrictions based on the user's
/// group policies. See the module docs for details.
pub async fn permissions_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip permissions for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    let endpoint = request.uri().path().to_string();

    // Extract the verified relay identity.
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();

    let identity = match identity {
        Some(id) => id,
        None => {
            // No identity — auth middleware should have already rejected
            // this (unless dev_mode). Allow through; auth handles it.
            return Ok(next.run(request).await);
        }
    };

    // Parse the user's groups.
    let groups: Vec<String> = identity
        .groups
        .as_deref()
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();

    // Resolve the effective policy.
    let policy = match state.policy_store.resolve_policy(&groups).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve policy");
            // Fail open on policy store errors to avoid locking out all
            // users due to a DB issue. Log loudly.
            return Ok(next.run(request).await);
        }
    };

    // Check device revocation and auto-register the device. The device is
    // identified by the relay-side identity (identity_id, falling back to
    // the subject). In production (mTLS) the transport layer has already
    // authenticated the relay's client certificate; the identity header
    // (set by the relay, unspoofable over mTLS) identifies the user/device.
    // Auto-registration keeps `devices` populated so admins can revoke;
    // `last_seen_at` is refreshed on every request.
    let device_id = identity
        .identity_id
        .clone()
        .unwrap_or_else(|| identity.subject.clone());
    match state.device_store.is_revoked(&device_id).await {
        Ok(Some(true)) => {
            return deny(
                &state,
                &identity,
                &endpoint,
                None,
                "device_revoked",
                StatusCode::FORBIDDEN,
            )
            .await;
        }
        Ok(Some(false)) | Ok(None) => {
            // Not revoked (or not yet registered) — register/refresh.
            if let Err(e) = state
                .device_store
                .upsert_device(&device_id, &identity.subject, identity.email.as_deref())
                .await
            {
                // Best-effort: a failure to register must not block traffic.
                tracing::warn!(error = %e, "failed to upsert device registration");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to check device revocation; allowing");
        }
    }

    // Check endpoint restriction.
    if !policy.is_endpoint_allowed(&endpoint) {
        return deny(
            &state,
            &identity,
            &endpoint,
            None,
            "endpoint_not_allowed",
            StatusCode::FORBIDDEN,
        )
        .await;
    }

    // Check model restriction. We need to read the body to extract the model,
    // then put it back. For GET requests (e.g. /v1/models), there's no body
    // model to check.
    let method = request.method().clone();
    if method == axum::http::Method::POST {
        let (parts, body) = request.into_parts();
        let body_bytes = to_bytes(body, super::MAX_BODY_SIZE).await.map_err(|e| {
            tracing::error!(error = %e, "permissions: failed to read body");
            StatusCode::BAD_REQUEST
        })?;

        let model = http_util::extract_model(&body_bytes);

        if let Some(ref model_name) = model {
            if !policy.is_model_allowed(model_name) {
                return deny(
                    &state,
                    &identity,
                    &endpoint,
                    model.as_deref(),
                    "model_not_allowed",
                    StatusCode::FORBIDDEN,
                )
                .await;
            }
        }

        // Reassemble the request with the body.
        request = Request::from_parts(parts, Body::from(body_bytes));
    }

    // Check daily quotas (pre-flight). Usage counters accumulate as
    // requests complete, so a single request may overshoot its token quota
    // by up to one request's worth of tokens — the next request is denied.
    if policy.daily_request_quota.is_some() || policy.daily_token_quota.is_some() {
        let usage = match state.usage_tracker.get_usage(&identity.subject).await {
            Ok(usage) => usage,
            Err(e) => {
                tracing::warn!(error = %e, "failed to check usage; allowing");
                None
            }
        };
        if let Some(usage) = usage {
            if let Some(daily_request_quota) = policy.daily_request_quota {
                if usage.request_count >= daily_request_quota {
                    return deny(
                        &state,
                        &identity,
                        &endpoint,
                        None,
                        "quota_exceeded",
                        StatusCode::TOO_MANY_REQUESTS,
                    )
                    .await;
                }
            }
            if let Some(daily_token_quota) = policy.daily_token_quota {
                if usage.token_count >= daily_token_quota {
                    return deny(
                        &state,
                        &identity,
                        &endpoint,
                        None,
                        "token_quota_exceeded",
                        StatusCode::TOO_MANY_REQUESTS,
                    )
                    .await;
                }
            }
        }
    }

    // All checks passed — insert the permission decision for the forward
    // handler to log.
    request.extensions_mut().insert(PermissionDecision {
        decision: "allowed".into(),
        reason: None,
    });

    Ok(next.run(request).await)
}

/// Records a denied audit entry and returns the given status code.
async fn deny(
    state: &AppState,
    identity: &super::auth::VerifiedRelayIdentity,
    endpoint: &str,
    model: Option<&str>,
    reason: &str,
    status: StatusCode,
) -> Result<Response, StatusCode> {
    tracing::warn!(
        user_subject = %identity.subject,
        endpoint = %endpoint,
        model = ?model,
        reason = %reason,
        "request denied by permissions policy"
    );

    let entry = AuditEntry {
        device_id: identity
            .identity_id
            .clone()
            .unwrap_or_else(|| identity.subject.clone()),
        user_subject: identity.subject.clone(),
        model: model.map(String::from),
        // Provider resolution occurs in the forward handler. Denials in this
        // middleware happen before a provider is selected.
        backend: "unresolved".into(),
        status: status.as_u16() as i32,
        latency_ms: 0,
        stream: false,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        identity_id: identity.identity_id.clone(),
        email: identity.email.clone(),
        groups: identity.groups.clone(),
        endpoint: Some(endpoint.to_string()),
        request_id: identity.request_id.clone(),
        permission_decision: Some("denied".into()),
        denial_reason: Some(reason.to_string()),
        cost_usd: None,
    };
    if let Err(e) = state.audit.record(&entry).await {
        tracing::error!(error = %e, "failed to write denied audit entry");
    }

    let body = serde_json::json!({
        "error": {
            "message": format!("access denied: {reason}"),
            "type": "permission_denied",
        }
    });
    let response = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build denial response");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderStore;
    use crate::usage::UsageTracker;
    use axum::Router;
    use oidc_agent_common::identity;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    async fn test_state() -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("perms");
        let db = crate::db::setup(&url).await.expect("db setup");
        let audit = crate::audit::AuditLogger::new(db.clone());
        AppState {
            config: oidc_agent_common::config::CentralConfig {
                listen_addr: "127.0.0.1:0".parse().expect("addr"),
                database_url: "sqlite://test.db".into(),
                oidc: oidc_agent_common::config::OidcConfig {
                    issuer: "https://idp.example.com".into(),
                    client_id: "test".into(),
                    client_secret_env: "TEST".into(),
                    redirect_uri: "http://127.0.0.1:0/callback".into(),
                    scopes: vec!["openid".into()],
                },
                mtls: oidc_agent_common::config::MtlsServerConfig {
                    ca_cert_path: "/ca.pem".into(),
                    server_cert_path: "/server.pem".into(),
                    server_key_path: "/server.key".into(),
                },
                admin: None,
                pricing: None,
                dev_mode: true,
                rate_limit_requests: 60,
                rate_limit_window_secs: 60,
            },
            provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
            client: reqwest::Client::new(),
            audit,
            rate_limiter: None,
            policy_store: crate::policy::PolicyStore::new(db.clone()),
            device_store: crate::device_store::DeviceStore::new(db.clone()),
            usage_tracker: UsageTracker::new(db),
            price_table: crate::pricing::PriceTable::empty(),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(())
    }

    fn chat_request(subject: &str, groups: &str) -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header(identity::HEADER_USER_SUBJECT, subject)
            .header(identity::HEADER_IDENTITY_ID, format!("{subject}-identity"))
            .header(identity::HEADER_USER_GROUPS, groups)
            .body(Body::from(
                r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
            ))
            .expect("build request")
    }

    #[tokio::test]
    async fn token_quota_denies_when_accumulated_usage_exceeds() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(500), None)
            .await
            .expect("policy");
        // User already consumed 500 tokens today.
        state
            .usage_tracker
            .increment("quota-user", None, 1, 500, 0.0)
            .await
            .expect("seed usage");

        let response = test_router(state)
            .oneshot(chat_request("quota-user", r#"["engineering"]"#))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "accumulated tokens at the quota must deny with 429"
        );
    }

    #[tokio::test]
    async fn token_quota_allows_when_under_quota() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(1000), None)
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-2", None, 1, 499, 0.0)
            .await
            .expect("seed usage");

        let response = test_router(state)
            .oneshot(chat_request("quota-user-2", r#"["engineering"]"#))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "tokens under the quota must be allowed"
        );
    }

    #[tokio::test]
    async fn token_quota_unset_allows_any_usage() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-3", None, 5, 1_000_000, 0.0)
            .await
            .expect("seed usage");

        let response = test_router(state)
            .oneshot(chat_request("quota-user-3", r#"["engineering"]"#))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "no token quota configured means unlimited"
        );
    }

    #[tokio::test]
    async fn request_quota_still_denies_when_exceeded() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, Some(1))
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-4", None, 1, 0, 0.0)
            .await
            .expect("seed usage");

        let response = test_router(state)
            .oneshot(chat_request("quota-user-4", r#"["engineering"]"#))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request-count quota must still be enforced"
        );
    }

    #[tokio::test]
    async fn device_auto_registers_on_first_request() {
        let state = test_state().await;
        let device_store = state.device_store.clone();

        let response = test_router(state)
            .oneshot(chat_request("device-user", r#"[]"#))
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::OK);

        let devices = device_store.list_devices().await.expect("list devices");
        let device = devices
            .iter()
            .find(|d| d.cert_fingerprint == "device-user-identity")
            .expect("device must be auto-registered keyed by identity_id");
        assert_eq!(device.user_subject, "device-user");
        assert!(!device.revoked);
    }

    #[tokio::test]
    async fn revoked_device_is_denied() {
        let state = test_state().await;
        state
            .device_store
            .upsert_device("device-user-identity", "device-user", None)
            .await
            .expect("register");
        state
            .device_store
            .revoke("device-user-identity")
            .await
            .expect("revoke");

        let response = test_router(state)
            .oneshot(chat_request("device-user", r#"[]"#))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a revoked device must be denied"
        );
    }
}
