//! Permissions middleware for the central proxy.
//!
//! This middleware enforces group-based authorization policies after the
//! relay identity has been verified by [`auth_middleware`]. It:
//!
//! 1. Extracts the `VerifiedRelayIdentity` from request extensions.
//! 2. Parses the user's groups (JSON array string).
//! 3. Resolves the effective policy via [`PolicyStore::resolve_policy`].
//! 4. Extracts the requested model from the request body.
//! 5. Checks the model against the policy's allowlist.
//! 6. Checks the endpoint against the policy's allowlist.
//! 7. On denial, writes an audit entry with `permission_decision="denied"`
//!    and returns `403 Forbidden`.
//! 8. On allow, inserts a `PermissionDecision` into extensions for the
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
use oidc_agent_common::error::Error;

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

        let model = extract_model(&body_bytes);

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
        backend: state.config.backend.name.clone(),
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

/// Extracts the `model` field from a JSON request body.
fn extract_model(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("model")?.as_str().map(String::from)
}

// Unused import suppression — Error is used in deny's error mapping path
// indirectly via tracing. Keep for future use.
#[allow(dead_code)]
fn _error_forbidden(msg: &str) -> Error {
    Error::forbidden(msg)
}
