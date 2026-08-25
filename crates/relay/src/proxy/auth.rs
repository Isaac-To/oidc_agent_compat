//! Authentication middleware for the relay proxy.
//!
//! Validates the local API key from the `Authorization: Bearer <key>` header
//! against the key store. Uses constant-time comparison to prevent timing
//! attacks.
//!
//! # Security
//!
//! - Extracts the bearer token via [`oidc_agent_common::keys::extract_bearer`].
//! - Hashes the token and looks it up in the database.
//! - Uses [`subtle::ConstantTimeEq`] for the final comparison.
//! - Never logs the key.
//! - Returns `401 Unauthorized` on missing/invalid keys.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::AppState;

/// The authentication middleware.
///
/// Extracts the `Authorization: Bearer <key>` header, validates it against the
/// key store, and attaches the identity to the request extensions. Returns
/// `401 Unauthorized` on missing or invalid keys.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    // Extract the Authorization header.
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let bearer = auth_header.and_then(oidc_agent_common::keys::extract_bearer);

    let bearer = match bearer {
        Some(b) => b,
        None => {
            tracing::warn!("rejected request without valid Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Verify the key against the store.
    match state.key_store.verify_key(bearer).await {
        Ok(Some((key, identity))) => {
            // Attach the identity to the request extensions for downstream use.
            request.extensions_mut().insert(VerifiedIdentity {
                identity_id: identity.id,
                subject: identity.subject,
                email: identity.email,
                groups: identity.groups,
                key_id: key.id,
            });
            Ok(next.run(request).await)
        }
        Ok(None) => {
            tracing::warn!("rejected request with invalid API key");
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(e) => {
            tracing::error!(error = %e, "key verification failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The verified identity attached to a request after auth.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The database ID of the identity.
    pub identity_id: String,
    /// The subject from the IdP.
    pub subject: String,
    /// The email, if provided.
    pub email: Option<String>,
    /// The group/role memberships (JSON array string), if provided.
    pub groups: Option<String>,
    /// The database ID of the key used.
    pub key_id: String,
}
