//! Authentication middleware for the central proxy.
//!
//! The central proxy receives requests from relays over mTLS (transport-level
//! auth). On top of that, the relay forwards the verified user identity as
//! `X-OAC-User-Subject` / `X-OAC-User-Email` / `X-OAC-Identity-Id` headers.
//! These headers are set by the relay ONLY from its auth-middleware-verified
//! identity (never from the incoming request headers), so a client cannot
//! spoof them over the mTLS channel.
//!
//! # Security
//!
//! - Requires the `X-OAC-User-Subject` header on all non-healthz routes.
//! - Rejects requests missing the identity header with `401 Unauthorized`.
//! - Attaches the verified identity to the request extensions for downstream
//!   audit logging.
//! - In `dev_mode`, a missing identity is allowed (for the dev stack where
//!   the relay auto-mints a dev key and forwards the dev identity).

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::AppState;

/// The verified user identity attached to a central-proxy request after auth.
#[derive(Debug, Clone)]
pub struct VerifiedRelayIdentity {
    /// The user subject (from the IdP, forwarded by the relay).
    pub subject: String,
    /// The user email, if provided.
    pub email: Option<String>,
    /// The relay-side identity database ID.
    pub identity_id: Option<String>,
}

/// The authentication middleware for the central proxy.
///
/// Extracts the relay-forwarded identity headers and attaches them to the
/// request extensions. Returns `401 Unauthorized` if the `X-OAC-User-Subject`
/// header is missing (unless `dev_mode` is true).
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    let headers = request.headers();
    let subject = headers
        .get("x-oac-user-subject")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let email = headers
        .get("x-oac-user-email")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let identity_id = headers
        .get("x-oac-identity-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let subject = match subject {
        Some(s) if !s.is_empty() => s,
        _ => {
            if state.config.dev_mode {
                // In dev mode, allow requests without identity headers (the
                // dev stack's relay forwards the dev identity, but be
                // permissive for manual curl testing).
                tracing::warn!(
                    "dev_mode: allowing central request without X-OAC-User-Subject"
                );
                return Ok(next.run(request).await);
            }
            tracing::warn!("rejected central request without X-OAC-User-Subject");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Attach the verified identity to the request extensions.
    request.extensions_mut().insert(VerifiedRelayIdentity {
        subject,
        email,
        identity_id,
    });

    Ok(next.run(request).await)
}
