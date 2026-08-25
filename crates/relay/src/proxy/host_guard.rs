//! Host header validation middleware (DNS rebinding defense).
//!
//! This middleware rejects any request whose `Host` header is not a loopback
//! address. This prevents DNS rebinding attacks where a malicious webpage
//! resolves its domain to `127.0.0.1` and issues requests to the local relay.
//!
//! # Security
//!
//! - Runs BEFORE auth, so unauthenticated requests with bad Host headers are
//!   rejected early.
//! - Only allows `127.0.0.1:port`, `localhost:port`, and `[::1]:port`.
//!
//! # References
//!
//! - Jackson et al., "Protecting Browsers from DNS Rebinding Attacks,"
//!   Stanford, 2007.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::AppState;

/// The Host header validation middleware.
///
/// Rejects requests whose `Host` header is not in the allowed set (loopback
/// addresses only). Returns `400 Bad Request` on mismatch.
pub async fn host_guard_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let allowed = super::allowed_hosts(&state.listen_addr, state.config.dev_mode);
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok());

    match host {
        // RFC 7230 §5.4: Host header values are case-insensitive.
        Some(h) if allowed.iter().any(|a| a.eq_ignore_ascii_case(h)) => Ok(next.run(request).await),
        _ => {
            tracing::warn!(
                host = ?host,
                "rejected request with invalid Host header (DNS rebinding defense)"
            );
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
