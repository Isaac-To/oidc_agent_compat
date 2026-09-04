//! Authentication middleware for the relay proxy.
//!
//! The relay is a **dumb forwarder**: it does not verify tokens locally.
//! This middleware only checks that an `Authorization: Bearer <token>` header
//! is present (a non-empty bearer) and attaches a minimal
//! [`VerifiedIdentity`] with all identity fields set to `None`. The real
//! token verification and identity extraction happens at the central proxy,
//! which is the sole verification authority (zero-trust).
//!
//! In `dev_mode`, the auth check is skipped entirely — requests without an
//! `Authorization` header are allowed through. Central will still reject
//! unauthenticated requests (it verifies the bearer token via its token
//! store), so this does not weaken security.
//!
//! # Security
//!
//! - Extracts the bearer token via [`oidc_agent_common::keys::extract_bearer`].
//! - Never logs the token.
//! - Returns `401 Unauthorized` when a bearer token is missing (non-dev mode
//!   only). The token itself is **not** verified here; central verifies it.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::AppState;

/// The authentication middleware.
///
/// In non-dev mode, requires a non-empty `Authorization: Bearer <token>`
/// header and attaches a minimal [`VerifiedIdentity`] (all fields `None`).
/// In dev mode, passes every request through without checking the header.
///
/// The token is **not** verified locally — central is the sole verification
/// authority.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    // In dev mode, skip the auth check entirely. Central will reject
    // unauthenticated requests via its token store.
    if state.config.dev_mode {
        // Attach a minimal identity so the activity logger has a struct to
        // read (all fields are None — the relay does not know the identity).
        request.extensions_mut().insert(VerifiedIdentity::minimal());
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

    // The relay does NOT verify the bearer token. It only checks that a
    // non-empty bearer is present. Central verifies it via its token store.
    // Attach a minimal identity (all fields None) for the activity logger.
    let _ = bearer; // presence check only; value is forwarded by the handler
    request.extensions_mut().insert(VerifiedIdentity::minimal());
    Ok(next.run(request).await)
}

/// The verified identity attached to a request after auth.
///
/// In the zero-trust model, the relay does not know the identity — central
/// extracts it from the token. All fields are `Option` and are `None` on
/// the relay side. The struct is kept for compatibility with the activity
/// logger, which records whatever minimal info is available.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The database ID of the identity (`None` on the relay).
    pub identity_id: Option<String>,
    /// The subject from the IdP (`None` on the relay).
    pub subject: Option<String>,
    /// The email, if known (`None` on the relay).
    pub email: Option<String>,
    /// The group/role memberships (`None` on the relay).
    pub groups: Option<String>,
    /// The database ID of the key used (`None` on the relay).
    pub key_id: Option<String>,
}

impl VerifiedIdentity {
    /// Creates a minimal `VerifiedIdentity` with all fields set to `None`.
    ///
    /// The relay does not know the identity; central extracts it from the
    /// token.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            identity_id: None,
            subject: None,
            email: None,
            groups: None,
            key_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{AppState, router};
    use axum::body::Body;
    use axum::http::StatusCode;
    use oidc_agent_common::config::{CentralConnectionConfig, OidcConfig, RelayConfig};
    use tower::ServiceExt;

    /// Builds an AppState with the given `dev_mode` flag and a central URL
    /// that points nowhere (requests that reach the forward handler will
    /// fail, but the auth middleware runs first and returns before
    /// forwarding on rejection).
    ///
    /// In non-dev mode, `build_client` would require mTLS cert files; we use
    /// a plain `reqwest::Client::new()` instead since these tests only
    /// exercise the auth middleware (not the forward handler).
    async fn test_state(dev_mode: bool) -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("relay-auth");
        let db = crate::db::setup(&url).await.expect("db");
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            database_url: "sqlite://test.db".into(),
            oidc: OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "t".into(),
                client_secret_env: "T".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            central: CentralConnectionConfig {
                url: "http://127.0.0.1:1".into(),
                ca_cert_path: "/ca.pem".into(),
                client_cert_path: "/c.pem".into(),
                client_key_path: "/c.key".into(),
            },
            dev_mode,
        };
        AppState {
            config: config.clone(),
            // Use a plain client to avoid mTLS cert loading in non-dev mode;
            // the auth middleware runs before the forward handler so the
            // client is never actually used for the auth rejection tests.
            client: reqwest::Client::new(),
            listen_addr: "127.0.0.1:8787".parse().expect("addr"),
            activity: crate::activity::ActivityLogger::new(db),
            device_fingerprint: None,
        }
    }

    /// A request to /healthz — exempt from auth in both modes.
    fn healthz_request() -> Request<Body> {
        Request::builder()
            .uri("/healthz")
            .header("host", "127.0.0.1:8787")
            .body(Body::empty())
            .expect("build request")
    }

    /// A request with an Authorization: Bearer header to a proxied route.
    fn authed_request() -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .header("authorization", "Bearer oac_test_token")
            .header("content-type", "application/json")
            .header("host", "127.0.0.1:8787")
            .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
            .expect("build request")
    }

    /// A request without an Authorization header to a proxied route.
    fn unauthed_request() -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("host", "127.0.0.1:8787")
            .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
            .expect("build request")
    }

    #[tokio::test]
    async fn healthz_bypasses_auth_in_non_dev_mode() {
        let state = test_state(false).await;
        let app = router(state);
        let resp = app.oneshot(healthz_request()).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authed_request_passes_through_in_non_dev_mode() {
        // In non-dev mode, a request with a valid Bearer header passes the
        // auth middleware (the token is NOT verified by the relay). The
        // forward handler then tries to reach central at 127.0.0.1:1 which
        // refuses the connection → 502 Bad Gateway. We assert the middleware
        // did NOT return 401.
        let state = test_state(false).await;
        let app = router(state);
        let resp = app.oneshot(authed_request()).await.expect("router");
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a request with a Bearer header must pass the auth middleware"
        );
    }

    #[tokio::test]
    async fn unauthed_request_rejected_in_non_dev_mode() {
        let state = test_state(false).await;
        let app = router(state);
        let resp = app.oneshot(unauthed_request()).await.expect("router");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a request without Authorization in non-dev mode must get 401"
        );
    }

    #[tokio::test]
    async fn unauthed_request_passes_through_in_dev_mode() {
        // In dev mode, the auth check is skipped entirely. The request
        // reaches the forward handler, which fails to connect to central
        // (127.0.0.1:1) → 502. We assert the middleware did NOT return 401.
        let state = test_state(true).await;
        let app = router(state);
        let resp = app.oneshot(unauthed_request()).await.expect("router");
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "dev mode must allow requests without Authorization through"
        );
    }
}
