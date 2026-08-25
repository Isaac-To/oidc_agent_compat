//! Proxy core for the relay.
//!
//! This module implements the Axum router, middleware, and forward handler
//! that relay agent requests to the central proxy over mTLS.
//!
//! # Security
//!
//! - **Host header validation** (DNS rebinding defense): rejects requests
//!   whose `Host` is not a loopback address.
//! - **Auth middleware**: validates the local API key via constant-time
//!   comparison.
//! - **Hop-by-hop header stripping** (RFC 7230 §6.1) on forwarded requests.
//! - **mTLS** to the central proxy (TLS 1.3).
//! - **Raw byte SSE passthrough** for streaming responses.

pub mod auth;
pub mod forward;
pub mod host_guard;

use std::net::SocketAddr;

use axum::Router;
use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::Result;
use tower_http::limit::RequestBodyLimitLayer;

use crate::activity::ActivityLogger;
use crate::keystore::KeyStore;

/// The shared application state for the relay proxy.
#[derive(Clone)]
pub struct AppState {
    /// The key store for validating local keys.
    pub key_store: KeyStore,
    /// The relay configuration.
    pub config: RelayConfig,
    /// The HTTP client for forwarding to the central proxy.
    pub client: reqwest::Client,
    /// The actual bound listen address (may differ from config if port 0).
    pub listen_addr: SocketAddr,
    /// The relay-side activity logger.
    pub activity: ActivityLogger,
}

/// The maximum request body size (10 MB).
///
/// Re-exported from [`oidc_agent_common::http_util`] so both proxies share
/// a single source of truth.
pub const MAX_BODY_SIZE: usize = oidc_agent_common::http_util::MAX_BODY_SIZE;

/// Builds the Axum router for the relay proxy.
///
/// # Security
///
/// The router applies the Host header validation middleware first (before
/// auth), then auth, then the proxy handler. Body size limits are applied
/// globally.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route(
            "/v1/chat/completions",
            axum::routing::post(forward::proxy_handler),
        )
        .route("/v1/responses", axum::routing::post(forward::proxy_handler))
        .route("/v1/models", axum::routing::get(forward::proxy_handler))
        .route(
            "/v1/embeddings",
            axum::routing::post(forward::proxy_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            host_guard::host_guard_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state)
}

/// Starts the relay proxy server.
///
/// # Errors
///
/// Returns [`Error`] if the server fails to bind or start.
pub async fn serve(config: RelayConfig, key_store: KeyStore) -> Result<()> {
    let client = forward::build_client(&config)?;
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    let listen_addr = listener.local_addr()?;
    let activity = ActivityLogger::new(key_store.db.clone());
    let state = AppState {
        key_store,
        config: config.clone(),
        client,
        listen_addr,
        activity,
    };
    let app = router(state);
    tracing::info!("relay listening on {}", listen_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(oidc_agent_common::shutdown::shutdown_signal())
        .await?;
    Ok(())
}

/// Returns the allowed Host header values for the given listen address.
///
/// # Security
///
/// Used by the Host header validation middleware to reject DNS rebinding
/// attacks. Only loopback addresses are allowed. In dev mode, the Docker
/// service name `relay` is also allowed so containerized agents (e.g. Goose)
/// can connect via the Docker network.
#[must_use]
pub fn allowed_hosts(listen_addr: &SocketAddr, dev_mode: bool) -> Vec<String> {
    let port = listen_addr.port();
    let mut hosts = vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    if dev_mode {
        // Allow the Docker service name for containerized agents.
        hosts.push(format!("relay:{port}"));
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_hosts_includes_loopback_variants() {
        let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let hosts = allowed_hosts(&addr, false);
        assert!(hosts.contains(&"127.0.0.1:8787".to_string()));
        assert!(hosts.contains(&"localhost:8787".to_string()));
        assert!(hosts.contains(&"[::1]:8787".to_string()));
    }

    #[test]
    fn allowed_hosts_includes_relay_in_dev_mode() {
        let addr: SocketAddr = "0.0.0.0:8787".parse().unwrap();
        let hosts = allowed_hosts(&addr, true);
        assert!(hosts.contains(&"relay:8787".to_string()));
    }

    #[test]
    fn allowed_hosts_excludes_relay_in_prod_mode() {
        let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let hosts = allowed_hosts(&addr, false);
        assert!(!hosts.contains(&"relay:8787".to_string()));
    }
}
