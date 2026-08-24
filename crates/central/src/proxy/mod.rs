//! Proxy core for the central proxy.
//!
//! This module implements the Axum router, auth middleware, and forward
//! handler that receives mTLS-authenticated relay requests and forwards
//! them to the OpenAI-compatible backend with the master key.
//!
//! # Security
//!
//! - **Master key injection**: the master backend key is loaded from the
//!   secret store into `Zeroizing` memory and injected into upstream
//!   requests. It never appears in logs, errors, or responses.
//! - **Hop-by-hop header stripping** (RFC 7230 §6.1).
//! - **SSRF prevention**: the backend URL comes from config only.
//! - **Raw byte SSE passthrough** for streaming responses.
//! - **Audit logging**: every request is recorded.

pub mod forward;

use std::sync::Arc;

use axum::Router;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::error::Result;
use tower_http::limit::RequestBodyLimitLayer;
use zeroize::Zeroizing;

use crate::audit::AuditLogger;

/// The shared application state for the central proxy.
#[derive(Clone)]
pub struct AppState {
    /// The central proxy configuration.
    pub config: CentralConfig,
    /// The master backend key, held in `Zeroizing` memory.
    pub master_key: Arc<Zeroizing<String>>,
    /// The HTTP client for forwarding to the backend.
    pub client: reqwest::Client,
    /// The audit logger.
    pub audit: AuditLogger,
}

/// The maximum request body size (10 MB).
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Builds the Axum router for the central proxy.
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
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state)
}

/// Starts the central proxy server.
///
/// # Errors
///
/// Returns [`Error`] if the server fails to bind or start.
pub async fn serve(
    config: CentralConfig,
    master_key: Zeroizing<String>,
    audit: AuditLogger,
) -> Result<()> {
    let client = forward::build_client()?;
    let state = AppState {
        config: config.clone(),
        master_key: Arc::new(master_key),
        client,
        audit,
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("bind: {e}")))?;
    tracing::info!("central proxy listening on {}", config.listen_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(oidc_agent_common::shutdown::shutdown_signal())
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("serve: {e}")))?;
    Ok(())
}
