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

pub mod auth;
pub mod forward;
pub mod permissions;
pub mod rate_limit;

use std::sync::Arc;

use axum::Router;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::error::Result;
use tower_http::limit::RequestBodyLimitLayer;
use zeroize::Zeroizing;

use crate::audit::AuditLogger;
use crate::device_store::DeviceStore;
use crate::policy::PolicyStore;
use crate::pricing::PriceTable;
use crate::usage::UsageTracker;

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
    /// The rate limiter (None in dev mode).
    pub rate_limiter: Option<rate_limit::RateLimiter>,
    /// The group policy store.
    pub policy_store: PolicyStore,
    /// The device store.
    pub device_store: DeviceStore,
    /// The usage tracker (for quota enforcement and reporting).
    pub usage_tracker: UsageTracker,
    /// The pricing table (for cost tracking; empty if no pricing configured).
    pub price_table: PriceTable,
}

impl AppState {
    /// Returns the admin group name if the admin API is enabled, or `None`
    /// if the admin config is absent (admin API disabled).
    #[must_use]
    pub fn admin_group(&self) -> Option<&str> {
        self.config.admin.as_ref().map(|a| a.admin_group.as_str())
    }
}

/// The maximum request body size (10 MB).
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Builds the Axum router for the central proxy.
///
/// # Security
///
/// The router applies the auth middleware (validating relay-forwarded
/// identity headers) before the proxy handler. Body size limits are applied
/// globally.
pub fn router(state: AppState) -> Router {
    let mut proxy_router = Router::new()
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
            rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            permissions::permissions_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state.clone());

    // Merge the admin API router if an admin config is present.
    if let Some(admin_group) = state.admin_group() {
        let admin_state = crate::admin::AdminState {
            policy_store: state.policy_store.clone(),
            device_store: state.device_store.clone(),
            audit: state.audit.clone(),
            usage_tracker: state.usage_tracker.clone(),
            admin_group: admin_group.to_string(),
        };
        proxy_router = proxy_router.merge(crate::admin::router(admin_state));
    }

    proxy_router
}

/// Starts the central proxy server.
///
/// # Security
///
/// In production mode (`dev_mode = false`), the server binds with mTLS
/// (TLS 1.3) using the company CA, requiring relay client certificates. In
/// dev mode, it serves plain HTTP (for the containerized dev stack where
/// mTLS is not needed).
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
    let rate_limiter = if config.dev_mode {
        None
    } else {
        Some(rate_limit::RateLimiter::new(
            rate_limit::DEFAULT_RATE_LIMIT,
            rate_limit::DEFAULT_WINDOW,
        ))
    };
    let policy_store = PolicyStore::new(audit.db().clone());
    let device_store = DeviceStore::new(audit.db().clone());
    let usage_tracker = UsageTracker::new(audit.db().clone());
    let price_table = config
        .pricing
        .as_ref()
        .map(PriceTable::from_config)
        .unwrap_or_else(PriceTable::empty);

    // Auto-fetch prices from the backend at startup (best-effort). Manual
    // config overrides take precedence over fetched prices.
    if let Err(e) = price_table
        .fetch_from_backend(&client, &config.backend.base_url)
        .await
    {
        tracing::warn!(error = %e, "failed to fetch initial model prices from backend");
    }
    // Spawn a background task to refresh fetched prices periodically.
    // The interval is configurable via [central.pricing] fetch_interval_secs
    // (default 3600s = 1 hour; 0 disables auto-fetch).
    let fetch_interval = config
        .pricing
        .as_ref()
        .map(|p| p.fetch_interval_secs)
        .unwrap_or(3600);
    if fetch_interval > 0 {
        price_table.spawn_refresh_task(
            client.clone(),
            config.backend.base_url.clone(),
            std::time::Duration::from_secs(fetch_interval),
        );
    }

    let state = AppState {
        config: config.clone(),
        master_key: Arc::new(master_key),
        client,
        audit,
        rate_limiter,
        policy_store,
        device_store,
        usage_tracker,
        price_table,
    };
    let app = router(state);

    if config.dev_mode {
        // Dev mode: plain HTTP (for containerized dev stack).
        let listener = tokio::net::TcpListener::bind(&config.listen_addr)
            .await
            .map_err(|e| oidc_agent_common::error::Error::Http(format!("bind: {e}")))?;
        tracing::info!(
            "central proxy listening on {} (dev HTTP)",
            config.listen_addr
        );
        axum::serve(listener, app)
            .with_graceful_shutdown(oidc_agent_common::shutdown::shutdown_signal())
            .await
            .map_err(|e| oidc_agent_common::error::Error::Http(format!("serve: {e}")))?;
        return Ok(());
    }

    // Production mode: mTLS (TLS 1.3, client cert required).
    let server_config = oidc_agent_common::mtls::build_server_config(
        &config.mtls.ca_cert_path,
        &config.mtls.server_cert_path,
        &config.mtls.server_key_path,
    )?;

    // Set ALPN protocols for HTTP/1.1 (axum-server requires this when
    // building from a raw ServerConfig).
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        let _ = oidc_agent_common::shutdown::shutdown_signal().await;
        shutdown_handle.shutdown();
    });

    tracing::info!("central proxy listening on {} (mTLS)", config.listen_addr);
    axum_server::bind_rustls(config.listen_addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("serve: {e}")))?;
    Ok(())
}
