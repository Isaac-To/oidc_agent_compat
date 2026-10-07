//! Test utilities for the central proxy crate.
//!
//! This module is only compiled when the `test-utils` feature is enabled
//! (i.e., in test builds of dependent crates). It provides builders that
//! eliminate the boilerplate of constructing [`AppState`] in tests.
//!
//! # Example
//!
//! ```ignore
//! use oac_central::test_utils::TestCentralState;
//!
//! let state = TestCentralState::new().await;
//! let addr = state.spawn().await;
//! ```

use std::net::SocketAddr;

use axum::Router;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::persistence::temp_sqlite_url;
use sea_orm::DatabaseConnection;
use zeroize::Zeroizing;

use crate::admin::AdminState;
use crate::audit::AuditLogger;
use crate::device_store::DeviceStore;
use crate::mcp::McpManager;
use crate::policy::PolicyStore;
use crate::pricing::PriceTable;
use crate::provider::{ProviderInput, ProviderStore};
use crate::proxy::{self, AppState};
use crate::token_store::{MintRequest, TokenStore};
use crate::usage::UsageTracker;

/// A builder for constructing a central proxy [`AppState`] in tests.
///
/// Eliminates the ~40 lines of boilerplate that was previously duplicated
/// across every test file. Each call to [`TestCentralState::new`] creates
/// a fresh temp SQLite database with all stores wired up.
pub struct TestCentralState {
    /// The database connection (shared by all stores).
    pub db: DatabaseConnection,
    /// The audit logger.
    pub audit: AuditLogger,
    /// The provider store.
    pub provider_store: ProviderStore,
    /// The policy store.
    pub policy_store: PolicyStore,
    /// The device store.
    pub device_store: DeviceStore,
    /// The usage tracker.
    pub usage_tracker: UsageTracker,
    /// The MCP manager.
    pub mcp_manager: McpManager,
    /// The token store.
    pub token_store: TokenStore,
    /// The central config (dev mode by default).
    pub config: CentralConfig,
}

impl TestCentralState {
    /// Creates a new test state with a fresh temp database.
    ///
    /// All stores are created and wired to the same database. The config
    /// is a dev-mode [`CentralConfig::test_dev`].
    ///
    /// # Panics
    ///
    /// Panics if the database setup or MCP manager creation fails.
    pub async fn new() -> Self {
        let url = temp_sqlite_url("central-test");
        let db = crate::db::setup(&url).await.expect("db setup");
        Self::with_db(db).await
    }

    /// Creates a new test state with a specific database connection.
    ///
    /// Useful when you need to share the database across multiple states
    /// or inspect it directly.
    ///
    /// # Panics
    ///
    /// Panics if the MCP manager creation fails.
    pub async fn with_db(db: DatabaseConnection) -> Self {
        let audit = AuditLogger::new(db.clone());
        let mcp_db = db.clone();
        Self {
            db: db.clone(),
            audit: audit.clone(),
            provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
            policy_store: PolicyStore::new(db.clone()),
            device_store: DeviceStore::new(db.clone()),
            usage_tracker: UsageTracker::new(db.clone()),
            mcp_manager: McpManager::new(mcp_db, Zeroizing::new([7_u8; 32])).expect("mcp manager"),
            token_store: TokenStore::new(db),
            config: CentralConfig::test_dev(),
        }
    }

    /// Sets the config (e.g., to override `dev_mode` or rate limits).
    #[must_use]
    pub fn with_config(mut self, config: CentralConfig) -> Self {
        self.config = config;
        self
    }

    /// Registers a mock provider pointing at the given backend URL.
    ///
    /// # Panics
    ///
    /// Panics if the provider upsert fails.
    pub async fn with_provider(self, id: &str, base_url: &str, key: &str) -> Self {
        self.provider_store
            .upsert_provider(&ProviderInput {
                id: id.into(),
                name: id.into(),
                base_url: base_url.into(),
                enabled: true,
                is_default: true,
                models: Some(vec!["gpt-4".into()]),
            })
            .await
            .expect("provider");
        self.provider_store
            .add_key(id, "test-key", key, 0, &[])
            .await
            .expect("provider key");
        self
    }

    /// Builds the [`AppState`] from this test state.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client build fails.
    #[must_use]
    pub fn build_state(&self) -> AppState {
        AppState {
            config: self.config.clone(),
            provider_store: self.provider_store.clone(),
            client: proxy::forward::build_client().expect("client"),
            audit: self.audit.clone(),
            rate_limiter: None,
            policy_store: self.policy_store.clone(),
            device_store: self.device_store.clone(),
            usage_tracker: self.usage_tracker.clone(),
            price_table: PriceTable::empty(),
            mcp_manager: self.mcp_manager.clone(),
            token_store: self.token_store.clone(),
        }
    }

    /// Builds the [`AppState`] and spawns the central proxy on a random port.
    ///
    /// Returns the bound address and the HTTP client.
    ///
    /// # Panics
    ///
    /// Panics if the listener bind or client build fails.
    pub async fn spawn(&self) -> (SocketAddr, reqwest::Client) {
        let state = self.build_state();
        let app = proxy::router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind central");
        let addr = listener.local_addr().expect("central addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, reqwest::Client::new())
    }

    /// Mints a token directly via the token store and returns the plaintext.
    ///
    /// # Panics
    ///
    /// Panics if the mint fails.
    pub async fn mint_token(&self, subject: &str, groups: Option<&str>) -> String {
        let minted = self
            .token_store
            .mint_token(&MintRequest {
                subject: subject.into(),
                issuer: "https://idp.example.com".into(),
                email: None,
                display_name: None,
                groups: groups.map(String::from),
                identity_id: Some(format!("{subject}-identity")),
                label: "test".into(),
                expires_at: None,
                device_fingerprint: None,
            })
            .await
            .expect("mint token");
        minted.plaintext.to_string()
    }

    /// Builds the [`AdminState`] from this test state.
    ///
    /// Used by admin API integration tests that drive the admin router
    /// directly via `tower::ServiceExt::oneshot`.
    #[must_use]
    pub fn build_admin_state(&self) -> AdminState {
        AdminState {
            policy_store: self.policy_store.clone(),
            provider_store: self.provider_store.clone(),
            device_store: self.device_store.clone(),
            audit: self.audit.clone(),
            usage_tracker: self.usage_tracker.clone(),
            mcp_manager: self.mcp_manager.clone(),
            token_store: self.token_store.clone(),
            admin_group: "oac-admins".into(),
        }
    }

    /// Mints an admin token (member of `oac-admins` group).
    ///
    /// # Panics
    ///
    /// Panics if the mint fails.
    pub async fn mint_admin_token(&self) -> String {
        self.mint_token("admin-user", Some(r#"["oac-admins"]"#))
            .await
    }

    /// Mints a non-admin token (member of `engineering` group only).
    ///
    /// # Panics
    ///
    /// Panics if the mint fails.
    pub async fn mint_non_admin_token(&self) -> String {
        self.mint_token("regular-user", Some(r#"["engineering"]"#))
            .await
    }
}

/// Spawns an Axum router on a random port and returns its address.
///
/// This is a convenience wrapper around the common pattern of binding a
/// `TcpListener` on `127.0.0.1:0`, spawning `axum::serve`, and returning
/// the bound address.
///
/// # Panics
///
/// Panics if the listener bind fails.
#[must_use]
pub async fn spawn_server(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let addr = listener.local_addr().expect("server addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// Creates a minimal mock OpenAI-compatible backend router.
///
/// Returns a router that serves:
/// - `GET /v1/models` → `{"data": [{"id": "gpt-4"}]}`
/// - `POST /v1/chat/completions` → `{"choices": [{"message": {"content": "hello"}}], "usage": {...}}`
/// - `POST /v1/embeddings` → `{"data": [{"embedding": [0.1, 0.2, 0.3]}]}`
pub fn mock_backend_router() -> Router {
    Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"choices": [{"message": {"content": "hello"}, "index": 0}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#,
                )
            }),
        )
        .route(
            "/v1/embeddings",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"data": [{"embedding": [0.1, 0.2, 0.3]}]}"#,
                )
            }),
        )
}
