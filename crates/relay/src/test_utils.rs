//! Test utilities for the relay proxy crate.
//!
//! This module is only compiled when the `test-utils` feature is enabled
//! (i.e., in test builds of dependent crates). It provides builders that
//! eliminate the boilerplate of constructing [`AppState`] in tests.
//!
//! # Example
//!
//! ```ignore
//! use oac_relay::test_utils::TestRelayState;
//!
//! let state = TestRelayState::new("http://127.0.0.1:1").await;
//! let addr = state.spawn().await;
//! ```

use std::net::SocketAddr;

use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::persistence::temp_sqlite_url;
use sea_orm::DatabaseConnection;

use crate::activity::ActivityLogger;
use crate::proxy::{self, AppState};

/// A builder for constructing a relay proxy [`AppState`] in tests.
///
/// Eliminates the ~30 lines of boilerplate that was previously duplicated
/// across every test file. Each call to [`TestRelayState::new`] creates
/// a fresh temp SQLite database with the activity logger wired up.
pub struct TestRelayState {
    /// The database connection.
    pub db: DatabaseConnection,
    /// The relay config (dev mode by default).
    pub config: RelayConfig,
    /// The activity logger.
    pub activity: ActivityLogger,
}

impl TestRelayState {
    /// Creates a new test state with a fresh temp database.
    ///
    /// The `central_url` parameter sets the central proxy URL (use
    /// `http://127.0.0.1:1` for a dead endpoint, or the actual address
    /// of a spawned central).
    ///
    /// # Panics
    ///
    /// Panics if the database setup fails.
    pub async fn new(central_url: &str) -> Self {
        let url = temp_sqlite_url("relay-test");
        let db = crate::db::setup(&url).await.expect("db setup");
        Self::with_db(db, central_url).await
    }

    /// Creates a new test state with a specific database connection.
    ///
    /// # Panics
    ///
    /// Panics if the database setup fails (not applicable here, but kept
    /// for API symmetry).
    pub async fn with_db(db: DatabaseConnection, central_url: &str) -> Self {
        Self {
            db: db.clone(),
            config: RelayConfig::test_dev(central_url),
            activity: ActivityLogger::new(db),
        }
    }

    /// Sets the config (e.g., to override `dev_mode` or listen address).
    #[must_use]
    pub fn with_config(mut self, config: RelayConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the [`AppState`] from this test state.
    ///
    /// The `listen_addr` is set to `127.0.0.1:0` by default (matching the
    /// config's listen address for random-port binding).
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client build fails.
    #[must_use]
    pub fn build_state(&self) -> AppState {
        AppState {
            config: self.config.clone(),
            client: proxy::forward::build_client(&self.config).expect("client"),
            listen_addr: self.config.listen_addr,
            activity: self.activity.clone(),
            device_fingerprint: None,
        }
    }

    /// Builds the [`AppState`] and spawns the relay proxy on a random port.
    ///
    /// Returns the bound address and the HTTP client. The `listen_addr`
    /// in the returned state's config is updated to the actual bound
    /// address.
    ///
    /// # Panics
    ///
    /// Panics if the listener bind or client build fails.
    pub async fn spawn(&self) -> (SocketAddr, reqwest::Client) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind relay");
        let addr = listener.local_addr().expect("relay addr");
        let mut state = self.build_state();
        state.listen_addr = addr;
        let app = proxy::router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, reqwest::Client::new())
    }
}
