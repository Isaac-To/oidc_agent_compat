//! OIDC login flow for the relay.
//!
//! This module implements the `login` subcommand: it runs the OIDC
//! authorization-code + PKCE flow against the enterprise IdP, persists the
//! identity, mints a local key, and injects it into the agent's config.
//!
//! # Security
//!
//! - Loopback redirect URI (`http://127.0.0.1:{port}/callback`), RFC 8252.
//! - PKCE S256, `state`, `nonce`.
//! - ID-token validation with alg pin {RS256, ES256}.
//! - The local key is never printed; it's auto-injected into the agent config.
//!
//! The actual OIDC client construction is deferred to Phase 2 integration
//! (it requires a real IdP for discovery). This module provides the orchestration
//! layer that ties together the keystore, agent_config, and OIDC client.

use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::{Error, Result};

use crate::agent_config::{AgentConfig, inject};
use crate::keystore::KeyStore;

/// The result of a successful login.
#[derive(Debug)]
pub struct LoginResult {
    /// The identity's subject (from the IdP).
    pub subject: String,
    /// The identity's email (if provided).
    pub email: Option<String>,
    /// The agent config injection result.
    pub injection: crate::agent_config::InjectionResult,
}

/// Orchestrates the login flow after OIDC authentication has completed.
///
/// This is called by the `login` subcommand after the OIDC callback has
/// returned the user's identity claims. It:
/// 1. Upserts the identity in the local database.
/// 2. Mints a new local API key.
/// 3. Injects the base URL + key into the agent's config.
///
/// # Security
///
/// The plaintext key is passed to `inject` and then dropped. It is never
/// printed or persisted.
///
/// # Errors
///
/// Returns [`Error`] if the database or config injection fails.
pub async fn complete_login(
    key_store: &KeyStore,
    config: &RelayConfig,
    issuer: &str,
    subject: &str,
    email: Option<&str>,
    display_name: Option<&str>,
    groups: Option<&str>,
) -> Result<LoginResult> {
    // 1. Upsert the identity.
    let identity = key_store
        .upsert_identity(issuer, subject, email, display_name, groups)
        .await?;

    // 2. Mint a new local key.
    let minted = key_store.mint_key(&identity.id, "default").await?;

    // 3. Inject into the agent config.
    let base_url = format!("http://{}/v1", config.listen_addr);
    let agent_config = AgentConfig {
        base_url,
        api_key: minted.plaintext.to_string(),
    };
    let injection = inject(&agent_config)?;

    Ok(LoginResult {
        subject: subject.to_string(),
        email: email.map(String::from),
        injection,
    })
}

/// Runs the full OIDC login flow.
///
/// This is a placeholder that will be implemented in Phase 2 integration with
/// a real IdP. The flow is:
/// 1. Build the OIDC client from config (discovery).
/// 2. Generate PKCE, state, nonce.
/// 3. Open a one-shot loopback HTTP listener.
/// 4. Open the browser to the authorization URL.
/// 5. Receive the callback, exchange the code, fetch userinfo.
/// 6. Validate the ID token (alg pin, nonce, at_hash, sub match).
/// 7. Call [`complete_login`] to persist + mint + inject.
///
/// # Errors
///
/// Returns [`Error::Oidc`] until the full flow is implemented.
pub async fn run_login(_config: &RelayConfig, _key_store: &KeyStore) -> Result<LoginResult> {
    Err(Error::oidc(
        "OIDC login flow not yet implemented — requires a real IdP for discovery. \
         Use complete_login() with pre-authenticated claims for testing.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KeyStore;

    async fn setup_test_db() -> KeyStore {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-login-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        let db = crate::db::setup(&url).await.expect("db setup");
        KeyStore::new(db)
    }

    fn test_config() -> RelayConfig {
        RelayConfig {
            listen_addr: "127.0.0.1:8787".parse().expect("valid addr"),
            database_url: "sqlite://test.db".into(),
            oidc: oidc_agent_common::config::OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "test".into(),
                client_secret_env: "TEST_SECRET".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            central: oidc_agent_common::config::CentralConnectionConfig {
                url: "https://central.example.com".into(),
                ca_cert_path: "/ca.pem".into(),
                client_cert_path: "/client.pem".into(),
                client_key_path: "/client.key".into(),
            },
        }
    }

    #[tokio::test]
    async fn complete_login_persists_identity_and_mints_key() {
        let store = setup_test_db().await;
        let config = test_config();
        let result = complete_login(
            &store,
            &config,
            "https://idp.example.com",
            "user123",
            Some("user@example.com"),
            Some("Test User"),
            None,
        )
        .await
        .expect("login");

        assert_eq!(result.subject, "user123");
        assert_eq!(result.email.as_deref(), Some("user@example.com"));

        // Verify the identity was persisted.
        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].subject, "user123");

        // Verify a key was minted.
        use crate::entity::api_key;
        let keys = api_key::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(keys.len(), 1, "exactly one key must be minted");
    }

    #[tokio::test]
    async fn complete_login_is_idempotent_for_same_identity() {
        let store = setup_test_db().await;
        let config = test_config();

        // First login.
        let _ = complete_login(
            &store,
            &config,
            "https://idp.example.com",
            "user123",
            None,
            None,
            None,
        )
        .await
        .expect("login 1");

        // Second login with the same identity.
        let _ = complete_login(
            &store,
            &config,
            "https://idp.example.com",
            "user123",
            None,
            None,
            None,
        )
        .await
        .expect("login 2");

        // Should have one identity but two keys.
        use crate::entity::{api_key, identity};
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1, "same identity must not be duplicated");

        let keys = api_key::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(keys.len(), 2, "each login mints a new key");
    }

    #[tokio::test]
    async fn run_login_returns_not_implemented() {
        let store = setup_test_db().await;
        let config = test_config();
        let err = run_login(&config, &store).await.unwrap_err();
        assert!(err.to_string().contains("not yet implemented"), "{err}");
    }
}
