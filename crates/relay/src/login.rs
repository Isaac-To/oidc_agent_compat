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

use std::time::Duration;

use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::oidc;

use crate::agent_config::{AgentConfig, inject};
use crate::keystore::KeyStore;

use openidconnect::core::{CoreJwsSigningAlgorithm, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, SubjectIdentifier,
};
use oidc_agent_common::oidc::{
    CustomClient, CustomIdTokenClaims, CustomProviderMetadata, CustomUserInfoClaims,
    groups_to_json_string, union_groups_roles,
};

/// The maximum time to wait for the user to complete the browser login (5 min).
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

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

/// Runs the full OIDC authorization-code + PKCE login flow.
///
/// # Flow
///
/// 1. Validate the loopback redirect URI (RFC 8252).
/// 2. Resolve the client secret from the environment.
/// 3. Discover the IdP's metadata via the issuer URL.
/// 4. Generate PKCE (S256), `state`, and `nonce`.
/// 5. Bind a one-shot loopback HTTP listener (random port).
/// 6. Build the authorization URL and open it in the browser.
/// 7. Receive the callback, verify `state`, exchange the code for tokens.
/// 8. Validate the ID token (alg pin {RS256, ES256}, iss, aud, exp, nonce,
///    signature via JWKS).
/// 9. Fetch userinfo (email, name, groups), falling back to ID-token claims.
/// 10. Call [`complete_login`] to persist + mint + inject.
///
/// # Security
///
/// - PKCE S256 (RFC 7636, RFC 9700 §2.1.1).
/// - `state` (CSRF) and `nonce` (replay) verified.
/// - ID-token signing algorithm pinned to {RS256, ES256}; `none` and HS*
///   rejected (OIDC Core §2, repo security research).
/// - Loopback redirect only (RFC 8252 §7.3).
/// - HTTP client never follows redirects (SSRF prevention).
/// - The local key is never printed; it's auto-injected into the agent config.
///
/// # Errors
///
/// Returns [`Error::Oidc`] on any protocol, validation, or network failure.
pub async fn run_login(config: &RelayConfig, key_store: &KeyStore) -> Result<LoginResult> {
    // 1. Validate the redirect URI is a loopback http URL.
    oidc::validate_loopback_redirect(&config.oidc.redirect_uri)?;

    // 2. Resolve the client secret from the environment.
    let client_secret = oidc::resolve_client_secret(&config.oidc)?;

    // 3. Build the HTTP client (no redirects, rustls, timeouts).
    let http_client = oidc::build_http_client()?;

    // 4. Discover the IdP metadata.
    let issuer_url = IssuerUrl::new(config.oidc.issuer.clone())
        .map_err(|e| Error::oidc(format!("invalid issuer URL: {e}")))?;
    let provider_metadata = CustomProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| Error::oidc(format!("OIDC discovery failed: {e}")))?;

    // 5. Bind a one-shot loopback listener to get a real port (RFC 8252 §7.3).
    //    The config redirect_uri may use port 0 (any port); we substitute the
    //    actual bound port. The IdP MUST allow any loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::oidc(format!("bind callback listener: {e}")))?;
    let callback_port = listener
        .local_addr()
        .map_err(|e| Error::oidc(format!("callback local_addr: {e}")))?
        .port();
    let redirect_uri_str = format!("http://127.0.0.1:{callback_port}/callback");
    let redirect_uri = RedirectUrl::new(redirect_uri_str)
        .map_err(|e| Error::oidc(format!("invalid redirect URL: {e}")))?;

    // 6. Build the OIDC client.
    let client = CustomClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc.client_id.clone()),
        Some(ClientSecret::new(client_secret)),
    )
    .set_redirect_uri(redirect_uri);

    // 7. Generate PKCE (S256), state, and nonce.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // 8. Build the authorization URL.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        // Add configured scopes (skip "openid", already added).
        .add_scopes(
            config
                .oidc
                .scopes
                .iter()
                .filter(|s| s.as_str() != "openid")
                .map(|s| Scope::new(s.clone())),
        )
        .set_pkce_challenge(pkce_challenge)
        .url();

    // 9. Open the browser (best effort); always print the URL as fallback.
    let url_string = authorize_url.to_string();
    println!("Open this URL in your browser to log in:\n{url_string}\n");
    open_browser(&url_string);

    // 10. Wait for the callback (with timeout).
    let (code, state) = wait_for_callback(listener, CALLBACK_TIMEOUT).await?;

    // 11. Verify state (CSRF defense).
    if state.secret() != csrf_state.secret() {
        return Err(Error::oidc(
            "state mismatch — possible CSRF attack or stale callback",
        ));
    }

    // 12. Exchange the code for tokens (with PKCE verifier).
    let token_response = client
        .exchange_code(code)
        .map_err(|e| Error::oidc(format!("prepare token exchange: {e}")))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| Error::oidc(format!("token exchange failed: {e}")))?;

    // 13. Extract and validate the ID token.
    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or_else(|| Error::oidc("IdP did not return an ID token"))?;

    // 13a. Alg pin: reject anything other than RS256/ES256 BEFORE verifying
    //     the signature (defense in depth; the crate's verifier accepts
    //     whatever alg the JWKS advertises).
    let signing_alg = id_token
        .signing_alg()
        .map_err(|e| Error::oidc(format!("ID token has no signing algorithm: {e}")))?;
    if !is_allowed_alg(signing_alg) {
        return Err(Error::oidc(
            "ID token signed with disallowed algorithm; only RS256/ES256 are accepted",
        ));
    }

    // 13b. Verify the ID token claims (iss, aud, exp, nonce, signature).
    let id_token_claims: &CustomIdTokenClaims = id_token
        .claims(&client.id_token_verifier(), &nonce)
        .map_err(|e| Error::oidc(format!("ID token validation failed: {e}")))?;

    // 13c. Verify the at_hash claim (OIDC Core §3.1.3.7 step 3).
    // If the IdP includes an at_hash in the ID token, we verify it against
    // the access token to prevent token substitution attacks.
    if let Some(expected_at_hash) = id_token_claims.access_token_hash() {
        let id_token_verifier = client.id_token_verifier();
        let signing_key = id_token
            .signing_key(&id_token_verifier)
            .map_err(|e| Error::oidc(format!("ID token signing key lookup failed: {e}")))?;
        let actual_at_hash = openidconnect::AccessTokenHash::from_token(
            token_response.access_token(),
            signing_alg,
            signing_key,
        )
        .map_err(|e| Error::oidc(format!("at_hash computation failed: {e}")))?;
        if actual_at_hash != *expected_at_hash {
            return Err(Error::oidc(
                "at_hash mismatch — access token may have been substituted",
            ));
        }
        tracing::debug!("at_hash verified successfully");
    }

    // 14. Fetch userinfo (email, name, groups); fall back to ID-token claims.
    let expected_subject = SubjectIdentifier::new(id_token_claims.subject().to_string());
    let (subject, email, display_name, groups) = match client.user_info(
        token_response.access_token().clone(),
        Some(expected_subject),
    ) {
        Ok(userinfo_request) => match userinfo_request.request_async(&http_client).await {
            Ok(userinfo) => {
                let userinfo: CustomUserInfoClaims = userinfo;
                let subject = userinfo.subject().to_string();
                let email = userinfo.email().map(|e| e.as_str().to_string());
                let display_name = userinfo
                    .name()
                    .and_then(|n| n.get(None))
                    .map(|n| n.as_str().to_string())
                    .or_else(|| {
                        userinfo
                            .preferred_username()
                            .map(|u| u.as_str().to_string())
                    });
                // Extract groups + roles from the additional claims and union
                // them into a single JSON array string.
                let groups = {
                    let combined = union_groups_roles(userinfo.additional_claims());
                    groups_to_json_string(&combined)
                };
                (subject, email, display_name, groups)
            }
            Err(e) => {
                tracing::warn!(error = %e, "userinfo request failed, falling back to ID-token claims");
                claims_from_id_token(id_token_claims)
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "userinfo endpoint unavailable, falling back to ID-token claims");
            claims_from_id_token(id_token_claims)
        }
    };

    // 15. Persist + mint + inject.
    complete_login(
        key_store,
        config,
        &config.oidc.issuer,
        &subject,
        email.as_deref(),
        display_name.as_deref(),
        groups.as_deref(),
    )
    .await
}

/// Returns `true` if the signing algorithm is RS256 or ES256.
///
/// # Security
///
/// Rejects `none` (no signature) and all HS* (HMAC) algorithms, which would
/// be insecure for ID-token validation (OIDC Core §2). This is a defense in
/// depth on top of the crate's verifier, which accepts whatever alg the
/// JWKS advertises.
fn is_allowed_alg(alg: &CoreJwsSigningAlgorithm) -> bool {
    matches!(
        alg,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 // RS256
            | CoreJwsSigningAlgorithm::EcdsaP256Sha256 // ES256
    )
}

/// Extracts identity fields from the ID-token claims (fallback when userinfo
/// is unavailable).
///
/// Group and role claims are extracted from the additional claims (via
/// [`CustomAdditionalClaims`]) and unioned into a single JSON array string
/// for storage in the `identities.groups` column.
fn claims_from_id_token(
    claims: &CustomIdTokenClaims,
) -> (String, Option<String>, Option<String>, Option<String>) {
    let subject = claims.subject().to_string();
    let email = claims.email().map(|e| e.as_str().to_string());
    let email_verified = claims.email_verified().unwrap_or(false);
    // Prefer the userinfo-style name; fall back to preferred_username.
    let display_name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.as_str().to_string())
        .or_else(|| claims.preferred_username().map(|u| u.as_str().to_string()));
    // Extract groups + roles from the additional claims and union them.
    let groups = {
        let combined = union_groups_roles(claims.additional_claims());
        groups_to_json_string(&combined)
    };
    let _ = email_verified;
    (subject, email, display_name, groups)
}

/// Waits for a single OIDC callback on the loopback listener.
///
/// Parses the GET request, extracts `code` and `state` from the query string,
/// writes a minimal HTML response, and returns the authorization code and
/// state. Times out after `timeout`.
///
/// # Errors
///
/// Returns [`Error::Oidc`] on timeout, parse failure, or missing parameters.
async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    timeout: Duration,
) -> Result<(AuthorizationCode, CsrfToken)> {
    let accept_result = tokio::time::timeout(timeout, listener.accept()).await;
    let (stream, _) = match accept_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Error::oidc(format!("accept callback: {e}"))),
        Err(_) => return Err(Error::oidc("timed out waiting for login callback")),
    };

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let mut stream = stream;
    let mut buf = Vec::with_capacity(1024);
    // Read the request headers (the callback is a small GET).
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;

    let request_str = String::from_utf8_lossy(&buf);
    // The first line looks like: GET /callback?code=...&state=... HTTP/1.1
    let request_line = request_str
        .lines()
        .next()
        .ok_or_else(|| Error::oidc("empty callback request"))?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::oidc("malformed callback request line"))?;

    // Parse the query string.
    let query = path.split('?').nth(1).unwrap_or("");
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();

    // Check for an error response from the IdP.
    if let Some(err) = params.get("error") {
        let desc = params.get("error_description").copied().unwrap_or("");
        return Err(Error::oidc(format!("IdP returned error: {err} {desc}")));
    }

    let code = params
        .get("code")
        .ok_or_else(|| Error::oidc("callback missing 'code' parameter"))?;
    let state = params
        .get("state")
        .ok_or_else(|| Error::oidc("callback missing 'state' parameter"))?;

    // Write a minimal HTML response.
    let body = "<!DOCTYPE html><html><body><h1>Login complete</h1>\
                 <p>You can close this window and return to your terminal.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    Ok((
        AuthorizationCode::new((*code).to_string()),
        CsrfToken::new((*state).to_string()),
    ))
}

/// Attempts to open the given URL in the user's default browser.
///
/// Tries `open` (macOS), `xdg-open` (Linux), and `start` (Windows). Logs a
/// warning on failure; the caller has already printed the URL as a fallback.
fn open_browser(url: &str) {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    let (cmd, args) = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (cmd, args) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args) = ("cmd", vec!["/C", "start", "", url]);

    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    {
        let _ = url;
        tracing::warn!("unsupported platform for browser launch; open the URL manually");
        return;
    }

    match Command::new(cmd).args(&args).spawn() {
        Ok(_) => tracing::info!("opened browser for OIDC login"),
        Err(e) => tracing::warn!(error = %e, "failed to open browser; open the URL manually"),
    }
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
            dev_mode: false,
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
    async fn run_login_no_longer_returns_placeholder() {
        // run_login is now implemented. Against a fake issuer (and without
        // the client secret env var set), it must fail with a real error —
        // NOT the old "not yet implemented" placeholder. We don't set the
        // secret env var (set_var is unsafe in edition 2024 and the crate
        // forbids unsafe), so it fails at the secret check; that's still a
        // valid non-placeholder error.
        let store = setup_test_db().await;
        let config = test_config();
        let err = run_login(&config, &store).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("not yet implemented"),
            "run_login must no longer return the placeholder error: {msg}"
        );
        // It should fail at either the secret check or discovery.
        assert!(
            msg.contains("client secret") || msg.contains("discovery") || msg.contains("issuer"),
            "expected a secret/discovery/issuer error, got: {msg}"
        );
    }

    #[test]
    fn is_allowed_alg_accepts_rs256_and_es256() {
        assert!(is_allowed_alg(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
        ));
        assert!(is_allowed_alg(&CoreJwsSigningAlgorithm::EcdsaP256Sha256));
    }

    #[test]
    fn is_allowed_alg_rejects_none_and_hmac() {
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::None));
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::HmacSha256));
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::HmacSha512));
        // Other RSA/ECDSA variants are also rejected (only RS256/ES256 allowed).
        assert!(!is_allowed_alg(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384
        ));
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::EcdsaP384Sha384));
    }

    #[tokio::test]
    async fn complete_login_persists_groups() {
        let store = setup_test_db().await;
        let config = test_config();
        let groups_json = r#"["engineering","ai-users"]"#;
        let _ = complete_login(
            &store,
            &config,
            "https://idp.example.com",
            "user-groups",
            Some("user@example.com"),
            None,
            Some(groups_json),
        )
        .await
        .expect("login");

        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0].groups.as_deref(),
            Some(groups_json),
            "groups must be persisted in the identities table"
        );
    }

    #[test]
    fn claims_from_id_token_extracts_groups_and_roles() {
        // Build a CustomIdTokenClaims from a JSON string containing groups + roles.
        let json = r#"{
            "iss": "https://idp.example.com",
            "sub": "user-grp",
            "aud": "test",
            "exp": 9999999999,
            "iat": 1000000000,
            "groups": ["engineering", "ai-users"],
            "roles": ["admin", "ai-users"]
        }"#;
        let claims: CustomIdTokenClaims = serde_json::from_str(json).expect("parse claims");
        let (subject, _email, _display, groups) = claims_from_id_token(&claims);
        assert_eq!(subject, "user-grp");
        let groups = groups.expect("groups must be extracted");
        let parsed: Vec<String> = serde_json::from_str(&groups).expect("parse groups json");
        // Union of groups + roles, deduplicated and sorted.
        assert_eq!(parsed, vec!["admin", "ai-users", "engineering"]);
    }

    #[test]
    fn claims_from_id_token_no_groups_returns_none() {
        let json = r#"{
            "iss": "https://idp.example.com",
            "sub": "user-nogrp",
            "aud": "test",
            "exp": 9999999999,
            "iat": 1000000000
        }"#;
        let claims: CustomIdTokenClaims = serde_json::from_str(json).expect("parse claims");
        let (_subject, _email, _display, groups) = claims_from_id_token(&claims);
        assert!(groups.is_none(), "groups must be None when no claims present");
    }

    #[tokio::test]
    async fn wait_for_callback_parses_code_and_state() {
        // Bind a listener, then connect and send a crafted callback request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn a client that sends the callback.
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?code=abc123&state=xyz789 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            // Read the response (discard).
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let (code, state) = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .expect("callback");
        assert_eq!(code.secret(), "abc123");
        assert_eq!(state.secret(), "xyz789");
    }

    #[tokio::test]
    async fn wait_for_callback_rejects_missing_code() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?state=xyz789 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing 'code'"), "{err}");
    }

    #[tokio::test]
    async fn wait_for_callback_surfaces_idp_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?error=access_denied&error_description=user+cancelled HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("access_denied"), "{err}");
    }
}
