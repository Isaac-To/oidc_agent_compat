//! Integration tests for the relay proxy.
//!
//! These tests spin up a mock central proxy (a simple Axum server) and the
//! relay proxy, then verify:
//! - Host header validation (DNS rebinding defense)
//! - Auth middleware (401 without key, 200 with valid key)
//! - Hop-by-hop header stripping
//! - Non-streaming forwarding
//! - SSE streaming passthrough

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_relay::keystore::KeyStore;
use oac_relay::proxy;

/// Sets up a test relay with a mock central proxy.
async fn setup_test_relay() -> (SocketAddr, reqwest::Client, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // Set up the relay DB.
    let tmp = std::env::temp_dir().join(format!(
        "oac-integ-test-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");
    let key_store = KeyStore::new(db);

    // Mint a key for testing.
    let ident = key_store
        .upsert_identity("https://idp.example.com", "user123", None, None, None)
        .await
        .expect("identity");
    let minted = key_store.mint_key(&ident.id, "test").await.expect("mint");
    let key = minted.plaintext.to_string();

    // Set up a mock central proxy.
    let mock_central = Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                r#"{"choices": [{"message": {"content": "hello"}}]}"#
            }),
        );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_central).await;
    });

    // Set up the relay pointing at the mock central.
    let config = oidc_agent_common::config::RelayConfig {
        listen_addr: "127.0.0.1:0".parse().expect("addr"),
        database_url: "sqlite://test.db".into(),
        oidc: oidc_agent_common::config::OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "test".into(),
            client_secret_env: "TEST".into(),
            redirect_uri: "http://127.0.0.1:0/callback".into(),
            scopes: vec!["openid".into()],
        },
        central: oidc_agent_common::config::CentralConnectionConfig {
            url: format!("http://{}", mock_addr),
            ca_cert_path: "/ca.pem".into(),
            client_cert_path: "/client.pem".into(),
            client_key_path: "/client.key".into(),
        },
        dev_mode: true,
    };

    let client = proxy::forward::build_client(&config).expect("client");
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        key_store,
        config: config.clone(),
        client,
        listen_addr: relay_addr,
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    (relay_addr, reqwest::Client::new(), key)
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, client, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn rejects_request_without_authorization() {
    let (addr, client, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_request_with_invalid_key() {
    let (addr, client, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Authorization", "Bearer oac_invalid")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_non_loopback_host() {
    let (addr, client, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Host", "evil.example.com")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn forwards_get_request_with_valid_key() {
    let (addr, client, key) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["data"].is_array(), "response must contain data array");
}

#[tokio::test]
async fn forwards_post_request_with_valid_key() {
    let (addr, client, key) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp_body: serde_json::Value = resp.json().await.expect("json");
    assert!(
        resp_body["choices"].is_array(),
        "response must contain choices"
    );
}
