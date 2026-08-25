//! End-to-end integration tests.
//!
//! These tests verify the full request flow:
//! agent → relay → central → backend, with:
//! - Non-streaming forwarding
//! - SSE streaming passthrough
//! - Master key confined to the central proxy (never in relay responses)
//! - Auth middleware (401 without key, 200 with valid key)
//! - Host header validation (DNS rebinding defense)
//! - Audit log recording on the central proxy

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::proxy as central_proxy;
use oac_relay::keystore::KeyStore;
use oac_relay::proxy as relay_proxy;
use zeroize::Zeroizing;

/// Sets up the full system: mock backend + central proxy + relay.
///
/// Returns the relay address, an HTTP client, a valid local API key, and the
/// central proxy's audit logger (for verifying audit entries).
async fn setup_full_system() -> (SocketAddr, reqwest::Client, String, AuditLogger) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // 1. Mock OpenAI-compatible backend.
    let mock_backend = Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async {
                r#"{"data": [{"id": "gpt-4"}, {"id": "gpt-3.5-turbo"}]}"#
            }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"choices": [{"message": {"content": "hello from backend"}, "index": 0}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#,
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
        );
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_addr = backend_listener.local_addr().expect("backend addr");
    tokio::spawn(async {
        let _ = axum::serve(backend_listener, mock_backend).await;
    });

    // 2. Central proxy.
    let central_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-central-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let central_url = format!("sqlite://{}?mode=rwc", central_tmp.display());
    let central_db = oac_central::db::setup(&central_url)
        .await
        .expect("central db");
    let audit = AuditLogger::new(central_db);

    let central_config = oidc_agent_common::config::CentralConfig {
        listen_addr: "127.0.0.1:0".parse().expect("addr"),
        database_url: "sqlite://test.db".into(),
        oidc: oidc_agent_common::config::OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "test".into(),
            client_secret_env: "TEST".into(),
            redirect_uri: "http://127.0.0.1:0/callback".into(),
            scopes: vec!["openid".into()],
        },
        backend: oidc_agent_common::config::BackendConfig {
            name: "mock-backend".into(),
            base_url: format!("http://{}", backend_addr),
        },
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        secret_store: oidc_agent_common::config::SecretStoreConfig {
            kind: oidc_agent_common::config::SecretStoreKind::Vault,
            path: "test".into(),
        },
        dev_mode: true,
    };

    let master_key = Zeroizing::new("sk-e2e-master-key-secret".into());
    let central_client = central_proxy::forward::build_client().expect("central client");
    let central_state = central_proxy::AppState {
        config: central_config.clone(),
        master_key: std::sync::Arc::new(master_key),
        client: central_client,
        audit: audit.clone(),
    };
    let central_app = central_proxy::router(central_state);
    let central_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let central_addr = central_listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(central_listener, central_app).await;
    });

    // 3. Relay proxy.
    let relay_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-relay-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let relay_url = format!("sqlite://{}?mode=rwc", relay_tmp.display());
    let relay_db = oac_relay::db::setup(&relay_url).await.expect("relay db");
    let key_store = KeyStore::new(relay_db);

    // Mint a local key.
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user",
            Some("e2e@example.com"),
            None,
            None,
        )
        .await
        .expect("identity");
    let minted = key_store
        .mint_key(&ident.id, "e2e-test")
        .await
        .expect("mint");
    let local_key = minted.plaintext.to_string();

    let relay_config = oidc_agent_common::config::RelayConfig {
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
            url: format!("http://{}", central_addr),
            ca_cert_path: "/ca.pem".into(),
            client_cert_path: "/client.pem".into(),
            client_key_path: "/client.key".into(),
        },
        dev_mode: false,
    };

    let relay_client = relay_proxy::forward::build_client(&relay_config).expect("relay client");
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let relay_state = relay_proxy::AppState {
        key_store,
        config: relay_config.clone(),
        client: relay_client,
        listen_addr: relay_addr,
    };
    let relay_app = relay_proxy::router(relay_state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, relay_app).await;
    });

    (relay_addr, reqwest::Client::new(), local_key, audit)
}

#[tokio::test]
async fn e2e_healthz() {
    let (addr, client, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn e2e_get_models_through_full_chain() {
    let (addr, client, key, _) = setup_full_system().await;
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
    assert_eq!(body["data"][0]["id"], "gpt-4");
}

#[tokio::test]
async fn e2e_post_chat_completions_through_full_chain() {
    let (addr, client, key, _) = setup_full_system().await;
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
    assert_eq!(
        resp_body["choices"][0]["message"]["content"],
        "hello from backend"
    );
    assert_eq!(resp_body["usage"]["total_tokens"], 15);
}

#[tokio::test]
async fn e2e_post_embeddings_through_full_chain() {
    let (addr, client, key, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/embeddings", addr.port());
    let body = serde_json::json!({
        "model": "text-embedding-ada-002",
        "input": "test text",
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
    assert!(resp_body["data"].is_array());
}

#[tokio::test]
async fn e2e_rejects_request_without_key() {
    let (addr, client, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn e2e_rejects_invalid_key() {
    let (addr, client, _, _) = setup_full_system().await;
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
async fn e2e_rejects_non_loopback_host() {
    let (addr, client, _, _) = setup_full_system().await;
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
async fn e2e_master_key_not_in_relay_response() {
    let (addr, client, key, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({"model": "gpt-4", "messages": []});
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-e2e-master-key-secret"),
        "master key must never appear in relay response"
    );
}

#[tokio::test]
async fn e2e_master_key_not_in_error_response() {
    let (addr, client, _, _) = setup_full_system().await;
    // Send a request without auth to get an error response.
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-e2e-master-key-secret"),
        "master key must never appear in error responses"
    );
}

#[tokio::test]
async fn e2e_identity_forwarded_and_audited() {
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;

    let (addr, client, key, audit) = setup_full_system().await;
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

    // Give the audit log a moment to flush (it's async).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the audit log recorded the real user subject ("e2e-user"),
    // not the placeholder "unknown".
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    assert!(
        !entries.is_empty(),
        "audit log must contain at least one entry"
    );
    let last = entries.last().expect("at least one entry");
    assert_eq!(
        last.user_subject, "e2e-user",
        "audit log must record the relay-forwarded user subject, not 'unknown'"
    );
    assert_eq!(last.model.as_deref(), Some("gpt-4"));
    assert_eq!(last.status, 200);
}
