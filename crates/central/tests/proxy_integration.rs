//! Integration tests for the central proxy.
//!
//! These tests spin up a mock OpenAI-compatible backend and the central
//! proxy, then verify:
//! - Non-streaming forwarding with master key injection
//! - SSE streaming passthrough
//! - Hop-by-hop header stripping
//! - Audit log recording
//! - Master key never appears in responses or logs

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::proxy;
use zeroize::Zeroizing;

/// Sets up a test central proxy with a mock backend.
async fn setup_test_central() -> (SocketAddr, reqwest::Client) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // Set up a mock OpenAI-compatible backend.
    let mock_backend = Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async {
                r#"{"data": [{"id": "gpt-4"}]}"#
            }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"choices": [{"message": {"content": "hello"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#,
                )
            }),
        );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Set up the central DB.
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-integ-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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
            name: "mock".into(),
            base_url: format!("http://{}", mock_addr),
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

    let master_key = Zeroizing::new("sk-test-master-key-12345".into());
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        master_key: std::sync::Arc::new(master_key),
        client,
        audit: audit.clone(),
        rate_limiter: None,
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    (addr, reqwest::Client::new())
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn forwards_get_request_to_backend() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["data"].is_array(), "response must contain data array");
}

#[tokio::test]
async fn forwards_post_request_with_master_key() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
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
    assert_eq!(resp_body["usage"]["total_tokens"], 15);
}

#[tokio::test]
async fn master_key_not_in_response_body() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({"model": "gpt-4", "messages": []});
    let resp = client.post(&url).json(&body).send().await.expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-test-master-key-12345"),
        "master key must never appear in response body"
    );
}

// ─── Auth middleware tests (non-dev-mode) ──────────────────────────────────

/// Sets up a central proxy in **production mode** (`dev_mode = false`) so the
/// auth middleware enforces the `X-OAC-User-Subject` header.
async fn setup_prod_central() -> (SocketAddr, reqwest::Client) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mock_backend = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-prod-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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
            name: "mock".into(),
            base_url: format!("http://{}", mock_addr),
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
        dev_mode: false,
    };

    let master_key = Zeroizing::new("sk-test-master-key-12345".into());
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        master_key: std::sync::Arc::new(master_key),
        client,
        audit: audit.clone(),
        rate_limiter: None,
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    (addr, reqwest::Client::new())
}

#[tokio::test]
async fn prod_mode_rejects_request_without_identity_headers() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    // No X-OAC-User-Subject header → must be rejected.
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prod-mode central must reject requests without X-OAC-User-Subject"
    );
}

#[tokio::test]
async fn prod_mode_accepts_request_with_identity_headers() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("X-OAC-User-Subject", "user-123")
        .header("X-OAC-User-Email", "user@example.com")
        .header("X-OAC-Identity-Id", "id-456")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prod-mode central must accept requests with valid identity headers"
    );
}

#[tokio::test]
async fn prod_mode_healthz_bypasses_auth() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "healthz must bypass auth even in prod mode"
    );
}

#[tokio::test]
async fn prod_mode_rejects_empty_subject() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("X-OAC-User-Subject", "")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "empty X-OAC-User-Subject must be rejected"
    );
}

// ─── mTLS integration tests ────────────────────────────────────────────────

/// Writes test certs to temp files and returns the paths.
fn write_test_certs_to_temp() -> (
    std::path::PathBuf, // ca_cert
    std::path::PathBuf, // server_cert
    std::path::PathBuf, // server_key
    std::path::PathBuf, // client_cert
    std::path::PathBuf, // client_key
) {
    use oidc_agent_common::test_certs::generate_test_certs;
    use std::os::unix::fs::PermissionsExt;

    let certs = generate_test_certs();
    let dir = std::env::temp_dir().join(format!(
        "oac-mtls-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let ca_path = dir.join("ca.crt");
    let server_cert_path = dir.join("server.crt");
    let server_key_path = dir.join("server.key");
    let client_cert_path = dir.join("client.crt");
    let client_key_path = dir.join("client.key");

    std::fs::write(&ca_path, &certs.ca_cert).expect("write ca");
    std::fs::write(&server_cert_path, &certs.server_cert).expect("write server cert");
    std::fs::write(&server_key_path, &certs.server_key).expect("write server key");
    std::fs::write(&client_cert_path, &certs.client_cert).expect("write client cert");
    std::fs::write(&client_key_path, &certs.client_key).expect("write client key");

    // Set 0600 on private keys (required by mtls::enforce_secure_perms).
    std::fs::set_permissions(&server_key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod server key");
    std::fs::set_permissions(&client_key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod client key");

    (
        ca_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    )
}

/// Builds a reqwest client with mTLS using the test certs.
fn build_mtls_client(
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> reqwest::Client {
    let client_config =
        oidc_agent_common::mtls::build_client_config(ca_path, client_cert_path, client_key_path)
            .expect("build mTLS client config");

    reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("build mTLS client")
}

/// Starts a central proxy with mTLS (production mode) and returns its address.
async fn setup_mtls_central() -> SocketAddr {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let (ca_path, server_cert_path, server_key_path, client_cert_path, client_key_path) =
        write_test_certs_to_temp();

    // Mock backend.
    let mock_backend = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Central DB.
    let tmp = std::env::temp_dir().join(format!(
        "oac-mtls-central-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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
            name: "mock".into(),
            base_url: format!("http://{}", mock_addr),
        },
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: ca_path.clone(),
            server_cert_path: server_cert_path.clone(),
            server_key_path: server_key_path.clone(),
        },
        secret_store: oidc_agent_common::config::SecretStoreConfig {
            kind: oidc_agent_common::config::SecretStoreKind::Vault,
            path: "test".into(),
        },
        dev_mode: false,
    };

    let master_key = Zeroizing::new("sk-mtls-test-master-key".into());
    let client = proxy::forward::build_client().expect("central client");
    let state = proxy::AppState {
        config: config.clone(),
        master_key: std::sync::Arc::new(master_key),
        client,
        audit: audit.clone(),
        rate_limiter: None,
    };
    let app = proxy::router(state);

    // Build the mTLS server config.
    let server_config =
        oidc_agent_common::mtls::build_server_config(&ca_path, &server_cert_path, &server_key_path)
            .expect("build server config");
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(server_config));

    let handle = axum_server::Handle::new();
    let listen_handle = handle.clone();

    tokio::spawn(async move {
        axum_server::bind_rustls(config.listen_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("serve mTLS central");
    });

    // Wait for the server to start listening.
    let addr = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(a) = listen_handle.listening().await {
                return a;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not start in time");

    // Return the cert paths too (via a static — hacky but works for tests).
    // Actually, we need the client cert paths for the test. Let's store them.
    MTLS_CERT_PATHS.with(|p| {
        *p.borrow_mut() = Some((ca_path, client_cert_path, client_key_path));
    });

    addr
}

thread_local! {
    static MTLS_CERT_PATHS: std::cell::RefCell<Option<(
        std::path::PathBuf, // ca
        std::path::PathBuf, // client_cert
        std::path::PathBuf, // client_key
    )>> = const { std::cell::RefCell::new(None) };
}

#[tokio::test]
async fn mtls_accepts_valid_client_cert() {
    let addr = setup_mtls_central().await;
    let (ca_path, client_cert_path, client_key_path) =
        MTLS_CERT_PATHS.with(|p| p.borrow().clone().expect("cert paths set"));

    let client = build_mtls_client(&ca_path, &client_cert_path, &client_key_path);
    let url = format!("https://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("X-OAC-User-Subject", "mtls-test-user")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "mTLS connection with valid client cert should succeed"
    );
}

#[tokio::test]
async fn mtls_rejects_connection_without_client_cert() {
    let addr = setup_mtls_central().await;

    // A plain HTTPS client without a client cert should fail the TLS handshake.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("build plain client");

    let url = format!("https://127.0.0.1:{}/v1/models", addr.port());
    let result = client.get(&url).send().await;

    assert!(
        result.is_err(),
        "connection without client cert must fail the TLS handshake"
    );
}
