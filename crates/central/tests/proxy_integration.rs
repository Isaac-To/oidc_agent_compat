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
use oac_central::provider::{ProviderInput, ProviderStore};
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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: true,
    };

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
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

// ─── Streaming usage accounting tests ──────────────────────────────────────

#[tokio::test]
async fn streaming_response_records_token_usage_after_stream_completes() {
    use std::sync::{Arc, Mutex};

    // Capture the request bodies received by the mock backend so the test
    // can assert the include_usage injection reached the upstream.
    let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();

    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
        "data: [DONE]\n\n",
    );

    let mock_backend = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: String| {
            let captured = captured.clone();
            async move {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                    captured.lock().expect("lock").push(value);
                }
                ([("content-type", "text/event-stream")], sse_body)
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-stream-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");

    let usage_tracker = oac_central::usage::UsageTracker::new(audit.db().clone());
    let state = proxy::AppState {
        config: oidc_agent_common::config::CentralConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            database_url: "sqlite://test.db".into(),
            oidc: oidc_agent_common::config::OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "test".into(),
                client_secret_env: "TEST".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            mtls: oidc_agent_common::config::MtlsServerConfig {
                ca_cert_path: "/ca.pem".into(),
                server_cert_path: "/server.pem".into(),
                server_key_path: "/server.key".into(),
            },
            admin: None,
            pricing: None,
            dev_mode: true,
        },
        provider_store,
        client: proxy::forward::build_client().expect("client"),
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: usage_tracker.clone(),
        price_table: oac_central::pricing::PriceTable::empty(),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Send a streaming request with a relay identity header (dev mode still
    // attaches the identity when the header is present — required for the
    // usage counters to be incremented).
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "stream": true,
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-OAC-User-Subject", "stream-user-1")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "text/event-stream"
    );
    // Consume the entire stream (the deferred accounting task runs after
    // the stream completes).
    let resp_text = resp.text().await.expect("stream body");
    assert!(resp_text.contains("[DONE]"));
    assert!(resp_text.contains("\"total_tokens\":15"));

    // The upstream must have received the include_usage injection.
    {
        let bodies = received.lock().expect("lock");
        let upstream_body = bodies
            .first()
            .expect("mock backend must have received the request");
        assert_eq!(
            upstream_body["stream_options"]["include_usage"],
            serde_json::Value::Bool(true),
            "central must inject stream_options.include_usage for streaming requests"
        );
    }

    // The usage counters must reflect the streamed usage (deferred task).
    let mut usage = None;
    for _ in 0..50 {
        usage = usage_tracker
            .get_usage("stream-user-1")
            .await
            .expect("usage");
        if usage.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let usage = usage.expect("usage must be recorded after the stream completes");
    assert_eq!(usage.request_count, 1);
    assert_eq!(
        usage.token_count, 15,
        "streamed token usage must be recorded"
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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: false,
    };

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: ca_path.clone(),
            server_cert_path: server_cert_path.clone(),
            server_key_path: server_key_path.clone(),
        },
        admin: None,
        pricing: None,
        dev_mode: false,
    };

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-mtls-test-master-key", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("central client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
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

// ─── Provider routing & key selection integration tests ───────────────────

use std::sync::Arc;
use tokio::sync::Mutex;

/// A recording mock backend: captures Authorization headers and returns a
/// marker in the body. If `accept_key` is set, requests whose Authorization
/// header doesn't match get a 401 (to exercise key fallback).
async fn spawn_recording_backend(
    marker: &'static str,
    accept_key: Option<&'static str>,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen.clone();
    let accept = accept_key.map(String::from);

    let app = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(
            move |headers: axum::http::HeaderMap,
                  _body: axum::body::Bytes| {
                let seen = seen_clone.clone();
                let accept = accept.clone();
                let marker = marker;
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    seen.lock().await.push(auth.clone());
                    if let Some(good) = &accept {
                        if &auth != good {
                            return (
                                axum::http::StatusCode::UNAUTHORIZED,
                                [("content-type", "application/json")],
                                r#"{"error": {"message": "bad key"}}"#.to_string(),
                            );
                        }
                    }
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        format!(
                            r#"{{"choices": [{{"message": {{"content": "{marker}"}}}}], "usage": {{"total_tokens": 1}}}}"#
                        ),
                    )
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording backend");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, seen)
}

/// A configured provider for the multi-provider test helper.
struct TestProvider {
    id: &'static str,
    models: Option<Vec<&'static str>>,
    is_default: bool,
    keys: Vec<(&'static str, i32, Vec<&'static str>)>, // (secret, priority, groups)
}

/// Spins up central (dev mode) with recording backends per provider and
/// returns the central address plus the captured-auth handles per provider.
async fn setup_multi_provider_central(
    providers: Vec<TestProvider>,
) -> (SocketAddr, Vec<Arc<Mutex<Vec<String>>>>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut seen_handles = Vec::new();
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-routing-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    for provider in providers {
        // Each provider gets its own backend so routing is observable by
        // which marker comes back.
        let (backend_addr, seen) =
            spawn_recording_backend(Box::leak(provider.id.to_string().into_boxed_str()), None)
                .await;
        seen_handles.push(seen);
        provider_store
            .upsert_provider(&ProviderInput {
                id: provider.id.into(),
                name: provider.id.into(),
                base_url: format!("http://{backend_addr}"),
                enabled: true,
                is_default: provider.is_default,
                models: provider
                    .models
                    .map(|models| models.into_iter().map(String::from).collect()),
            })
            .await
            .expect("provider");
        for (secret, priority, groups) in provider.keys {
            let groups: Vec<String> = groups.into_iter().map(String::from).collect();
            provider_store
                .add_key(provider.id, "test-key", secret, priority, &groups)
                .await
                .expect("provider key");
        }
    }

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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: true,
    };
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, seen_handles)
}

/// POSTs a chat completion and returns (status, body).
async fn post_completion(
    client: &reqwest::Client,
    addr: &SocketAddr,
    model: &str,
    groups: &[&str],
) -> (reqwest::StatusCode, String) {
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let groups_json = serde_json::json!(groups).to_string();
    let req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-OAC-User-Subject", "routing-test-user")
        .header("X-OAC-User-Groups", groups_json)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hi"}],
        }));
    let resp = req.send().await.expect("request");
    let status = resp.status();
    (status, resp.text().await.expect("body"))
}

#[tokio::test]
async fn routes_request_to_provider_matching_model() {
    let (addr, _seen) = setup_multi_provider_central(vec![
        TestProvider {
            id: "provider-alpha",
            models: Some(vec!["model-a"]),
            is_default: false,
            keys: vec![("sk-alpha", 0, vec![])],
        },
        TestProvider {
            id: "provider-beta",
            models: Some(vec!["model-b"]),
            is_default: false,
            keys: vec![("sk-beta", 0, vec![])],
        },
    ])
    .await;

    let client = reqwest::Client::new();
    let (status, body) = post_completion(&client, &addr, "model-b", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("provider-beta"),
        "model-b must be served by provider-beta, got: {body}"
    );
    assert!(
        !body.contains("provider-alpha"),
        "model-b must not hit provider-alpha, got: {body}"
    );
}

#[tokio::test]
async fn unknown_model_falls_back_to_default_provider() {
    let (addr, _seen) = setup_multi_provider_central(vec![
        TestProvider {
            id: "provider-alpha",
            models: Some(vec!["model-a"]),
            is_default: false,
            keys: vec![("sk-alpha", 0, vec![])],
        },
        TestProvider {
            id: "provider-default",
            models: None,
            is_default: true,
            keys: vec![("sk-default", 0, vec![])],
        },
    ])
    .await;

    let client = reqwest::Client::new();
    let (status, body) = post_completion(&client, &addr, "totally-unknown", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("provider-default"),
        "unknown model must fall back to the default provider, got: {body}"
    );
}

#[tokio::test]
async fn group_restricted_key_serves_only_matching_groups() {
    let (addr, seen) = setup_multi_provider_central(vec![TestProvider {
        id: "restricted",
        models: None,
        is_default: true,
        keys: vec![("sk-eng-only", 0, vec!["engineering"])],
    }])
    .await;

    let client = reqwest::Client::new();

    // Matching group → key is used.
    let (status, body) = post_completion(&client, &addr, "any-model", &["engineering"]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert_eq!(
        seen[0].lock().await.len(),
        1,
        "authorized group must reach the backend exactly once"
    );

    // Non-matching group → no authorized key → upstream failure surfaced.
    let (status, body) = post_completion(&client, &addr, "any-model", &["sales"]).await;
    assert_ne!(status, reqwest::StatusCode::OK);
    assert!(
        !body.contains("sk-eng-only"),
        "key material must never appear in error responses: {body}"
    );
    assert_eq!(
        seen[0].lock().await.len(),
        1,
        "unauthorized group must not reach the backend"
    );
}

#[tokio::test]
async fn missing_identity_groups_cannot_use_restricted_keys() {
    // No X-OAC-User-Groups header at all in dev mode → empty group set →
    // restricted keys are unavailable.
    let (addr, seen) = setup_multi_provider_central(vec![TestProvider {
        id: "restricted",
        models: None,
        is_default: true,
        keys: vec![("sk-eng-only", 0, vec!["engineering"])],
    }])
    .await;

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-OAC-User-Subject", "groupless-user")
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_ne!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        seen[0].lock().await.len(),
        0,
        "no groups + restricted key must not reach the backend"
    );
}

#[tokio::test]
async fn key_falls_back_on_upstream_401() {
    // One provider whose backend rejects the primary key and accepts the
    // secondary. Central must retry with the next authorized key.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let (backend_addr, seen) = spawn_recording_backend("fallback-ok", Some("sk-good")).await;
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-fallback-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "fallback".into(),
            name: "fallback".into(),
            base_url: format!("http://{backend_addr}"),
            enabled: true,
            is_default: true,
            models: None,
        })
        .await
        .expect("provider");
    provider_store
        .add_key("fallback", "bad", "sk-bad", 0, &[])
        .await
        .expect("bad key");
    provider_store
        .add_key("fallback", "good", "sk-good", 1, &[])
        .await
        .expect("good key");

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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: true,
    };
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-OAC-User-Subject", "fallback-user")
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("fallback-ok"), "body: {body}");

    // Both keys were tried, in priority order.
    let seen = seen.lock().await;
    assert_eq!(&*seen, &["sk-bad".to_string(), "sk-good".to_string()]);
}

#[tokio::test]
async fn no_provider_configured_returns_error_without_key_leak() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-noprovider-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));

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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: true,
    };
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "no provider configured must fail closed"
    );
    let body = resp.text().await.expect("body");
    assert!(
        !body.contains("sk-"),
        "error responses must not leak key material: {body}"
    );
}
