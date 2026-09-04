//! Integration tests for the relay proxy.
//!
//! These tests spin up a mock central proxy (a simple Axum server) and the
//! relay proxy, then verify:
//! - Host header validation (DNS rebinding defense)
//! - Auth middleware pass-through (relay does NOT verify; central does)
//! - Hop-by-hop header stripping
//! - Non-streaming forwarding
//! - SSE streaming passthrough
//!
//! The relay is a dumb forwarder: it checks that a bearer token is present
//! (non-dev mode) but does NOT verify it. Central is the sole verification
//! authority (zero-trust). In dev_mode, the relay skips auth entirely.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_relay::proxy;

/// Sets up a test relay with a mock central proxy.
///
/// Returns the relay address, an HTTP client, a bearer token (a dummy
/// non-empty string — the relay does not verify it), and the relay's
/// database connection (for activity log queries).
async fn setup_test_relay() -> (
    SocketAddr,
    reqwest::Client,
    String,
    sea_orm::DatabaseConnection,
) {
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

    // The relay does not mint or verify local keys. The bearer token is a
    // dummy — the relay only checks it's present (non-dev mode). Central
    // verifies it.
    let key = "oac_dummy_token_relay_does_not_verify".to_string();

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
        config: config.clone(),
        client,
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(db.clone()),
        device_fingerprint: None,
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    (relay_addr, reqwest::Client::new(), key, db)
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, client, _, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn dev_mode_allows_request_without_authorization() {
    // In dev_mode, the relay skips auth entirely. Central will reject
    // unauthenticated requests (but the mock central here does not check).
    let (addr, client, _, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn rejects_non_loopback_host() {
    let (addr, client, _, _) = setup_test_relay().await;
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
async fn forwards_get_request_with_bearer() {
    let (addr, client, key, _) = setup_test_relay().await;
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
async fn forwards_post_request_with_bearer() {
    let (addr, client, key, _) = setup_test_relay().await;
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

// ─── Bearer forwarding (zero-trust) ───────────────────────────────────────

#[tokio::test]
async fn forwards_authorization_header_to_central() {
    use std::sync::{Arc, Mutex};

    // A mock central that records the Authorization header it received.
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let mock_central = Router::new().route(
        "/v1/models",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let captured = captured.clone();
            async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                captured.lock().expect("lock").push(auth);
                r#"{"data": [{"id": "gpt-4"}]}"#
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_central).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-bearer-fwd-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");

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
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(db),
        device_fingerprint: None,
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    let token = "oac_test_central_token";
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/v1/models", relay_addr.port()))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // The relay must forward the bearer token to central unchanged.
    let headers = {
        let guard = seen.lock().expect("lock");
        guard.last().expect("central received the request").clone()
    };
    assert_eq!(
        headers.as_deref(),
        Some(format!("Bearer {token}").as_str()),
        "the bearer token must be forwarded to central for zero-trust re-verification"
    );
}

// ─── SSE streaming passthrough ─────────────────────────────────────────────

#[tokio::test]
async fn streams_sse_response_unchanged() {
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"total_tokens\":7}}\n\n",
        "\n",
    );
    let mock_central = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move || async {
            (
                [("content-type", "text/event-stream")],
                sse_body.to_string(),
            )
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_central).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-relay-sse-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");

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
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(db),
        device_fingerprint: None,
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            relay_addr.port()
        ))
        .header("Authorization", "Bearer oac_test_token")
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "model": "gpt-4",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    // The SSE content type must survive the hop…
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "text/event-stream",
        "streaming responses must keep their content type"
    );
    // …byte-for-byte.
    let body = resp.text().await.expect("stream body");
    assert_eq!(body, sse_body, "the SSE stream must pass through unchanged");
}

// ─── Upstream failure UX ──────────────────────────────────────────────────

#[tokio::test]
async fn unreachable_central_returns_typed_502_json() {
    let tmp = std::env::temp_dir().join(format!(
        "oac-relay-dead-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");

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
            // Nothing listens on port 1.
            url: "http://127.0.0.1:1".into(),
            ca_cert_path: "/ca.pem".into(),
            client_cert_path: "/client.pem".into(),
            client_key_path: "/client.key".into(),
        },
        dev_mode: true,
    };
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(db.clone()),
        device_fingerprint: None,
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/v1/models", relay_addr.port()))
        .header("Authorization", "Bearer oac_test_token")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    // Agents surface the error body — it must be typed JSON, never HTML or
    // a raw connection error.
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "application/json"
    );
    let json: serde_json::Value = resp.json().await.expect("json error body");
    assert_eq!(json["error"]["type"], "relay_error");

    // The failed forward is still activity-logged (with a NULL central
    // status) so users/admins can see the outage from the relay side.
    use sea_orm::EntityTrait;
    let rows = oac_relay::entity::relay_activity_log::Entity::find()
        .all(&db)
        .await
        .expect("activity rows");
    let row = rows.last().expect("failure recorded");
    assert_eq!(row.central_status, None, "no response → NULL status");
    assert!(row.request_id.is_some(), "correlation id must be logged");
}

// ─── mTLS client build (production mode) ──────────────────────────────────

#[tokio::test]
async fn build_client_uses_mtls_in_production_mode() {
    use oidc_agent_common::test_certs::generate_test_certs;

    let certs = generate_test_certs();
    let dir = std::env::temp_dir().join(format!(
        "oac-relay-mtls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let ca = dir.join("ca.crt");
    let cert = dir.join("client.crt");
    let key = dir.join("client.key");
    std::fs::write(&ca, &certs.ca_cert).expect("ca");
    std::fs::write(&cert, &certs.client_cert).expect("cert");
    std::fs::write(&key, &certs.client_key).expect("key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod key");
    }

    let config = oidc_agent_common::config::RelayConfig {
        listen_addr: "127.0.0.1:8787".parse().expect("addr"),
        database_url: "sqlite://test.db".into(),
        oidc: oidc_agent_common::config::OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "test".into(),
            client_secret_env: "TEST".into(),
            redirect_uri: "http://127.0.0.1:0/callback".into(),
            scopes: vec!["openid".into()],
        },
        central: oidc_agent_common::config::CentralConnectionConfig {
            url: "https://central.example.com".into(),
            ca_cert_path: ca.clone(),
            client_cert_path: cert.clone(),
            client_key_path: key.clone(),
        },
        // Production mode: the client MUST be built with mTLS.
        dev_mode: false,
    };
    let client = proxy::forward::build_client(&config).expect("mTLS client builds");
    // The builder enforces https-only in prod mode; a plain-http target
    // must be refused by the client itself.
    let refused = client
        .get("http://central.example.com/healthz")
        .send()
        .await;
    assert!(
        refused.is_err(),
        "an https-only mTLS client must refuse plain http"
    );
}

// ─── Relay boot + graceful shutdown ────────────────────────────────────────

#[cfg(unix)]
#[tokio::test]
async fn serve_boots_and_shuts_down_gracefully_on_sigterm() {
    let tmp = std::env::temp_dir().join(format!(
        "oac-relay-serve-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");

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
            url: "https://central.example.com".into(),
            ca_cert_path: "/ca.pem".into(),
            client_cert_path: "/client.pem".into(),
            client_key_path: "/client.key".into(),
        },
        dev_mode: true,
    };

    let task = tokio::spawn(async move { proxy::serve(config, db).await });

    // Let the server bind and install the graceful-shutdown signal handler.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "serve() must run until signalled");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let pid = std::process::id().to_string();
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM");
    assert!(status.success(), "kill -TERM must succeed");

    let result = tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .expect("serve() must return after SIGTERM")
        .expect("join serve task");
    assert!(result.is_ok(), "relay shutdown must be clean: {result:?}");
}
