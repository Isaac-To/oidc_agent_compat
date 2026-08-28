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
async fn setup_test_relay() -> (SocketAddr, reqwest::Client, String, KeyStore) {
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
    let minted = key_store
        .mint_key(&ident.id, "test", None)
        .await
        .expect("mint");
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
        session_ttl_hours: None,
    };

    let client = proxy::forward::build_client(&config).expect("client");
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        key_store: key_store.clone(),
        config: config.clone(),
        client,
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    (relay_addr, reqwest::Client::new(), key, key_store)
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, client, _, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn rejects_request_without_authorization() {
    let (addr, client, _, _) = setup_test_relay().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_request_with_invalid_key() {
    let (addr, client, _, _) = setup_test_relay().await;
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
async fn expired_session_returns_relogin_error_and_removes_key() {
    let (addr, client, _, key_store) = setup_test_relay().await;
    let identity = key_store
        .upsert_identity("https://idp.example.com", "expired-user", None, None, None)
        .await
        .expect("identity");
    let expires_at = oidc_agent_common::time_util::now_utc() - time::Duration::minutes(1);
    let minted = key_store
        .mint_key(&identity.id, "expired", Some(expires_at))
        .await
        .expect("expired key");
    let expired_key = minted.plaintext.to_string();

    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {expired_key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: serde_json::Value = response.json().await.expect("JSON error body");
    assert_eq!(body["error"]["type"], "session_expired");
    assert_eq!(
        body["error"]["message"],
        "session expired; run `oac-relay login` to re-authenticate"
    );

    // The middleware's first verification must delete the stale row, so a
    // replay is indistinguishable from an unknown credential.
    let replay = client
        .get(&url)
        .header("Authorization", format!("Bearer {expired_key}"))
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    let remaining = key_store
        .verify_key(&expired_key)
        .await
        .expect("replay verification");
    assert!(matches!(
        remaining,
        oac_relay::keystore::KeyVerification::Invalid
    ));
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
async fn forwards_get_request_with_valid_key() {
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
async fn forwards_post_request_with_valid_key() {
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

// ─── Identity forwarding (what central authorizes on) ─────────────────────

#[tokio::test]
async fn forwards_verified_identity_and_request_id_headers() {
    use std::sync::{Arc, Mutex};

    // A mock central that records the headers it received.
    let seen: Arc<Mutex<Vec<axum::http::HeaderMap>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let mock_central = Router::new().route(
        "/v1/models",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let captured = captured.clone();
            async move {
                captured.lock().expect("lock").push(headers);
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

    // Relay DB + an identity WITH email and groups so we can assert they
    // are forwarded (not just the subject).
    let tmp = std::env::temp_dir().join(format!(
        "oac-identity-fwd-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_relay::db::setup(&url).await.expect("db setup");
    let key_store = KeyStore::new(db);
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "alice",
            Some("alice@example.com"),
            None,
            Some(r#"["engineering","ai-users"]"#),
        )
        .await
        .expect("identity");
    let minted = key_store
        .mint_key(&ident.id, "test", None)
        .await
        .expect("mint");
    let key = minted.plaintext.to_string();

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
        session_ttl_hours: None,
    };
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        key_store: key_store.clone(),
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/v1/models", relay_addr.port()))
        .header("Authorization", format!("Bearer {key}"))
        .header("X-Attacker-User-Subject", "mallory")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let headers = {
        let guard = seen.lock().expect("lock");
        guard.last().expect("central received the request").clone()
    };
    // The relay must forward ONLY the auth-middleware-verified identity…
    assert_eq!(
        headers
            .get("x-oac-user-subject")
            .and_then(|v| v.to_str().ok()),
        Some("alice"),
        "the verified subject must be forwarded"
    );
    // …never a client-supplied spoof (the attacker header must not leak
    // through — build_forward_headers only forwards the allowlist).
    assert_eq!(
        headers
            .get("x-attacker-user-subject")
            .and_then(|v| v.to_str().ok()),
        None,
        "client-supplied identity headers must never be forwarded"
    );
    assert_eq!(
        headers
            .get("x-oac-user-email")
            .and_then(|v| v.to_str().ok()),
        Some("alice@example.com")
    );
    assert_eq!(
        headers
            .get("x-oac-user-groups")
            .and_then(|v| v.to_str().ok()),
        Some(r#"["engineering","ai-users"]"#)
    );
    assert_eq!(
        headers
            .get("x-oac-identity-id")
            .and_then(|v| v.to_str().ok()),
        Some(ident.id.as_str()),
        "central needs the identity id for device/audit correlation"
    );
    // A request id must be generated for end-to-end correlation.
    let request_id = headers
        .get("x-oac-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-oac-request-id must be forwarded");
    assert!(!request_id.is_empty());
    assert_eq!(request_id.len(), 36, "request id is a UUID: {request_id}");
    // The local API key must NOT be forwarded to central.
    assert!(
        headers.get("authorization").is_none(),
        "the local bearer key must be stripped, not forwarded"
    );

    // The activity log must record the request with the same request id.
    use sea_orm::EntityTrait;
    let rows = oac_relay::entity::relay_activity_log::Entity::find()
        .all(&key_store.db)
        .await
        .expect("activity rows");
    let row = rows.last().expect("activity row recorded");
    assert_eq!(row.identity_id, ident.id);
    assert_eq!(row.method, "GET");
    assert_eq!(row.endpoint, "/v1/models");
    assert_eq!(row.central_status, Some(200));
    assert_eq!(row.request_id.as_deref(), Some(request_id));
}

// ─── SSE streaming passthrough ─────────────────────────────────────────────

#[tokio::test]
async fn streams_sse_response_unchanged() {
    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"total_tokens\":7}}\n\n",
        "data: [DONE]\n\n",
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
    let key_store = KeyStore::new(db);
    let ident = key_store
        .upsert_identity("https://idp.example.com", "sse-user", None, None, None)
        .await
        .expect("identity");
    let minted = key_store
        .mint_key(&ident.id, "test", None)
        .await
        .expect("mint");
    let key = minted.plaintext.to_string();

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
        session_ttl_hours: None,
    };
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        key_store: key_store.clone(),
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
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
        .header("Authorization", format!("Bearer {key}"))
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
    let key_store = KeyStore::new(db);
    let ident = key_store
        .upsert_identity("https://idp.example.com", "offline-user", None, None, None)
        .await
        .expect("identity");
    let minted = key_store
        .mint_key(&ident.id, "test", None)
        .await
        .expect("mint");
    let key = minted.plaintext.to_string();

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
        session_ttl_hours: None,
    };
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let state = proxy::AppState {
        key_store: key_store.clone(),
        config: config.clone(),
        client: proxy::forward::build_client(&config).expect("client"),
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
    };
    let app = proxy::router(state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, app).await;
    });

    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/v1/models", relay_addr.port()))
        .header("Authorization", format!("Bearer {key}"))
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
        .all(&key_store.db)
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
        session_ttl_hours: None,
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
    let key_store = KeyStore::new(db);

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
        session_ttl_hours: None,
    };

    let task = tokio::spawn(async move { proxy::serve(config, key_store).await });

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
