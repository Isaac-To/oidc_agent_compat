//! End-to-end MCP relay tests.
//!
//! Verifies the full MCP flow:
//! agent → relay → central → upstream MCP server, with:
//! - Per-tool allow (200 + upstream passthrough) and per-tool deny (403).
//! - Central MCP audit rows recording mcp_server / mcp_tool / mcp_method.
//! - Relay activity rows with the same MCP metadata.
//! - Auth required on the relay (401 without key).
//! - The upstream MCP server only ever sees allowed tool calls.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::proxy as central_proxy;
use oac_relay::keystore::KeyStore;
use oac_relay::proxy as relay_proxy;
use zeroize::Zeroizing;

/// A lightweight in-process mock MCP server (Streamable HTTP + JSON-RPC).
fn mock_mcp_server() -> Router {
    let call_count = std::sync::Arc::new(AtomicU64::new(0));
    let count = call_count.clone();
    Router::new().route(
        "/mcp",
        axum::routing::any(move |body: axum::body::Body| {
            let count = count.clone();
            async move {
                let bytes = axum::body::to_bytes(body, 1 << 20)
                    .await
                    .unwrap_or_default();
                // Record which server hit us and echo a JSON-RPC response.
                if bytes.is_empty() {
                    return (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        r#"{"jsonrpc":"2.0","id":null,"result":{}}"#.to_string(),
                    );
                }
                count.fetch_add(1, Ordering::SeqCst);
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                let method = value.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
                match method {
                    "tools/call" => {
                        let name = value
                            .pointer("/params/name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let result = if name == "read_file" {
                            serde_json::json!({
                                "content": [{"type":"text","text":"file contents"}],
                                "isError": false,
                            })
                        } else {
                            serde_json::json!({
                                "content": [{"type":"text","text":"generic"}],
                                "isError": false,
                            })
                        };
                        (
                            axum::http::StatusCode::OK,
                            [("content-type", "application/json")],
                            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
                                .to_string(),
                        )
                    }
                    "tools/list" => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "tools": [ {"name":"read_file","description":"read"} ] }
                        })
                        .to_string(),
                    ),
                    _ => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
                    ),
                }
            }
        }),
    )
}

/// Full MCP e2e system: mock MCP server + central (with a registered MCP
/// server and a per-group tool policy) + relay authenticated as a user.
async fn setup_mcp_system() -> (
    SocketAddr,                    // relay addr
    reqwest::Client,               // client
    String,                        // local key
    String,                        // mcp server id
    AuditLogger,                   // central audit
    oac_relay::keystore::KeyStore, // relay keystore
) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // 1. Upstream mock MCP server at /mcp.
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mcp");
    let mcp_addr = mcp_listener.local_addr().expect("mcp addr");
    tokio::spawn(async move {
        let _ = axum::serve(mcp_listener, mock_mcp_server()).await;
    });
    let mcp_base = format!("http://{mcp_addr}/mcp");

    // 2. Central proxy.
    let central_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-mcp-central-{}-{counter}-{}.db",
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
        mtls: oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: "/ca.pem".into(),
            server_cert_path: "/server.pem".into(),
            server_key_path: "/server.key".into(),
        },
        admin: None,
        pricing: None,
        dev_mode: true,
        rate_limit_requests: 60,
        rate_limit_window_secs: 60,
    };

    let provider_store =
        oac_central::provider::ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    let mcp_manager =
        oac_central::mcp::McpManager::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));

    // Register an MCP server "fs" pointing at the mock server, with an auth
    // header (encrypted at rest) so we can assert it is forwarded.
    mcp_manager
        .upsert_server(&oac_central::mcp::McpServerInput {
            id: "fs".into(),
            name: "Fake FS".into(),
            base_url: mcp_base.clone(),
            enabled: true,
            auth_header: Some("Authorization: Bearer e2e-secret".into()),
        })
        .await
        .expect("register mcp server");

    // Register a per-group policy allowing only read_file on server fs.
    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
        .await
        .expect("mcp policy");

    let central_client = central_proxy::forward::build_client().expect("central client");
    let central_state = central_proxy::AppState {
        config: central_config.clone(),
        provider_store,
        client: central_client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store,
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager,
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
        "oac-e2e-mcp-relay-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let relay_url = format!("sqlite://{}?mode=rwc", relay_tmp.display());
    let relay_db = oac_relay::db::setup(&relay_url).await.expect("relay db");
    let key_store = KeyStore::new(relay_db);

    // Identity with the "eng" group so central resolves the MCP policy.
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "mcp-user",
            Some("mcp@example.com"),
            None,
            Some(r#"["eng"]"#),
        )
        .await
        .expect("identity");
    let minted = key_store
        .mint_key(&ident.id, "mcp-e2e", None)
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
        dev_mode: true,
        session_ttl_hours: None,
    };

    let relay_client = relay_proxy::forward::build_client(&relay_config).expect("relay client");
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let relay_state = relay_proxy::AppState {
        key_store: key_store.clone(),
        config: relay_config.clone(),
        client: relay_client,
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
    };
    let relay_app = relay_proxy::router(relay_state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, relay_app).await;
    });

    (
        relay_addr,
        reqwest::Client::new(),
        local_key,
        "fs".to_string(),
        audit,
        key_store,
    )
}

/// Builds a `tools/call` JSON-RPC request body.
fn tools_call(name: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": name, "arguments": { "path": "/tmp/x" } },
    })
}

#[tokio::test]
async fn allowed_tool_is_forwarded_and_audited() {
    let (relay_addr, client, key, _server, audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json");
    let text = body
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(text, "file contents", "upstream passthrough");

    // Central audit recorded the MCP fields.
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("audit load");
    let mcp = entries
        .iter()
        .find(|e| e.mcp_server.as_deref() == Some("fs"))
        .expect("mcp audit row");
    assert_eq!(mcp.mcp_tool.as_deref(), Some("read_file"));
    assert_eq!(mcp.mcp_method.as_deref(), Some("tools/call"));
    assert_eq!(mcp.permission_decision.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn denied_tool_returns_403_and_is_denited_in_audit() {
    let (relay_addr, client, key, _server, audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    // delete_file is NOT allowed by the "eng" policy.
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("delete_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // Central audit recorded a denied MCP entry.
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("audit load");
    let denied = entries
        .iter()
        .find(|e| e.mcp_tool.as_deref() == Some("delete_file"))
        .expect("denied mcp audit row");
    assert_eq!(denied.mcp_server.as_deref(), Some("fs"));
    assert_eq!(denied.permission_decision.as_deref(), Some("denied"));
    assert!(denied.denial_reason.is_some());
}

#[tokio::test]
async fn relay_requires_auth_for_mcp() {
    let (relay_addr, client, _key, _server, _audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn relay_activity_records_mcp_metadata() {
    let (relay_addr, client, key, _server, _audit, key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    use sea_orm::EntityTrait;
    let entries = oac_relay::entity::relay_activity_log::Entity::find()
        .all(&key_store.db)
        .await
        .expect("relay activity load");
    let mcp = entries
        .iter()
        .find(|e| e.mcp_server.as_deref() == Some("fs"))
        .expect("relay mcp activity row");
    assert_eq!(mcp.mcp_tool.as_deref(), Some("read_file"));
    assert_eq!(mcp.mcp_method.as_deref(), Some("tools/call"));
    assert_eq!(mcp.central_status, Some(200));
}
