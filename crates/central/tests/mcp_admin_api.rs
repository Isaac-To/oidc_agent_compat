//! Integration tests for the MCP admin API endpoints.
//!
//! These tests drive the admin router directly (via `tower::ServiceExt::
//! oneshot`) and verify:
//! - `POST /admin/v1/mcp/servers` creates a server from a body-carried id.
//! - `POST` without a body id is rejected with 400 (not a 500 from a path
//!   extractor mismatch).
//! - `PUT /admin/v1/mcp/servers/{id}` upserts and the path `{id}` wins over
//!   any body id.
//! - Get/list/delete round trip, and the auth header is never returned.
//! - Admin auth: 401 without a bearer token, 403 without the admin group.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use axum::http::{Request, StatusCode};
use oac_central::admin::{self, AdminState};
use oac_central::audit::AuditLogger;
use oac_central::device_store::DeviceStore;
use oac_central::policy::PolicyStore;
use oac_central::provider::ProviderStore;
use oac_central::usage::UsageTracker;
use tower::util::ServiceExt;
use zeroize::Zeroizing;

/// Sets up the admin router and returns it together with an admin bearer
/// token and a non-admin bearer token.
async fn setup_router() -> (axum::Router, String, String) {
    let url = oidc_agent_common::persistence::temp_sqlite_url("admin-mcp");
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let state = AdminState {
        policy_store: PolicyStore::new(db.clone()),
        provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
        device_store: DeviceStore::new(db.clone()),
        audit,
        usage_tracker: UsageTracker::new(db.clone()),
        mcp_manager: oac_central::mcp::McpManager::new(db.clone(), Zeroizing::new([7_u8; 32])),
        token_store: oac_central::token_store::TokenStore::new(db),
        admin_group: "oac-admins".into(),
    };
    let admin_token = mint_admin_token(&state).await;
    let non_admin_token = state
        .token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "regular-user".into(),
            issuer: "https://idp.example.com".into(),
            email: None,
            display_name: None,
            groups: Some(r#"["engineering"]"#.into()),
            identity_id: None,
            label: "non-admin".into(),
            expires_at: None,
        })
        .await
        .expect("mint non-admin token");
    let non_admin_token = non_admin_token.plaintext.to_string();
    (admin::router(state), admin_token, non_admin_token)
}

/// Mints an admin token via the token store and returns the plaintext.
async fn mint_admin_token(state: &AdminState) -> String {
    let minted = state
        .token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "admin-user".into(),
            issuer: "https://idp.example.com".into(),
            email: None,
            display_name: None,
            groups: Some(r#"["oac-admins"]"#.into()),
            identity_id: None,
            label: "test".into(),
            expires_at: None,
        })
        .await
        .expect("mint admin token");
    minted.plaintext.to_string()
}

/// Builds an admin-authenticated JSON request with a bearer token.
fn admin_request(
    method: &str,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> Request<axum::body::Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        builder
            .body(axum::body::Body::from(body.to_string()))
            .expect("request body")
    } else {
        builder.body(axum::body::Body::empty()).expect("empty body")
    }
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json body")
}

fn server_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": "Filesystem",
        "base_url": "http://mcp-upstream.example/mcp",
        "enabled": true,
    })
}

// --- Auth middleware ---

#[tokio::test]
async fn admin_requires_bearer_token() {
    let (router, _admin_token, _non_admin_token) = setup_router().await;
    let resp = router
        .oneshot(
            Request::get("/admin/v1/mcp/servers")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_rejects_non_admin_group() {
    let (router, _admin_token, non_admin_token) = setup_router().await;
    let resp = router
        .oneshot(
            Request::get("/admin/v1/mcp/servers")
                .header("authorization", format!("Bearer {non_admin_token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// --- MCP server CRUD ---

#[tokio::test]
async fn post_creates_mcp_server_with_body_id() {
    let (router, admin_token, _non_admin_token) = setup_router().await;
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/mcp/servers",
            &admin_token,
            Some(server_body("fs")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "POST must create, not 500");
    let body = body_json(resp).await;
    assert_eq!(body["id"], "fs");
    assert_eq!(body["name"], "Filesystem");
    assert_eq!(body["has_auth"], false);
}

#[tokio::test]
async fn post_without_body_id_is_rejected_400() {
    let (router, admin_token, _non_admin_token) = setup_router().await;
    // Omitting `id` deserializes to the empty string (serde default) and
    // must be rejected by the handler with 400, not a 500 from a path
    // extractor mismatch.
    let mut body = server_body("fs");
    body.as_object_mut().unwrap().remove("id");
    let resp = router
        .oneshot(admin_request(
            "POST",
            "/admin/v1/mcp/servers",
            &admin_token,
            Some(body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_takes_id_from_path_and_ignores_body_id() {
    let (router, admin_token, _non_admin_token) = setup_router().await;

    // Create via POST first.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/mcp/servers",
            &admin_token,
            Some(server_body("fs")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // PUT to /mcp/servers/gh with a mismatched body id: the path wins.
    let mut body = server_body("wrong-id");
    body["name"] = serde_json::json!("GitHub");
    let resp = router
        .clone()
        .oneshot(admin_request(
            "PUT",
            "/admin/v1/mcp/servers/gh",
            &admin_token,
            Some(body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["id"], "gh", "path id must win over body id");
    assert_eq!(body["name"], "GitHub");

    // The original "fs" server is untouched.
    let resp = router
        .oneshot(admin_request(
            "GET",
            "/admin/v1/mcp/servers/fs",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_server_crud_round_trip() {
    let (router, admin_token, _non_admin_token) = setup_router().await;

    // Create.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/mcp/servers",
            &admin_token,
            Some(server_body("fs")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List contains it.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "GET",
            "/admin/v1/mcp/servers",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Get by id.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "GET",
            "/admin/v1/mcp/servers/fs",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["id"], "fs");

    // Delete → {"deleted": true}, then get → 404.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "DELETE",
            "/admin/v1/mcp/servers/fs",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["deleted"], true);

    let resp = router
        .oneshot(admin_request(
            "GET",
            "/admin/v1/mcp/servers/fs",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_server_response_never_contains_auth_header() {
    let (router, admin_token, _non_admin_token) = setup_router().await;
    let mut body = server_body("fs");
    body["auth_header"] = serde_json::json!("Authorization: Bearer ***");
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/mcp/servers",
            &admin_token,
            Some(body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(
        body.get("auth_header").is_none(),
        "auth header must not be echoed"
    );
    assert_eq!(body["has_auth"], true);

    // Also not on GET.
    let resp = router
        .oneshot(admin_request(
            "GET",
            "/admin/v1/mcp/servers/fs",
            &admin_token,
            None,
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert!(body.get("auth_header").is_none());
    assert_eq!(body["has_auth"], true);
}
