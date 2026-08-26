//! Integration tests for the provider/key admin API endpoints.
//!
//! These tests drive the admin router directly (via `tower::ServiceExt::
//! oneshot`) and verify:
//! - Provider CRUD endpoints (create, get, list, update, delete, default).
//! - Provider-key endpoints (add, list, update, delete).
//! - Key plaintext is never present in any response (metadata only).
//! - Admin auth: 401 without identity headers, 403 without the admin group.

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

const TEST_KEY_PLAINTEXT: &str = "sk-admin-test-secret-12345";

async fn setup_router() -> (axum::Router, ProviderStore) {
    let url = oidc_agent_common::persistence::temp_sqlite_url("admin-providers");
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    let state = AdminState {
        policy_store: PolicyStore::new(db.clone()),
        provider_store: provider_store.clone(),
        device_store: DeviceStore::new(db.clone()),
        audit,
        usage_tracker: UsageTracker::new(db),
        admin_group: "oac-admins".into(),
    };
    (admin::router(state), provider_store)
}

/// Builds an admin-authenticated JSON request with an axum body.
fn admin_request(
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<axum::body::Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-oac-user-subject", "admin-user")
        .header("x-oac-user-groups", r#"["oac-admins"]"#);
    if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        builder
            .body(axum::body::Body::from(body.to_string()))
            .expect("request body")
    } else {
        builder.body(axum::body::Body::empty()).expect("empty body")
    }
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn provider_body() -> serde_json::Value {
    serde_json::json!({
        "id": "openai",
        "name": "OpenAI",
        "base_url": "https://api.openai.com",
        "enabled": true,
        "is_default": true,
        "models": ["gpt-4o", "gpt-4o-mini"],
    })
}

// --- Auth middleware ---

#[tokio::test]
async fn admin_requires_identity_headers() {
    let (router, _store) = setup_router().await;
    let resp = router
        .oneshot(
            Request::get("/admin/v1/providers")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_rejects_non_admin_group() {
    let (router, _store) = setup_router().await;
    let resp = router
        .oneshot(
            Request::get("/admin/v1/providers")
                .header("x-oac-user-subject", "regular-user")
                .header("x-oac-user-groups", r#"["engineering"]"#)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_accepts_admin_group_member() {
    let (router, _store) = setup_router().await;
    let resp = router
        .oneshot(admin_request("GET", "/admin/v1/providers", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Provider CRUD ---

#[tokio::test]
async fn provider_crud_round_trip() {
    let (router, _store) = setup_router().await;

    // Create.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(json["id"], "openai");
    assert_eq!(json["models"], serde_json::json!(["gpt-4o", "gpt-4o-mini"]));

    // Get.
    let resp = router
        .clone()
        .oneshot(admin_request("GET", "/admin/v1/providers/openai", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    assert_eq!(json["base_url"], "https://api.openai.com");
    assert_eq!(json["is_default"], true);

    // List.
    let resp = router
        .clone()
        .oneshot(admin_request("GET", "/admin/v1/providers", None))
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    let list = json.as_array().expect("array");
    assert_eq!(list.len(), 1);

    // Update.
    let mut updated = provider_body();
    updated["name"] = serde_json::json!("OpenAI v2");
    updated["models"] = serde_json::json!(["gpt-4.1"]);
    let resp = router
        .clone()
        .oneshot(admin_request(
            "PUT",
            "/admin/v1/providers/openai",
            Some(updated),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    assert_eq!(json["name"], "OpenAI v2");
    assert_eq!(json["models"], serde_json::json!(["gpt-4.1"]));

    // Delete.
    let resp = router
        .clone()
        .oneshot(admin_request("DELETE", "/admin/v1/providers/openai", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Gone.
    let resp = router
        .oneshot(admin_request("GET", "/admin/v1/providers/openai", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn provider_crud_rejects_invalid_payloads() {
    let (router, _store) = setup_router().await;

    let mut bad_url = provider_body();
    bad_url["base_url"] = serde_json::json!("ftp://nope");
    let resp = router
        .clone()
        .oneshot(admin_request("POST", "/admin/v1/providers", Some(bad_url)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let mut missing = provider_body();
    missing["id"] = serde_json::json!("");
    let resp = router
        .clone()
        .oneshot(admin_request("POST", "/admin/v1/providers", Some(missing)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn get_and_delete_missing_provider_return_404() {
    let (router, _store) = setup_router().await;
    let resp = router
        .clone()
        .oneshot(admin_request("GET", "/admin/v1/providers/ghost", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = router
        .oneshot(admin_request("DELETE", "/admin/v1/providers/ghost", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn set_default_marks_exactly_one_provider() {
    let (router, store) = setup_router().await;
    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();
    let mut second = provider_body();
    second["id"] = serde_json::json!("anthropic");
    second["name"] = serde_json::json!("Anthropic");
    second["base_url"] = serde_json::json!("https://api.anthropic.com");
    second["is_default"] = serde_json::json!(false);
    router
        .clone()
        .oneshot(admin_request("POST", "/admin/v1/providers", Some(second)))
        .await
        .unwrap();

    let resp = router
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/anthropic/default",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let openai = store
        .get_provider("openai")
        .await
        .expect("get")
        .expect("exists");
    let anthropic = store
        .get_provider("anthropic")
        .await
        .expect("get")
        .expect("exists");
    assert!(!openai.is_default);
    assert!(anthropic.is_default);
}

// --- Provider keys ---

#[tokio::test]
async fn key_endpoints_return_metadata_only() {
    let (router, _store) = setup_router().await;
    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();

    // Add a key.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/openai/keys",
            Some(serde_json::json!({
                "key": TEST_KEY_PLAINTEXT,
                "label": "production",
                "priority": 0,
                "allowed_groups": ["engineering"],
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let add_body = body_string(resp).await;
    assert!(
        !add_body.contains(TEST_KEY_PLAINTEXT),
        "key add response must not echo plaintext"
    );
    let json: serde_json::Value = serde_json::from_str(&add_body).expect("json");
    let key_id = json["id"].as_str().expect("key id").to_string();
    assert_eq!(json["label"], "production");
    assert_eq!(json["allowed_groups"], serde_json::json!(["engineering"]));

    // List keys — metadata only.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "GET",
            "/admin/v1/providers/openai/keys",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_body = body_string(resp).await;
    assert!(
        !list_body.contains(TEST_KEY_PLAINTEXT),
        "key list response must not contain plaintext"
    );
    let json: serde_json::Value = serde_json::from_str(&list_body).expect("json");
    let keys = json.as_array().expect("array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["key_digest"].as_str().map(str::len), Some(64));

    // Update the key.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "PUT",
            &format!("/admin/v1/providers/openai/keys/{key_id}"),
            Some(serde_json::json!({
                "label": "production-v2",
                "priority": 5,
                "enabled": false,
                "allowed_groups": ["sales"],
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    assert_eq!(json["label"], "production-v2");
    assert_eq!(json["priority"], 5);
    assert_eq!(json["enabled"], false);
    assert_eq!(json["allowed_groups"], serde_json::json!(["sales"]));

    // Delete the key.
    let resp = router
        .clone()
        .oneshot(admin_request(
            "DELETE",
            &format!("/admin/v1/providers/openai/keys/{key_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Empty afterwards.
    let resp = router
        .oneshot(admin_request(
            "GET",
            "/admin/v1/providers/openai/keys",
            None,
        ))
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    assert_eq!(json.as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn key_endpoints_return_404_for_missing_provider_or_key() {
    let (router, _store) = setup_router().await;

    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/ghost/keys",
            Some(serde_json::json!({
                "key": TEST_KEY_PLAINTEXT,
                "label": "x",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();

    let resp = router
        .clone()
        .oneshot(admin_request(
            "GET",
            "/admin/v1/providers/openai/keys/missing",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = router
        .clone()
        .oneshot(admin_request(
            "PUT",
            "/admin/v1/providers/openai/keys/missing",
            Some(serde_json::json!({
                "label": "x",
                "priority": 0,
                "enabled": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = router
        .oneshot(admin_request(
            "DELETE",
            "/admin/v1/providers/openai/keys/missing",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn key_add_rejects_invalid_bodies() {
    let (router, _store) = setup_router().await;
    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();

    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/openai/keys",
            Some(serde_json::json!({ "key": "", "label": "x" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let resp = router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/openai/keys",
            Some(serde_json::json!({
                "key": TEST_KEY_PLAINTEXT,
                "label": "x",
                "allowed_groups": [""],
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn deleting_provider_removes_its_keys() {
    let (router, store) = setup_router().await;
    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();
    router
        .clone()
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers/openai/keys",
            Some(serde_json::json!({
                "key": TEST_KEY_PLAINTEXT,
                "label": "production",
            })),
        ))
        .await
        .unwrap();

    router
        .oneshot(admin_request("DELETE", "/admin/v1/providers/openai", None))
        .await
        .unwrap();

    assert!(
        store
            .list_keys("openai")
            .await
            .expect("list keys")
            .is_empty()
    );
}

#[tokio::test]
async fn admin_mutations_are_recorded_in_the_admin_audit_log() {
    let (router, store) = setup_router().await;
    router
        .oneshot(admin_request(
            "POST",
            "/admin/v1/providers",
            Some(provider_body()),
        ))
        .await
        .unwrap();

    // Provider mutations must be recorded in the append-only admin audit
    // log (read directly from the store's DB — there is no read endpoint
    // for admin_audit_log).
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::admin_audit_log::Entity::find()
        .all(store.db())
        .await
        .expect("load admin audit");
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "upsert_provider" && entry.target == "openai"),
        "expected an upsert_provider audit entry for 'openai', got: {:?}",
        entries.iter().map(|e| e.action.clone()).collect::<Vec<_>>()
    );
}
