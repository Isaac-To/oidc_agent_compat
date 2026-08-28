//! Forward handler for the relay proxy.
//!
//! This handler receives authenticated agent requests and forwards them to
//! the central proxy over mTLS. It strips hop-by-hop headers, replaces the
//! incoming `Authorization` (local key) with the user token, and passes
//! streaming responses through as raw bytes.
//!
//! # Security
//!
//! - **Hop-by-hop header stripping** (RFC 7230 §6.1): removes `Connection`,
//!   `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
//!   `Trailer`, `Transfer-Encoding`, `Upgrade`, and any header named in the
//!   `Connection` header.
//! - **mTLS** to the central proxy (TLS 1.3, company CA).
//! - **Raw byte SSE passthrough** for streaming responses.
//! - **SSRF prevention**: the central URL comes from config only; the request
//!   path is sanitized (rejects `..`, `//`, absolute URLs).

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::http_util;
use oidc_agent_common::identity;

use super::AppState;

/// Builds the HTTP client for forwarding to the central proxy.
///
/// # Security
///
/// - `rustls-tls` for certificate verification.
/// - No `danger_accept_invalid_certs`.
/// - Timeouts to prevent hanging.
/// - In production mode (`dev_mode = false`), uses mTLS with the relay's
///   client cert and the company CA for server verification.
/// - In dev mode, uses plain HTTP (no mTLS) for the containerized dev stack.
///
/// # Errors
///
/// Returns [`Error::Http`] if the client cannot be built.
pub fn build_client(config: &RelayConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        // Never follow redirects — prevents SSRF amplification if the central
        // returns a redirect to an internal service.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(10));

    if !config.dev_mode {
        // Production mode: mTLS client cert + CA for server verification.
        let client_config = oidc_agent_common::mtls::build_client_config(
            &config.central.ca_cert_path,
            &config.central.client_cert_path,
            &config.central.client_key_path,
        )?;

        // Convert the rustls ClientConfig into a reqwest identity + root cert.
        // reqwest's rustls backend accepts a pre-built ClientConfig via
        // `use_preconfigured_tls`.
        builder = builder
            .use_preconfigured_tls(client_config)
            .https_only(true);
    }

    builder
        .build()
        .map_err(|e| Error::Http(format!("build forward client: {e}")))
}

/// Builds the `/v1` routes that forward to the central proxy.
pub fn v1_routes() -> Router<AppState> {
    Router::new()
        .route("/chat/completions", post(proxy_handler))
        .route("/responses", post(proxy_handler))
        .route("/models", get(proxy_handler))
        .route("/embeddings", post(proxy_handler))
}

/// The proxy handler that forwards requests to the central proxy.
pub async fn proxy_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = std::time::Instant::now();

    // Generate a request ID for end-to-end correlation across relay and
    // central. This is forwarded as the x-oac-request-id header and logged
    // on both sides.
    let request_id = uuid::Uuid::new_v4().to_string();

    // Capture the method and path before the request is consumed.
    let method = request.method().to_string();
    let endpoint = request.uri().path().to_string();

    // Extract the verified identity (attached by auth middleware) before
    // the request body is consumed.
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedIdentity>()
        .cloned();

    let result = forward_request(&state, request, identity.as_ref(), &request_id).await;

    // Record a relay-side activity log entry (best-effort; log on failure).
    let latency_ms = start.elapsed().as_millis() as i64;
    let (central_status, model) = match &result {
        Ok((resp, model)) => (Some(resp.status().as_u16() as i32), model.clone()),
        Err(_) => (None, None),
    };
    if let Some(ident) = &identity {
        let entry = crate::activity::RelayActivityEntry {
            identity_id: ident.identity_id.clone(),
            key_id: ident.key_id.clone(),
            method,
            endpoint,
            model,
            central_status,
            latency_ms,
            request_id: Some(request_id.clone()),
        };
        if let Err(e) = state.activity.record(&entry).await {
            tracing::error!(error = %e, request_id = %request_id, "failed to write relay activity log");
        }
    }

    match result {
        Ok((resp, _)) => resp,
        Err(e) => {
            tracing::error!(error = %e, request_id = %request_id, "forward failed");
            let body = serde_json::json!({
                "error": {
                    "message": "upstream request failed",
                    "type": "relay_error",
                }
            });
            (
                StatusCode::BAD_GATEWAY,
                [("content-type", "application/json")],
                body.to_string(),
            )
                .into_response()
        }
    }
}

/// Forwards a single request to the central proxy.
///
/// # Security
///
/// The relay replaces the incoming `Authorization` (the local API key) with
/// the verified user identity, forwarded as `X-OAC-User-Subject`,
/// `X-OAC-User-Email`, `X-OAC-User-Groups`, and `X-OAC-Identity-Id` headers.
/// The central proxy uses these for audit logging and authorization. The
/// local key is never forwarded to the central proxy.
///
/// Returns the response and the parsed model (for activity logging).
async fn forward_request(
    state: &AppState,
    request: axum::extract::Request,
    identity: Option<&super::auth::VerifiedIdentity>,
    request_id: &str,
) -> Result<(Response<Body>, Option<String>)> {
    let (parts, body) = request.into_parts();

    // Read the body.
    let body_bytes = axum::body::to_bytes(body, super::MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Http(format!("read body: {e}")))?;

    // Extract the model from the request body (for activity logging).
    let model = http_util::extract_model(&body_bytes);

    // Build the upstream URL from the request path.
    let path = parts.uri.path();
    let sanitized = http_util::sanitize_path(path)?;
    let upstream_url = format!("{}{}", state.config.central.url, sanitized);

    // Build the upstream request with sanitized headers.
    let forward_headers = http_util::build_forward_headers(&parts.headers);
    let mut upstream = state
        .client
        .request(parts.method, &upstream_url)
        .body(body_bytes);

    for (name, value) in &forward_headers {
        upstream = upstream.header(name, value);
    }

    // Forward the verified user identity to the central proxy for audit
    // logging and authorization. These headers are set by the relay ONLY
    // from the auth-middleware-verified identity (never from the incoming
    // request headers), so a client cannot spoof them.
    if let Some(ident) = identity {
        if let Ok(v) = HeaderValue::from_str(&ident.subject) {
            upstream = upstream.header(identity::HEADER_USER_SUBJECT, v);
        }
        if let Some(email) = &ident.email {
            if let Ok(v) = HeaderValue::from_str(email) {
                upstream = upstream.header(identity::HEADER_USER_EMAIL, v);
            }
        }
        if let Some(groups) = &ident.groups {
            if let Ok(v) = HeaderValue::from_str(groups) {
                upstream = upstream.header(identity::HEADER_USER_GROUPS, v);
            }
        }
        if let Ok(v) = HeaderValue::from_str(&ident.identity_id) {
            upstream = upstream.header(identity::HEADER_IDENTITY_ID, v);
        }
    }

    // Forward the request ID for end-to-end correlation.
    if let Ok(v) = HeaderValue::from_str(request_id) {
        upstream = upstream.header(identity::HEADER_REQUEST_ID, v);
    }

    // Send the request.
    let upstream_resp = upstream
        .send()
        .await
        .map_err(|e| Error::Http(format!("upstream request: {e}")))?;

    // Build the response.
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Check if this is a streaming response (SSE). Content-Type values are
    // case-insensitive per RFC 7231 §3.1.1.1.
    let content_type = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let is_stream = http_util::is_sse_content_type(content_type);

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        // Strip hop-by-hop headers and content-length from the response.
        // Axum recomputes content-length from the actual body, and the
        // upstream's value is wrong for streaming responses (where the body
        // is re-framed by bytes_stream()).
        let name_lower = name.as_str().to_lowercase();
        if !http_util::is_response_header_stripped(&name_lower) {
            response_builder = response_builder.header(name, value);
        }
    }

    if is_stream {
        // Stream the response body as raw bytes.
        let stream = upstream_resp.bytes_stream();
        let body = Body::from_stream(stream);
        let resp = response_builder
            .body(body)
            .map_err(|e| Error::Http(format!("build stream response: {e}")))?;
        Ok((resp, model))
    } else {
        // Buffer the response body.
        let body = upstream_resp
            .bytes()
            .await
            .map_err(|e| Error::Http(format!("read upstream body: {e}")))?;
        let resp = response_builder
            .body(Body::from(body))
            .map_err(|e| Error::Http(format!("build response: {e}")))?;
        Ok((resp, model))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// `v1_routes` is the mountable surface an embedder composes into a
    /// larger router; pin that all four OpenAI-compatible endpoints exist.
    #[tokio::test]
    async fn v1_routes_registers_all_four_endpoints() {
        use crate::proxy::AppState;

        let url = oidc_agent_common::persistence::temp_sqlite_url("fwd-routes");
        let db = crate::db::setup(&url).await.expect("db");
        let key_store = crate::keystore::KeyStore::new(db.clone());
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().expect("addr"),
            database_url: "sqlite://test.db".into(),
            oidc: oidc_agent_common::config::OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "t".into(),
                client_secret_env: "T".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            central: oidc_agent_common::config::CentralConnectionConfig {
                url: "http://127.0.0.1:1".into(),
                ca_cert_path: "/ca.pem".into(),
                client_cert_path: "/c.pem".into(),
                client_key_path: "/c.key".into(),
            },
            dev_mode: true,
            session_ttl_hours: None,
        };
        let state = AppState {
            key_store,
            config: config.clone(),
            client: build_client(&config).expect("client"),
            listen_addr: "127.0.0.1:8787".parse().expect("addr"),
            activity: crate::activity::ActivityLogger::new(db),
        };
        let app = v1_routes().with_state(state);

        // All four routes must resolve (405 vs 404 distinguishes "wrong
        // method" from "route missing").
        for (method, path) in [
            (axum::http::Method::POST, "/chat/completions"),
            (axum::http::Method::POST, "/responses"),
            (axum::http::Method::GET, "/models"),
            (axum::http::Method::POST, "/embeddings"),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("router");
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{method} {path} must be registered"
            );
        }
    }
}
