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
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::{Error, Result};

use super::AppState;

/// Hop-by-hop headers that must be stripped when forwarding (RFC 7230 §6.1).
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// End-to-end headers that are safe to forward.
pub const FORWARDABLE_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
];

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
    // Generate a request ID for end-to-end correlation across relay and
    // central. This is forwarded as the x-oac-request-id header and logged
    // on both sides.
    let request_id = uuid::Uuid::new_v4().to_string();

    // Extract the verified identity (attached by auth middleware) before
    // the request body is consumed.
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedIdentity>()
        .cloned();
    match forward_request(&state, request, identity.as_ref(), &request_id).await {
        Ok(resp) => resp,
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
async fn forward_request(
    state: &AppState,
    request: axum::extract::Request,
    identity: Option<&super::auth::VerifiedIdentity>,
    request_id: &str,
) -> Result<Response<Body>> {
    let (parts, body) = request.into_parts();

    // Read the body.
    let body_bytes = axum::body::to_bytes(body, super::MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Http(format!("read body: {e}")))?;

    // Build the upstream URL from the request path.
    let path = parts.uri.path();
    let sanitized = sanitize_path(path)?;
    let upstream_url = format!("{}{}", state.config.central.url, sanitized);

    // Build the upstream request with sanitized headers.
    let forward_headers = build_forward_headers(&parts.headers);
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
            upstream = upstream.header("x-oac-user-subject", v);
        }
        if let Some(email) = &ident.email {
            if let Ok(v) = HeaderValue::from_str(email) {
                upstream = upstream.header("x-oac-user-email", v);
            }
        }
        if let Some(groups) = &ident.groups {
            if let Ok(v) = HeaderValue::from_str(groups) {
                upstream = upstream.header("x-oac-user-groups", v);
            }
        }
        if let Ok(v) = HeaderValue::from_str(&ident.identity_id) {
            upstream = upstream.header("x-oac-identity-id", v);
        }
    }

    // Forward the request ID for end-to-end correlation.
    if let Ok(v) = HeaderValue::from_str(request_id) {
        upstream = upstream.header("x-oac-request-id", v);
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
    let is_stream = content_type.to_lowercase().contains("text/event-stream");

    let mut response_builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        // Strip hop-by-hop headers from the response too.
        let name_lower = name.as_str().to_lowercase();
        // Also strip Content-Length — Axum recomputes it from the actual body,
        // and the upstream's Content-Length is wrong for streaming responses
        // (where the body is re-framed by bytes_stream()).
        if !HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) && name_lower != "content-length" {
            response_builder = response_builder.header(name, value);
        }
    }

    if is_stream {
        // Stream the response body as raw bytes.
        let stream = upstream_resp.bytes_stream();
        let body = Body::from_stream(stream);
        response_builder
            .body(body)
            .map_err(|e| Error::Http(format!("build stream response: {e}")))
    } else {
        // Buffer the response body.
        let body = upstream_resp
            .bytes()
            .await
            .map_err(|e| Error::Http(format!("read upstream body: {e}")))?;
        response_builder
            .body(Body::from(body))
            .map_err(|e| Error::Http(format!("build response: {e}")))
    }
}

/// Sanitizes the request path to prevent SSRF and path traversal.
///
/// Rejects paths containing:
/// - `..` (literal or URL-encoded as `%2e%2e` or `%2E%2E`)
/// - `//` (double slashes)
/// - `\` (backslashes, which some upstreams normalize to `/`)
/// - Absolute URLs (`http://` or `https://`)
///
/// # Errors
///
/// Returns [`Error::Http`] if the path is unsafe.
fn sanitize_path(path: &str) -> Result<String> {
    // Reject literal `..` and backslashes.
    if path.contains("..") {
        return Err(Error::Http(format!("path contains '..': {path}")));
    }
    if path.contains('\\') {
        return Err(Error::Http(format!("path contains backslash: {path}")));
    }
    // Reject URL-encoded `..` (%2e%2e, case-insensitive).
    let path_lower = path.to_lowercase();
    if path_lower.contains("%2e%2e") || path_lower.contains("%2e.") || path_lower.contains(".%2e") {
        return Err(Error::Http(format!("path contains encoded '..': {path}")));
    }
    if path.contains("//") {
        return Err(Error::Http(format!("path contains '//': {path}")));
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return Err(Error::Http(format!("path is absolute URL: {path}")));
    }
    Ok(path.to_string())
}

/// Builds the set of headers to forward to the upstream, stripping hop-by-hop
/// headers and any headers named in the `Connection` header.
fn build_forward_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    // Collect headers named in the Connection header (these are hop-by-hop).
    let connection_headers: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(|h| h.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let mut result = Vec::new();
    for name in FORWARDABLE_HEADERS {
        if let Some(value) = headers.get(*name) {
            // Skip if this header is named in Connection.
            if connection_headers.iter().any(|h| h == name) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                HeaderName::try_from(*name),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                result.push((n, v));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_accepts_normal_paths() {
        assert_eq!(
            sanitize_path("/v1/chat/completions").unwrap(),
            "/v1/chat/completions"
        );
        assert_eq!(sanitize_path("/v1/models").unwrap(), "/v1/models");
    }

    #[test]
    fn sanitize_path_rejects_dot_dot() {
        assert!(sanitize_path("/v1/../etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_url_encoded_dot_dot() {
        assert!(sanitize_path("/v1/%2e%2e/etc/passwd").is_err());
        assert!(sanitize_path("/v1/%2E%2E/etc/passwd").is_err());
        assert!(sanitize_path("/v1/%2e./etc/passwd").is_err());
        assert!(sanitize_path("/v1/.%2e/etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_backslash() {
        assert!(sanitize_path("/v1/\\..\\etc/passwd").is_err());
    }

    #[test]
    fn sanitize_path_rejects_double_slash() {
        assert!(sanitize_path("/v1//chat").is_err());
    }

    #[test]
    fn sanitize_path_rejects_absolute_url() {
        assert!(sanitize_path("http://evil.example.com/v1").is_err());
        assert!(sanitize_path("https://evil.example.com/v1").is_err());
    }

    #[test]
    fn build_forward_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("authorization", "Bearer oac_secret".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();

        // content-type should be forwarded.
        assert!(
            names.contains(&"content-type"),
            "content-type must be forwarded"
        );
        // Hop-by-hop headers should NOT be forwarded.
        assert!(
            !names.contains(&"connection"),
            "connection must be stripped"
        );
        assert!(
            !names.contains(&"transfer-encoding"),
            "transfer-encoding must be stripped"
        );
        // Authorization is not in FORWARDABLE_HEADERS, so it's not forwarded.
        assert!(
            !names.contains(&"authorization"),
            "authorization must not be forwarded (replaced by upstream auth)"
        );
    }

    #[test]
    fn build_forward_headers_strips_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());
        // Simulate a Connection header that names "accept" as per-connection.
        headers.insert("connection", "accept".parse().unwrap());

        let forwarded = build_forward_headers(&headers);
        let names: Vec<&str> = forwarded.iter().map(|(n, _)| n.as_str()).collect();

        // "accept" is named in Connection, so it should be stripped.
        assert!(
            !names.contains(&"accept"),
            "headers named in Connection must be stripped"
        );
        // content-type is not named in Connection, so it should be forwarded.
        assert!(names.contains(&"content-type"));
    }

    #[test]
    fn hop_by_hop_headers_list_is_complete() {
        // RFC 7230 §6.1 canonical list.
        assert!(HOP_BY_HOP_HEADERS.contains(&"connection"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"keep-alive"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authenticate"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"proxy-authorization"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"te"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"trailer"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"upgrade"));
    }
}
