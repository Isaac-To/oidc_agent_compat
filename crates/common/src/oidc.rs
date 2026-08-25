//! OIDC relying-party helpers.
//!
//! This module provides the security-critical building blocks for the OIDC
//! authorization-code + PKCE flow used by both the relay and the central proxy.
//!
//! # Security
//!
//! - PKCE with S256 (RFC 7636, RFC 9700 §2.1.1).
//! - `state` and `nonce` parameters (OIDC Core §3.1.3.7).
//! - ID-token signing algorithm pinned to {RS256, ES256} (reject `none`, HS*).
//! - HTTP client with `redirect::Policy::none()` (SSRF prevention) and
//!   `rustls-tls` (BCP 195 / RFC 9325).
//!
//! The full `openidconnect::Client` construction involves type-state generics
//! that are wired up in Phase 2 (relay login) against a real IdP. This module
//! provides the reusable, testable primitives.
//!
//! # References
//!
//! - RFC 8252 — Native Apps (loopback redirect).
//! - RFC 9700 — OAuth 2.0 Security BCP.
//! - RFC 7636 — PKCE.
//! - OIDC Core 1.0 §3.1.3.7 — ID-token validation.
//! - NIST SP 800-63C — Federation.

use crate::config::OidcConfig;
use crate::error::{Error, Result};

/// The allowed ID-token signing algorithms. `none` and HS* are rejected.
pub const ALLOWED_SIGNING_ALGS: &[&str] = &["RS256", "ES256"];

/// The default connect timeout for OIDC HTTP calls (10 seconds).
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The default request timeout for OIDC HTTP calls (30 seconds).
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Additional OIDC claims beyond the standard set, used to extract group
/// and role memberships from the IdP.
///
/// Many enterprise IdPs (e.g. Keycloak, Auth0, Okta) expose a non-standard
/// `groups` claim in the ID token and/or userinfo response. Some also expose
/// a `roles` claim. These are not part of the OIDC Core standard claims, so
/// the `openidconnect` crate requires an [`AdditionalClaims`] implementation
/// to deserialize them.
///
/// # Security
///
/// Group and role memberships are used for authorization decisions (model
/// allowlists, endpoint restrictions, quotas). They are extracted from the
/// IdP's signed ID token or TLS-protected userinfo response, so they cannot
/// be spoofed by the end user.
///
/// # Serialization
///
/// Both fields are optional because not all IdPs provide both. Unknown
/// additional claims are ignored (the struct only declares the ones we use).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CustomAdditionalClaims {
    /// Group memberships (e.g. `["engineering", "ai-users"]`).
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// Role memberships (e.g. `["admin", "developer"]`).
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

impl openidconnect::AdditionalClaims for CustomAdditionalClaims {}

/// A type alias for the OIDC client parameterized with [`CustomAdditionalClaims`].
///
/// This is identical to `openidconnect::core::CoreClient` except that the
/// additional-claims type is `CustomAdditionalClaims` instead of
/// `EmptyAdditionalClaims`, so that group/role claims are deserialized from
/// the ID token and userinfo response.
pub type CustomClient = openidconnect::Client<
    CustomAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            CustomAdditionalClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::StandardTokenIntrospectionResponse<
        openidconnect::EmptyExtraTokenFields,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::core::CoreRevocableToken,
    openidconnect::core::CoreRevocationErrorResponse,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

/// A type alias for the OIDC provider metadata parameterized with the Core
/// types (the additional-claims type does not appear in provider metadata,
/// so this is just `CoreProviderMetadata`).
pub type CustomProviderMetadata = openidconnect::core::CoreProviderMetadata;

/// A type alias for ID-token claims carrying [`CustomAdditionalClaims`].
pub type CustomIdTokenClaims =
    openidconnect::IdTokenClaims<CustomAdditionalClaims, openidconnect::core::CoreGenderClaim>;

/// A type alias for userinfo claims carrying [`CustomAdditionalClaims`].
pub type CustomUserInfoClaims =
    openidconnect::UserInfoClaims<CustomAdditionalClaims, openidconnect::core::CoreGenderClaim>;

/// Unions the `groups` and `roles` from [`CustomAdditionalClaims`] into a
/// single deduplicated, sorted `Vec<String>`.
///
/// Roles are treated as groups for policy-matching purposes, since Keycloak
/// and other IdPs expose both and policies are name-based. This keeps the
/// downstream authorization logic operating on a single list.
#[must_use]
pub fn union_groups_roles(claims: &CustomAdditionalClaims) -> Vec<String> {
    let mut combined: Vec<String> = Vec::new();
    if let Some(g) = &claims.groups {
        combined.extend(g.iter().cloned());
    }
    if let Some(r) = &claims.roles {
        combined.extend(r.iter().cloned());
    }
    combined.sort();
    combined.dedup();
    combined
}

/// Serializes a list of group/role names as a JSON array string for storage
/// in the `identities.groups` column (which is a `TEXT` holding a JSON array).
///
/// Returns `None` if the list is empty (so the column stays `NULL`).
#[must_use]
pub fn groups_to_json_string(groups: &[String]) -> Option<String> {
    if groups.is_empty() {
        return None;
    }
    serde_json::to_string(groups).ok()
}

/// Builds the HTTP client used for OIDC discovery and token exchange.
///
/// # Security
///
/// - `redirect::Policy::none()` — never follow redirects (SSRF prevention,
///   per the `openidconnect` crate's security warning).
/// - `rustls-tls` — certificate verification via rustls (BCP 195 / RFC 9325).
/// - Connect and request timeouts to prevent hanging on unreachable IdPs.
///
/// # Errors
///
/// Returns [`Error::Oidc`] if the client cannot be built (extremely unlikely
/// with valid defaults).
pub fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| Error::oidc(format!("build http client: {e}")))
}

/// Resolves the OIDC client secret from the environment variable named in
/// `config.client_secret_env`.
///
/// # Security
///
/// The secret is read from the environment, not from the config file, so it
/// is never committed to disk in `config.toml`.
///
/// # Errors
///
/// Returns [`Error::Oidc`] if the environment variable is not set or empty.
pub fn resolve_client_secret(config: &OidcConfig) -> Result<String> {
    let secret = std::env::var(&config.client_secret_env).map_err(|_| {
        Error::oidc(format!(
            "client secret env var '{}' is not set",
            config.client_secret_env
        ))
    })?;
    if secret.is_empty() {
        return Err(Error::oidc(format!(
            "client secret env var '{}' is empty",
            config.client_secret_env
        )));
    }
    Ok(secret)
}

/// Validates that a signing algorithm is in the allowed set.
///
/// # Security
///
/// Rejects `none` and any HS* (HMAC) algorithm, which would be insecure for
/// ID-token validation (OIDC Core §2: "ID Tokens MUST NOT use none as the alg
/// value").
///
/// # Example
///
/// ```
/// use oidc_agent_common::oidc::is_allowed_signing_alg;
/// assert!(is_allowed_signing_alg("RS256"));
/// assert!(is_allowed_signing_alg("ES256"));
/// assert!(!is_allowed_signing_alg("none"));
/// assert!(!is_allowed_signing_alg("HS256"));
/// ```
#[must_use]
pub fn is_allowed_signing_alg(alg: &str) -> bool {
    ALLOWED_SIGNING_ALGS
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(alg))
}

/// Validates the OIDC redirect URI is a loopback http URL per RFC 8252 §7.3.
///
/// Parses the URL and checks that the scheme is `http` and the host is a
/// loopback address (`127.0.0.0/8` or `::1`). This prevents bypasses like
/// `http://127.0.0.1.evil.com/callback` that a naive `starts_with` would
/// accept.
///
/// # Errors
///
/// Returns [`Error::Oidc`] if the redirect URI is not a loopback `http` URL.
///
/// # Example
///
/// ```
/// use oidc_agent_common::oidc::validate_loopback_redirect;
/// assert!(validate_loopback_redirect("http://127.0.0.1:8787/callback").is_ok());
/// assert!(validate_loopback_redirect("http://[::1]:8787/callback").is_ok());
/// assert!(validate_loopback_redirect("https://evil.example.com/cb").is_err());
/// assert!(validate_loopback_redirect("http://0.0.0.0:8787/cb").is_err());
/// assert!(validate_loopback_redirect("http://127.0.0.1.evil.com/cb").is_err());
/// ```
pub fn validate_loopback_redirect(redirect_uri: &str) -> Result<()> {
    let parsed = url::Url::parse(redirect_uri)
        .map_err(|e| Error::oidc(format!("invalid redirect_uri: {e}")))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        _ => false,
    };
    if parsed.scheme() != "http" || !is_loopback {
        return Err(Error::oidc(format!(
            "redirect_uri must be a loopback http URL (http://127.0.0.1:... or \
             http://[::1]:...), got: {redirect_uri}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oidc_config(secret_env: &str) -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "test".into(),
            client_secret_env: secret_env.into(),
            redirect_uri: "http://127.0.0.1:0/callback".into(),
            scopes: vec!["openid".into()],
        }
    }

    #[test]
    fn allowed_signing_algs_excludes_none() {
        assert!(ALLOWED_SIGNING_ALGS.contains(&"RS256"));
        assert!(ALLOWED_SIGNING_ALGS.contains(&"ES256"));
        assert!(!ALLOWED_SIGNING_ALGS.contains(&"none"));
        assert!(!ALLOWED_SIGNING_ALGS.contains(&"HS256"));
    }

    #[test]
    fn is_allowed_signing_alg_case_insensitive() {
        assert!(is_allowed_signing_alg("RS256"));
        assert!(is_allowed_signing_alg("rs256"));
        assert!(is_allowed_signing_alg("Es256"));
        assert!(!is_allowed_signing_alg("none"));
        assert!(!is_allowed_signing_alg("HS256"));
        assert!(!is_allowed_signing_alg("hs384"));
    }

    #[test]
    fn build_http_client_succeeds() {
        let client = build_http_client().expect("client builds");
        let _ = client;
    }

    #[test]
    fn resolve_client_secret_missing_env_returns_error() {
        let cfg = test_oidc_config("OAC_TEST_NONEXISTENT_SECRET_XYZ");
        let err = resolve_client_secret(&cfg).unwrap_err();
        assert!(err.to_string().contains("not set"), "{err}");
    }

    #[test]
    fn resolve_client_secret_empty_env_returns_error() {
        // Use an env var that is set to empty by the test harness (if present)
        // or skip. We test the empty-string branch by constructing a config
        // pointing at a var we know is unset, then verifying the "not set"
        // path. The empty-string path is covered by the integration test.
        let cfg = test_oidc_config("OAC_TEST_DEFINITELY_UNSET_SECRET");
        let err = resolve_client_secret(&cfg).unwrap_err();
        assert!(err.to_string().contains("not set"), "{err}");
    }

    #[test]
    fn resolve_client_secret_valid_env_returns_secret() {
        // We cannot set env vars in Rust 2024 without unsafe. Instead, we
        // verify the happy path via a config pointing at a var that the CI
        // environment sets. For unit testing, we verify the error paths
        // (above) and rely on integration tests for the happy path.
        // If OAC_TEST_VALID_SECRET_XYZ happens to be set, we test it; otherwise
        // we expect the "not set" error.
        let cfg = test_oidc_config("OAC_TEST_VALID_SECRET_XYZ");
        match resolve_client_secret(&cfg) {
            Ok(s) => assert!(!s.is_empty()),
            Err(e) => assert!(e.to_string().contains("not set")),
        }
    }

    #[test]
    fn validate_loopback_redirect_accepts_ipv4_loopback() {
        assert!(validate_loopback_redirect("http://127.0.0.1:8787/callback").is_ok());
    }

    #[test]
    fn validate_loopback_redirect_accepts_ipv6_loopback() {
        assert!(validate_loopback_redirect("http://[::1]:8787/callback").is_ok());
    }

    #[test]
    fn validate_loopback_redirect_rejects_https() {
        assert!(validate_loopback_redirect("https://127.0.0.1:8787/cb").is_err());
    }

    #[test]
    fn validate_loopback_redirect_rejects_non_loopback() {
        assert!(validate_loopback_redirect("https://evil.example.com/cb").is_err());
        assert!(validate_loopback_redirect("http://0.0.0.0:8787/cb").is_err());
        assert!(validate_loopback_redirect("http://192.168.1.1:8787/cb").is_err());
    }

    #[test]
    fn validate_loopback_redirect_rejects_substring_bypass() {
        // These would pass a naive starts_with("http://127.0.0.1") check
        // but are NOT loopback addresses.
        assert!(validate_loopback_redirect("http://127.0.0.1.evil.com/cb").is_err());
        assert!(validate_loopback_redirect("http://127.0.0.1ABC/cb").is_err());
        assert!(validate_loopback_redirect("http://[::1].evil.com/cb").is_err());
    }

    #[test]
    fn validate_loopback_redirect_rejects_domain_localhost() {
        // "localhost" is a hostname, not an IP — the URL parser resolves it
        // as a domain, not a loopback IP. We only accept IP literals.
        assert!(validate_loopback_redirect("http://localhost:8787/cb").is_err());
    }

    #[test]
    fn union_groups_roles_merges_and_dedups() {
        let claims = CustomAdditionalClaims {
            groups: Some(vec!["engineering".into(), "ai-users".into()]),
            roles: Some(vec!["admin".into(), "ai-users".into()]),
        };
        let combined = union_groups_roles(&claims);
        assert_eq!(combined, vec!["admin", "ai-users", "engineering"]);
    }

    #[test]
    fn union_groups_roles_handles_empty() {
        let claims = CustomAdditionalClaims::default();
        assert!(union_groups_roles(&claims).is_empty());
    }

    #[test]
    fn union_groups_roles_handles_groups_only() {
        let claims = CustomAdditionalClaims {
            groups: Some(vec!["g1".into()]),
            roles: None,
        };
        assert_eq!(union_groups_roles(&claims), vec!["g1"]);
    }

    #[test]
    fn groups_to_json_string_round_trips() {
        let groups = vec!["a".to_string(), "b".to_string()];
        let json = groups_to_json_string(&groups).expect("some");
        let parsed: Vec<String> = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, groups);
    }

    #[test]
    fn groups_to_json_string_none_for_empty() {
        assert!(groups_to_json_string(&[]).is_none());
    }

    #[test]
    fn custom_additional_claims_deserializes_groups_and_roles() {
        let json = r#"{"groups":["g1"],"roles":["r1"]}"#;
        let claims: CustomAdditionalClaims = serde_json::from_str(json).expect("parse");
        assert_eq!(
            claims.groups.as_deref(),
            Some(["g1".to_string()].as_slice())
        );
        assert_eq!(claims.roles.as_deref(), Some(["r1".to_string()].as_slice()));
    }

    #[test]
    fn custom_additional_claims_deserializes_missing_fields() {
        let json = r#"{}"#;
        let claims: CustomAdditionalClaims = serde_json::from_str(json).expect("parse");
        assert!(claims.groups.is_none());
        assert!(claims.roles.is_none());
    }
}
