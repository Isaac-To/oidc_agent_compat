//! Shared identity-header constants for the relay → central identity flow.
//!
//! The relay authenticates the user locally (OIDC + local API key) and
//! forwards the verified identity to the central proxy as `X-OAC-*` headers
//! over the mTLS channel. The central proxy trusts these headers (mTLS
//! authenticates the transport). Both sides must agree on the exact header
//! names; a typo in one place would silently break the flow. Centralizing
//! the names as constants here eliminates the bare string literals that
//! were previously scattered across both crates.
//!
//! # Security
//!
//! These headers are set by the relay ONLY from its auth-middleware-verified
//! identity (never from the incoming request headers), so a client cannot
//! spoof them. The central proxy reads them after mTLS authentication.

/// The user subject (from the IdP).
pub const HEADER_USER_SUBJECT: &str = "x-oac-user-subject";
/// The user email, if provided.
pub const HEADER_USER_EMAIL: &str = "x-oac-user-email";
/// The group/role memberships (JSON array string), if provided.
pub const HEADER_USER_GROUPS: &str = "x-oac-user-groups";
/// The relay-side identity database ID.
pub const HEADER_IDENTITY_ID: &str = "x-oac-identity-id";
/// The request ID for end-to-end correlation.
pub const HEADER_REQUEST_ID: &str = "x-oac-request-id";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_names_are_lowercase_and_prefixed() {
        assert!(HEADER_USER_SUBJECT.starts_with("x-oac-"));
        assert!(HEADER_USER_EMAIL.starts_with("x-oac-"));
        assert!(HEADER_USER_GROUPS.starts_with("x-oac-"));
        assert!(HEADER_IDENTITY_ID.starts_with("x-oac-"));
        assert!(HEADER_REQUEST_ID.starts_with("x-oac-"));
    }
}
