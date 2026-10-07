//! Shared identity-header constants for the relay → central identity flow.
//!
//! # Architecture (zero-trust)
//!
//! The relay authenticates the user locally (OIDC login) and obtains a
//! central-minted opaque bearer token. The relay forwards this token to the
//! central proxy over mTLS. The central proxy verifies the token against its
//! own token store — it does **NOT** trust any relay-forwarded identity
//! headers. The identity (subject, email, groups) comes solely from the
//! token record in the central database.
//!
//! The only relay→central headers still in use are:
//! - [`HEADER_REQUEST_ID`] — end-to-end request correlation.
//! - [`HEADER_DEVICE_FINGERPRINT`] — mTLS client cert fingerprint for
//!   device-bound tokens.
//!
//! The `X-OAC-User-*` and `X-OAC-Identity-Id` headers from the pre-zero-trust
//! architecture are **deprecated** and no longer read by central. They are
//! kept here as deprecated constants so any lingering references produce a
//! compile-time warning rather than a silent typo.

/// The request ID for end-to-end correlation.
pub const HEADER_REQUEST_ID: &str = "x-oac-request-id";
/// The SHA-256 fingerprint of the relay's mTLS client cert (device binding).
pub const HEADER_DEVICE_FINGERPRINT: &str = "x-oac-device-fingerprint";

/// Deprecated: the central proxy no longer trusts relay-forwarded identity
/// headers (zero-trust architecture). Identity comes from the token store.
#[deprecated(note = "zero-trust: central does not trust relay-forwarded identity headers")]
pub const HEADER_USER_SUBJECT: &str = "x-oac-user-subject";
/// Deprecated: the central proxy no longer trusts relay-forwarded identity
/// headers (zero-trust architecture). Identity comes from the token store.
#[deprecated(note = "zero-trust: central does not trust relay-forwarded identity headers")]
pub const HEADER_USER_EMAIL: &str = "x-oac-user-email";
/// Deprecated: the central proxy no longer trusts relay-forwarded identity
/// headers (zero-trust architecture). Identity comes from the token store.
#[deprecated(note = "zero-trust: central does not trust relay-forwarded identity headers")]
pub const HEADER_USER_GROUPS: &str = "x-oac-user-groups";
/// Deprecated: the central proxy no longer trusts relay-forwarded identity
/// headers (zero-trust architecture). Identity comes from the token store.
#[deprecated(note = "zero-trust: central does not trust relay-forwarded identity headers")]
pub const HEADER_IDENTITY_ID: &str = "x-oac-identity-id";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_names_are_lowercase_and_prefixed() {
        assert!(HEADER_REQUEST_ID.starts_with("x-oac-"));
        assert!(HEADER_DEVICE_FINGERPRINT.starts_with("x-oac-"));
        #[allow(deprecated)]
        {
            assert!(HEADER_USER_SUBJECT.starts_with("x-oac-"));
            assert!(HEADER_USER_EMAIL.starts_with("x-oac-"));
            assert!(HEADER_USER_GROUPS.starts_with("x-oac-"));
            assert!(HEADER_IDENTITY_ID.starts_with("x-oac-"));
        }
    }
}
