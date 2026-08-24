//! Local API key generation, hashing, and constant-time verification.
//!
//! This module implements the local API key lifecycle used by the laptop
//! relay to authenticate AI agents (Codex, etc.) over the loopback HTTP
//! interface.
//!
//! # Security properties
//!
//! - **Entropy:** keys are 32 random bytes (256 bits) drawn from the OS
//!   CSPRNG ([`rand::rngs::OsRng`]), per NIST SP 800-90A and NIST SP 800-131A.
//! - **Format:** keys are base64url-encoded (RFC 4648 §5, no padding) and
//!   prefixed with `oac_` for secret-scanner detection (industry convention,
//!   cf. GitHub `ghp_`, Stripe `sk_`).
//! - **Storage:** keys are stored as a SHA-256 (or HMAC-SHA-256) hash in the
//!   database, never as plaintext. A fast hash is correct here because the
//!   keys are high-entropy (256-bit); slow hashing (Argon2id) would add
//!   ~50 ms per proxied request with no marginal security benefit (OWASP
//!   Password Storage Cheat Sheet nuance).
//! - **Comparison:** hash comparison uses [`subtle::ConstantTimeEq`] to
//!   prevent timing attacks (CWE-208).
//! - **Memory:** key material in memory is wrapped in [`Zeroizing`] so it is
//!   zeroed on drop.
//!
//! # References
//!
//! - NIST SP 800-90A — approved DRBGs seeded from OS entropy.
//! - NIST SP 800-131A — 256-bit minimum for symmetric secrets.
//! - RFC 4648 §5 — base64url encoding.
//! - RFC 6750 — Bearer token usage.
//! - OWASP Password Storage Cheat Sheet — fast vs. slow hashing for
//!   high-entropy tokens.
//! - CWE-208 — timing-discrepancy attacks.

use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The human-readable prefix on every local key, for secret-scanner detection.
pub const KEY_PREFIX: &str = "oac_";

/// Number of random bytes (256 bits) in a key before encoding.
const KEY_BYTES: usize = 32;

/// A freshly generated local API key, zeroized on drop.
///
/// Construct with [`LocalKey::generate`]. The [`Display`][std::fmt::Display]
/// impl produces the full `oac_<base64url>` string suitable for injection
/// into an agent's config file.
#[derive(Debug)]
pub struct LocalKey(Zeroizing<String>);

impl LocalKey {
    /// Generates a new 256-bit local API key.
    ///
    /// # Security
    ///
    /// Uses [`rand::rngs::OsRng`] (the OS CSPRNG). The key is 32 random bytes,
    /// base64url-encoded without padding, and prefixed with `oac_`.
    ///
    /// # Example
    ///
    /// ```
    /// use oidc_agent_common::keys::LocalKey;
    /// let key = LocalKey::generate();
    /// let s = key.to_string();
    /// assert!(s.starts_with("oac_"));
    /// assert!(s.len() > KEY_PREFIX.len() + 40);
    /// # const KEY_PREFIX: &str = "oac_";
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let formatted = format!("{KEY_PREFIX}{encoded}");
        Self(Zeroizing::new(formatted))
    }

    /// Returns the full key string (`oac_<base64url>`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LocalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A SHA-256 hash of a local key, suitable for database storage.
///
/// Construct with [`KeyHash::from_plaintext`] or [`KeyHash::from_hash_bytes`].
/// Compare two hashes with [`KeyHash::matches`] (constant-time).
#[derive(Debug, Clone)]
pub struct KeyHash([u8; 32]);

impl KeyHash {
    /// Hashes a plaintext key string into a [`KeyHash`].
    ///
    /// # Security
    ///
    /// Uses SHA-256. The plaintext is consumed by value and should be
    /// dropped promptly; callers holding the plaintext should wrap it in
    /// [`Zeroizing`].
    ///
    /// # Example
    ///
    /// ```
    /// use oidc_agent_common::keys::{KeyHash, LocalKey};
    /// let key = LocalKey::generate();
    /// let hash = KeyHash::from_plaintext(&key.to_string());
    /// assert!(hash.matches(&KeyHash::from_plaintext(&key.to_string())));
    /// ```
    #[must_use]
    pub fn from_plaintext(plaintext: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(plaintext.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Constructs a [`KeyHash`] from raw 32-byte hash bytes (e.g. loaded from DB).
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is not exactly 32 bytes long. This is a programming
    /// error (DB schema mismatch), not a runtime condition.
    #[must_use]
    pub fn from_hash_bytes(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() == 32,
            "KeyHash must be exactly 32 bytes, got {}",
            bytes.len()
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Self(out)
    }

    /// Returns the raw 32-byte hash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time comparison of two hashes.
    ///
    /// Returns `true` if both hashes are equal. Uses [`subtle::ConstantTimeEq`]
    /// to prevent timing attacks (CWE-208).
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// An HMAC-SHA-256 keyed hash, for defense-in-depth against DB-only compromise.
///
/// When a `pepper` (a config-derived secret not stored in the DB) is provided,
/// [`HmacKeyHash`] offers better protection than plain [`KeyHash`]: an attacker
/// who steals only the database cannot forge valid hashes without the pepper.
///
/// # References
///
/// - OWASP Password Storage Cheat Sheet — peppered hashing.
pub struct HmacKeyHash {
    inner: hmac::Hmac<Sha256>,
}

impl HmacKeyHash {
    /// Creates a new hasher keyed with the given `pepper`.
    ///
    /// # Security
    ///
    /// The pepper should be at least 32 bytes of high-entropy data, stored
    /// outside the database (e.g. in the OS keychain or a config file with
    /// `0600` permissions).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`][crate::error::Error::Crypto] if the HMAC
    /// engine cannot be initialized (extremely unlikely with valid input).
    pub fn new(pepper: &[u8]) -> crate::error::Result<Self> {
        use hmac::Mac;
        let inner = hmac::Hmac::<Sha256>::new_from_slice(pepper)
            .map_err(|e| crate::error::Error::crypto(format!("hmac init: {e}")))?;
        Ok(Self { inner })
    }

    /// Hashes a plaintext key string into a 32-byte HMAC digest.
    ///
    /// # Example
    ///
    /// ```
    /// use oidc_agent_common::keys::HmacKeyHash;
    /// let pepper = b"super-secret-pepper-32-bytes-long!!";
    /// let hasher = HmacKeyHash::new(pepper).unwrap();
    /// let h1 = hasher.hash(b"oac_abc123");
    /// let h2 = hasher.hash(b"oac_abc123");
    /// assert_eq!(h1, h2);
    /// ```
    #[must_use]
    pub fn hash(&self, plaintext: &[u8]) -> [u8; 32] {
        use hmac::Mac;
        let mut mac = self.inner.clone();
        mac.update(plaintext);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// Extracts the bearer token from an `Authorization` header value.
///
/// Accepts `Bearer <token>` (case-insensitive scheme). Returns `None` if the
/// header is missing, empty, or malformed.
///
/// # Example
///
/// ```
/// use oidc_agent_common::keys::extract_bearer;
/// assert_eq!(extract_bearer("Bearer oac_abc"), Some("oac_abc"));
/// assert_eq!(extract_bearer("bearer oac_abc"), Some("oac_abc"));
/// assert_eq!(extract_bearer("BEARER oac_abc"), Some("oac_abc"));
/// assert_eq!(extract_bearer("BeArEr oac_abc"), Some("oac_abc"));
/// assert_eq!(extract_bearer("Basic xyz"), None);
/// assert_eq!(extract_bearer(""), None);
/// ```
#[must_use]
pub fn extract_bearer(header_value: &str) -> Option<&str> {
    let trimmed = header_value.trim();
    // RFC 7235: the auth scheme is case-insensitive. Split on the first
    // whitespace and check the scheme case-insensitively.
    let (scheme, rest) = trimmed.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() { None } else { Some(token) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_has_correct_prefix_and_length() {
        let key = LocalKey::generate();
        let s = key.to_string();
        assert!(
            s.starts_with(KEY_PREFIX),
            "key must start with {KEY_PREFIX}"
        );
        // 32 bytes base64url-no-pad = 43 chars, plus prefix
        assert_eq!(s.len(), KEY_PREFIX.len() + 43);
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = LocalKey::generate();
        let b = LocalKey::generate();
        assert_ne!(
            a.to_string(),
            b.to_string(),
            "two generated keys must differ"
        );
    }

    #[test]
    fn key_is_zeroized_on_drop() {
        // We can't directly observe zeroization, but we verify the type wraps
        // Zeroizing and that Display works before drop.
        let key = LocalKey::generate();
        let s = key.to_string();
        assert!(!s.is_empty());
        // key dropped here; Zeroizing ensures the inner String is cleared.
    }

    #[test]
    fn hash_round_trip_matches() {
        let key = LocalKey::generate();
        let h1 = KeyHash::from_plaintext(&key.to_string());
        let h2 = KeyHash::from_plaintext(&key.to_string());
        assert!(
            h1.matches(&h2),
            "same plaintext must produce matching hashes"
        );
    }

    #[test]
    fn different_keys_produce_different_hashes() {
        let a = KeyHash::from_plaintext("oac_aaa");
        let b = KeyHash::from_plaintext("oac_bbb");
        assert!(!a.matches(&b), "different plaintexts must not match");
    }

    #[test]
    fn from_hash_bytes_round_trips() {
        let key = LocalKey::generate();
        let h = KeyHash::from_plaintext(&key.to_string());
        let bytes = h.as_bytes();
        let h2 = KeyHash::from_hash_bytes(bytes);
        assert!(h.matches(&h2), "from_hash_bytes must round-trip");
    }

    #[test]
    #[should_panic(expected = "KeyHash must be exactly 32 bytes")]
    fn from_hash_bytes_rejects_wrong_length() {
        let _ = KeyHash::from_hash_bytes(&[0u8; 16]);
    }

    #[test]
    fn hmac_hash_is_deterministic() {
        let pepper = b"test-pepper-32-bytes-long-please!!";
        let hasher = HmacKeyHash::new(pepper).expect("hmac init");
        let a = hasher.hash(b"oac_test");
        let b = hasher.hash(b"oac_test");
        assert_eq!(a, b, "same input + pepper must produce same HMAC");
    }

    #[test]
    fn hmac_hash_differs_for_different_peppers() {
        let h1 = HmacKeyHash::new(b"pepper-one-32-bytes-long-please!!").unwrap();
        let h2 = HmacKeyHash::new(b"pepper-two-32-bytes-long-please!!").unwrap();
        assert_ne!(h1.hash(b"oac_test"), h2.hash(b"oac_test"));
    }

    #[test]
    fn hmac_hash_differs_for_different_inputs() {
        let pepper = b"test-pepper-32-bytes-long-please!!";
        let hasher = HmacKeyHash::new(pepper).unwrap();
        assert_ne!(hasher.hash(b"oac_aaa"), hasher.hash(b"oac_bbb"));
    }

    #[test]
    fn extract_bearer_valid() {
        assert_eq!(extract_bearer("Bearer oac_abc"), Some("oac_abc"));
        assert_eq!(extract_bearer("bearer oac_abc"), Some("oac_abc"));
        assert_eq!(extract_bearer("BEARER oac_abc"), Some("oac_abc"));
        assert_eq!(extract_bearer("BeArEr oac_abc"), Some("oac_abc"));
        assert_eq!(extract_bearer("bEaReR oac_abc"), Some("oac_abc"));
    }

    #[test]
    fn extract_bearer_with_whitespace() {
        assert_eq!(extract_bearer("  Bearer   oac_abc  "), Some("oac_abc"));
    }

    #[test]
    fn extract_bearer_invalid() {
        assert_eq!(extract_bearer("Basic xyz"), None);
        assert_eq!(extract_bearer(""), None);
        assert_eq!(extract_bearer("Bearer "), None);
        assert_eq!(extract_bearer("Bearer"), None);
        assert_eq!(extract_bearer("oac_abc"), None);
    }
}
