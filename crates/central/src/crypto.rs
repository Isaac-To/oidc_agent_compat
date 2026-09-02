//! Shared cryptographic helpers for the central proxy.
//!
//! Provides the AES-256-GCM encryption key parser and SHA-256 digest
//! helper used by both the provider key store ([`crate::provider`]) and the
//! MCP server store ([`crate::mcp`]). Centralizing these avoids duplicated
//! parsing logic and inconsistent error messages.

use oidc_agent_common::error::{Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Parses a 32-byte AES-256 key from a 64-character hexadecimal string.
///
/// Leading and trailing whitespace is trimmed before parsing. The key is
/// returned in [`Zeroizing`] memory so it is cleared on drop.
///
/// # Errors
///
/// Returns [`Error::Config`] when the value is not exactly 64 hexadecimal
/// characters or contains non-hexadecimal characters.
pub fn encryption_key_from_hex(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return Err(Error::Config(
            "encryption key must be exactly 64 hexadecimal characters".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(
            std::str::from_utf8(chunk)
                .map_err(|_| Error::Config("encryption key must be hexadecimal".into()))?,
            16,
        )
        .map_err(|_| Error::Config("encryption key must be hexadecimal".into()))?;
        if let Some(slot) = key.get_mut(i) {
            *slot = byte;
        }
    }
    Ok(key)
}

/// Computes the SHA-256 digest of a byte slice and returns it as a
/// lowercase hexadecimal string.
#[must_use]
pub fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let out = hasher.finalize();
    format!("{out:x}")
}
