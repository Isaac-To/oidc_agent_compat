//! mTLS (mutual TLS) configuration builders for relay ↔ central communication.
//!
//! This module builds [`rustls`] client and server configurations that enforce
//! mutual authentication using a company-issued CA. The relay presents a
//! per-device client certificate; the central proxy validates it against the
//! CA and records the device identity.
//!
//! # Security
//!
//! - TLS 1.3 is preferred (RFC 8446); TLS 1.2 is the minimum.
//! - Server certificate verification is always enabled; `danger_accept_invalid`
//!   is never used.
//! - Client certificates are required on the server side (mutual auth).
//! - PEM files loaded from disk must have `0600` permissions for private keys.
//!
//! # References
//!
//! - RFC 8446 — TLS 1.3.
//! - RFC 9325 — TLS Best Current Practices (BCP 195).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{Error, Result};

/// Loads PEM-encoded certificates from a file.
///
/// # Errors
///
/// Returns [`Error::Tls`] if the file cannot be read or the PEM is malformed.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Tls(format!("read cert file {}: {e}", path.display())))?;
    let mut reader = std::io::Cursor::new(bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Tls(format!("parse PEM certs: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Tls(format!(
            "no certificates found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

/// Loads a PEM-encoded private key from a file.
///
/// # Errors
///
/// Returns [`Error::Tls`] if the file cannot be read, the PEM is malformed,
/// or no private key is found.
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Tls(format!("read key file {}: {e}", path.display())))?;
    let mut reader = std::io::Cursor::new(bytes);
    let keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::private_key(&mut reader)
        .map(|opt| opt.into_iter().collect())
        .map_err(|e| Error::Tls(format!("parse PEM key: {e}")))?;
    keys.into_iter()
        .next()
        .ok_or_else(|| Error::Tls(format!("no private key in {}", path.display())))
}

/// Verifies that a file has `0600` permissions (owner read/write only).
///
/// On non-Unix systems this is a no-op (returns `Ok`).
///
/// # Errors
///
/// Returns [`Error::Tls`] on Unix if the file permissions are more permissive
/// than `0600`.
#[cfg(unix)]
pub fn enforce_secure_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(path).map_err(|e| Error::Tls(format!("stat {}: {e}", path.display())))?;
    let mode = metadata.permissions().mode();
    // Mask to the permission bits (0o7777 includes setuid etc.).
    let perm_bits = mode & 0o777;
    if perm_bits != 0o600 {
        return Err(Error::Tls(format!(
            "file {} has permissions {perm_bits:o}; expected 0600 for private keys",
            path.display()
        )));
    }
    Ok(())
}

/// Verifies that a file has `0600` permissions. No-op on non-Unix.
#[cfg(not(unix))]
#[allow(clippy::missing_docs_in_private_items)]
pub fn enforce_secure_perms(_path: &Path) -> Result<()> {
    Ok(())
}

/// Builds a rustls [`ClientConfig`] for the relay to connect to the central
/// proxy with mTLS.
///
/// # Arguments
///
/// * `ca_cert_path` — Path to the company CA certificate (PEM).
/// * `client_cert_path` — Path to the relay's client certificate (PEM).
/// * `client_key_path` — Path to the relay's client private key (PEM, `0600`).
///
/// # Errors
///
/// Returns [`Error::Tls`] if any file cannot be read, the PEM is malformed,
/// or the TLS configuration cannot be built.
pub fn build_client_config(
    ca_cert_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
) -> Result<ClientConfig> {
    enforce_secure_perms(client_key_path)?;

    let ca_certs = load_certs(ca_cert_path)?;
    let client_certs = load_certs(client_cert_path)?;
    let client_key = load_private_key(client_key_path)?;

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| Error::Tls(format!("add CA cert: {e}")))?;
    }

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| Error::Tls(format!("build client config: {e}")))
}

/// Builds a rustls [`ServerConfig`] for the central proxy to require mTLS
/// from relays.
///
/// # Arguments
///
/// * `ca_cert_path` — Path to the company CA certificate (PEM).
/// * `server_cert_path` — Path to the server certificate (PEM).
/// * `server_key_path` — Path to the server private key (PEM, `0600`).
///
/// # Errors
///
/// Returns [`Error::Tls`] if any file cannot be read, the PEM is malformed,
/// or the TLS configuration cannot be built.
pub fn build_server_config(
    ca_cert_path: &Path,
    server_cert_path: &Path,
    server_key_path: &Path,
) -> Result<ServerConfig> {
    enforce_secure_perms(server_key_path)?;

    let ca_certs = load_certs(ca_cert_path)?;
    let server_certs = load_certs(server_cert_path)?;
    let server_key = load_private_key(server_key_path)?;

    let mut client_auth_root = RootCertStore::empty();
    for cert in ca_certs {
        client_auth_root
            .add(cert)
            .map_err(|e| Error::Tls(format!("add client CA cert: {e}")))?;
    }

    let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_root))
        .build()
        .map_err(|e| Error::Tls(format!("build client verifier: {e}")))?;

    ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| Error::Tls(format!("build server config: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_certs_missing_file_returns_tls_error() {
        let err = load_certs(Path::new("/nonexistent/cert.pem")).unwrap_err();
        assert!(err.to_string().contains("read cert file"), "{err}");
    }

    #[test]
    fn load_private_key_missing_file_returns_tls_error() {
        let err = load_private_key(Path::new("/nonexistent/key.pem")).unwrap_err();
        assert!(err.to_string().contains("read key file"), "{err}");
    }

    #[test]
    fn load_certs_empty_file_returns_tls_error() {
        let tmp = tempfile_in_memory("");
        let err = load_certs(&tmp).unwrap_err();
        assert!(err.to_string().contains("no certificates"), "{err}");
    }

    #[test]
    fn load_private_key_empty_file_returns_tls_error() {
        let tmp = tempfile_in_memory("");
        let err = load_private_key(&tmp).unwrap_err();
        assert!(err.to_string().contains("no private key"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn enforce_secure_perms_rejects_world_readable() {
        let tmp = tempfile_in_memory("test");
        // Set permissive perms.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = enforce_secure_perms(&tmp).unwrap_err();
        assert!(err.to_string().contains("0600"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn enforce_secure_perms_accepts_0600() {
        let tmp = tempfile_in_memory("test");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(enforce_secure_perms(&tmp).is_ok());
    }

    /// Creates a temp file with the given content and returns its path.
    fn tempfile_in_memory(content: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "oac-test-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(&path, content).expect("write temp file");
        path
    }
}
