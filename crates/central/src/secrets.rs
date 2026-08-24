//! Secret store abstraction for the master backend key.
//!
//! The central proxy holds the master backend key in a managed secret store
//! (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault). This
//! module provides a trait abstraction so the central proxy is portable
//! across backends.
//!
//! # Security
//!
//! - The master key is loaded into [`Zeroizing`] memory at startup.
//! - It is never written to disk, never logged, never sent to any laptop.
//! - The `set-backend-key` subcommand writes the key via `rpassword` (no echo)
//!   directly to the secret store.
//!
//! # v1
//!
//! v1 ships a [`FileSecretStore`] for development/testing (reads from a file
//! with `0600` permissions). Production deployments use Vault or AWS SM
//! (Phase 2).

use std::path::PathBuf;

use oidc_agent_common::error::{Error, Result};
use zeroize::Zeroizing;

/// A trait for secret stores that hold the master backend key.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Loads the master key from the store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SecretStore`] if the key cannot be loaded.
    async fn load_master_key(&self) -> Result<Zeroizing<String>>;

    /// Stores the master key in the store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SecretStore`] if the key cannot be stored.
    async fn store_master_key(&self, key: &str) -> Result<()>;
}

/// A file-based secret store for development/testing.
///
/// Reads/writes the master key from a file with `0600` permissions. This is
/// NOT suitable for production — use [`VaultSecretStore`] or
/// [`AwsSecretStore`] (Phase 2).
pub struct FileSecretStore {
    /// The path to the key file.
    path: PathBuf,
}

impl FileSecretStore {
    /// Creates a new `FileSecretStore` pointing at the given path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait::async_trait]
impl SecretStore for FileSecretStore {
    async fn load_master_key(&self) -> Result<Zeroizing<String>> {
        // Enforce 0600 permissions on read (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&self.path)
                .map_err(|e| Error::SecretStore(format!("stat {}: {e}", self.path.display())))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(Error::SecretStore(format!(
                    "master key file {} has permissions {mode:o}; expected 0600",
                    self.path.display()
                )));
            }
        }

        // Read into Zeroizing memory directly — no intermediate plain String.
        let contents = Zeroizing::new(
            std::fs::read_to_string(&self.path)
                .map_err(|e| Error::SecretStore(format!("read {}: {e}", self.path.display())))?,
        );
        let trimmed = Zeroizing::new(contents.trim().to_string());
        if trimmed.is_empty() {
            return Err(Error::SecretStore(format!(
                "master key file {} is empty",
                self.path.display()
            )));
        }
        Ok(trimmed)
    }

    async fn store_master_key(&self, key: &str) -> Result<()> {
        std::fs::write(&self.path, key)
            .map_err(|e| Error::SecretStore(format!("write {}: {e}", self.path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::SecretStore(format!("chmod {}: {e}", self.path.display())))?;
        }
        Ok(())
    }
}

/// Creates a [`SecretStore`] from the config.
///
/// # Errors
///
/// Returns [`Error::SecretStore`] if the backend kind is not supported.
pub fn from_config(
    config: &oidc_agent_common::config::SecretStoreConfig,
) -> Result<Box<dyn SecretStore>> {
    match config.kind {
        oidc_agent_common::config::SecretStoreKind::File => Ok(Box::new(FileSecretStore::new(
            std::path::PathBuf::from(&config.path),
        ))),
        oidc_agent_common::config::SecretStoreKind::Vault => {
            // Phase 2: implement Vault client.
            Err(Error::SecretStore(
                "Vault backend not yet implemented — use 'file' for dev".into(),
            ))
        }
        oidc_agent_common::config::SecretStoreKind::Aws => {
            // Phase 2: implement AWS SM client.
            Err(Error::SecretStore(
                "AWS Secrets Manager backend not yet implemented — use 'file' for dev".into(),
            ))
        }
        oidc_agent_common::config::SecretStoreKind::Gcp => Err(Error::SecretStore(
            "GCP Secret Manager backend not yet implemented".into(),
        )),
        oidc_agent_common::config::SecretStoreKind::Azure => Err(Error::SecretStore(
            "Azure Key Vault backend not yet implemented".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_secret_store_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-secret-test-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let store = FileSecretStore::new(tmp.clone());

        // Store a key.
        store
            .store_master_key("sk-test-master-key-12345")
            .await
            .expect("store");

        // Load it back.
        let loaded = store.load_master_key().await.expect("load");
        assert_eq!(&*loaded, "sk-test-master-key-12345");

        // Verify file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600, got {mode:o}");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn file_secret_store_rejects_empty_key() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-secret-empty-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(&tmp, "  \n  ").expect("write");
        let store = FileSecretStore::new(tmp.clone());
        let err = store.load_master_key().await.unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn file_secret_store_trims_whitespace() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-secret-trim-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let store = FileSecretStore::new(tmp.clone());
        store
            .store_master_key("sk-key-with-newline\n")
            .await
            .expect("store");
        let loaded = store.load_master_key().await.expect("load");
        assert_eq!(&*loaded, "sk-key-with-newline");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn from_config_vault_returns_not_implemented() {
        let cfg = oidc_agent_common::config::SecretStoreConfig {
            kind: oidc_agent_common::config::SecretStoreKind::Vault,
            path: "secret/data/oac".into(),
        };
        let result = from_config(&cfg);
        assert!(result.is_err(), "Vault should not be implemented yet");
        let err = result.err().unwrap();
        assert!(err.to_string().contains("not yet implemented"), "{err}");
    }
}
