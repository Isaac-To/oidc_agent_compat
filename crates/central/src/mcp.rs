//! Runtime-managed MCP server endpoints for the central proxy.
//!
//! MCP servers are configured through the admin API and stored in the
//! central database. Optional per-server auth headers (e.g. an
//! `Authorization` value) are encrypted with AES-256-GCM before persistence
//! and resolved only into the forwarding path as zeroizing plaintext — never
//! logged, never returned by any API.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryOrder, Set,
    Statement, Value,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::time_util;

use crate::entity::mcp_server;

/// A configured MCP server endpoint (metadata only; no plaintext auth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerInfo {
    /// Stable server identifier.
    pub id: String,
    /// Human-readable name for audit and admin display.
    pub name: String,
    /// Base URL of the MCP Streamable HTTP endpoint.
    pub base_url: String,
    /// Whether this server accepts traffic.
    pub enabled: bool,
    /// Whether an auth header is configured for this server.
    pub has_auth: bool,
    /// Creation time.
    pub created_at: time::PrimitiveDateTime,
    /// Last update time.
    pub updated_at: time::PrimitiveDateTime,
}

/// Incremental input used to create a new MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerInput {
    /// Stable server identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Base URL of the MCP Streamable HTTP endpoint.
    pub base_url: String,
    /// Whether this server accepts traffic.
    pub enabled: bool,
    /// Optional `Header-Name: value` pair to attach on every forwarded
    /// request to this server (e.g. `Authorization: Bearer ...`). Stored
    /// encrypted at rest.
    pub auth_header: Option<String>,
}

impl McpServerInput {
    /// Validates that all fields are well-formed.
    pub fn validate(&self) -> Result<()> {
        let id = self.id.trim();
        if id.is_empty() || id.contains('/') || id.contains(' ') {
            return Err(Error::Config(
                "MCP server id must be non-empty and must not contain '/' or spaces".into(),
            ));
        }
        if self.name.trim().is_empty() {
            return Err(Error::Config("MCP server name must not be empty".into()));
        }
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(Error::Config(format!(
                "MCP server base_url must be an absolute http(s) URL, got '{}'",
                self.base_url
            )));
        }
        Ok(())
    }
}

/// An update to an MCP server, retaining its stable identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerUpdate {
    /// Human-readable name.
    pub name: String,
    /// Base URL of the MCP Streamable HTTP endpoint.
    pub base_url: String,
    /// Whether this server accepts traffic.
    pub enabled: bool,
    /// New `Header: value` pair, or `None` to keep the existing encrypted
    /// value unchanged.
    pub auth_header: Option<Option<String>>,
}

/// A resolved, ready-to-use MCP server connection.
///
/// The auth header, if any, is a zeroizing plaintext that is dropped once
/// the request completes.
#[derive(Debug)]
pub struct ResolvedMcpServer {
    /// Stable server identifier.
    pub id: String,
    /// Base URL of the MCP endpoint.
    pub base_url: String,
    /// Full `Header: value` pair to attach, or `None`.
    pub auth_header: Option<Zeroizing<String>>,
}

/// Stores MCP server metadata and encrypted auth headers in the central DB.
#[derive(Clone)]
pub struct McpManager {
    db: DatabaseConnection,
    encryption_key: Arc<Zeroizing<[u8; 32]>>,
    /// The outbound HTTP client used to reach upstream MCP servers.
    client: reqwest::Client,
}

impl McpManager {
    /// Creates an `McpManager` with the supplied 32-byte encryption key and
    /// an HTTP client tailored for MCP forwarding (no redirects followed).
    #[must_use]
    pub fn new(db: DatabaseConnection, encryption_key: Zeroizing<[u8; 32]>) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("mcp client builder should never fail");
        Self {
            db,
            encryption_key: Arc::new(encryption_key),
            client,
        }
    }

    /// Returns a reference to the underlying database connection.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Returns a reference to the outbound HTTP client.
    #[must_use]
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Parses a 32-byte AES key from a hexadecimal string.
    ///
    /// # Errors
    /// Returns [`Error::Config`] if the value is not exactly 64 hexadecimal
    /// characters.
    pub fn encryption_key_from_hex(value: &str) -> Result<Zeroizing<[u8; 32]>> {
        let trimmed = value.trim();
        if trimmed.len() != 64 {
            return Err(Error::Config(
                "MCP encryption key must be exactly 64 hexadecimal characters".into(),
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
            let byte = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| {
                Error::Config("MCP encryption key must be hexadecimal".into())
            })?, 16)
            .map_err(|_| Error::Config("MCP encryption key must be hexadecimal".into()))?;
            key[i] = byte;
        }
        Ok(key)
    }

    /// Creates a new MCP server, encrypting any supplied auth header.
    ///
    /// If a server with the same id already exists, its name/base_url/enabled
    /// are updated, and the auth header is replaced only when a new one is
    /// supplied.
    ///
    /// # Errors
    /// Returns [`Error::Config`] on validation failure, or
    /// [`Error::Database`] on persistence failure.
    pub async fn upsert_server(&self, input: &McpServerInput) -> Result<McpServerInfo> {
        input.validate()?;
        let now = time_util::now_utc();
        let (ciphertext, nonce): (Vec<u8>, [u8; 12]) = match &input.auth_header {
            Some(header) => encrypt(&self.encryption_key, header)?,
            None => (Vec::new(), [0u8; 12]),
        };
        let existing = mcp_server::Entity::find_by_id(&input.id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("load mcp server: {e}")))?;

        if let Some(existing) = existing {
            // Update in place. The auth header is replaced only when a new
            // value is supplied.
            let mut active: mcp_server::ActiveModel = existing.into();
            active.name = Set(input.name.trim().to_string());
            active.base_url = Set(input.base_url.trim().to_string());
            active.enabled = Set(input.enabled);
            if input.auth_header.is_some() {
                active.auth_ciphertext = Set(ciphertext.clone());
                active.auth_nonce = Set(nonce.to_vec());
            }
            active.updated_at = Set(now);
            let model = active
                .update(&self.db)
                .await
                .map_err(|e| Error::database(format!("update mcp server: {e}")))?;
            Ok(self.info(model))
        } else {
            // Insert via raw SQL. Sea-ORM's `insert()` relied on
            // last_insert_id for the string PK on SQLite, which failed; raw
            // SQL matches the proven provider-store pattern.
            let id = input.id.trim().to_string();
            self.db
                .execute(Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    "INSERT INTO mcp_servers (id, name, base_url, enabled, auth_ciphertext, auth_nonce, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    vec![
                        id.clone().into(),
                        input.name.trim().to_string().into(),
                        input.base_url.trim().to_string().into(),
                        Value::Bool(Some(input.enabled)),
                        Value::Bytes(Some(Box::new(ciphertext))),
                        Value::Bytes(Some(Box::new(nonce.to_vec()))),
                        time_util::format_time(&now).into(),
                        time_util::format_time(&now).into(),
                    ],
                ))
                .await
                .map_err(|e| Error::database(format!("insert mcp server: {e}")))?;
            self.get_server(&id)
                .await?
                .ok_or_else(|| Error::database("mcp server inserted but could not be loaded"))
        }
    }

    /// Returns the metadata for a single MCP server, if present.
    pub async fn get_server(&self, id: &str) -> Result<Option<McpServerInfo>> {
        let row = mcp_server::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("get mcp server: {e}")))?;
        Ok(row.map(|m| self.info(m)))
    }

    /// Lists all configured MCP servers, ordered by id.
    pub async fn list_servers(&self) -> Result<Vec<McpServerInfo>> {
        let rows = mcp_server::Entity::find()
            .order_by_asc(mcp_server::Column::Id)
            .all(&self.db)
            .await
            .map_err(|e| Error::database(format!("list mcp servers: {e}")))?;
        Ok(rows.into_iter().map(|m| self.info(m)).collect())
    }

    /// Deletes an MCP server. Returns `true` if a server was removed.
    pub async fn delete_server(&self, id: &str) -> Result<bool> {
        let result = mcp_server::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::database(format!("delete mcp server: {e}")))?;
        Ok(result.rows_affected > 0)
    }

    /// Resolves a server for outbound forwarding, plus its decrypted auth
    /// header (zeroized on drop). Returns `Ok(None)` if the server does not
    /// exist or is disabled.
    ///
    /// # Errors
    /// Returns [`Error::Config`] if the decrypted auth header could not be
    /// decoded (SQLite stores `BLOB`; stored plaintext bytes are safe), or
    /// [`Error::Crypto`] on decrypt failure, or [`Error::Database`] on DB
    /// failure.
    pub async fn resolve_server(&self, id: &str) -> Result<Option<ResolvedMcpServer>> {
        let row = mcp_server::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("resolve mcp server: {e}")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !row.enabled {
            return Ok(None);
        }
        let auth_header = if row.auth_ciphertext.is_empty() {
            None
        } else {
            let plain = decrypt(&self.encryption_key, &row.auth_ciphertext, &row.auth_nonce)?;
            let s = String::from_utf8(plain.as_slice().to_vec())
                .map_err(|_| Error::crypto("stored MCP auth header is not valid UTF-8"))?;
            Some(Zeroizing::new(s))
        };
        Ok(Some(ResolvedMcpServer {
            id: row.id,
            base_url: row.base_url,
            auth_header,
        }))
    }

    fn info(&self, model: mcp_server::Model) -> McpServerInfo {
        McpServerInfo {
            id: model.id,
            name: model.name,
            base_url: model.base_url,
            enabled: model.enabled,
            has_auth: !model.auth_ciphertext.is_empty(),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

/// Encrypts `secret` with AES-256-GCM using `key`.
fn encrypt(key: &[u8; 32], secret: &str) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::crypto("invalid MCP encryption key"))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|_| Error::crypto("encrypt MCP auth header"))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypts `ciphertext` for `nonce` using `key`.
fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::crypto("invalid MCP auth header nonce"))?;
    let nonce = Nonce::from(*nonce);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::crypto("invalid MCP encryption key"))?;
    let plain = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::crypto("decrypt MCP auth header"))?;
    Ok(Zeroizing::new(plain))
}

/// Computes the SHA-256 of a value (used for diagnostics; never stored where
/// it would leak).
#[allow(dead_code)]
pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc_agent_common::persistence;
    use sea_orm_migration::MigratorTrait;

    async fn setup_manager(key: Zeroizing<[u8; 32]>) -> McpManager {
        let url = persistence::temp_sqlite_url("mcp");
        let db = sea_orm::Database::connect(&url).await.expect("connect");
        crate::migration::Migrator::up(&db, None).await.expect("migrate");
        McpManager::new(db, key)
    }

    #[tokio::test]
    async fn upsert_and_resolve_round_trip_with_auth() {
        let mgr = setup_manager(Zeroizing::new([7u8; 32])).await;
        let input = McpServerInput {
            id: "github".into(),
            name: "GitHub".into(),
            base_url: "https://mcp.example.com".into(),
            enabled: true,
            auth_header: Some("Authorization: Bearer sekrit".into()),
        };
        mgr.upsert_server(&input).await.expect("upsert");
        let info = mgr.get_server("github").await.expect("get").expect("some");
        assert!(info.has_auth);
        assert!(!info.base_url.is_empty());

        let resolved = mgr.resolve_server("github").await.expect("resolve");
        let resolved = resolved.expect("server exists");
        assert_eq!(resolved.base_url, "https://mcp.example.com");
        assert_eq!(
            resolved.auth_header.as_deref().map(AsRef::as_ref),
            Some("Authorization: Bearer sekrit")
        );
    }

    #[tokio::test]
    async fn disabled_server_is_not_resolved() {
        let mgr = setup_manager(Zeroizing::new([7u8; 32])).await;
        mgr.upsert_server(&McpServerInput {
            id: "down".into(),
            name: "Down".into(),
            base_url: "https://mcp.example.com".into(),
            enabled: false,
            auth_header: None,
        })
        .await
        .expect("upsert");
        assert!(mgr.resolve_server("down").await.expect("resolve").is_none());
    }

    #[tokio::test]
    async fn delete_server_removes_it() {
        let mgr = setup_manager(Zeroizing::new([7u8; 32])).await;
        mgr.upsert_server(&McpServerInput {
            id: "s".into(),
            name: "S".into(),
            base_url: "https://mcp.example.com".into(),
            enabled: true,
            auth_header: None,
        })
        .await
        .expect("upsert");
        assert!(mgr.delete_server("s").await.expect("delete"));
        assert!(!mgr.delete_server("s").await.expect("delete again"));
        assert!(mgr.get_server("s").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn wrong_key_cannot_decrypt_auth() {
        // Decrypting ciphertext produced under a different key must fail
        // cleanly rather than returning garbage.
        let right = [3u8; 32];
        let (ct, nonce) = encrypt(&right, "Authorization: Bearer sekrit").expect("encrypt");
        let wrong = Zeroizing::new([9u8; 32]);
        assert!(decrypt(&wrong, &ct, &nonce).is_err());
    }

    #[test]
    fn validates_server_input() {
        let good = McpServerInput {
            id: "a".into(),
            name: "A".into(),
            base_url: "https://x".into(),
            enabled: true,
            auth_header: None,
        };
        assert!(good.validate().is_ok());
        let bad = McpServerInput {
            id: "a/b".into(),
            ..good.clone()
        };
        assert!(bad.validate().is_err());
        let bad_url = McpServerInput {
            base_url: "ftp://x".into(),
            ..good.clone()
        };
        assert!(bad_url.validate().is_err());
    }

    #[test]
    fn parses_hex_encryption_key() {
        let key = McpManager::encryption_key_from_hex(&"ab".repeat(32)).expect("valid");
        assert_eq!(key.len(), 32);
    }
    #[test]
    fn rejects_invalid_encryption_key() {
        assert!(McpManager::encryption_key_from_hex("nope").is_err());
        assert!(McpManager::encryption_key_from_hex(&"ab".repeat(31)).is_err());
        #[allow(clippy::indexing_slicing)]
        {
            let s = "ab".repeat(31) + "zz";
            assert!(McpManager::encryption_key_from_hex(&s).is_err());
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [3u8; 32];
        let (ct, nonce) = encrypt(&key, "secret").expect("encrypt");
        assert_ne!(ct, b"secret");
        let pt = decrypt(&key, &ct, &nonce).expect("decrypt");
        assert_eq!(pt.as_slice(), b"secret".as_slice());
    }
}