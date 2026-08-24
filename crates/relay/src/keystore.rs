//! Key store service — manages local API keys in the database.
//!
//! This module provides the business logic for minting, storing, looking up,
//! and verifying local API keys. It uses the crypto primitives from
//! [`oidc_agent_common::keys`] and the sea-orm entities.
//!
//! # Security
//!
//! - Keys are minted with 256 bits of OS CSPRNG entropy.
//! - Only the SHA-256 hash is stored in the database; the plaintext key is
//!   returned to the caller once (for agent config injection) and never
//!   persisted.
//! - Verification uses constant-time comparison via [`subtle::ConstantTimeEq`].

use oidc_agent_common::keys::{KeyHash, LocalKey};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Statement, Value,
};
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::entity::{api_key, identity};
use oidc_agent_common::error::{Error, Result};

/// Returns the current UTC time as a `PrimitiveDateTime` (for sea-orm).
fn now_utc() -> PrimitiveDateTime {
    let offset = time::OffsetDateTime::now_utc();
    PrimitiveDateTime::new(offset.date(), offset.time())
}

/// Formats a `PrimitiveDateTime` as a string for SQLite.
fn format_time(t: &PrimitiveDateTime) -> String {
    // Use the time crate's built-in format items.
    t.format(time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second]"
    ))
    .unwrap_or_default()
}

/// A key store backed by the relay's SQLite database.
#[derive(Clone)]
pub struct KeyStore {
    /// The database connection (pub(crate) for use in main.rs logout).
    pub db: DatabaseConnection,
}

/// The result of minting a key: the plaintext key (returned once) and the
/// identity it's bound to.
pub struct MintedKey {
    /// The plaintext local key. The caller must inject this into the agent
    /// config and then drop it. It is never persisted.
    pub plaintext: LocalKey,
    /// The database ID of the key record.
    pub key_id: String,
    /// The database ID of the identity.
    pub identity_id: String,
}

impl KeyStore {
    /// Creates a new `KeyStore` wrapping the given database connection.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Finds an existing identity by issuer + subject, or creates a new one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query/insert failure.
    pub async fn upsert_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        groups: Option<&str>,
    ) -> Result<identity::Model> {
        // Try to find an existing identity.
        let existing = identity::Entity::find()
            .filter(identity::Column::Issuer.eq(issuer))
            .filter(identity::Column::Subject.eq(subject))
            .one(&self.db)
            .await
            .map_err(|e| Error::Database(format!("find identity: {e}")))?;

        if let Some(model) = existing {
            return Ok(model);
        }

        // Create a new identity using parameterized SQL.
        let now = now_utc();
        let id = Uuid::new_v4().to_string();
        let now_str = format_time(&now);
        let email_val = email
            .map(|e| Value::String(Some(Box::new(e.to_string()))))
            .unwrap_or(Value::String(None));
        let display_val = display_name
            .map(|d| Value::String(Some(Box::new(d.to_string()))))
            .unwrap_or(Value::String(None));
        let groups_val = groups
            .map(|g| Value::String(Some(Box::new(g.to_string()))))
            .unwrap_or(Value::String(None));
        let sql = "INSERT INTO identities (id, issuer, subject, email, display_name, groups, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)";
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    id.clone().into(),
                    issuer.to_string().into(),
                    subject.to_string().into(),
                    email_val,
                    display_val,
                    groups_val,
                    now_str.into(),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("insert identity: {e}")))?;
        Ok(identity::Model {
            id,
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            email: email.map(String::from),
            display_name: display_name.map(String::from),
            groups: groups.map(String::from),
            created_at: now,
        })
    }

    /// Mints a new local API key bound to the given identity.
    ///
    /// # Security
    ///
    /// The plaintext key is returned once via [`MintedKey`]; only the SHA-256
    /// hash is stored in the database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert failure.
    pub async fn mint_key(&self, identity_id: &str, label: &str) -> Result<MintedKey> {
        let plaintext = LocalKey::generate();
        let hash = KeyHash::from_plaintext(&plaintext.to_string());
        let now = now_utc();
        let key_id = Uuid::new_v4().to_string();
        let now_str = format_time(&now);

        // Use parameterized SQL to prevent injection.
        let sql = "INSERT INTO api_keys (id, identity_id, key_hash, label, created_at, last_used_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)";
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    key_id.clone().into(),
                    identity_id.to_string().into(),
                    Value::Bytes(Some(Box::new(hash.as_bytes().to_vec()))),
                    label.to_string().into(),
                    now_str.into(),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("insert api key: {e}")))?;

        Ok(MintedKey {
            plaintext,
            key_id,
            identity_id: identity_id.to_string(),
        })
    }

    /// Verifies a bearer token against the stored key hashes.
    ///
    /// Returns the matching key + identity if found, or `None` if no key
    /// matches. Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Security
    ///
    /// Iterates through **all** keys and compares each in constant time,
    /// without early return — this prevents timing leaks that would reveal
    /// which key index matched (CWE-208). On a match, updates `last_used_at`
    /// using parameterized SQL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn verify_key(
        &self,
        bearer_token: &str,
    ) -> Result<Option<(api_key::Model, identity::Model)>> {
        let candidate_hash = KeyHash::from_plaintext(bearer_token);

        // Load all keys. For a laptop relay with a handful of keys this is
        // fine. For a larger deployment, we'd index by hash and do a direct
        // lookup (the hash is not secret once computed).
        let keys = api_key::Entity::find()
            .find_also_related(identity::Entity)
            .all(&self.db)
            .await
            .map_err(|e| Error::Database(format!("load keys: {e}")))?;

        // Iterate ALL keys without early return to prevent timing leaks.
        let mut found: Option<(api_key::Model, identity::Model)> = None;
        for (key, ident) in &keys {
            let stored_hash = KeyHash::from_hash_bytes(&key.key_hash);
            if stored_hash.matches(&candidate_hash) && found.is_none() {
                let ident = ident.clone().ok_or_else(|| {
                    Error::Database(format!(
                        "key {} has no associated identity (foreign key violation)",
                        key.id
                    ))
                })?;
                found = Some((key.clone(), ident));
            }
        }

        // Update last_used_at if we found a match (outside the loop).
        if let Some((key, _)) = &found {
            let now = now_utc();
            let now_str = format_time(&now);
            let sql = "UPDATE api_keys SET last_used_at = $1 WHERE id = $2";
            let _ = self
                .db
                .execute(Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    sql,
                    vec![now_str.into(), key.id.clone().into()],
                ))
                .await
                .map_err(|e| Error::Database(format!("update last_used_at: {e}")))?;
        }

        Ok(found)
    }

    /// Revokes (deletes) all keys for the given identity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on delete failure.
    pub async fn revoke_all_keys(&self, identity_id: &str) -> Result<u64> {
        let result = api_key::Entity::delete_many()
            .filter(api_key::Column::IdentityId.eq(identity_id))
            .exec(&self.db)
            .await
            .map_err(|e| Error::Database(format!("revoke keys: {e}")))?;
        Ok(result.rows_affected)
    }

    /// Revokes (deletes) a single key by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on delete failure.
    pub async fn revoke_key(&self, key_id: &str) -> Result<bool> {
        let result = api_key::Entity::delete_by_id(key_id.to_string())
            .exec(&self.db)
            .await
            .map_err(|e| Error::Database(format!("revoke key: {e}")))?;
        Ok(result.rows_affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> KeyStore {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-keystore-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        let db = crate::db::setup(&url).await.expect("db setup");
        KeyStore::new(db)
    }

    #[tokio::test]
    async fn upsert_identity_creates_new() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity(
                "https://idp.example.com",
                "user123",
                Some("user@example.com"),
                None,
                None,
            )
            .await
            .expect("upsert");
        assert_eq!(ident.issuer, "https://idp.example.com");
        assert_eq!(ident.subject, "user123");
        assert_eq!(ident.email.as_deref(), Some("user@example.com"));
    }

    #[tokio::test]
    async fn upsert_identity_returns_existing() {
        let store = setup_test_db().await;
        let first = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("upsert 1");
        let second = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("upsert 2");
        assert_eq!(
            first.id, second.id,
            "same issuer+subject must return same identity"
        );
    }

    #[tokio::test]
    async fn mint_key_stores_hash_not_plaintext() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store.mint_key(&ident.id, "codex").await.expect("mint");
        // The plaintext key must have the oac_ prefix.
        assert!(minted.plaintext.to_string().starts_with("oac_"));
        // Verify the stored hash is 32 bytes and is NOT the plaintext.
        let keys = api_key::Entity::find()
            .all(&store.db)
            .await
            .expect("load keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_hash.len(), 32);
        assert!(!keys[0].key_hash.starts_with(b"oac_"));
    }

    #[tokio::test]
    async fn verify_key_succeeds_with_valid_token() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store.mint_key(&ident.id, "codex").await.expect("mint");
        let token = minted.plaintext.to_string();
        let result = store.verify_key(&token).await.expect("verify");
        assert!(result.is_some(), "valid key must verify");
        let (key, identity) = result.unwrap();
        assert_eq!(key.identity_id, ident.id);
        assert_eq!(identity.subject, "user123");
    }

    #[tokio::test]
    async fn verify_key_fails_with_invalid_token() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let _ = store.mint_key(&ident.id, "codex").await.expect("mint");
        let result = store.verify_key("oac_invalid_token").await.expect("verify");
        assert!(result.is_none(), "invalid key must not verify");
    }

    #[tokio::test]
    async fn verify_key_updates_last_used_at() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store.mint_key(&ident.id, "codex").await.expect("mint");
        let token = minted.plaintext.to_string();

        // Before verification, last_used_at is None.
        let keys_before = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(keys_before[0].last_used_at.is_none());

        // Verify.
        let _ = store.verify_key(&token).await.expect("verify");

        // After verification, last_used_at is set.
        let keys_after = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(
            keys_after[0].last_used_at.is_some(),
            "last_used_at must be set"
        );
    }

    #[tokio::test]
    async fn revoke_all_keys_deletes_keys_for_identity() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let _ = store.mint_key(&ident.id, "codex").await.expect("mint 1");
        let _ = store.mint_key(&ident.id, "copilot").await.expect("mint 2");

        let deleted = store.revoke_all_keys(&ident.id).await.expect("revoke");
        assert_eq!(deleted, 2, "both keys must be deleted");

        let remaining = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(remaining.is_empty(), "no keys must remain");
    }

    #[tokio::test]
    async fn revoke_key_deletes_single_key() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store.mint_key(&ident.id, "codex").await.expect("mint");

        let deleted = store.revoke_key(&minted.key_id).await.expect("revoke");
        assert!(deleted, "key must be deleted");

        let remaining = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(remaining.is_empty(), "no keys must remain");
    }

    #[tokio::test]
    async fn revoke_nonexistent_key_returns_false() {
        let store = setup_test_db().await;
        let deleted = store.revoke_key("nonexistent-uuid").await.expect("revoke");
        assert!(!deleted, "nonexistent key must return false");
    }
}
