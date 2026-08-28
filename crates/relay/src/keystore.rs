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
use oidc_agent_common::time_util;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Statement, Value,
};
use uuid::Uuid;

use crate::entity::{api_key, identity};
use oidc_agent_common::error::{Error, Result};

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

/// The outcome of verifying a bearer token against the key store.
#[derive(Debug)]
pub enum KeyVerification {
    /// The token matches an active, unexpired key.
    Valid(Box<(api_key::Model, identity::Model)>),
    /// The token matches a stored hash but the session has expired; the
    /// stored row has been deleted.
    Expired,
    /// No stored key matches the token.
    Invalid,
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
        let now = time_util::now_utc();
        let id = Uuid::new_v4().to_string();
        let now_str = time_util::format_time(&now);
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
    pub async fn mint_key(
        &self,
        identity_id: &str,
        label: &str,
        expires_at: Option<time::PrimitiveDateTime>,
    ) -> Result<MintedKey> {
        let plaintext = LocalKey::generate();
        let hash = KeyHash::from_plaintext(&plaintext.to_string());
        let now = time_util::now_utc();
        let key_id = Uuid::new_v4().to_string();
        let now_str = time_util::format_time(&now);

        let expires_val = expires_at
            .map(|t| Value::String(Some(Box::new(time_util::format_time(&t)))))
            .unwrap_or(Value::String(None));

        // Use parameterized SQL to prevent injection.
        let sql = "INSERT INTO api_keys (id, identity_id, key_hash, label, created_at, last_used_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NULL, $6)";
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
                    expires_val,
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

    /// Mints a local API key from a caller-supplied plaintext string.
    ///
    /// # Security
    ///
    /// This is intended **only** for seeding a well-known development key
    /// (e.g. when `dev_mode` is enabled) so containerized agents can
    /// authenticate without running the full OIDC login flow. It must never
    /// be used to mint production keys — production keys must come from
    /// [`KeyStore::mint_key`] so they carry 256 bits of OS CSPRNG entropy.
    ///
    /// Like [`mint_key`], only the SHA-256 hash is stored; the plaintext is
    /// returned once via [`MintedKey`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert failure.
    pub async fn mint_dev_key(
        &self,
        identity_id: &str,
        label: &str,
        plaintext: &str,
    ) -> Result<MintedKey> {
        let key = LocalKey::from_string(plaintext.to_string());
        let hash = KeyHash::from_plaintext(&key.to_string());
        let now = time_util::now_utc();
        let key_id = Uuid::new_v4().to_string();
        let now_str = time_util::format_time(&now);

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
            .map_err(|e| Error::Database(format!("insert dev api key: {e}")))?;

        Ok(MintedKey {
            plaintext: key,
            key_id,
            identity_id: identity_id.to_string(),
        })
    }

    /// Verifies a bearer token against the stored key hashes.
    ///
    /// Returns a [`KeyVerification`]: [`KeyVerification::Valid`] with the
    /// matching key + identity, [`KeyVerification::Expired`] when the token
    /// matches a key whose session has expired (the row is deleted), or
    /// [`KeyVerification::Invalid`] when no key matches. Uses constant-time
    /// comparison to prevent timing attacks.
    ///
    /// # Security
    ///
    /// Iterates through **all** keys and compares each in constant time,
    /// without early return — this prevents timing leaks that would reveal
    /// which key index matched (CWE-208). On a match, updates `last_used_at`
    /// using parameterized SQL. Expired key rows are deleted so stale
    /// credentials do not linger on the laptop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn verify_key(&self, bearer_token: &str) -> Result<KeyVerification> {
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
        let now = time_util::now_utc();
        let mut found: Option<(api_key::Model, identity::Model)> = None;
        let mut expired_id: Option<String> = None;
        for (key, ident) in &keys {
            let stored_hash = KeyHash::from_hash_bytes(&key.key_hash);
            if stored_hash.matches(&candidate_hash) && found.is_none() {
                // A matched key may have an expired session.
                if let Some(expires_at) = key.expires_at {
                    if now >= expires_at {
                        expired_id = Some(key.id.clone());
                        continue;
                    }
                }
                let ident = ident.clone().ok_or_else(|| {
                    Error::Database(format!(
                        "key {} has no associated identity (foreign key violation)",
                        key.id
                    ))
                })?;
                found = Some((key.clone(), ident));
            }
        }

        // Delete an expired matched key so the stale credential cannot be
        // replayed later (best-effort; verification already rejected it).
        if let Some(key_id) = expired_id {
            tracing::warn!(
                key_id = %key_id,
                "session key expired — run `oac-relay login` to re-authenticate"
            );
            if let Err(e) = api_key::Entity::delete_by_id(key_id).exec(&self.db).await {
                tracing::warn!(error = %e, "failed to delete expired api key");
            }
            return Ok(KeyVerification::Expired);
        }

        // Update last_used_at if we found a match (outside the loop).
        if let Some((key, _)) = &found {
            let now = time_util::now_utc();
            let now_str = time_util::format_time(&now);
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

        match found {
            Some(pair) => Ok(KeyVerification::Valid(Box::new(pair))),
            None => Ok(KeyVerification::Invalid),
        }
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
        let url = oidc_agent_common::persistence::temp_sqlite_url("keystore");
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
        let minted = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");
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
    async fn mint_dev_key_stores_hash_of_known_plaintext() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("dev", "dev-user", None, None, None)
            .await
            .expect("identity");
        let known = "oac_test_key_alice";
        let minted = store
            .mint_dev_key(&ident.id, "dev", known)
            .await
            .expect("mint dev key");
        // The returned plaintext must be exactly the supplied string.
        assert_eq!(minted.plaintext.to_string(), known);
        // Only one key, and its hash is 32 bytes (not the plaintext).
        let keys = api_key::Entity::find()
            .all(&store.db)
            .await
            .expect("load keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_hash.len(), 32);
        assert!(!keys[0].key_hash.starts_with(b"oac_"));
    }

    #[tokio::test]
    async fn mint_dev_key_verifies_with_known_plaintext() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("dev", "dev-user", None, None, None)
            .await
            .expect("identity");
        let known = "oac_test_key_alice";
        let _ = store
            .mint_dev_key(&ident.id, "dev", known)
            .await
            .expect("mint dev key");
        // The known plaintext must verify.
        let result = store.verify_key(known).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Valid(_)),
            "known dev key must verify"
        );
        if let KeyVerification::Valid(pair) = result {
            let (key, identity) = &*pair;
            assert_eq!(key.identity_id, ident.id);
            assert_eq!(identity.subject, "dev-user");
        }
        // A wrong key must not verify.
        let wrong = store
            .verify_key("oac_test_key_bob")
            .await
            .expect("verify wrong");
        assert!(
            matches!(wrong, KeyVerification::Invalid),
            "a different key must not verify"
        );
    }

    #[tokio::test]
    async fn verify_key_succeeds_with_valid_token() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");
        let token = minted.plaintext.to_string();
        let result = store.verify_key(&token).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Valid(_)),
            "valid key must verify"
        );
        if let KeyVerification::Valid(pair) = result {
            let (key, identity) = &*pair;
            assert_eq!(key.identity_id, ident.id);
            assert_eq!(identity.subject, "user123");
        }
    }

    #[tokio::test]
    async fn verify_key_fails_with_invalid_token() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let _ = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");
        let result = store.verify_key("oac_invalid_token").await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Invalid),
            "invalid key must not verify"
        );
    }

    #[tokio::test]
    async fn verify_key_updates_last_used_at() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");
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
    async fn key_with_future_expiry_verifies() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let expires = time_util::now_utc() + time::Duration::hours(24);
        let minted = store
            .mint_key(&ident.id, "codex", Some(expires))
            .await
            .expect("mint");
        let token = minted.plaintext.to_string();

        let result = store.verify_key(&token).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Valid(_)),
            "a key with future expiry must verify"
        );
    }

    #[tokio::test]
    async fn expired_key_is_rejected_and_deleted() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let expires = time_util::now_utc() - time::Duration::hours(1);
        let minted = store
            .mint_key(&ident.id, "codex", Some(expires))
            .await
            .expect("mint");
        let token = minted.plaintext.to_string();

        // First verification reports Expired…
        let result = store.verify_key(&token).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Expired),
            "an expired key must be rejected as Expired"
        );

        // …and the row is deleted, so subsequent attempts are Invalid.
        let result = store.verify_key(&token).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Invalid),
            "a deleted expired key must report Invalid on retry"
        );
        let remaining = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(remaining.is_empty(), "expired key row must be deleted");
    }

    #[tokio::test]
    async fn key_without_expiry_never_expires() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let minted = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");
        let keys = api_key::Entity::find().all(&store.db).await.expect("load");
        assert!(keys[0].expires_at.is_none(), "no expiry configured");
        let token = minted.plaintext.to_string();
        let result = store.verify_key(&token).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Valid(_)),
            "keys without expiry must keep verifying"
        );
    }

    #[tokio::test]
    async fn revoke_all_keys_deletes_keys_for_identity() {
        let store = setup_test_db().await;
        let ident = store
            .upsert_identity("https://idp.example.com", "user123", None, None, None)
            .await
            .expect("identity");
        let _ = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint 1");
        let _ = store
            .mint_key(&ident.id, "copilot", None)
            .await
            .expect("mint 2");

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
        let minted = store
            .mint_key(&ident.id, "codex", None)
            .await
            .expect("mint");

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

    #[tokio::test]
    async fn schema_rejects_keys_with_dangling_identity() {
        let store = setup_test_db().await;
        // The `api_keys.identity_id` foreign key is the first line of
        // defence against the corrupted state `verify_key` guards against:
        // the database itself must refuse an orphaned key row.
        let plaintext = "oac_orphan_key";
        let hash = KeyHash::from_plaintext(plaintext);
        use sea_orm::ConnectionTrait;
        let result = store
            .db
            .execute(sea_orm::Statement::from_sql_and_values(
                store.db.get_database_backend(),
                "INSERT INTO api_keys (id, identity_id, key_hash, label, created_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                vec![
                    "orphan-key-id".into(),
                    "no-such-identity".into(),
                    sea_orm::Value::Bytes(Some(Box::new(hash.as_bytes().to_vec()))),
                    "orphan".into(),
                    "2026-01-01 00:00:00".into(),
                ],
            ))
            .await;

        let err = result.expect_err("the FK constraint must reject the orphan");
        assert!(
            err.to_string().contains("FOREIGN KEY"),
            "the failure must be the FK constraint: {err}"
        );

        // And the orphan key (which was never stored) cannot verify.
        let result = store.verify_key(plaintext).await.expect("verify");
        assert!(
            matches!(result, KeyVerification::Invalid),
            "a key that was never stored must not verify"
        );
    }

    #[tokio::test]
    async fn db_getter_is_usable() {
        let store = setup_test_db().await;
        use sea_orm::{ConnectionTrait, Statement};
        let row = store
            .db
            .query_one(Statement::from_string(
                store.db.get_database_backend(),
                "SELECT 1 AS one".to_string(),
            ))
            .await
            .expect("query")
            .expect("row");
        assert_eq!(row.try_get::<i64>("", "one").unwrap_or(0), 1);
    }
}
