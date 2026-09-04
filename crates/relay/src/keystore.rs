//! Identity store — persists OIDC identities for login convenience.
//!
//! The relay no longer mints, stores, or verifies local API keys. Token
//! verification is the sole responsibility of the central proxy (zero-trust).
//! This module retains only the [`KeyStore::upsert_identity`] method so the
//! relay can record an OIDC identity locally (issuer + subject + email +
//! groups) and avoid forcing the user to re-run the full OIDC flow on every
//! restart.
//!
//! The type is still named [`KeyStore`] for compatibility with call sites
//! (`login.rs`, `main.rs`); it no longer holds any key material.
//!
//! # Security
//!
//! - No key hashes are stored; the `api_keys` table is unused by the relay
//!   (the migration that creates it is retained for downgrade compatibility).
//! - Identity records are derived from verified OIDC userinfo and are used
//!   only for login convenience and relay-side activity logging.

use oidc_agent_common::time_util;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Statement, Value,
};
use uuid::Uuid;

use crate::entity::identity;
use oidc_agent_common::error::{Error, Result};

/// A store backed by the relay's SQLite database.
///
/// Despite the historical name, this type no longer manages API keys. It
/// persists OIDC identities (via [`KeyStore::upsert_identity`]) and exposes
/// the underlying [`DatabaseConnection`] (pub, for the activity logger and
/// login flow).
#[derive(Clone)]
pub struct KeyStore {
    /// The database connection (pub for use in main.rs and the activity logger).
    pub db: DatabaseConnection,
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
