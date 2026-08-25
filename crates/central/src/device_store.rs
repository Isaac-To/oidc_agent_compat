//! Device registration and revocation store.
//!
//! The `devices` table records relay devices identified by their mTLS
//! client certificate fingerprint. Devices can be revoked by an admin,
//! preventing further access even if the cert is still valid.
//!
//! # Enforcement
//!
//! Device revocation is enforced in production mode (mTLS) by the
//! permissions middleware. In dev mode (no mTLS, no client certs), device
//! checks are skipped.

use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::PrimitiveDateTime;
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};

use crate::entity::device;

/// The device store, backed by the central proxy's database.
#[derive(Clone)]
pub struct DeviceStore {
    db: DatabaseConnection,
}

impl DeviceStore {
    /// Creates a new `DeviceStore`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Returns a reference to the underlying database connection.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Lists all registered devices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn list_devices(&self) -> Result<Vec<device::Model>> {
        device::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| Error::Database(format!("list devices: {e}")))
    }

    /// Gets a device by its cert fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn get_device(&self, fingerprint: &str) -> Result<Option<device::Model>> {
        device::Entity::find()
            .filter(device::Column::CertFingerprint.eq(fingerprint))
            .one(&self.db)
            .await
            .map_err(|e| Error::Database(format!("get device: {e}")))
    }

    /// Registers or updates a device. If a device with the given fingerprint
    /// exists, its `last_seen_at` and `user_email` are updated; otherwise a
    /// new device is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert/update failure.
    pub async fn upsert_device(
        &self,
        cert_fingerprint: &str,
        user_subject: &str,
        user_email: Option<&str>,
    ) -> Result<device::Model> {
        let existing = self.get_device(cert_fingerprint).await?;
        let now = now_utc();
        let now_str = format_time(&now);

        if let Some(model) = existing {
            // Update last_seen_at and user_email.
            let sql = "UPDATE devices SET last_seen_at = $1, user_email = $2 WHERE id = $3";
            let email_val = user_email
                .map(|e| sea_orm::Value::String(Some(Box::new(e.to_string()))))
                .unwrap_or(sea_orm::Value::String(None));
            self.db
                .execute(sea_orm::Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    sql,
                    vec![now_str.into(), email_val, model.id.clone().into()],
                ))
                .await
                .map_err(|e| Error::Database(format!("update device: {e}")))?;
            Ok(device::Model {
                id: model.id,
                cert_fingerprint: model.cert_fingerprint,
                user_subject: model.user_subject,
                user_email: user_email.map(String::from),
                revoked: model.revoked,
                created_at: model.created_at,
                last_seen_at: Some(now),
            })
        } else {
            let id = Uuid::new_v4().to_string();
            let email_val = user_email
                .map(|e| sea_orm::Value::String(Some(Box::new(e.to_string()))))
                .unwrap_or(sea_orm::Value::String(None));
            let sql = "INSERT INTO devices \
                 (id, cert_fingerprint, user_subject, user_email, revoked, created_at, last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)";
            self.db
                .execute(sea_orm::Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    sql,
                    vec![
                        id.clone().into(),
                        cert_fingerprint.to_string().into(),
                        user_subject.to_string().into(),
                        email_val,
                        sea_orm::Value::Bool(Some(false)),
                        now_str.clone().into(),
                        now_str.into(),
                    ],
                ))
                .await
                .map_err(|e| Error::Database(format!("insert device: {e}")))?;
            Ok(device::Model {
                id,
                cert_fingerprint: cert_fingerprint.to_string(),
                user_subject: user_subject.to_string(),
                user_email: user_email.map(String::from),
                revoked: false,
                created_at: now,
                last_seen_at: Some(now),
            })
        }
    }

    /// Sets the revoked flag for a device identified by cert fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on update failure.
    pub async fn set_revoked(&self, fingerprint: &str, revoked: bool) -> Result<bool> {
        let sql = "UPDATE devices SET revoked = $1 WHERE cert_fingerprint = $2";
        let result = self
            .db
            .execute(sea_orm::Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    sea_orm::Value::Bool(Some(revoked)),
                    fingerprint.to_string().into(),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("set revoked: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Revokes a device (sets `revoked = true`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on update failure.
    pub async fn revoke(&self, fingerprint: &str) -> Result<bool> {
        self.set_revoked(fingerprint, true).await
    }

    /// Reinstates a revoked device (sets `revoked = false`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on update failure.
    pub async fn reinstate(&self, fingerprint: &str) -> Result<bool> {
        self.set_revoked(fingerprint, false).await
    }

    /// Checks whether a device with the given fingerprint is revoked.
    ///
    /// Returns `Ok(None)` if the device is not registered, `Ok(Some(true))`
    /// if revoked, `Ok(Some(false))` if registered and active.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn is_revoked(&self, fingerprint: &str) -> Result<Option<bool>> {
        let device = self.get_device(fingerprint).await?;
        Ok(device.map(|d| d.revoked))
    }
}

/// Returns the current UTC time as a `PrimitiveDateTime`.
fn now_utc() -> PrimitiveDateTime {
    let offset = time::OffsetDateTime::now_utc();
    PrimitiveDateTime::new(offset.date(), offset.time())
}

/// Formats a `PrimitiveDateTime` for SQLite.
fn format_time(t: &PrimitiveDateTime) -> String {
    t.format(time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second]"
    ))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> DeviceStore {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-device-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        let db = crate::db::setup(&url).await.expect("db setup");
        DeviceStore::new(db)
    }

    #[tokio::test]
    async fn upsert_device_creates_new() {
        let store = setup_test_db().await;
        let device = store
            .upsert_device("fp-123", "user-1", Some("user@example.com"))
            .await
            .expect("upsert");
        assert_eq!(device.cert_fingerprint, "fp-123");
        assert_eq!(device.user_subject, "user-1");
        assert!(!device.revoked);
    }

    #[tokio::test]
    async fn upsert_device_updates_existing() {
        let store = setup_test_db().await;
        store
            .upsert_device("fp-456", "user-1", Some("old@example.com"))
            .await
            .expect("upsert 1");
        store
            .upsert_device("fp-456", "user-1", Some("new@example.com"))
            .await
            .expect("upsert 2");

        let devices = store.list_devices().await.expect("list");
        assert_eq!(devices.len(), 1, "upsert must not duplicate");
        assert_eq!(
            devices[0].user_email.as_deref(),
            Some("new@example.com"),
            "email must be updated"
        );
    }

    #[tokio::test]
    async fn revoke_and_reinstate() {
        let store = setup_test_db().await;
        store
            .upsert_device("fp-789", "user-2", None)
            .await
            .expect("upsert");

        let revoked = store.revoke("fp-789").await.expect("revoke");
        assert!(revoked);
        assert_eq!(
            store.is_revoked("fp-789").await.expect("check"),
            Some(true)
        );

        let reinstated = store.reinstate("fp-789").await.expect("reinstate");
        assert!(reinstated);
        assert_eq!(
            store.is_revoked("fp-789").await.expect("check"),
            Some(false)
        );
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_false() {
        let store = setup_test_db().await;
        let revoked = store.revoke("nonexistent").await.expect("revoke");
        assert!(!revoked);
    }

    #[tokio::test]
    async fn is_revoked_nonexistent_returns_none() {
        let store = setup_test_db().await;
        assert!(store.is_revoked("nonexistent").await.expect("check").is_none());
    }
}
