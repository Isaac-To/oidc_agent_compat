//! Database setup and migration runner for the relay.

use oidc_agent_common::error::Result;
use oidc_agent_common::persistence;
use sea_orm::DatabaseConnection;

use crate::migration::Migrator;

/// Establishes a connection to the SQLite database and runs migrations.
///
/// # Security
///
/// On Unix, the database file is created with `0600` permissions so other
/// local users cannot read the key hashes.
///
/// # Errors
///
/// Returns [`oidc_agent_common::error::Error::Database`] if the connection
/// fails or migrations error.
pub async fn setup(database_url: &str) -> Result<DatabaseConnection> {
    let db = persistence::setup_database::<Migrator>(database_url).await?;

    // On Unix, tighten the file permissions if this is a sqlite:// URL.
    #[cfg(unix)]
    if let Some(path) = persistence::sqlite_path(database_url) {
        persistence::enforce_db_perms(&path)?;
    }

    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[tokio::test]
    async fn setup_creates_and_migrates_temp_db() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-test-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}", tmp.display());
        let db = setup(&url).await.expect("setup succeeds");
        let backend = db.get_database_backend();
        assert!(
            matches!(backend, sea_orm::DatabaseBackend::Sqlite),
            "expected sqlite backend"
        );
        // Verify the tables were created by querying them.
        let stmt = sea_orm::Statement::from_sql_and_values(
            backend,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='identities'",
            vec![],
        );
        let rows = db.query_all(stmt).await.expect("query tables");
        assert!(
            !rows.is_empty(),
            "identities table must exist after migration"
        );
        // Run setup again to verify idempotency.
        let _ = setup(&url).await.expect("idempotent setup");
        // Clean up.
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn setup_sets_0600_perms_on_db_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!(
            "oac-test-perms-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}", tmp.display());
        let _ = setup(&url).await.expect("setup succeeds");
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "db file must have 0600 permissions, got {mode:o}"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
