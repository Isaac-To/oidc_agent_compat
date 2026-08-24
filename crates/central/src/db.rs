//! Database setup and migration runner for the central proxy.

use oidc_agent_common::error::{Error, Result};
use sea_orm::{ConnectOptions, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

use crate::migration::Migrator;

/// Establishes a connection to the database and runs migrations.
///
/// # Errors
///
/// Returns [`Error::Database`] if the connection fails or migrations error.
pub async fn setup(database_url: &str) -> Result<DatabaseConnection> {
    let url = if database_url.starts_with("sqlite://") && !database_url.contains('?') {
        format!("{database_url}?mode=rwc")
    } else {
        database_url.to_string()
    };
    let options = ConnectOptions::new(url);
    let db = sea_orm::Database::connect(options)
        .await
        .map_err(|e| Error::Database(format!("connect: {e}")))?;

    Migrator::up(&db, None)
        .await
        .map_err(|e| Error::Database(format!("migrate: {e}")))?;

    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[tokio::test]
    async fn setup_creates_and_migrates_temp_db() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!(
            "oac-central-test-{}-{counter}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let url = format!("sqlite://{}", tmp.display());
        let db = setup(&url).await.expect("setup succeeds");
        let backend = db.get_database_backend();
        assert!(matches!(backend, sea_orm::DatabaseBackend::Sqlite));

        // Verify the tables were created.
        let stmt = sea_orm::Statement::from_sql_and_values(
            backend,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'",
            vec![],
        );
        let rows = db.query_all(stmt).await.expect("query");
        assert!(!rows.is_empty(), "devices table must exist");

        // Idempotent.
        let _ = setup(&url).await.expect("idempotent setup");
        let _ = std::fs::remove_file(&tmp);
    }
}
