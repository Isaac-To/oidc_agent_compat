//! Database setup and migration runner for the central proxy.

use oidc_agent_common::error::Result;
use oidc_agent_common::persistence;
use sea_orm::DatabaseConnection;

use crate::migration::Migrator;

/// Establishes a connection to the database and runs migrations.
///
/// # Errors
///
/// Returns [`oidc_agent_common::error::Error::Database`] if the connection
/// fails or migrations error.
pub async fn setup(database_url: &str) -> Result<DatabaseConnection> {
    persistence::setup_database::<Migrator>(database_url).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[tokio::test]
    async fn setup_creates_and_migrates_temp_db() {
        let url = oidc_agent_common::persistence::temp_sqlite_url("central-db");
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
    }
}
