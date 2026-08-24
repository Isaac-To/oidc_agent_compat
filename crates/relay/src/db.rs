//! Database setup and migration runner for the relay.

use std::path::Path;

use oidc_agent_common::error::{Error, Result};
use sea_orm::{ConnectOptions, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

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
/// Returns [`Error::Database`] if the connection fails or migrations error.
pub async fn setup(database_url: &str) -> Result<DatabaseConnection> {
    // For sqlite:// URLs, append ?mode=rwc so sqlx creates the file if it
    // doesn't exist.
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

    // On Unix, tighten the file permissions if this is a sqlite:// URL.
    #[cfg(unix)]
    if let Some(path) = sqlite_path(database_url) {
        enforce_db_perms(&path)?;
    }

    Ok(db)
}

/// Extracts the filesystem path from a `sqlite://` URL.
fn sqlite_path(url: &str) -> Option<std::path::PathBuf> {
    let path = url.strip_prefix("sqlite://")?;
    let expanded = shellexpand(path);
    Some(std::path::PathBuf::from(expanded))
}

/// Expands `~` in a path.
fn shellexpand(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    path.to_string()
}

/// Enforces `0600` permissions on the database file.
#[cfg(unix)]
fn enforce_db_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Database(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::missing_docs_in_private_items)]
fn enforce_db_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[test]
    fn sqlite_path_extracts_path() {
        let path = sqlite_path("sqlite:///tmp/test.db").unwrap();
        assert_eq!(path, std::path::PathBuf::from("/tmp/test.db"));
    }

    #[test]
    fn sqlite_path_returns_none_for_non_sqlite() {
        assert!(sqlite_path("postgres://localhost/db").is_none());
    }

    #[test]
    fn shellexpand_passes_through_absolute_paths() {
        let result = shellexpand("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }

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
