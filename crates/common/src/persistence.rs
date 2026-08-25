//! Shared SQLite persistence helpers for the relay and central proxies.
//!
//! Both proxies use sea-orm over SQLite with sea-orm-migration. The
//! connection setup (URL normalization, `ConnectOptions`, connect, run
//! migrations) was previously duplicated across the two crates; this module
//! centralizes it. Each crate still owns its own `Migrator` (different
//! migration lists), but the runner invocation is identical.
//!
//! # Security
//!
//! On Unix, the relay's database file holds key hashes and must be `0600`.
//! [`setup_sqlite`] optionally tightens permissions after migration. The
//! central proxy's database holds audit logs (less sensitive) and skips
//! this step.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use sea_orm::{ConnectOptions, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

/// Connects to a SQLite (or other) database, runs the given migrator, and
/// returns the connection.
///
/// For `sqlite://` URLs without a query string, appends `?mode=rwc` so the
/// file is created if it does not exist.
///
/// # Errors
///
/// Returns [`Error::Database`] if the connection or migration fails.
pub async fn setup_database<M>(database_url: &str) -> Result<DatabaseConnection>
where
    M: MigratorTrait,
{
    let url = normalize_sqlite_url(database_url);
    let options = ConnectOptions::new(url);
    let db = sea_orm::Database::connect(options)
        .await
        .map_err(|e| Error::Database(format!("connect: {e}")))?;
    M::up(&db, None)
        .await
        .map_err(|e| Error::Database(format!("migrate: {e}")))?;
    Ok(db)
}

/// Normalizes a `sqlite://` URL by appending `?mode=rwc` if it has no query
/// string. Non-sqlite URLs are returned unchanged.
fn normalize_sqlite_url(database_url: &str) -> String {
    if database_url.starts_with("sqlite://") && !database_url.contains('?') {
        format!("{database_url}?mode=rwc")
    } else {
        database_url.to_string()
    }
}

/// Extracts the filesystem path from a `sqlite://` URL, expanding `~` to
/// the user's home directory. Returns `None` for non-sqlite URLs.
#[must_use]
pub fn sqlite_path(url: &str) -> Option<PathBuf> {
    let path = url.strip_prefix("sqlite://")?;
    let expanded = shellexpand(path);
    Some(PathBuf::from(expanded))
}

/// Expands a leading `~/` to the user's home directory.
fn shellexpand(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return format!("{}/{}", home.to_string_lossy(), rest);
        }
    }
    path.to_string()
}

/// Enforces `0600` permissions on the database file (Unix only). No-op on
/// non-Unix platforms.
///
/// # Errors
///
/// Returns [`Error::Database`] if the permissions cannot be set.
pub fn enforce_db_perms(path: &Path) -> Result<()> {
    enforce_db_perms_inner(path)
}

#[cfg(unix)]
fn enforce_db_perms_inner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Database(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::missing_docs_in_private_items)]
fn enforce_db_perms_inner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_sqlite_url_appends_mode_rwc() {
        assert_eq!(
            normalize_sqlite_url("sqlite:///tmp/test.db"),
            "sqlite:///tmp/test.db?mode=rwc"
        );
    }

    #[test]
    fn normalize_sqlite_url_preserves_existing_query() {
        assert_eq!(
            normalize_sqlite_url("sqlite:///tmp/test.db?mode=ro"),
            "sqlite:///tmp/test.db?mode=ro"
        );
    }

    #[test]
    fn normalize_sqlite_url_passes_through_non_sqlite() {
        assert_eq!(
            normalize_sqlite_url("postgres://localhost/db"),
            "postgres://localhost/db"
        );
    }

    #[test]
    fn sqlite_path_extracts_path() {
        let path = sqlite_path("sqlite:///tmp/test.db").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test.db"));
    }

    #[test]
    fn sqlite_path_returns_none_for_non_sqlite() {
        assert!(sqlite_path("postgres://localhost/db").is_none());
    }

    #[test]
    fn shellexpand_passes_through_absolute_paths() {
        assert_eq!(shellexpand("/absolute/path"), "/absolute/path");
    }
}
