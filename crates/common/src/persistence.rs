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
/// the user's home directory. Returns `None` for non-sqlite URLs. Any query
/// string (e.g. `?mode=rwc`) is stripped.
#[must_use]
pub fn sqlite_path(url: &str) -> Option<PathBuf> {
    let path = url.strip_prefix("sqlite://")?;
    // Strip any query string (e.g. "?mode=rwc").
    let path = path.split('?').next().unwrap_or(path);
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

/// Generates a unique temporary SQLite database URL for tests.
///
/// Returns a `sqlite://<temp_dir>/oac-<prefix>-<pid>-<counter>-<nanos>.db?mode=rwc`
/// URL. Each call returns a distinct path via a process-local atomic counter
/// plus a nanosecond timestamp, so parallel tests never collide.
///
/// This is gated behind the `test-utils` feature so it is only compiled into
/// test builds of dependent crates.
#[cfg(feature = "test-utils")]
#[must_use]
pub fn temp_sqlite_url(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    let tmp = std::env::temp_dir().join(format!(
        "oac-{prefix}-test-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    format!("sqlite://{}?mode=rwc", tmp.display())
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
    fn sqlite_path_strips_query_string() {
        let path = sqlite_path("sqlite:///tmp/test.db?mode=rwc").unwrap();
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

    #[test]
    fn sqlite_path_expands_home_tilde() {
        // Config files use `~/...` paths. On platforms where HOME is set
        // (the shell environments this targets), the tilde resolves against
        // it; the point is that sqlite_path() survives a `~` path and never
        // panics, and when HOME is present the leading `~/` is expanded.
        if let Ok(home) = std::env::var("HOME") {
            let path = sqlite_path("sqlite://~/library/relay.db").expect("path");
            // Shell-expand the expected HOME the same way the platform
            // separator does, so this is robust on Windows too (where the
            // forward-slash join is normalized by PathBuf).
            let home_normalized = home.replace('\\', "/");
            let expected = PathBuf::from(format!("{home_normalized}/library/relay.db"));
            if let Some(path_str) = path.to_str() {
                let as_expected =
                    path_str.replace('\\', "/") == expected.to_string_lossy().replace('\\', "/");
                assert!(as_expected, "tilde must expand to HOME; got {path:?}");
            }
        } else {
            // No HOME configured (e.g. some CI Windows images): the path
            // must still resolve without panicking.
            let path = sqlite_path("sqlite://~/library/relay.db").expect("path");
            assert!(!path.as_os_str().is_empty());
        }
    }

    #[test]
    fn enforce_db_perms_tightens_mode_and_tolerates_missing_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = std::env::temp_dir().join(format!(
                "oac-perms-{}-{}.db",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
            ));
            std::fs::write(&tmp, b"x").expect("write");
            // World-readable first.
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
                .expect("chmod 644");
            enforce_db_perms(&tmp).expect("enforce");
            let mode = std::fs::metadata(&tmp).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "db must be owner-only: {mode:o}");
            let _ = std::fs::remove_file(&tmp);
        }

        // A missing file must not error (fresh installs haven't created it).
        enforce_db_perms(Path::new("/nonexistent/oac-missing.db")).expect("missing is ok");
    }
}
