//! Sea-ORM migrations for the relay database.
//!
//! This module defines the initial schema migration and a [`Migrator`] that
//! implements [`MigratorTrait`] so the [`db`] module can run all migrations.

use sea_orm_migration::prelude::*;

/// The initial migration that creates the `identities` and `api_keys` tables.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m000001_initial_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Identity::Table)
                    .col(
                        ColumnDef::new(Identity::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Identity::Issuer).string().not_null())
                    .col(ColumnDef::new(Identity::Subject).string().not_null())
                    .col(ColumnDef::new(Identity::Email).string().null())
                    .col(ColumnDef::new(Identity::DisplayName).string().null())
                    .col(ColumnDef::new(Identity::Groups).string().null())
                    .col(
                        ColumnDef::new(Identity::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ApiKey::Table)
                    .col(ColumnDef::new(ApiKey::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(ApiKey::IdentityId).string().not_null())
                    .col(ColumnDef::new(ApiKey::KeyHash).binary_len(32).not_null())
                    .col(ColumnDef::new(ApiKey::Label).string().not_null())
                    .col(
                        ColumnDef::new(ApiKey::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ApiKey::LastUsedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_api_keys_identity_id")
                            .from(ApiKey::Table, ApiKey::IdentityId)
                            .to(Identity::Table, Identity::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ApiKey::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Identity::Table).to_owned())
            .await?;
        Ok(())
    }
}

/// Iden for the `identities` table.
#[derive(Iden)]
pub enum Identity {
    /// The table.
    #[iden = "identities"]
    Table,
    /// Primary key.
    Id,
    /// The OIDC issuer URL.
    Issuer,
    /// The subject identifier.
    Subject,
    /// The email claim.
    Email,
    /// The display name.
    DisplayName,
    /// The groups claim.
    Groups,
    /// Creation timestamp.
    CreatedAt,
}

/// Iden for the `api_keys` table.
#[derive(Iden)]
pub enum ApiKey {
    /// The table.
    #[iden = "api_keys"]
    Table,
    /// Primary key.
    Id,
    /// Foreign key to identities.
    IdentityId,
    /// The SHA-256 hash of the key.
    KeyHash,
    /// A human-readable label.
    Label,
    /// Creation timestamp.
    CreatedAt,
    /// Last-used timestamp.
    LastUsedAt,
    /// Session expiry timestamp (NULL = never expires).
    ExpiresAt,
}

/// The migrator that runs all relay migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(Migration),
            Box::new(Migration0002RelayActivityLog),
            Box::new(Migration0003ApiKeyExpiry),
            Box::new(Migration0004McpActivity),
        ]
    }
}

/// Migration 0003: add the `expires_at` column to `api_keys`.
///
/// Keys minted after OIDC login can carry a session lifetime (relay config
/// `session_ttl_hours`). `NULL` means the key never expires (the v1 default
/// and the dev-mode seeded key). Expired keys are rejected at verification
/// time and their rows deleted.
pub struct Migration0003ApiKeyExpiry;

impl MigrationName for Migration0003ApiKeyExpiry {
    fn name(&self) -> &str {
        "m000003_api_key_expiry"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0003ApiKeyExpiry {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKey::Table)
                    .add_column(
                        ColumnDef::new(ApiKey::ExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKey::Table)
                    .drop_column(ApiKey::ExpiresAt)
                    .to_owned(),
            )
            .await
    }
}

/// Migration 0002: create the append-only `relay_activity_log` table.
///
/// This table records every request forwarded by the relay, mirroring the
/// central audit log but from the relay's perspective. It captures local
/// key usage, forwarded request metadata, and the central response status,
/// enabling relay-side observability and correlation with the central
/// audit log via the shared `request_id`.
pub struct Migration0002RelayActivityLog;

impl MigrationName for Migration0002RelayActivityLog {
    fn name(&self) -> &str {
        "m000002_relay_activity_log"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0002RelayActivityLog {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(RelayActivityLog::Table)
                    .col(
                        ColumnDef::new(RelayActivityLog::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RelayActivityLog::IdentityId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RelayActivityLog::KeyId).string().not_null())
                    .col(ColumnDef::new(RelayActivityLog::Method).string().not_null())
                    .col(
                        ColumnDef::new(RelayActivityLog::Endpoint)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RelayActivityLog::Model).string().null())
                    .col(
                        ColumnDef::new(RelayActivityLog::CentralStatus)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(RelayActivityLog::LatencyMs)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RelayActivityLog::RequestId).string().null())
                    .col(
                        ColumnDef::new(RelayActivityLog::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Append-only triggers (mirror the central audit_log pattern).
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS relay_activity_log_no_update \
                 BEFORE UPDATE ON relay_activity_log \
                 BEGIN SELECT RAISE(ABORT, 'relay_activity_log is append-only'); END;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS relay_activity_log_no_delete \
                 BEFORE DELETE ON relay_activity_log \
                 BEGIN SELECT RAISE(ABORT, 'relay_activity_log is append-only'); END;",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RelayActivityLog::Table).to_owned())
            .await
    }
}

/// Iden for the `relay_activity_log` table.
#[derive(Iden)]
pub enum RelayActivityLog {
    /// The table.
    #[iden = "relay_activity_log"]
    Table,
    /// Primary key (UUID).
    Id,
    /// The identity that made the request.
    IdentityId,
    /// The API key used.
    KeyId,
    /// The HTTP method.
    Method,
    /// The request endpoint/path.
    Endpoint,
    /// The model requested (if parseable).
    Model,
    /// The HTTP status from the central proxy.
    CentralStatus,
    /// The request latency in milliseconds.
    LatencyMs,
    /// The request ID for end-to-end correlation.
    RequestId,
    /// Creation timestamp.
    CreatedAt,
}

/// Migration 0004: add MCP activity columns to `relay_activity_log`.
///
/// MCP requests are log-stamped on the relay with the MCP server, method,
/// and tool so relay-side activity correlates with central MCP audit rows.
/// All new columns are nullable so existing rows remain valid.
pub struct Migration0004McpActivity;

impl MigrationName for Migration0004McpActivity {
    fn name(&self) -> &str {
        "m000004_mcp_activity"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0004McpActivity {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (col, ty) in [
            ("mcp_server", "TEXT"),
            ("mcp_tool", "TEXT"),
            ("mcp_method", "TEXT"),
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE relay_activity_log ADD COLUMN {col} {ty};"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite ALTERed columns are not dropped; forward-only in practice.
        let _ = manager;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::MigratorTrait;

    /// The relay schema must survive a full down → up cycle (operators
    /// resetting a laptop database rely on this), and every `down`
    /// implementation is exercised here.
    #[tokio::test]
    async fn migrations_round_trip_down_then_up() {
        let url = oidc_agent_common::persistence::temp_sqlite_url("relay-mig");
        let db = sea_orm::Database::connect(&url).await.expect("connect");

        Migrator::up(&db, None).await.expect("up");

        // The schema accepts writes (including the 0003 expires_at column).
        {
            use sea_orm::ConnectionTrait;
            db.execute_unprepared(
                "INSERT INTO identities (id, issuer, subject, created_at) \
                 VALUES ('i1', 'https://idp', 'u', '2026-01-01 00:00:00')",
            )
            .await
            .expect("insert identity");
            db.execute_unprepared(
                "INSERT INTO api_keys (id, identity_id, key_hash, label, created_at, expires_at) \
                 VALUES ('k1', 'i1', x'00', 'test', '2026-01-01 00:00:00', NULL)",
            )
            .await
            .expect("insert key with expires_at");
        }

        Migrator::down(&db, None).await.expect("down");
        {
            use sea_orm::ConnectionTrait;
            let tables: Vec<String> = db
                .query_all(sea_orm::Statement::from_string(
                    db.get_database_backend(),
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%seaql%'"
                        .to_string(),
                ))
                .await
                .expect("list tables")
                .iter()
                .map(|row| row.try_get("", "name").unwrap_or_default())
                .collect();
            assert!(
                tables.is_empty(),
                "down must drop all tables, still present: {tables:?}"
            );
        }

        Migrator::up(&db, None).await.expect("up again");
        {
            use sea_orm::ConnectionTrait;
            db.execute_unprepared(
                "INSERT INTO identities (id, issuer, subject, created_at) \
                 VALUES ('i2', 'https://idp', 'u2', '2026-01-02 00:00:00')",
            )
            .await
            .expect("insert after round trip");
        }
    }

    /// The migrator must register every migration exactly once, in order.
    #[test]
    fn migrator_lists_all_migrations_in_order() {
        let migrations = Migrator::migrations();
        let names: Vec<String> = migrations.iter().map(|m| m.name().to_string()).collect();
        assert_eq!(
            names,
            vec![
                "m000001_initial_schema",
                "m000002_relay_activity_log",
                "m000003_api_key_expiry",
                "m000004_mcp_activity",
            ],
            "migration order is part of the schema contract"
        );
    }
}
