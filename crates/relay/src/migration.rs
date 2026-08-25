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
}

/// The migrator that runs all relay migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Migration), Box::new(Migration0002RelayActivityLog)]
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
