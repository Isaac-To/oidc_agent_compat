//! Sea-ORM migrations for the central proxy database.

use sea_orm_migration::prelude::*;

/// The initial migration that creates the `devices` and `audit_log` tables.
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
                    .table(Device::Table)
                    .col(ColumnDef::new(Device::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Device::CertFingerprint).string().not_null())
                    .col(ColumnDef::new(Device::UserSubject).string().not_null())
                    .col(ColumnDef::new(Device::UserEmail).string().null())
                    .col(
                        ColumnDef::new(Device::Revoked)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Device::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Device::LastSeenAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AuditLog::Table)
                    .col(
                        ColumnDef::new(AuditLog::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuditLog::DeviceId).string().not_null())
                    .col(ColumnDef::new(AuditLog::UserSubject).string().not_null())
                    .col(ColumnDef::new(AuditLog::Model).string().null())
                    .col(ColumnDef::new(AuditLog::Backend).string().not_null())
                    .col(ColumnDef::new(AuditLog::Status).integer().not_null())
                    .col(ColumnDef::new(AuditLog::LatencyMs).big_integer().not_null())
                    .col(
                        ColumnDef::new(AuditLog::Stream)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(AuditLog::PromptTokens).integer().null())
                    .col(ColumnDef::new(AuditLog::CompletionTokens).integer().null())
                    .col(ColumnDef::new(AuditLog::TotalTokens).integer().null())
                    .col(
                        ColumnDef::new(AuditLog::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create an append-only trigger on the audit_log table (SQLite).
        // This prevents UPDATE and DELETE operations, enforcing tamper-
        // evidence at the database level.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS audit_log_no_update \
                 BEFORE UPDATE ON audit_log \
                 BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete \
                 BEFORE DELETE ON audit_log \
                 BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditLog::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Device::Table).to_owned())
            .await?;
        Ok(())
    }
}

/// Iden for the `devices` table.
#[derive(Iden)]
pub enum Device {
    /// The table.
    #[iden = "devices"]
    Table,
    /// Primary key.
    Id,
    /// The cert fingerprint.
    CertFingerprint,
    /// The user subject.
    UserSubject,
    /// The user email.
    UserEmail,
    /// Whether the device is revoked.
    Revoked,
    /// Creation timestamp.
    CreatedAt,
    /// Last-seen timestamp.
    LastSeenAt,
}

/// Iden for the `audit_log` table.
#[derive(Iden)]
pub enum AuditLog {
    /// The table.
    #[iden = "audit_log"]
    Table,
    /// Primary key.
    Id,
    /// The device ID.
    DeviceId,
    /// The user subject.
    UserSubject,
    /// The model requested.
    Model,
    /// The backend name.
    Backend,
    /// The HTTP status code.
    Status,
    /// The latency in milliseconds.
    LatencyMs,
    /// Whether the response was streamed.
    Stream,
    /// Prompt token count.
    PromptTokens,
    /// Completion token count.
    CompletionTokens,
    /// Total token count.
    TotalTokens,
    /// Creation timestamp.
    CreatedAt,
}

/// The migrator that runs all central proxy migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Migration), Box::new(Migration0002AuditEnrichment)]
    }
}

/// Migration 0002: enrich the `audit_log` table with identity, groups,
/// endpoint, request-id, permission-decision, and cost columns.
///
/// These columns support the permissions and user-activity-logging feature.
/// All new columns are nullable so existing rows remain valid.
pub struct Migration0002AuditEnrichment;

impl MigrationName for Migration0002AuditEnrichment {
    fn name(&self) -> &str {
        "m000002_audit_enrichment"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0002AuditEnrichment {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add nullable columns to audit_log. SQLite supports ALTER TABLE
        // ADD COLUMN for nullable columns without a default.
        let cols = [
            ("identity_id", "TEXT"),
            ("email", "TEXT"),
            ("groups", "TEXT"),
            ("endpoint", "TEXT"),
            ("request_id", "TEXT"),
            ("permission_decision", "TEXT"),
            ("denial_reason", "TEXT"),
            ("cost_usd", "REAL"),
        ];
        for (col, ty) in cols {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE audit_log ADD COLUMN {col} {ty};"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite does not support DROP COLUMN before 3.35. Recreate the
        // table without the new columns. For simplicity (and because this
        // is a forward-only migration in practice), we no-op the down path.
        let _ = manager;
        Ok(())
    }
}
