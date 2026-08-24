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
        vec![Box::new(Migration)]
    }
}
