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
        vec![
            Box::new(Migration),
            Box::new(Migration0002AuditEnrichment),
            Box::new(Migration0003GroupPolicies),
            Box::new(Migration0004UsageCounters),
            Box::new(Migration0005Providers),
            Box::new(Migration0006TokenSaver),
            Box::new(Migration0007CollapseRepeatedLines),
        ]
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

/// Migration 0003: create the `group_policies` and `admin_audit_log` tables.
///
/// `group_policies` stores per-group authorization policies (model
/// allowlists, endpoint restrictions, quotas) managed via the admin API.
/// `admin_audit_log` is an append-only record of admin API mutations for
/// accountability.
pub struct Migration0003GroupPolicies;

impl MigrationName for Migration0003GroupPolicies {
    fn name(&self) -> &str {
        "m000003_group_policies"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0003GroupPolicies {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(GroupPolicy::Table)
                    .col(
                        ColumnDef::new(GroupPolicy::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GroupPolicy::GroupName)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(GroupPolicy::AllowedModels).string().null())
                    .col(
                        ColumnDef::new(GroupPolicy::AllowedEndpoints)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GroupPolicy::DailyTokenQuota)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GroupPolicy::DailyRequestQuota)
                            .big_integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GroupPolicy::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GroupPolicy::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AdminAuditLog::Table)
                    .col(
                        ColumnDef::new(AdminAuditLog::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AdminAuditLog::AdminSubject)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AdminAuditLog::Action).string().not_null())
                    .col(ColumnDef::new(AdminAuditLog::Target).string().not_null())
                    .col(ColumnDef::new(AdminAuditLog::Payload).string().null())
                    .col(
                        ColumnDef::new(AdminAuditLog::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Append-only triggers on admin_audit_log.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS admin_audit_log_no_update \
                 BEFORE UPDATE ON admin_audit_log \
                 BEGIN SELECT RAISE(ABORT, 'admin_audit_log is append-only'); END;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TRIGGER IF NOT EXISTS admin_audit_log_no_delete \
                 BEFORE DELETE ON admin_audit_log \
                 BEGIN SELECT RAISE(ABORT, 'admin_audit_log is append-only'); END;",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AdminAuditLog::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(GroupPolicy::Table).to_owned())
            .await
    }
}

/// Iden for the `group_policies` table.
#[derive(Iden)]
pub enum GroupPolicy {
    /// The table.
    #[iden = "group_policies"]
    Table,
    /// Primary key (UUID).
    Id,
    /// The group name (unique).
    GroupName,
    /// JSON array of allowed models (NULL = all allowed).
    AllowedModels,
    /// JSON array of allowed endpoints (NULL = all allowed).
    AllowedEndpoints,
    /// Daily token quota (NULL = unlimited).
    DailyTokenQuota,
    /// Daily request quota (NULL = unlimited).
    DailyRequestQuota,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Iden for the `admin_audit_log` table.
#[derive(Iden)]
pub enum AdminAuditLog {
    /// The table.
    #[iden = "admin_audit_log"]
    Table,
    /// Primary key (UUID).
    Id,
    /// The admin's subject (from the admin token).
    AdminSubject,
    /// The action performed (e.g. `upsert_policy`, `delete_policy`).
    Action,
    /// The target of the action (e.g. group name or device fingerprint).
    Target,
    /// The request payload (JSON), if any.
    Payload,
    /// Creation timestamp.
    CreatedAt,
}

/// Migration 0004: create the `usage_counters` table for quota tracking.
///
/// Each row tracks a user's cumulative usage (request count, token count,
/// cost) for a given period (daily or monthly). Updated incrementally per
/// request via UPSERT.
pub struct Migration0004UsageCounters;

impl MigrationName for Migration0004UsageCounters {
    fn name(&self) -> &str {
        "m000004_usage_counters"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0004UsageCounters {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UsageCounter::Table)
                    .col(
                        ColumnDef::new(UsageCounter::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UsageCounter::UserSubject)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UsageCounter::GroupName).string().null())
                    .col(ColumnDef::new(UsageCounter::PeriodDate).date().not_null())
                    .col(ColumnDef::new(UsageCounter::PeriodKind).string().not_null())
                    .col(
                        ColumnDef::new(UsageCounter::RequestCount)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UsageCounter::TokenCount)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UsageCounter::CostUsd)
                            .float()
                            .not_null()
                            .default(0.0),
                    )
                    .index(
                        Index::create()
                            .name("idx_usage_counters_unique")
                            .col(UsageCounter::UserSubject)
                            .col(UsageCounter::PeriodDate)
                            .col(UsageCounter::PeriodKind)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UsageCounter::Table).to_owned())
            .await
    }
}

/// Migration 0005: create the `providers`, `provider_keys`, and
/// `provider_key_access` tables for runtime-managed multi-provider support.
///
/// Providers are OpenAI-compatible backends managed via the admin API
/// (not config). Each provider declares the models it serves so central
/// can route by model name. Provider API keys are encrypted at rest with
/// AES-256-GCM; only ciphertext and nonce are stored. Group-based access
/// control on individual keys is enforced via `provider_key_access`.
pub struct Migration0005Providers;

impl MigrationName for Migration0005Providers {
    fn name(&self) -> &str {
        "m000005_providers"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0005Providers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Provider::Table)
                    .col(
                        ColumnDef::new(Provider::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Provider::Name).string().not_null())
                    .col(ColumnDef::new(Provider::BaseUrl).string().not_null())
                    .col(
                        ColumnDef::new(Provider::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Provider::IsDefault)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(Provider::Models).string().null())
                    .col(
                        ColumnDef::new(Provider::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Provider::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProviderKey::Table)
                    .col(
                        ColumnDef::new(ProviderKey::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ProviderKey::ProviderId).string().not_null())
                    .col(ColumnDef::new(ProviderKey::Label).string().not_null())
                    .col(
                        ColumnDef::new(ProviderKey::Priority)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(ProviderKey::Ciphertext).blob().not_null())
                    .col(ColumnDef::new(ProviderKey::Nonce).blob().not_null())
                    .col(ColumnDef::new(ProviderKey::KeyDigest).string().not_null())
                    .col(
                        ColumnDef::new(ProviderKey::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(ProviderKey::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProviderKey::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_provider_keys_provider")
                            .from(ProviderKey::Table, ProviderKey::ProviderId)
                            .to(Provider::Table, Provider::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProviderKeyAccess::Table)
                    .col(
                        ColumnDef::new(ProviderKeyAccess::ProviderKeyId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProviderKeyAccess::GroupName)
                            .string()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(ProviderKeyAccess::ProviderKeyId)
                            .col(ProviderKeyAccess::GroupName),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_provider_key_access_key")
                            .from(ProviderKeyAccess::Table, ProviderKeyAccess::ProviderKeyId)
                            .to(ProviderKey::Table, ProviderKey::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProviderKeyAccess::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ProviderKey::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Provider::Table).to_owned())
            .await
    }
}

/// Iden for the `providers` table.
#[derive(Iden)]
pub enum Provider {
    /// The table.
    #[iden = "providers"]
    Table,
    /// Primary key.
    Id,
    /// Human-readable name.
    Name,
    /// Base URL of the backend.
    BaseUrl,
    /// Whether the provider is enabled.
    Enabled,
    /// Whether this is the default provider.
    IsDefault,
    /// JSON array of model patterns (NULL = all models).
    Models,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Iden for the `provider_keys` table.
#[derive(Iden)]
pub enum ProviderKey {
    /// The table.
    #[iden = "provider_keys"]
    Table,
    /// Primary key (UUID).
    Id,
    /// The provider this key belongs to.
    ProviderId,
    /// Human-readable label.
    Label,
    /// Priority for selection (lower = higher priority).
    Priority,
    /// AES-256-GCM ciphertext.
    Ciphertext,
    /// 12-byte GCM nonce.
    Nonce,
    /// SHA-256 digest of plaintext (hex).
    KeyDigest,
    /// Whether the key is enabled.
    Enabled,
    /// Creation timestamp.
    CreatedAt,
    /// Last-update timestamp.
    UpdatedAt,
}

/// Iden for the `provider_key_access` table.
#[derive(Iden)]
pub enum ProviderKeyAccess {
    /// The table.
    #[iden = "provider_key_access"]
    Table,
    /// The provider key ID.
    ProviderKeyId,
    /// The group name.
    GroupName,
}

/// Iden for the `usage_counters` table.
#[derive(Iden)]
pub enum UsageCounter {
    /// The table.
    #[iden = "usage_counters"]
    Table,
    /// Primary key (UUID).
    Id,
    /// The user subject.
    UserSubject,
    /// The group name (optional, for group-level reporting).
    GroupName,
    /// The period date (e.g. 2026-08-25 for daily).
    PeriodDate,
    /// The period kind: `daily` or `monthly`.
    PeriodKind,
    /// Cumulative request count for the period.
    RequestCount,
    /// Cumulative token count for the period.
    TokenCount,
    /// Cumulative cost in USD for the period.
    CostUsd,
}

/// Migration 0006: add the token-saver feature to `group_policies` and
/// enrich `audit_log` with token-saver accounting.
///
/// The token-saver lets admins enable safe request optimisers per group. It
/// is added as columns on `group_policies`:
/// - `token_saver_enabled`: master on/off switch (default `false`).
/// - `max_input_tokens`: a per-request input-token budget. When a request
///   exceeds it, the oldest whole turns are dropped (never truncated) until
///   it fits. `NULL` disables budget trimming.
///
/// The audit log gains per-request accounting so admins can "watch what is
/// going on":
/// - `token_saver_applied`: whether the optimiser changed the request.
/// - `tokens_saved`: estimated tokens saved.
/// - `messages_dropped`: total whole messages removed (dups + budget + empty).
/// - `saver_reasons`: JSON array of human-readable reason tags.
///
/// All new columns are nullable, so existing rows remain valid. SQLite has no
/// `DROP COLUMN` for these ALTERed columns; the `down` path is a no-op
/// (consistent with the 0002 enrichment migration).
pub struct Migration0006TokenSaver;

impl MigrationName for Migration0006TokenSaver {
    fn name(&self) -> &str {
        "m000006_token_saver"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0006TokenSaver {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add token-saver columns to group_policies.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE group_policies \
                 ADD COLUMN token_saver_enabled BOOLEAN NOT NULL DEFAULT false;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE group_policies \
                 ADD COLUMN max_input_tokens BIGINT NULL;",
            )
            .await?;

        // Add token-saver accounting columns to audit_log.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE audit_log \
                 ADD COLUMN token_saver_applied BOOLEAN NULL;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE audit_log \
                 ADD COLUMN tokens_saved BIGINT NULL;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE audit_log \
                 ADD COLUMN messages_dropped BIGINT NULL;",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE audit_log \
                 ADD COLUMN saver_reasons TEXT NULL;",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite does not support DROP COLUMN before 3.35 for ALTERed
        // columns. This migration is forward-only in practice; no-op down.
        let _ = manager;
        Ok(())
    }
}

/// Migration 0007: add the RTK-adapted repeated-line collapse toggle to
/// `group_policies`.
///
/// `collapse_repeated_lines` lets admins enable the consecutive repeated-line
/// collapse pass (adapting RTK's log-line collapse) on top of the token
/// saver. It defaults to `false` — this pass is a more aggressive (still
/// audited) optimization that admins opt into explicitly.
pub struct Migration0007CollapseRepeatedLines;

impl MigrationName for Migration0007CollapseRepeatedLines {
    fn name(&self) -> &str {
        "m000007_collapse_repeated_lines"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration0007CollapseRepeatedLines {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE group_policies \
                 ADD COLUMN collapse_repeated_lines BOOLEAN NOT NULL DEFAULT false;",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let _ = manager;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::MigratorTrait;

    /// The full migration chain must be reversible and re-runnable: an
    /// operator resetting a database relies on `down` then `up` leaving a
    /// working schema. This also exercises every `down` implementation.
    #[tokio::test]
    async fn migrations_round_trip_down_then_up() {
        let url = oidc_agent_common::persistence::temp_sqlite_url("central-mig");
        let db = sea_orm::Database::connect(&url).await.expect("connect");

        // Up: fresh schema.
        Migrator::up(&db, None).await.expect("up");

        // The core tables exist and accept writes.
        {
            use sea_orm::ConnectionTrait;
            db.execute_unprepared(
                "INSERT INTO devices (id, cert_fingerprint, user_subject, revoked, created_at) \
                 VALUES ('d1', 'fp', 'u', 0, '2026-01-01 00:00:00')",
            )
            .await
            .expect("insert device");
        }

        // Down: everything is removed.
        Migrator::down(&db, None).await.expect("down");
        {
            use sea_orm::ConnectionTrait;
            let tables: Vec<String> = db
                .query_all(
                    sea_orm::Statement::from_string(
                        db.get_database_backend(),
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%seaql%'"
                        .to_string(),
                ),
                )
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

        // Up again: the schema is rebuilt and usable.
        Migrator::up(&db, None).await.expect("up again");
        {
            use sea_orm::ConnectionTrait;
            db.execute_unprepared(
                "INSERT INTO devices (id, cert_fingerprint, user_subject, revoked, created_at) \
                 VALUES ('d2', 'fp2', 'u2', 0, '2026-01-02 00:00:00')",
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
                "m000002_audit_enrichment",
                "m000003_group_policies",
                "m000004_usage_counters",
                "m000005_providers",
                "m000006_token_saver",
                "m000007_collapse_repeated_lines",
            ],
            "migration order is part of the schema contract"
        );
    }
}
