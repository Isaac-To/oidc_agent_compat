//! Sea-ORM migrations for the relay database.
//!
//! This module defines the initial schema migration and a [`Migrator`] that
//! implements [`MigratorTrait`] so the [`db`] module can run all migrations.

use sea_orm_migration::prelude::*;

/// The initial migration that creates the `identities` and `api_keys` tables.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Identity::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Identity::Id).uuid().not_null().primary_key())
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
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKey::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ApiKey::IdentityId).uuid().not_null())
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
        vec![Box::new(Migration)]
    }
}
