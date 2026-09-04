//! Sea-ORM entities for the relay's local database.
//!
//! The `api_key` entity has been removed — the relay no longer mints or
//! verifies local API keys (central is the sole token verification
//! authority). The `api_keys` table still exists in the schema (created by
//! migration 0001, extended by 0003) for downgrade compatibility, but no
//! Rust code references it.

pub mod identity;
pub mod relay_activity_log;
