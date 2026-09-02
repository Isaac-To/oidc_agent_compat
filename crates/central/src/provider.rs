//! Runtime-managed providers and encrypted provider API keys.
//!
//! Providers and their API keys are managed through the admin API and stored
//! in the central database. Provider key material is encrypted with
//! AES-256-GCM before persistence and is returned only as zeroizing plaintext
//! to the forwarding path. The admin API exposes metadata, never key
//! material.

use std::collections::HashSet;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Statement, Value,
};
// sha2 is used indirectly via crate::crypto::sha256_hex.
use uuid::Uuid;
use zeroize::Zeroizing;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::time_util;

use crate::entity::{provider, provider_key, provider_key_access};

/// Metadata about a provider key. Plaintext key material is intentionally
/// absent from this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderKeyInfo {
    /// Key identifier.
    pub id: String,
    /// Provider identifier.
    pub provider_id: String,
    /// Human-readable label.
    pub label: String,
    /// Selection priority; lower values are preferred.
    pub priority: i32,
    /// SHA-256 digest of the key, useful for identifying rotations.
    pub key_digest: String,
    /// Whether the key is eligible for selection.
    pub enabled: bool,
    /// Groups allowed to use this key. An empty list means unrestricted.
    pub allowed_groups: Vec<String>,
    /// Creation time.
    pub created_at: time::PrimitiveDateTime,
    /// Last update time.
    pub updated_at: time::PrimitiveDateTime,
}

/// A provider input used by create and update operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInput {
    /// Stable provider identifier.
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// OpenAI-compatible backend base URL.
    pub base_url: String,
    /// Whether the provider accepts traffic.
    pub enabled: bool,
    /// Whether this is the fallback provider.
    pub is_default: bool,
    /// Exact model names served by this provider. `None` means all models.
    pub models: Option<Vec<String>>,
}

/// An update to a provider, retaining its stable identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderUpdate {
    /// Human-readable provider name.
    pub name: String,
    /// OpenAI-compatible backend base URL.
    pub base_url: String,
    /// Whether the provider accepts traffic.
    pub enabled: bool,
    /// Whether this is the fallback provider.
    pub is_default: bool,
    /// Exact model names served by this provider. `None` means all models.
    pub models: Option<Vec<String>>,
}

/// An update to provider-key metadata and access rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderKeyUpdate {
    /// Human-readable label.
    pub label: String,
    /// Selection priority; lower values are preferred.
    pub priority: i32,
    /// Whether the key is eligible for selection.
    pub enabled: bool,
    /// Groups allowed to use this key. An empty list means unrestricted.
    pub allowed_groups: Vec<String>,
}

/// A decrypted key selected for one upstream request.
#[derive(Debug)]
pub struct ResolvedProviderKey {
    /// Key identifier, used to exclude it during fallback.
    pub id: String,
    /// Decrypted API key. It is zeroized when dropped.
    pub secret: Zeroizing<String>,
}

/// Provider store backed by the central database.
#[derive(Clone)]
pub struct ProviderStore {
    db: DatabaseConnection,
    encryption_key: Arc<Zeroizing<[u8; 32]>>,
}

impl ProviderStore {
    /// Creates a provider store with the supplied 32-byte encryption key.
    #[must_use]
    pub fn new(db: DatabaseConnection, encryption_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            db,
            encryption_key: Arc::new(encryption_key),
        }
    }

    /// Returns a reference to the underlying database connection.
    ///
    /// Mirrors [`crate::policy::PolicyStore::db`] so callers (and tests)
    /// can share one connection across stores.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Parses a 32-byte AES key from a hexadecimal string.
    ///
    /// Delegates to [`crate::crypto::encryption_key_from_hex`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the value is not exactly 64 hexadecimal
    /// characters long.
    pub fn encryption_key_from_hex(value: &str) -> Result<Zeroizing<[u8; 32]>> {
        crate::crypto::encryption_key_from_hex(value)
    }

    /// Lists all providers in stable identifier order.
    pub async fn list_providers(&self) -> Result<Vec<provider::Model>> {
        provider::Entity::find()
            .order_by_asc(provider::Column::Id)
            .all(&self.db)
            .await
            .map_err(|e| Error::database(format!("list providers: {e}")))
    }

    /// Gets one provider by identifier.
    pub async fn get_provider(&self, id: &str) -> Result<Option<provider::Model>> {
        provider::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("get provider: {e}")))
    }

    /// Creates or updates a provider.
    pub async fn upsert_provider(&self, input: &ProviderInput) -> Result<provider::Model> {
        validate_provider_input(input)?;
        let now = time_util::now_utc();
        let models = serialize_models(input.models.as_deref())?;
        let existing = self.get_provider(&input.id).await?;

        if let Some(existing) = existing {
            let active: provider::ActiveModel = existing.into();
            let mut active = active;
            active.name = sea_orm::Set(input.name.clone());
            active.base_url = sea_orm::Set(input.base_url.clone());
            active.enabled = sea_orm::Set(input.enabled);
            active.is_default = sea_orm::Set(input.is_default);
            active.models = sea_orm::Set(models);
            active.updated_at = sea_orm::Set(now);
            let updated = active
                .update(&self.db)
                .await
                .map_err(|e| Error::database(format!("update provider: {e}")))?;
            if input.is_default {
                self.clear_other_defaults(&input.id).await?;
            }
            Ok(updated)
        } else {
            let id = input.id.clone();
            self.db
                .execute(Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    "INSERT INTO providers (id, name, base_url, enabled, is_default, models, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    vec![
                        id.clone().into(),
                        input.name.clone().into(),
                        input.base_url.clone().into(),
                        Value::Bool(Some(input.enabled)),
                        Value::Bool(Some(input.is_default)),
                        models
                            .clone()
                            .map(|value| Value::String(Some(Box::new(value))))
                            .unwrap_or(Value::String(None)),
                        time_util::format_time(&now).into(),
                        time_util::format_time(&now).into(),
                    ],
                ))
                .await
                .map_err(|e| Error::database(format!("insert provider: {e}")))?;
            if input.is_default {
                self.clear_other_defaults(&input.id).await?;
            }
            self.get_provider(&id)
                .await?
                .ok_or_else(|| Error::database("provider inserted but could not be loaded"))
        }
    }

    /// Deletes a provider and its keys.
    pub async fn delete_provider(&self, id: &str) -> Result<bool> {
        let result = provider::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(|e| Error::database(format!("delete provider: {e}")))?;
        Ok(result.rows_affected > 0)
    }

    /// Marks exactly one provider as the default fallback.
    pub async fn set_default_provider(&self, id: &str) -> Result<()> {
        let provider = self
            .get_provider(id)
            .await?
            .ok_or_else(|| Error::Config(format!("provider '{id}' not found")))?;
        if !provider.enabled {
            return Err(Error::Config(
                "a disabled provider cannot be default".into(),
            ));
        }
        self.clear_other_defaults(id).await?;
        let mut active: provider::ActiveModel = provider.into();
        active.is_default = sea_orm::Set(true);
        active.updated_at = sea_orm::Set(time_util::now_utc());
        active
            .update(&self.db)
            .await
            .map_err(|e| Error::database(format!("set default provider: {e}")))?;
        Ok(())
    }

    /// Resolves an enabled provider by exact model name, falling back to the
    /// enabled default provider when no model-specific provider matches.
    pub async fn resolve_provider_for_model(
        &self,
        model: Option<&str>,
    ) -> Result<Option<provider::Model>> {
        let providers = self
            .list_providers()
            .await?
            .into_iter()
            .filter(|p| p.enabled)
            .collect::<Vec<_>>();
        if let Some(model) = model {
            for candidate in &providers {
                if candidate.models.is_some()
                    && provider_models_contain(candidate.models.as_deref(), model)
                {
                    return Ok(Some(candidate.clone()));
                }
            }
        }
        Ok(providers.into_iter().find(|p| p.is_default))
    }

    /// Lists key metadata for a provider. Plaintext is never returned.
    pub async fn list_keys(&self, provider_id: &str) -> Result<Vec<ProviderKeyInfo>> {
        let keys = provider_key::Entity::find()
            .filter(provider_key::Column::ProviderId.eq(provider_id))
            .order_by_asc(provider_key::Column::Priority)
            .order_by_asc(provider_key::Column::CreatedAt)
            .all(&self.db)
            .await
            .map_err(|e| Error::database(format!("list provider keys: {e}")))?;
        self.key_infos(keys).await
    }

    /// Adds an encrypted API key to a provider.
    pub async fn add_key(
        &self,
        provider_id: &str,
        label: &str,
        secret: &str,
        priority: i32,
        allowed_groups: &[String],
    ) -> Result<ProviderKeyInfo> {
        if self.get_provider(provider_id).await?.is_none() {
            return Err(Error::Config(format!("provider '{provider_id}' not found")));
        }
        validate_key_input(label, secret, allowed_groups)?;
        let (ciphertext, nonce) = encrypt(&self.encryption_key, secret)?;
        let now = time_util::now_utc();
        let key_id = Uuid::new_v4().to_string();
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "INSERT INTO provider_keys (id, provider_id, label, priority, ciphertext, nonce, key_digest, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                vec![
                    key_id.clone().into(),
                    provider_id.to_string().into(),
                    label.trim().to_string().into(),
                    priority.into(),
                    Value::Bytes(Some(Box::new(ciphertext))),
                    Value::Bytes(Some(Box::new(nonce.to_vec()))),
                    digest(secret).into(),
                    Value::Bool(Some(true)),
                    time_util::format_time(&now).into(),
                    time_util::format_time(&now).into(),
                ],
            ))
            .await
            .map_err(|e| Error::database(format!("insert provider key: {e}")))?;
        let key = provider_key::Entity::find_by_id(&key_id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("load provider key: {e}")))?
            .ok_or_else(|| Error::database("provider key inserted but could not be loaded"))?;
        self.replace_access(&key.id, allowed_groups).await?;
        let groups = self.key_access_groups(&key.id).await?;
        self.key_info(key, groups)
    }

    /// Gets a single key row scoped to a provider, if it exists.
    ///
    /// Returns `Ok(None)` when the key does not exist for this provider
    /// (including when it belongs to a different provider).
    pub async fn get_key(
        &self,
        provider_id: &str,
        key_id: &str,
    ) -> Result<Option<provider_key::Model>> {
        provider_key::Entity::find()
            .filter(provider_key::Column::Id.eq(key_id))
            .filter(provider_key::Column::ProviderId.eq(provider_id))
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("get provider key: {e}")))
    }

    /// Updates key metadata and its group access list. Plaintext is not
    /// accepted or changed by this method; adding a replacement key is the
    /// key-rotation operation.
    pub async fn update_key(
        &self,
        provider_id: &str,
        key_id: &str,
        update: &ProviderKeyUpdate,
    ) -> Result<ProviderKeyInfo> {
        validate_key_input(
            &update.label,
            "placeholder-not-used",
            &update.allowed_groups,
        )?;
        let key = provider_key::Entity::find_by_id(key_id)
            .one(&self.db)
            .await
            .map_err(|e| Error::database(format!("get provider key: {e}")))?
            .ok_or_else(|| Error::Config(format!("provider key '{key_id}' not found")))?;
        if key.provider_id != provider_id {
            return Err(Error::Config(format!(
                "provider key '{key_id}' not found for provider '{provider_id}'"
            )));
        }
        let mut active: provider_key::ActiveModel = key.into();
        active.label = sea_orm::Set(update.label.trim().to_string());
        active.priority = sea_orm::Set(update.priority);
        active.enabled = sea_orm::Set(update.enabled);
        active.updated_at = sea_orm::Set(time_util::now_utc());
        let key = active
            .update(&self.db)
            .await
            .map_err(|e| Error::database(format!("update provider key: {e}")))?;
        self.replace_access(&key.id, &update.allowed_groups).await?;
        // Return the persisted access list so the response reflects the
        // canonical (sorted) storage order.
        let groups = self.key_access_groups(&key.id).await?;
        self.key_info(key, groups)
    }

    /// Deletes a provider key.
    pub async fn delete_key(&self, provider_id: &str, key_id: &str) -> Result<bool> {
        let result = provider_key::Entity::delete_many()
            .filter(provider_key::Column::Id.eq(key_id))
            .filter(provider_key::Column::ProviderId.eq(provider_id))
            .exec(&self.db)
            .await
            .map_err(|e| Error::database(format!("delete provider key: {e}")))?;
        Ok(result.rows_affected > 0)
    }

    /// Resolves the highest-priority enabled key authorized for the supplied
    /// groups, excluding keys already tried for this request.
    pub async fn resolve_key(
        &self,
        provider_id: &str,
        groups: &[String],
        excluded_key_ids: &HashSet<String>,
    ) -> Result<Option<ResolvedProviderKey>> {
        let keys = provider_key::Entity::find()
            .filter(provider_key::Column::ProviderId.eq(provider_id))
            .filter(provider_key::Column::Enabled.eq(true))
            .order_by_asc(provider_key::Column::Priority)
            .order_by_asc(provider_key::Column::CreatedAt)
            .all(&self.db)
            .await
            .map_err(|e| Error::database(format!("resolve provider key: {e}")))?;
        let group_set: HashSet<&str> = groups.iter().map(String::as_str).collect();
        for key in keys {
            if excluded_key_ids.contains(&key.id) {
                continue;
            }
            let access = self.key_access_groups(&key.id).await?;
            if !access.is_empty() && !access.iter().any(|g| group_set.contains(g.as_str())) {
                continue;
            }
            let secret = decrypt(&self.encryption_key, &key.ciphertext, &key.nonce)?;
            return Ok(Some(ResolvedProviderKey { id: key.id, secret }));
        }
        Ok(None)
    }

    async fn clear_other_defaults(&self, except_id: &str) -> Result<()> {
        let defaults = provider::Entity::find()
            .filter(provider::Column::IsDefault.eq(true))
            .filter(provider::Column::Id.ne(except_id))
            .all(&self.db)
            .await
            .map_err(|e| Error::database(format!("find default providers: {e}")))?;
        for item in defaults {
            let mut active: provider::ActiveModel = item.into();
            active.is_default = sea_orm::Set(false);
            active.updated_at = sea_orm::Set(time_util::now_utc());
            active
                .update(&self.db)
                .await
                .map_err(|e| Error::database(format!("clear default provider: {e}")))?;
        }
        Ok(())
    }

    async fn key_infos(&self, keys: Vec<provider_key::Model>) -> Result<Vec<ProviderKeyInfo>> {
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            let groups = self.key_access_groups(&key.id).await?;
            result.push(self.key_info(key, groups)?);
        }
        Ok(result)
    }

    /// Lists the group names allowed to use a provider key. An empty list
    /// means the key is unrestricted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn key_access_groups(&self, key_id: &str) -> Result<Vec<String>> {
        provider_key_access::Entity::find()
            .filter(provider_key_access::Column::ProviderKeyId.eq(key_id))
            .order_by_asc(provider_key_access::Column::GroupName)
            .all(&self.db)
            .await
            .map(|rows| rows.into_iter().map(|row| row.group_name).collect())
            .map_err(|e| Error::database(format!("load provider key access: {e}")))
    }

    async fn replace_access(&self, key_id: &str, groups: &[String]) -> Result<()> {
        provider_key_access::Entity::delete_many()
            .filter(provider_key_access::Column::ProviderKeyId.eq(key_id))
            .exec(&self.db)
            .await
            .map_err(|e| Error::database(format!("clear provider key access: {e}")))?;
        for group in groups {
            let group = group.trim();
            if group.is_empty() {
                continue;
            }
            provider_key_access::ActiveModel {
                provider_key_id: sea_orm::Set(key_id.to_string()),
                group_name: sea_orm::Set(group.to_string()),
            }
            .insert(&self.db)
            .await
            .map_err(|e| Error::database(format!("insert provider key access: {e}")))?;
        }
        Ok(())
    }

    fn key_info(
        &self,
        key: provider_key::Model,
        allowed_groups: Vec<String>,
    ) -> Result<ProviderKeyInfo> {
        Ok(ProviderKeyInfo {
            id: key.id,
            provider_id: key.provider_id,
            label: key.label,
            priority: key.priority,
            key_digest: key.key_digest,
            enabled: key.enabled,
            allowed_groups,
            created_at: key.created_at,
            updated_at: key.updated_at,
        })
    }
}

fn validate_provider_input(input: &ProviderInput) -> Result<()> {
    if input.id.trim().is_empty() || input.id.len() > 128 {
        return Err(Error::Config("provider id must be 1-128 characters".into()));
    }
    if input.name.trim().is_empty() || input.name.len() > 256 {
        return Err(Error::Config(
            "provider name must be 1-256 characters".into(),
        ));
    }
    validate_base_url(&input.base_url)?;
    if let Some(models) = &input.models {
        if models.iter().any(|m| m.trim().is_empty()) {
            return Err(Error::Config(
                "provider model names must not be empty".into(),
            ));
        }
    }
    Ok(())
}

fn validate_base_url(base_url: &str) -> Result<()> {
    let value = base_url.trim_end_matches('/');
    if !(value.starts_with("https://") || value.starts_with("http://")) || value.len() <= 8 {
        return Err(Error::Config(
            "provider base_url must be a non-empty http(s) URL".into(),
        ));
    }
    if value.contains('@') {
        return Err(Error::Config(
            "provider base_url must not contain userinfo".into(),
        ));
    }
    Ok(())
}

fn validate_key_input(label: &str, secret: &str, groups: &[String]) -> Result<()> {
    if label.trim().is_empty() || label.len() > 256 {
        return Err(Error::Config(
            "provider key label must be 1-256 characters".into(),
        ));
    }
    if secret.is_empty() {
        return Err(Error::Config("provider key must not be empty".into()));
    }
    if groups.iter().any(|group| group.trim().is_empty()) {
        return Err(Error::Config(
            "provider key access groups must not be empty".into(),
        ));
    }
    Ok(())
}

fn serialize_models(models: Option<&[String]>) -> Result<Option<String>> {
    models
        .map(|models| {
            serde_json::to_string(models)
                .map_err(|e| Error::Config(format!("serialize provider models: {e}")))
        })
        .transpose()
}

fn provider_models_contain(models: Option<&str>, requested: &str) -> bool {
    models
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .map(|values| values.iter().any(|value| value == requested))
        .unwrap_or(models.is_none())
}

fn digest(secret: &str) -> String {
    crate::crypto::sha256_hex(secret.as_bytes())
}

fn encrypt(key: &[u8; 32], secret: &str) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::crypto("invalid provider encryption key"))?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|_| Error::crypto("encrypt provider key"))?;
    Ok((ciphertext, nonce_bytes))
}

fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<String>> {
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::crypto("invalid provider key nonce"))?;
    let nonce = Nonce::from(*nonce);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::crypto("invalid provider encryption key"))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::crypto("decrypt provider key"))?;
    let value =
        String::from_utf8(plaintext).map_err(|_| Error::crypto("provider key is not UTF-8"));
    value.map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ActiveModelTrait;

    /// Builds a provider store over a fresh temp SQLite database.
    async fn setup_store() -> ProviderStore {
        setup_store_with_key(Zeroizing::new([7_u8; 32])).await
    }

    /// Builds a provider store over a fresh temp SQLite database with a
    /// caller-chosen encryption key, returning the database URL so a second
    /// store (e.g. with a wrong key) can be opened over the same data.
    async fn setup_store_with_key(key: Zeroizing<[u8; 32]>) -> ProviderStore {
        let url = oidc_agent_common::persistence::temp_sqlite_url("provider-store");
        let db = crate::db::setup(&url).await.expect("db setup");
        ProviderStore::new(db, key)
    }

    /// A valid provider input for tests.
    fn provider_input(id: &str) -> ProviderInput {
        ProviderInput {
            id: id.into(),
            name: format!("name-{id}"),
            base_url: format!("https://{id}.example.com"),
            enabled: true,
            is_default: false,
            models: None,
        }
    }

    #[tokio::test]
    async fn upsert_inserts_then_updates_without_duplicating() {
        let store = setup_store().await;
        let created = store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("insert");
        assert_eq!(created.id, "openai");
        assert!(!created.is_default);

        let mut input = provider_input("openai");
        input.name = "renamed".into();
        input.base_url = "https://v2.example.com".into();
        let updated = store.upsert_provider(&input).await.expect("update");
        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.base_url, "https://v2.example.com");
        assert_eq!(
            updated.created_at, created.created_at,
            "created_at preserved"
        );

        assert_eq!(store.list_providers().await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn delete_provider_cascades_to_keys_and_access() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .add_key("openai", "key", "sk-secret", 0, &["eng".into()])
            .await
            .expect("key");

        assert!(store.delete_provider("openai").await.expect("delete"));
        assert!(store.get_provider("openai").await.expect("get").is_none());
        assert!(
            store
                .list_keys("openai")
                .await
                .expect("list keys")
                .is_empty()
        );
        assert!(!store.delete_provider("openai").await.expect("re-delete"));
    }

    #[tokio::test]
    async fn setting_default_clears_previous_default() {
        let store = setup_store().await;
        let mut first = provider_input("a");
        first.is_default = true;
        store.upsert_provider(&first).await.expect("first");
        store
            .upsert_provider(&provider_input("b"))
            .await
            .expect("second");

        store.set_default_provider("b").await.expect("set default");

        let a = store
            .get_provider("a")
            .await
            .expect("get a")
            .expect("exists");
        let b = store
            .get_provider("b")
            .await
            .expect("get b")
            .expect("exists");
        assert!(!a.is_default);
        assert!(b.is_default);
    }

    #[tokio::test]
    async fn set_default_rejects_missing_or_disabled_provider() {
        let store = setup_store().await;
        assert!(store.set_default_provider("missing").await.is_err());

        let mut disabled = provider_input("disabled");
        disabled.enabled = false;
        store.upsert_provider(&disabled).await.expect("insert");
        assert!(store.set_default_provider("disabled").await.is_err());
    }

    #[tokio::test]
    async fn routing_prefers_model_specific_over_catch_all_and_default() {
        let store = setup_store().await;

        let mut specific = provider_input("specific");
        specific.models = Some(vec!["model-a".into()]);
        store.upsert_provider(&specific).await.expect("specific");

        let mut catch_all = provider_input("catch-all");
        catch_all.models = None;
        catch_all.is_default = true;
        store.upsert_provider(&catch_all).await.expect("catch-all");

        let resolved = store
            .resolve_provider_for_model(Some("model-a"))
            .await
            .expect("resolve")
            .expect("some provider");
        assert_eq!(resolved.id, "specific");

        let fallback = store
            .resolve_provider_for_model(Some("model-zz"))
            .await
            .expect("resolve")
            .expect("default provider");
        assert_eq!(fallback.id, "catch-all");

        // Exact matching only — a prefix of a served model must not match.
        let no_prefix_match = store
            .resolve_provider_for_model(Some("model"))
            .await
            .expect("resolve")
            .expect("default for prefix");
        assert_eq!(no_prefix_match.id, "catch-all");
    }

    #[tokio::test]
    async fn disabled_providers_are_skipped_for_routing() {
        let store = setup_store().await;

        let mut disabled = provider_input("disabled");
        disabled.enabled = false;
        disabled.models = Some(vec!["model-a".into()]);
        store.upsert_provider(&disabled).await.expect("disabled");

        let mut fallback = provider_input("fallback");
        fallback.is_default = true;
        store.upsert_provider(&fallback).await.expect("fallback");

        let resolved = store
            .resolve_provider_for_model(Some("model-a"))
            .await
            .expect("resolve")
            .expect("some provider");
        assert_eq!(resolved.id, "fallback");
    }

    #[tokio::test]
    async fn routing_without_providers_or_match_returns_none() {
        let store = setup_store().await;
        assert!(
            store
                .resolve_provider_for_model(Some("model-a"))
                .await
                .expect("resolve")
                .is_none()
        );

        store
            .upsert_provider(&provider_input("a"))
            .await
            .expect("insert");
        assert!(
            store
                .resolve_provider_for_model(Some("model-a"))
                .await
                .expect("resolve")
                .is_none(),
            "no default and no model match must resolve to None"
        );
    }

    #[tokio::test]
    async fn add_key_stores_digest_and_ciphertext_not_plaintext() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        let info = store
            .add_key("openai", "prod", "sk-plaintext-secret", 0, &[])
            .await
            .expect("add key");

        assert_eq!(info.key_digest, digest("sk-plaintext-secret"));

        // At-rest check: the stored row must not contain the plaintext.
        let row = provider_key::Entity::find_by_id(&info.id)
            .one(store_db(&store))
            .await
            .expect("load row")
            .expect("row exists");
        assert_ne!(row.ciphertext, b"sk-plaintext-secret".to_vec());
        assert_ne!(
            String::from_utf8_lossy(&row.ciphertext),
            "sk-plaintext-secret"
        );
        assert_eq!(row.nonce.len(), 12, "GCM nonce must be 96 bits");
        assert!(row.enabled);
    }

    #[tokio::test]
    async fn key_metadata_never_contains_plaintext() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .add_key("openai", "prod", "sk-never-appear", 0, &[])
            .await
            .expect("add key");

        let keys = store.list_keys("openai").await.expect("list keys");
        assert_eq!(keys.len(), 1);
        let rendered = format!("{keys:?}");
        assert!(
            !rendered.contains("sk-never-appear"),
            "key metadata must not contain plaintext"
        );
    }

    #[tokio::test]
    async fn nonces_are_unique_per_key() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        let first = store
            .add_key("openai", "one", "sk-a", 0, &[])
            .await
            .expect("key one");
        let second = store
            .add_key("openai", "two", "sk-a", 0, &[])
            .await
            .expect("key two");

        let rows = provider_key::Entity::find()
            .all(store_db(&store))
            .await
            .expect("rows");
        let nonce_of = |id: &str| {
            rows.iter()
                .find(|row| row.id == id)
                .map(|row| row.nonce.clone())
        };
        assert_ne!(
            nonce_of(&first.id).expect("first nonce"),
            nonce_of(&second.id).expect("second nonce"),
            "identical plaintexts must still use distinct nonces"
        );
    }

    #[tokio::test]
    async fn update_key_changes_metadata_and_groups() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .upsert_provider(&provider_input("other"))
            .await
            .expect("other provider");
        let info = store
            .add_key("openai", "old-label", "sk-secret", 5, &["eng".into()])
            .await
            .expect("add key");

        let updated = store
            .update_key(
                "openai",
                &info.id,
                &ProviderKeyUpdate {
                    label: "new-label".into(),
                    priority: 1,
                    enabled: false,
                    allowed_groups: vec!["sales".into(), "eng".into()],
                },
            )
            .await
            .expect("update key");
        assert_eq!(updated.label, "new-label");
        assert_eq!(updated.priority, 1);
        assert!(!updated.enabled);
        assert_eq!(
            updated.allowed_groups,
            vec![String::from("eng"), String::from("sales")]
        );

        // Cross-provider updates must be rejected.
        assert!(
            store
                .update_key(
                    "other",
                    &info.id,
                    &ProviderKeyUpdate {
                        label: "hijack".into(),
                        priority: 0,
                        enabled: true,
                        allowed_groups: vec![],
                    },
                )
                .await
                .is_err()
        );
        // Updating a missing key must fail.
        assert!(
            store
                .update_key(
                    "openai",
                    "missing-key",
                    &ProviderKeyUpdate {
                        label: "x".into(),
                        priority: 0,
                        enabled: true,
                        allowed_groups: vec![],
                    },
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn delete_key_is_provider_scoped() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .upsert_provider(&provider_input("other"))
            .await
            .expect("other provider");
        let info = store
            .add_key("openai", "key", "sk-secret", 0, &[])
            .await
            .expect("add key");

        assert!(
            !store
                .delete_key("other", &info.id)
                .await
                .expect("wrong provider delete"),
            "deleting via the wrong provider must not remove the key"
        );
        assert!(store.list_keys("openai").await.expect("list").len() == 1);

        assert!(store.delete_key("openai", &info.id).await.expect("delete"));
        assert!(store.list_keys("openai").await.expect("list").is_empty());
        assert!(
            !store
                .delete_key("openai", &info.id)
                .await
                .expect("re-delete")
        );
    }

    #[tokio::test]
    async fn add_key_rejects_missing_provider_and_bad_input() {
        let store = setup_store().await;
        assert!(
            store
                .add_key("missing", "label", "sk-secret", 0, &[])
                .await
                .is_err(),
            "keys require an existing provider"
        );

        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        assert!(
            store
                .add_key("openai", "", "sk-secret", 0, &[])
                .await
                .is_err(),
            "empty label rejected"
        );
        assert!(
            store.add_key("openai", "label", "", 0, &[]).await.is_err(),
            "empty secret rejected"
        );
        assert!(
            store
                .add_key("openai", "label", "sk-secret", 0, &["".into()])
                .await
                .is_err(),
            "empty group name rejected"
        );
    }

    #[tokio::test]
    async fn resolve_key_respects_priority_then_group_acl() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        // Priority 0 restricted to eng; priority 1 unrestricted.
        let restricted = store
            .add_key("openai", "eng-only", "sk-eng", 0, &["eng".into()])
            .await
            .expect("restricted key");
        store
            .add_key("openai", "shared", "sk-shared", 1, &[])
            .await
            .expect("shared key");

        // Matching group gets the higher-priority restricted key.
        let for_eng = store
            .resolve_key("openai", &["eng".into()], &HashSet::new())
            .await
            .expect("resolve")
            .expect("some key");
        assert_eq!(for_eng.id, restricted.id);
        assert_eq!(&*for_eng.secret, "sk-eng");

        // Non-matching group falls through to the unrestricted key.
        let for_sales = store
            .resolve_key("openai", &["sales".into()], &HashSet::new())
            .await
            .expect("resolve")
            .expect("some key");
        assert_eq!(&*for_sales.secret, "sk-shared");

        // No groups at all still uses the unrestricted key.
        let anonymous = store
            .resolve_key("openai", &[], &HashSet::new())
            .await
            .expect("resolve")
            .expect("some key");
        assert_eq!(&*anonymous.secret, "sk-shared");
    }

    #[tokio::test]
    async fn resolve_key_skips_disabled_and_excluded_keys() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        let primary = store
            .add_key("openai", "primary", "sk-primary", 0, &[])
            .await
            .expect("primary");
        let secondary = store
            .add_key("openai", "secondary", "sk-secondary", 1, &[])
            .await
            .expect("secondary");

        // Excluding the primary yields the secondary.
        let mut excluded = HashSet::new();
        excluded.insert(primary.id.clone());
        let next = store
            .resolve_key("openai", &[], &excluded)
            .await
            .expect("resolve")
            .expect("some key");
        assert_eq!(next.id, secondary.id);

        // Disabling the primary makes it ineligible even without exclusions.
        store
            .update_key(
                "openai",
                &primary.id,
                &ProviderKeyUpdate {
                    label: "primary".into(),
                    priority: 0,
                    enabled: false,
                    allowed_groups: vec![],
                },
            )
            .await
            .expect("disable");
        let resolved = store
            .resolve_key("openai", &[], &HashSet::new())
            .await
            .expect("resolve")
            .expect("some key");
        assert_eq!(resolved.id, secondary.id);

        // Excluding every key resolves to None.
        excluded.insert(secondary.id.clone());
        assert!(
            store
                .resolve_key("openai", &[], &excluded)
                .await
                .expect("resolve")
                .is_none()
        );
    }

    #[tokio::test]
    async fn resolve_key_returns_none_when_all_keys_restricted() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .add_key("openai", "eng", "sk-eng", 0, &["eng".into()])
            .await
            .expect("key");
        assert!(
            store
                .resolve_key("openai", &["sales".into()], &HashSet::new())
                .await
                .expect("resolve")
                .is_none()
        );
    }

    #[tokio::test]
    async fn wrong_encryption_key_cannot_read_stored_keys() {
        let url = oidc_agent_common::persistence::temp_sqlite_url("wrong-mek");
        let db = crate::db::setup(&url).await.expect("db setup");
        let store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        store
            .add_key("openai", "key", "sk-secret", 0, &[])
            .await
            .expect("key");

        let wrong_key_store = ProviderStore::new(db, Zeroizing::new([8_u8; 32]));
        let err = wrong_key_store
            .resolve_key("openai", &[], &HashSet::new())
            .await
            .expect_err("decryption with the wrong key must fail");
        assert!(
            err.to_string().contains("decrypt"),
            "expected a crypto decrypt error, got: {err}"
        );
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_to_decrypt() {
        let store = setup_store().await;
        store
            .upsert_provider(&provider_input("openai"))
            .await
            .expect("provider");
        let info = store
            .add_key("openai", "key", "sk-secret", 0, &[])
            .await
            .expect("key");

        // Corrupt the stored ciphertext directly in the database.
        let row = provider_key::Entity::find_by_id(&info.id)
            .one(store_db(&store))
            .await
            .expect("load")
            .expect("row");
        let mut active: provider_key::ActiveModel = row.into();
        let mut tampered = match active.ciphertext.clone() {
            sea_orm::ActiveValue::Set(value) | sea_orm::ActiveValue::Unchanged(value) => value,
            sea_orm::ActiveValue::NotSet => vec![0_u8; 16],
        };
        if tampered.is_empty() {
            tampered = vec![0_u8; 16];
        } else {
            tampered[0] ^= 0xFF;
        }
        active.ciphertext = sea_orm::Set(tampered);
        active
            .update(store_db(&store))
            .await
            .expect("tamper persist");

        let err = store
            .resolve_key("openai", &[], &HashSet::new())
            .await
            .expect_err("tampered ciphertext must fail authentication");
        assert!(
            err.to_string().contains("decrypt"),
            "expected a crypto decrypt error, got: {err}"
        );
    }

    #[tokio::test]
    async fn provider_validation_rejects_bad_input() {
        let store = setup_store().await;

        let mut empty_id = provider_input("");
        empty_id.id = "   ".into();
        assert!(store.upsert_provider(&empty_id).await.is_err());

        let mut long_name = provider_input("openai");
        long_name.name = "x".repeat(257);
        assert!(store.upsert_provider(&long_name).await.is_err());

        let mut ftp_url = provider_input("openai");
        ftp_url.base_url = "ftp://example.com".into();
        assert!(store.upsert_provider(&ftp_url).await.is_err());

        let mut userinfo_url = provider_input("openai");
        userinfo_url.base_url = "https://user:pass@example.com".into();
        assert!(store.upsert_provider(&userinfo_url).await.is_err());

        let mut short_url = provider_input("openai");
        short_url.base_url = "https://".into();
        assert!(store.upsert_provider(&short_url).await.is_err());

        let mut empty_model = provider_input("openai");
        empty_model.models = Some(vec!["".into()]);
        assert!(store.upsert_provider(&empty_model).await.is_err());
    }

    #[test]
    fn parses_hex_encryption_key() {
        let key = ProviderStore::encryption_key_from_hex(&"ab".repeat(32)).expect("valid key");
        assert_eq!(key[0], 0xab);
        assert_eq!(key[31], 0xab);
        let with_newline = "ab".repeat(32) + "\n";
        assert_eq!(
            ProviderStore::encryption_key_from_hex(&with_newline)
                .expect("trims whitespace")
                .len(),
            32
        );
    }

    #[test]
    fn rejects_invalid_encryption_key() {
        assert!(ProviderStore::encryption_key_from_hex("not-a-key").is_err());
        assert!(ProviderStore::encryption_key_from_hex(&"zz".repeat(32)).is_err());
        assert!(ProviderStore::encryption_key_from_hex(&"ab".repeat(31)).is_err());
        assert!(ProviderStore::encryption_key_from_hex(&"ab".repeat(33)).is_err());
    }

    #[test]
    fn provider_model_matching_is_exact() {
        let models = serde_json::to_string(&vec!["model-a", "model-b"]).expect("serialize");
        assert!(provider_models_contain(Some(&models), "model-a"));
        assert!(!provider_models_contain(Some(&models), "model"));
        assert!(!provider_models_contain(Some(&models), "MODEL-A"));
        assert!(provider_models_contain(None, "anything"));
        assert!(
            !provider_models_contain(Some("not-json"), "anything"),
            "unparseable model lists must not match"
        );
    }

    #[test]
    fn encrypt_round_trip_and_key_sensitivity() {
        let key = [7_u8; 32];
        let (ciphertext, nonce) = encrypt(&key, "secret-key").expect("encrypt");
        let plaintext = decrypt(&key, &ciphertext, &nonce).expect("decrypt");
        assert_eq!(&*plaintext, "secret-key");
        assert!(decrypt(&[8_u8; 32], &ciphertext, &nonce).is_err());

        // Tampering with either the ciphertext or the nonce must fail.
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;
        assert!(decrypt(&key, &tampered, &nonce).is_err());
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0xFF;
        assert!(decrypt(&key, &ciphertext, &bad_nonce).is_err());
        assert!(decrypt(&key, &ciphertext, &nonce[..8]).is_err());
    }

    #[test]
    fn digest_is_sha256_hex() {
        // Known SHA-256 vector: sha256("abc") starts with ba7816bf.
        assert!(digest("abc").starts_with("ba7816bf"));
        assert_eq!(digest("abc").len(), 64);
    }

    /// Returns a reference to the store's database connection for
    /// at-rest assertions in tests. Private fields are visible to this
    /// child module.
    fn store_db(store: &ProviderStore) -> &DatabaseConnection {
        &store.db
    }
}
